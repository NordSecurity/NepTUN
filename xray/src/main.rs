mod client;
mod event_loop;
mod key_pair;
mod pcap;
mod utils;

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::SystemTimeError,
};

use neptun::noise::{Tunn, TunnResult};

use ::pcap::Error as PcapError;
use clap::Parser;
use color_eyre::eyre::Result as EyreResult;

use tokio::{
    net::UdpSocket,
    sync::mpsc::{self, error::SendError},
};

use crate::{
    client::Client,
    event_loop::EventLoop,
    key_pair::KeyPair,
    pcap::process_pcap,
    utils::{configure_wg, run_command, write_to_csv, TestCmd},
};

const WG_NAME: &str = "xraywg1";

const WG_PORT: u16 = 41414;
const PLAINTEXT_PORT: u16 = 52525;
const CRYPTO_PORT: u16 = 63636;

const WG_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(100, 66, 0, 1), WG_PORT);
const PLAINTEXT_ADDR: SocketAddrV4 = SocketAddrV4::new(*WG_ADDR.ip(), PLAINTEXT_PORT);
const CRYPTO_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(100, 66, 0, 2), CRYPTO_PORT);
const CRYPTO_SOCK_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), CRYPTO_PORT);

type XRayResult<T> = Result<T, XRayError>;

#[derive(thiserror::Error, Debug)]
enum XRayError {
    #[error("IO error: {0:?}")]
    Io(#[from] std::io::Error),
    #[error("CSV error: {0:?}")]
    Csv(#[from] csv::Error),
    #[error("Command error: {0}")]
    ShellCommand(String),
    #[error("Handshake timed out")]
    HandshakeTimedOut,
    #[error("Unexpected TunnResult: {0:?}")]
    UnexpectedTunnResult(String),
    #[error("Unexpected packet type: {0}")]
    UnexpectedPacketType(u8),
    #[error("IPv6 is currently not supported")]
    Ipv6,
    #[error("Could not parse packet")]
    PacketParse,
    #[error("Unknown adapter type: {0}")]
    UnknownAdapter(String),
    #[error("SystemTimeError: {0:?}")]
    Time(#[from] SystemTimeError),
    #[error("Failed to send command over channel: {0:?}")]
    ChannelSend(#[from] SendError<TestCmd>),
    #[error("Pcap error: {0:?}")]
    Pcap(#[from] PcapError),
}

impl From<TunnResult<'_>> for XRayError {
    fn from(tunn_res: TunnResult<'_>) -> Self {
        Self::UnexpectedTunnResult(format!("{tunn_res:?}"))
    }
}

#[derive(Parser)]
struct CliArgs {
    #[arg(long, default_value = "neptun")]
    wg: String,
    #[arg(long, default_value = "crypto")]
    test_type: String,
    #[arg(long, default_value_t = 10)]
    packet_count: usize,
    #[arg(long)]
    csv_path: Option<String>,
    #[arg(long)]
    pcap_path: Option<String>,
}

impl CliArgs {
    fn csv_path(&self) -> String {
        self.csv_path.as_ref().cloned().unwrap_or_else(|| {
            format!(
                "results/xray_{}_{}_{}.csv",
                self.wg, self.test_type, self.packet_count
            )
        })
    }

    fn pcap_path(&self) -> String {
        self.pcap_path.as_ref().cloned().unwrap_or_else(|| {
            format!(
                "results/xray_{}_{}_{}.pcap",
                self.wg, self.test_type, self.packet_count
            )
        })
    }
}

#[tokio::main]
async fn main() -> EyreResult<()> {
    color_eyre::install()?;

    let cli_args = CliArgs::parse();

    let test_type = cli_args.test_type.clone();
    let packet_count = cli_args.packet_count;
    let csv_path = cli_args.csv_path();
    let pcap_path = cli_args.pcap_path();

    let wg_keys = KeyPair::new();
    let peer_keys = KeyPair::new();

    println!("Configuring wireguard with adapter type {}", cli_args.wg);
    configure_wg(
        cli_args.wg.as_str(),
        WG_NAME,
        &wg_keys,
        &peer_keys,
        WG_ADDR.port(),
        &[*WG_ADDR.ip()],
    )
    .await?;

    let (cmd_tx, cmd_rx) = mpsc::channel::<TestCmd>(100);

    let plaintext_sock = UdpSocket::bind(PLAINTEXT_ADDR).await?;
    let plaintext_client = Client::new(PLAINTEXT_ADDR, None, plaintext_sock);

    let crypto_sock = UdpSocket::bind(CRYPTO_SOCK_ADDR).await?;
    let tunn = Tunn::new(peer_keys.private, wg_keys.public, None, None, 123, None)
        .map_err(|s| XRayError::UnexpectedTunnResult(s.to_owned()))?;
    let mut crypto_client = Client::new(CRYPTO_ADDR, Some(tunn), crypto_sock);
    crypto_client.do_handshake(WG_ADDR).await?;

    let event_loop = EventLoop::new(cli_args, WG_ADDR, crypto_client, plaintext_client, cmd_rx);
    let task = tokio::task::spawn(event_loop.run());

    println!("Starting {test_type} test with {packet_count} packets");
    for i in 0..packet_count {
        if test_type == "crypto" {
            cmd_tx
                .send(TestCmd::SendEncrypted {
                    sock_dst: WG_ADDR,
                    packet_dst: PLAINTEXT_ADDR,
                    send_index: i as u64,
                })
                .await?;
        } else {
            cmd_tx
                .send(TestCmd::SendPlaintext {
                    dst: CRYPTO_ADDR,
                    send_index: i as u64,
                })
                .await?;
        }
    }
    cmd_tx.send(TestCmd::Done).await?;
    let mut event_loop = task.await.expect("Awaiting task should be successful")?;

    run_command("killall -w tcpdump".to_owned())
        .map_err(|s| XRayError::ShellCommand(s.to_owned()))?;
    let pcap_packets = process_pcap(&pcap_path, event_loop.tunn())?;

    let allowed_ports = [WG_PORT, PLAINTEXT_PORT, CRYPTO_PORT];
    let mut packets = event_loop.packets;
    for p in pcap_packets {
        if !allowed_ports.contains(&p.src.port()) || !allowed_ports.contains(&p.dst.port()) {
            continue;
        }
        match (test_type.as_str(), p.src.port(), p.dst.port()) {
            ("crypto", CRYPTO_PORT, WG_PORT) => {
                packets[p.send_index as usize].pre_wg_ts = Some(p.ts)
            }
            ("crypto", CRYPTO_PORT, PLAINTEXT_PORT) => {
                packets[p.send_index as usize].post_wg_ts = Some(p.ts)
            }
            ("plaintext", PLAINTEXT_PORT, CRYPTO_PORT) => {
                packets[p.send_index as usize].pre_wg_ts = Some(p.ts)
            }
            ("plaintext", WG_PORT, CRYPTO_PORT) => {
                packets[p.send_index as usize].post_wg_ts = Some(p.ts)
            }
            params => println!("Unexpected pcap packet found: {params:?}"),
        }
    }

    write_to_csv(&csv_path, &packets)?;

    Ok(())
}
