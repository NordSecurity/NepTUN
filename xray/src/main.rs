mod client;
mod event_loop;
mod key_pair;
mod utils;

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::SystemTimeError,
};

use neptun::noise::{Tunn, TunnResult};

use clap::Parser;
use tokio::{
    net::UdpSocket,
    sync::mpsc::{self, error::SendError},
};

use crate::{
    client::Client,
    event_loop::EventLoop,
    key_pair::KeyPair,
    utils::{configure_wg, TestCmd},
};

const WG_NAME: &str = "xraywg1";

const WG_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(100, 66, 0, 1), 41414);
const PLAINTEXT_ADDR: SocketAddrV4 = SocketAddrV4::new(*WG_ADDR.ip(), 52525);
const CRYPTO_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(100, 66, 0, 2), 63636);
const CRYPTO_SOCK_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 63636);

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
}

impl From<TunnResult<'_>> for XRayError {
    fn from(tunn_res: TunnResult<'_>) -> Self {
        Self::UnexpectedTunnResult(format!("{tunn_res:?}"))
    }
}

#[derive(Parser)]
struct Cli {
    /// Optional name to operate on
    wg: Option<String>,
    test_type: Option<String>,
    packet_count: Option<usize>,
    csv_name: Option<String>,
}

struct CliArgs {
    wg: String,
    test_type: String,
    packet_count: usize,
    csv_name: String,
}

impl From<Cli> for CliArgs {
    fn from(cli: Cli) -> Self {
        let wg = cli
            .wg
            .map(|wg| wg.to_lowercase())
            .unwrap_or_else(|| "neptun".to_owned());
        let test_type = cli
            .test_type
            .map(|wg| wg.to_lowercase())
            .unwrap_or_else(|| "crypto".to_owned());
        let packet_count = cli.packet_count.unwrap_or(10);
        let csv_name = cli
            .csv_name
            .map(|wg| wg.to_lowercase())
            .unwrap_or_else(|| format!("xray_metrics_{}_{}.csv", wg, test_type));
        Self {
            wg,
            test_type,
            packet_count,
            csv_name,
        }
    }
}

#[tokio::main]
async fn main() -> XRayResult<()> {
    let cli = Cli::parse();
    let cli_args = CliArgs::from(cli);
    let test_type = cli_args.test_type.clone();
    let packet_count = cli_args.packet_count;

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
                    index: i as u64,
                })
                .await?;
        } else {
            cmd_tx
                .send(TestCmd::SendPlaintext {
                    dst: CRYPTO_ADDR,
                    index: i as u64,
                })
                .await?;
        }
    }
    cmd_tx.send(TestCmd::Done).await?;

    task.await.expect("Awaiting task should be successful")?;

    Ok(())
}
