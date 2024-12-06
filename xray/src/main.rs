mod client;
mod event_loop;
mod key_pair;
mod utils;

use std::net::{Ipv4Addr, SocketAddrV4};

use neptun::noise::Tunn;

use tokio::{net::UdpSocket, sync::mpsc};

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

struct CliArgs {
    packet_count: usize,
    csv_name: String,
}

#[tokio::main]
async fn main() {
    let cli_args = std::env::args().collect::<Vec<_>>();
    let wg = cli_args
        .get(1)
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "neptun".to_owned());
    let test_type = cli_args
        .get(2)
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "crypto".to_owned());
    let packet_count = cli_args
        .get(3)
        .map(|s| {
            s.parse::<usize>()
                .expect("Packet count must be a positive integer")
        })
        .unwrap_or(10);
    let csv_name = cli_args
        .get(4)
        .cloned()
        .unwrap_or_else(|| format!("xray_metrics_{}_{}.csv", wg, test_type));

    let cli_args = CliArgs {
        packet_count,
        csv_name,
    };

    let wg_keys = KeyPair::new();
    let peer_keys = KeyPair::new();

    println!("Configuring wireguard with adapter type {wg}");
    configure_wg(
        wg.as_str(),
        WG_NAME,
        &wg_keys,
        &peer_keys,
        WG_ADDR.port(),
        &[*WG_ADDR.ip()],
    )
    .await;

    let (cmd_tx, cmd_rx) = mpsc::channel::<TestCmd>(100);

    let plaintext_sock = UdpSocket::bind(PLAINTEXT_ADDR).await.unwrap();
    let plaintext_client = Client::new(PLAINTEXT_ADDR, None, plaintext_sock);

    let crypto_sock = UdpSocket::bind(CRYPTO_SOCK_ADDR).await.unwrap();
    let tunn = Tunn::new(peer_keys.private, wg_keys.public, None, None, 123, None).unwrap();
    let mut crypto_client = Client::new(CRYPTO_ADDR, Some(tunn), crypto_sock);
    crypto_client.do_handshake(WG_ADDR).await;

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
                .await
                .unwrap();
        } else {
            cmd_tx
                .send(TestCmd::SendPlaintext {
                    dst: CRYPTO_ADDR,
                    index: i as u64,
                })
                .await
                .unwrap();
        }
    }
    cmd_tx.send(TestCmd::Done).await.unwrap();

    task.await.unwrap();
}
