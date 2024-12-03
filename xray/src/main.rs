mod client;
mod key_pair;
mod utils;

use std::net::SocketAddrV4;

use neptun::noise::Tunn;

use tokio::{
    net::UdpSocket,
    sync::mpsc,
    time::{Duration, Instant},
};

use crate::{
    client::Client,
    key_pair::KeyPair,
    utils::{configure_wg, write_to_csv, Packet, RecvType, SendType, TestCmd},
};

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

    let wg_name = "xraywg1";

    let wg_addr: SocketAddrV4 = "100.66.0.1:41414".parse().unwrap();
    let crypto_addr: SocketAddrV4 = "100.66.0.2:63636".parse().unwrap();
    let crypto_sock_addr: SocketAddrV4 = "127.0.0.1:63636".parse().unwrap();
    let pt_addr = SocketAddrV4::new(*wg_addr.ip(), 52525);

    println!("Configuring wireguard with adapter type {wg}");
    configure_wg(
        wg.as_str(),
        wg_name,
        &wg_keys,
        &peer_keys,
        wg_addr.port(),
        &[*wg_addr.ip()],
    )
    .await;

    let (cmd_tx, cmd_rx) = mpsc::channel::<TestCmd>(100);
    let (done_tx, mut done_rx) = mpsc::channel::<()>(1);

    let pt_sock = UdpSocket::bind(pt_addr).await.unwrap();
    let pt_client = Client::new(pt_addr, None, pt_sock);

    let crypto_sock = UdpSocket::bind(crypto_sock_addr).await.unwrap();
    let tunn = Tunn::new(peer_keys.private, wg_keys.public, None, None, 123, None).unwrap();
    let mut crypto_client = Client::new(crypto_addr, Some(tunn), crypto_sock);
    crypto_client.do_handshake(wg_addr).await;

    let mut event_loop =
        EventLoop::new(cli_args, wg_addr, crypto_client, pt_client, done_tx, cmd_rx);
    let task = tokio::task::spawn(async move {
        event_loop.run().await;
    });

    println!("Starting {test_type} test with {packet_count} packets");
    for i in 0..packet_count {
        if test_type == "crypto" {
            cmd_tx
                .send(TestCmd::SendEncrypted {
                    sock_dst: wg_addr,
                    packet_dst: pt_addr,
                    index: i as u64,
                })
                .await
                .unwrap();
        } else {
            cmd_tx
                .send(TestCmd::SendPlaintext {
                    dst: crypto_addr,
                    index: i as u64,
                })
                .await
                .unwrap();
        }
    }
    cmd_tx.send(TestCmd::Done).await.unwrap();

    done_rx.recv().await.unwrap();

    task.await.unwrap();
}

struct EventLoop {
    cli_args: CliArgs,
    wg_addr: SocketAddrV4,
    crypto_client: Client,
    pt_client: Client,
    done_tx: mpsc::Sender<()>,
    cmd_rx: mpsc::Receiver<TestCmd>,
    packets: Vec<Packet>,
    can_send: bool,
    is_done: bool,
    crypto_buf: Vec<u8>,
    pt_buf: Vec<u8>,
    recv_packet: usize,
}

impl EventLoop {
    fn new(
        cli_args: CliArgs,
        wg_addr: SocketAddrV4,
        crypto_client: Client,
        pt_client: Client,
        done_tx: mpsc::Sender<()>,
        cmd_rx: mpsc::Receiver<TestCmd>,
    ) -> Self {
        let packet_count = cli_args.packet_count;
        Self {
            cli_args,
            wg_addr,
            crypto_client,
            pt_client,
            done_tx,
            cmd_rx,
            packets: Vec::with_capacity(packet_count),
            can_send: true,
            is_done: false,
            crypto_buf: vec![0; 1024],
            pt_buf: vec![0; 1024],
            recv_packet: 1,
        }
    }

    async fn run(&mut self) {
        let mut wg_tick_interval = tokio::time::interval(Duration::from_millis(250));
        let finish_timeout = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(finish_timeout);
        loop {
            tokio::select! {
                _ = &mut finish_timeout, if self.is_done => {
                    self.on_finished(self.packets.len()).await;
                    break;
                },
                _ = wg_tick_interval.tick() => {
                    self.crypto_client.tick_timers(self.wg_addr).await;
                },
                Some(cmd) = self.cmd_rx.recv(), if self.can_send => {
                    self.on_recv_cmd(cmd, &mut finish_timeout).await;
                }
                rt = self.crypto_client.recv_packet(&mut self.crypto_buf) => {
                    let should_break = self.on_recv_crypto_packet(rt).await;
                    if should_break {
                        break;
                    }
                }
                rt = self.pt_client.recv_packet(&mut self.pt_buf) => {
                    let should_break = self.on_recv_plaintext_packet(rt).await;
                    if should_break {
                        break;
                    }
                }
            }
        }
    }

    async fn on_recv_cmd(
        &mut self,
        cmd: TestCmd,
        finish_timeout: &mut std::pin::Pin<&mut tokio::time::Sleep>,
    ) {
        match cmd {
            TestCmd::Done => {
                println!("All packets were sent. Waiting for maximum 10 seconds to receive");
                finish_timeout
                    .as_mut()
                    .reset(Instant::now() + Duration::from_secs(10));
                self.is_done = true;
            }
            TestCmd::SendEncrypted {
                sock_dst,
                packet_dst,
                index,
            } => {
                if index % (self.cli_args.packet_count / 10) as u64 == 0 {
                    println!("[Crypto] Sending packet with index {index}");
                }
                let mut payload = vec![0; Packet::send_size()];
                let send_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_micros();
                let mut packet = Packet {
                    index,
                    send_ts,
                    recv_ts: None,
                };
                packet.serialize(&mut payload, 0);

                packet.index = 0;
                self.packets.push(packet);

                let sr = self
                    .crypto_client
                    .send_packet(sock_dst, packet_dst, &payload)
                    .await;
                if !matches!(sr, SendType::Data) {
                    println!("Send {:?}", sr);
                }
                if matches!(sr, SendType::Handshake) {
                    self.can_send = false;
                }
            }
            TestCmd::SendPlaintext { dst, index } => {
                if index % (self.cli_args.packet_count / 10) as u64 == 0 {
                    println!("[Plaintext] Sending packet with index {index}");
                }
                let mut payload = vec![0; Packet::send_size()];
                let send_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_micros();
                let mut packet = Packet {
                    index,
                    send_ts,
                    recv_ts: None,
                };
                packet.serialize(&mut payload, 0);

                packet.index = 0;
                self.packets.push(packet);

                self.pt_client.send_packet(dst, dst, &payload).await;
            }
        }
    }

    async fn on_recv_crypto_packet(&mut self, rt: RecvType) -> bool {
        match rt {
            RecvType::Handshake => self.can_send = true,
            RecvType::Data {
                length: bytes_read, ..
            } => {
                if bytes_read == Packet::send_size() {
                    if self.recv_packet % (self.cli_args.packet_count / 10) == 0 {
                        println!("[Crypto] Received {} packets", self.recv_packet);
                    }
                    let index = u64::from_le_bytes(self.crypto_buf[0..8].try_into().unwrap());
                    let recv_ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_micros();
                    self.packets[index as usize].index = self.recv_packet as u64;
                    self.packets[index as usize].recv_ts = Some(recv_ts);
                    self.recv_packet += 1;
                }
            }
        }
        false
    }

    async fn on_recv_plaintext_packet(&mut self, rt: RecvType) -> bool {
        if let RecvType::Data {
            length: bytes_read, ..
        } = rt
        {
            if bytes_read == Packet::send_size() {
                if self.recv_packet % (self.cli_args.packet_count / 10) == 0 {
                    println!("[Plaintext] Received {} packets", self.recv_packet);
                }
                let index = u64::from_le_bytes(self.pt_buf[0..8].try_into().unwrap());
                let recv_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_micros();
                self.packets[index as usize].index = self.recv_packet as u64;
                self.packets[index as usize].recv_ts = Some(recv_ts);
                self.recv_packet += 1;
            }
        }
        false
    }

    async fn on_finished(&mut self, recv_packet_count: usize) {
        println!("Test done, received {recv_packet_count} packets");
        write_to_csv(&self.cli_args.csv_name, &self.packets);
        self.done_tx.send(()).await.unwrap();
    }
}
