use std::{net::SocketAddrV4, pin::Pin, time::Duration};

use tokio::{sync::mpsc, time::Instant};

use crate::{
    client::Client,
    utils::{write_to_csv, Packet, RecvType, SendType, TestCmd},
    CliArgs, XRayResult,
};

pub struct EventLoop {
    cli_args: CliArgs,
    wg_addr: SocketAddrV4,
    crypto_client: Client,
    plaintext_client: Client,
    cmd_rx: mpsc::Receiver<TestCmd>,
    packets: Vec<Packet>,
    can_send: bool,
    is_done: bool,
    crypto_buf: Vec<u8>,
    plaintext_buf: Vec<u8>,
    recv_packet: usize,
}

impl EventLoop {
    pub fn new(
        cli_args: CliArgs,
        wg_addr: SocketAddrV4,
        crypto_client: Client,
        plaintext_client: Client,
        cmd_rx: mpsc::Receiver<TestCmd>,
    ) -> Self {
        let packet_count = cli_args.packet_count;
        Self {
            cli_args,
            wg_addr,
            crypto_client,
            plaintext_client,
            cmd_rx,
            packets: Vec::with_capacity(packet_count),
            can_send: true,
            is_done: false,
            crypto_buf: vec![0; 1024],
            plaintext_buf: vec![0; 1024],
            recv_packet: 1,
        }
    }

    pub async fn run(mut self) -> XRayResult<()> {
        let mut wg_tick_interval = tokio::time::interval(Duration::from_millis(250));
        // This timeout is only actually used when the test is otherwise done
        // It is here set to one second just to initialize it, but is reset before it's actually used
        let finish_timeout = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(finish_timeout);
        loop {
            tokio::select! {
                _ = &mut finish_timeout, if self.is_done => {
                    self.on_finished(self.packets.len()).await?;
                    break;
                },
                _ = wg_tick_interval.tick() => {
                    self.crypto_client.tick_timers(self.wg_addr).await;
                },
                Some(cmd) = self.cmd_rx.recv(), if self.can_send => {
                    self.on_recv_cmd(cmd, &mut finish_timeout).await?;
                }
                Ok(rt) = self.crypto_client.recv_packet(&mut self.crypto_buf) => {
                    self.on_recv_crypto_packet(rt, &mut finish_timeout).await?;
                }
                Ok(rt) = self.plaintext_client.recv_packet(&mut self.plaintext_buf) => {
                    self.on_recv_plaintext_packet(rt, &mut finish_timeout).await?;
                }
            }
        }
        Ok(())
    }

    async fn on_recv_cmd(
        &mut self,
        cmd: TestCmd,
        finish_timeout: &mut Pin<&mut tokio::time::Sleep>,
    ) -> XRayResult<()> {
        fn prepare_packet(index: u64) -> XRayResult<(Packet, Vec<u8>)> {
            let mut payload = vec![0; Packet::send_size()];
            let send_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_micros();
            let mut packet = Packet {
                index,
                send_ts,
                recv_ts: None,
            };
            packet.serialize(&mut payload, 0);

            packet.index = 0;
            Ok((packet, payload))
        }
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
                let (packet, payload) = prepare_packet(index)?;
                self.packets.push(packet);

                let sr = self
                    .crypto_client
                    .send_packet(sock_dst, packet_dst, &payload)
                    .await?;
                self.can_send = !matches!(sr, SendType::Handshake);
            }
            TestCmd::SendPlaintext { dst, index } => {
                if index % (self.cli_args.packet_count / 10) as u64 == 0 {
                    println!("[Plaintext] Sending packet with index {index}");
                }
                let (packet, payload) = prepare_packet(index)?;
                self.packets.push(packet);

                self.plaintext_client
                    .send_packet(dst, dst, &payload)
                    .await?;
            }
        }
        Ok(())
    }

    async fn on_recv_crypto_packet(
        &mut self,
        rt: RecvType,
        finish_timeout: &mut Pin<&mut tokio::time::Sleep>,
    ) -> XRayResult<()> {
        match rt {
            RecvType::Handshake => self.can_send = true,
            RecvType::Data {
                length: bytes_read, ..
            } => {
                if bytes_read == Packet::send_size() {
                    if self.recv_packet % (self.cli_args.packet_count / 10) == 0 {
                        println!("[Crypto] Received {} packets", self.recv_packet);
                    }
                    let index = u64::from_le_bytes(
                        self.crypto_buf[0..8]
                            .try_into()
                            .expect("Received packet should contain a valid index"),
                    );
                    let recv_ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_micros();
                    self.packets[index as usize].index = self.recv_packet as u64;
                    self.packets[index as usize].recv_ts = Some(recv_ts);
                    self.recv_packet += 1;
                    self.on_maybe_recv_all(finish_timeout);
                }
            }
        }
        Ok(())
    }

    async fn on_recv_plaintext_packet(
        &mut self,
        rt: RecvType,
        finish_timeout: &mut Pin<&mut tokio::time::Sleep>,
    ) -> XRayResult<()> {
        if let RecvType::Data {
            length: bytes_read, ..
        } = rt
        {
            if bytes_read == Packet::send_size() {
                if self.recv_packet % (self.cli_args.packet_count / 10) == 0 {
                    println!("[Plaintext] Received {} packets", self.recv_packet);
                }
                let index = u64::from_le_bytes(
                    self.plaintext_buf[0..8]
                        .try_into()
                        .expect("Received packet should contain a valid index"),
                );
                let recv_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_micros();
                self.packets[index as usize].index = self.recv_packet as u64;
                self.packets[index as usize].recv_ts = Some(recv_ts);
                self.recv_packet += 1;
                self.on_maybe_recv_all(finish_timeout);
            }
        }
        Ok(())
    }

    fn on_maybe_recv_all(&self, finish_timeout: &mut Pin<&mut tokio::time::Sleep>) {
        if self.recv_packet > self.cli_args.packet_count {
            println!("All packets were received. Waiting 3 seconds to make sure pcap is properly populated");
            finish_timeout
                .as_mut()
                .reset(Instant::now() + Duration::from_secs(3));
        }
    }

    async fn on_finished(&mut self, recv_packet_count: usize) -> XRayResult<()> {
        println!("Test done, received {recv_packet_count} packets");
        write_to_csv(&self.cli_args.csv_name, &self.packets)
    }
}
