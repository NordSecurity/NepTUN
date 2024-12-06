use std::{
    net::{Ipv4Addr, SocketAddrV4},
    process::Command,
};

use tokio::net::UnixStream;

use crate::key_pair::{KeyPair, NepTUNKey};

#[derive(Debug)]
pub enum SendType {
    Plaintext,
    Handshake,
    Data,
    Tunn,
    None,
}

#[derive(Debug)]
pub enum RecvType {
    Handshake,
    Data { from: SocketAddrV4, length: usize },
}

#[derive(Copy, Clone)]
pub struct Packet {
    pub index: u64,
    pub send_ts: u128,
    pub recv_ts: Option<u128>,
}

impl Packet {
    pub const fn send_size() -> usize {
        std::mem::size_of::<u64>() + std::mem::size_of::<u128>()
    }

    pub fn serialize(&self, buf: &mut [u8], start: usize) {
        buf[start..start + std::mem::size_of::<u64>()].copy_from_slice(&self.index.to_le_bytes());
        buf[start + std::mem::size_of::<u64>()
            ..start + std::mem::size_of::<u64>() + std::mem::size_of::<u128>()]
            .copy_from_slice(&self.send_ts.to_le_bytes());
    }
}

pub enum TestCmd {
    SendEncrypted {
        sock_dst: SocketAddrV4,
        packet_dst: SocketAddrV4,
        index: u64,
    },
    SendPlaintext {
        dst: SocketAddrV4,
        index: u64,
    },
    Done,
}

pub fn run_command(cmd: String) -> Result<String, String> {
    let mut args = cmd.split_ascii_whitespace().collect::<Vec<_>>();
    let cmd = args.remove(0);
    match Command::new(cmd).args(args).output() {
        Ok(output) => {
            if output.status.success() {
                Ok(format!(
                    "Command ran successfully with output: {}",
                    String::from_utf8(output.stdout).unwrap()
                ))
            } else {
                Err(format!(
                    "Command failed with output: {}",
                    String::from_utf8(output.stderr).unwrap()
                ))
            }
        }
        Err(err) => Err(format!("Failed to run command with error: {err:?}")),
    }
}

pub fn write_to_csv(name: &str, packets: &[Packet]) {
    let file = std::fs::File::create(name).unwrap();
    let mut csv = csv::Writer::from_writer(file);

    csv.write_record(["Index", "Send TS", "Recv TS"]).unwrap();
    for info in packets {
        csv.write_record([
            info.index.to_string(),
            info.send_ts.to_string(),
            if let Some(recv_ts) = info.recv_ts {
                recv_ts.to_string()
            } else {
                "".to_owned()
            },
        ])
        .unwrap();
    }
    csv.flush().unwrap();
}

pub async fn configure_wg(
    adapter_type: &str,
    wg_name: &str,
    wg_keys: &KeyPair,
    peer_keys: &KeyPair,
    wg_port: u16,
    ips: &[Ipv4Addr],
) {
    for ip in ips {
        let ipnet = format!("{}/24", ip);
        run_command(format!("ip addr add {ipnet} dev {wg_name}")).unwrap();
    }

    match adapter_type {
        "native" | "boringtun" => configure_native_wg(wg_name, wg_keys, peer_keys, wg_port),
        "wggo" | "neptun" => configure_userspace_wg(wg_name, wg_keys, peer_keys, wg_port).await,
        _ => panic!("Unknown adapter type {adapter_type}"),
    }
}

pub fn configure_native_wg(wg_name: &str, wg_keys: &KeyPair, peer_keys: &KeyPair, wg_port: u16) {
    wg_keys.private.write_to_file("wg.sk");

    let wg_setup = format!("private-key wg.sk listen-port {wg_port}");
    let peer_setup = format!("peer {} allowed-ips 0.0.0.0/0", peer_keys.public.as_b64());
    let uapi_cmd = format!("sudo wg set {wg_name} {wg_setup} {peer_setup}");
    run_command(uapi_cmd).unwrap();
}

pub async fn configure_userspace_wg(
    wg_name: &str,
    wg_keys: &KeyPair,
    peer_keys: &KeyPair,
    wg_port: u16,
) {
    let uapi_cmd = format!(
        r#"set=1
private_key={}
listen_port={wg_port}
public_key={}
allowed_ip=0.0.0.0/0
"#,
        wg_keys.private.as_hex(),
        peer_keys.public.as_hex(),
    )
    .replace('\"', "");

    let uapi_sock = UnixStream::connect(format!("/var/run/wireguard/{}.sock", wg_name))
        .await
        .unwrap();

    write_to_uapi(&uapi_sock, &uapi_cmd).await;
}

pub async fn write_to_uapi(sock: &UnixStream, cmd: &str) {
    let cmd = cmd.as_bytes();
    sock.writable().await.unwrap();
    let bytes_written = sock.try_write(cmd).unwrap();
    assert_eq!(bytes_written, cmd.len());
}
