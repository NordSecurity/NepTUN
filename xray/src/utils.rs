use std::{net::Ipv4Addr, process::Command};

use tokio::net::UnixStream;

use crate::{
    key_pair::{KeyPair, NepTUNKey},
    types::{Packet, XRayError, XRayResult},
    Wg,
};

pub fn run_command(cmd: String) -> Result<String, String> {
    let mut args = cmd.split_ascii_whitespace().collect::<Vec<_>>();
    let cmd = args.remove(0);
    match Command::new(cmd).args(args).output() {
        Ok(output) => {
            if output.status.success() {
                Ok(format!(
                    "Command ran successfully with output: \n{}",
                    String::from_utf8(output.stdout).expect("Command output should be valid utf-8")
                ))
            } else {
                Err(format!(
                    "Command failed with output: \n{}",
                    String::from_utf8(output.stderr).expect("Command output should be valid utf-8")
                ))
            }
        }
        Err(err) => Err(format!("Failed to run command with error: {err:?}")),
    }
}

pub fn write_to_csv(name: &str, packets: &[Packet]) -> XRayResult<()> {
    let file = std::fs::File::create(name)?;
    let mut writer = csv::Writer::from_writer(file);

    for packet in packets {
        writer.serialize(packet)?;
    }

    writer.flush()?;
    Ok(())
}

pub async fn configure_wg(
    adapter_type: Wg,
    wg_name: &str,
    wg_keys: &KeyPair,
    peer_keys: &KeyPair,
    wg_port: u16,
    ips: &[Ipv4Addr],
) -> XRayResult<()> {
    for ip in ips {
        let ipnet = format!("{}/24", ip);
        run_command(format!("ip addr add {ipnet} dev {wg_name}"))
            .map_err(XRayError::ShellCommand)?;
    }

    match adapter_type {
        Wg::LinuxNative | Wg::BoringTun => {
            configure_native_wg(wg_name, wg_keys, peer_keys, wg_port)
        }
        Wg::WireguardGo | Wg::NepTUN => {
            configure_userspace_wg(wg_name, wg_keys, peer_keys, wg_port).await
        }
    }
}

pub fn configure_native_wg(
    wg_name: &str,
    wg_keys: &KeyPair,
    peer_keys: &KeyPair,
    wg_port: u16,
) -> XRayResult<()> {
    wg_keys.private.write_to_file("wg.sk")?;
    let wg_setup = format!("private-key wg.sk listen-port {wg_port}");
    let peer_setup = format!("peer {} allowed-ips 0.0.0.0/0", peer_keys.public.as_b64());
    let uapi_cmd = format!("sudo wg set {wg_name} {wg_setup} {peer_setup}");
    run_command(uapi_cmd).map_err(XRayError::ShellCommand)?;
    Ok(())
}

pub async fn configure_userspace_wg(
    wg_name: &str,
    wg_keys: &KeyPair,
    peer_keys: &KeyPair,
    wg_port: u16,
) -> XRayResult<()> {
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

    let uapi_sock = UnixStream::connect(format!("/var/run/wireguard/{}.sock", wg_name)).await?;
    uapi_sock.writable().await?;

    let bytes_written = uapi_sock.try_write(uapi_cmd.as_bytes())?;
    assert_eq!(bytes_written, uapi_cmd.len());

    Ok(())
}
