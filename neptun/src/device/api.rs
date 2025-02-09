// Copyright (c) 2024 Nord Security. All rights reserved.
// Copyright (c) 2019-2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::dev_lock::LockReadGuard;
use super::drop_privileges::get_saved_ids;
use super::{AllowedIP, Device, Error, SocketAddr};
use crate::device::Action;
use crate::serialization::KeyBytes;
use crate::x25519;
use hex::encode as encode_hex;
use libc::*;
use std::fs::{create_dir, remove_file};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::sync::atomic::Ordering;

const SOCK_DIR: &str = "/var/run/wireguard/";

fn create_sock_dir() {
    let _ = create_dir(SOCK_DIR); // Create the directory if it does not exist

    if let Ok((saved_uid, saved_gid)) = get_saved_ids() {
        unsafe {
            let c_path = std::ffi::CString::new(SOCK_DIR).unwrap();
            // The directory is under the root user, but we want to be able to
            // delete the files there when we exit, so we need to change the owner
            chown(
                c_path.as_bytes_with_nul().as_ptr() as _,
                saved_uid,
                saved_gid,
            );
        }
    }
}

impl Device {
    /// Register the api handler for this Device. The api handler receives stream connections on a Unix socket
    /// with a known path: /var/run/wireguard/{tun_name}.sock.
    pub fn register_api_handler(&mut self) -> Result<(), Error> {
        let path = format!("{}/{}.sock", SOCK_DIR, self.iface.name()?);

        create_sock_dir();

        let _ = remove_file(&path); // Attempt to remove the socket if already exists

        let api_listener = UnixListener::bind(&path).map_err(Error::ApiSocket)?; // Bind a new socket to the path

        self.cleanup_paths.push(path.clone());

        self.queue.new_event(
            api_listener.as_raw_fd(),
            Box::new(move |d, _| {
                // This is the closure that listens on the api unix socket
                let (api_conn, _) = match api_listener.accept() {
                    Ok(conn) => conn,
                    _ => return Action::Continue,
                };

                let mut reader = BufReader::new(&api_conn);
                let mut writer = BufWriter::new(&api_conn);
                api_exec(d, &mut reader, &mut writer);
                Action::Continue // Indicates the worker thread should continue as normal
            }),
        )?;

        self.register_monitor(path)?;
        self.register_api_signal_handlers()
    }

    fn register_monitor(&self, path: String) -> Result<(), Error> {
        self.queue.new_periodic_event(
            Box::new(move |d, _| {
                // This is not a very nice hack to detect if the control socket was removed
                // and exiting nicely as a result. We check every 3 seconds in a loop if the
                // file was deleted by stating it.
                // The problem is that on linux inotify can be used quite beautifully to detect
                // deletion, and kqueue EVFILT_VNODE can be used for the same purpose, but that
                // will require introducing new events, for no measurable benefit.
                // TODO: Could this be an issue if we restart the service too quickly?
                let path = std::path::Path::new(&path);
                if !path.exists() {
                    d.trigger_exit();
                    return Action::Exit;
                }

                // Periodically read the mtu of the interface in case it changes
                if let Ok(mtu) = d.iface.mtu() {
                    d.mtu.store(mtu, Ordering::Relaxed);
                }

                Action::Continue
            }),
            std::time::Duration::from_millis(1000),
        )?;

        Ok(())
    }

    fn register_api_signal_handlers(&self) -> Result<(), Error> {
        self.queue
            .new_signal_event(SIGINT, Box::new(move |_, _| Action::Exit))?;

        self.queue
            .new_signal_event(SIGTERM, Box::new(move |_, _| Action::Exit))?;

        Ok(())
    }
}

pub fn api_exec<R: Read, W: Write>(
    d: &mut LockReadGuard<Device>,
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
) {
    let mut status = 0;
    let mut cmd = String::new();
    while status == 0 && reader.read_line(&mut cmd).is_ok_and(|n| n > 0) {
        status = match d.closed {
            true => ENOENT,
            false => match cmd.as_ref() {
                // Only two commands are legal according to the protocol, get=1 and set=1.
                "get=1\n" => api_get(reader, writer, d),
                "set=1\n" => api_set(reader, d),
                _ => EIO,
            },
        };
        // The protocol requires to return an error code as the response, or zero on success
        writeln!(writer, "errno={}\n", status).ok();
        _ = writer.flush();
        cmd.clear();
    }
}

#[allow(unused_must_use)]
fn api_get<R: Read, W: Write>(
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
    d: &Device,
) -> i32 {
    if let Some(ref k) = d.key_pair {
        writeln!(writer, "private_key={}", encode_hex(k.0.to_bytes()));
    }

    if d.listen_port != 0 {
        writeln!(writer, "listen_port={}", d.listen_port);
    }

    if let Some(fwmark) = d.fwmark {
        writeln!(writer, "fwmark={}", fwmark);
    }

    for (k, peer) in d.peers.iter() {
        let (keepalive, last_handshake_time, stats) = {
            let tun = peer.tunnel.lock();
            (
                tun.persistent_keepalive(),
                tun.last_handshake_time(),
                tun.stats(),
            )
        };

        writeln!(writer, "public_key={}", encode_hex(k.as_bytes()));

        if let Some(ref key) = peer.preshared_key() {
            writeln!(writer, "preshared_key={}", encode_hex(key));
        }

        if let Some(keepalive) = keepalive {
            writeln!(writer, "persistent_keepalive_interval={}", keepalive);
        }

        if let Some(ref addr) = peer.endpoint().addr {
            writeln!(writer, "endpoint={}", addr);
        }

        for AllowedIP { addr, cidr } in peer.allowed_ips() {
            writeln!(writer, "allowed_ip={}/{}", addr, cidr);
        }

        if let Some(last_handshake_time) = last_handshake_time {
            writeln!(
                writer,
                "last_handshake_time_sec={}",
                last_handshake_time.as_secs()
            );
            writeln!(
                writer,
                "last_handshake_time_nsec={}",
                last_handshake_time.subsec_nanos()
            );
        }

        let (_, tx_bytes, rx_bytes, ..) = stats;

        writeln!(writer, "rx_bytes={}", rx_bytes);
        writeln!(writer, "tx_bytes={}", tx_bytes);
    }

    // get command requires an empty line, but there is no reason to be religious about it.
    // However we should consume it if it is present to correctly handle multi-command streams.
    // The error is returned only if there is anything else then empty line after get=1\n
    // If there is EOF we handle succesfully.
    let mut buf = String::new();
    match reader.read_line(&mut buf) {
        Ok(1) => {
            if buf == "\n" {
                0
            } else {
                EINVAL
            }
        }
        Ok(2..) => EINVAL,
        _ => 0,
    }
}

fn api_set<R: Read>(reader: &mut BufReader<R>, d: &mut LockReadGuard<Device>) -> i32 {
    d.try_writeable(
        |device| device.trigger_yield(),
        |device| {
            device.cancel_yield();

            let mut buf = String::new();

            while reader.read_line(&mut buf).is_ok() {
                let cmd = buf.trim_end(); // remove newline if any

                if cmd.is_empty() {
                    return 0; // Empty line ends set=1 command
                }
                {
                    let parsed_cmd: Vec<&str> = cmd.split('=').collect();
                    if parsed_cmd.len() != 2 {
                        return EPROTO;
                    }

                    let (key, val) = (parsed_cmd[0], parsed_cmd[1]);

                    match key {
                        "private_key" => match val.parse::<KeyBytes>() {
                            Ok(key_bytes) => {
                                device.set_key(x25519::StaticSecret::from(key_bytes.0))
                            }
                            Err(_) => return EINVAL,
                        },
                        "listen_port" => match val.parse::<u16>() {
                            Ok(port) => match device.open_listen_socket(port) {
                                Ok(()) => {}
                                Err(_) => return EADDRINUSE,
                            },
                            Err(_) => return EINVAL,
                        },
                        "fwmark" =>
                        {
                            #[cfg(any(
                                target_os = "android",
                                target_os = "fuchsia",
                                target_os = "linux"
                            ))]
                            match val.parse::<u32>() {
                                Ok(mark) => match device.set_fwmark(mark) {
                                    Ok(()) => {}
                                    Err(_) => return EADDRINUSE,
                                },
                                Err(_) => return EINVAL,
                            }
                        }
                        "replace_peers" => match val.parse::<bool>() {
                            Ok(true) => device.clear_peers(),
                            Ok(false) => {}
                            Err(_) => return EINVAL,
                        },
                        "public_key" => match val.parse::<KeyBytes>() {
                            // Indicates a new peer section
                            Ok(key_bytes) => {
                                return api_set_peer(
                                    reader,
                                    device,
                                    x25519::PublicKey::from(key_bytes.0),
                                )
                            }
                            Err(_) => return EINVAL,
                        },
                        _ => return EINVAL,
                    }
                }
                buf.clear();
            }

            0
        },
    )
    .unwrap_or(EIO)
}

fn api_set_peer<R: Read>(
    reader: &mut BufReader<R>,
    d: &mut Device,
    pub_key: x25519::PublicKey,
) -> i32 {
    let mut cmd = String::new();

    let mut update_only = false;
    let mut remove = false;
    let mut replace_ips = false;
    let mut endpoint = None;
    let mut keepalive = None;
    let mut public_key = pub_key;
    let mut preshared_key = None;
    let mut allowed_ips: Vec<AllowedIP> = vec![];
    while reader.read_line(&mut cmd).is_ok() {
        cmd.pop(); // remove newline if any
        if cmd.is_empty() {
            let res = d.update_peer(
                public_key,
                update_only,
                remove,
                replace_ips,
                endpoint,
                allowed_ips.as_slice(),
                keepalive,
                preshared_key,
            );
            allowed_ips.clear(); //clear the vector content after update
            return res.and(Ok(0)).unwrap_or(EINVAL);
        }
        {
            let parsed_cmd: Vec<&str> = cmd.splitn(2, '=').collect();
            if parsed_cmd.len() != 2 {
                return EPROTO;
            }
            let (key, val) = (parsed_cmd[0], parsed_cmd[1]);
            match key {
                "update_only" => match val.parse::<bool>().map(|val| update_only = val) {
                    Ok(_) => {}
                    Err(_) => return EINVAL,
                },
                "remove" => match val.parse::<bool>().map(|val| remove = val) {
                    Ok(_) => {}
                    Err(_) => return EINVAL,
                },
                "preshared_key" => match val.parse::<KeyBytes>() {
                    Ok(key_bytes) => preshared_key = Some(key_bytes.0),
                    Err(_) => return EINVAL,
                },
                "endpoint" => match val.parse::<SocketAddr>() {
                    Ok(addr) => endpoint = Some(addr),
                    Err(_) => return EINVAL,
                },
                "persistent_keepalive_interval" => match val.parse::<u16>() {
                    Ok(interval) => keepalive = Some(interval),
                    Err(_) => return EINVAL,
                },
                "replace_allowed_ips" => match val.parse::<bool>() {
                    Ok(true) => replace_ips = true,
                    Ok(false) => replace_ips = false,
                    Err(_) => return EINVAL,
                },
                "allowed_ip" => match val.parse::<AllowedIP>() {
                    Ok(ip) => allowed_ips.push(ip),
                    Err(_) => return EINVAL,
                },
                "public_key" => {
                    // Indicates a new peer section. Commit changes for current peer, and continue to next peer
                    let res = d.update_peer(
                        public_key,
                        update_only,
                        remove,
                        replace_ips,
                        endpoint,
                        allowed_ips.as_slice(),
                        keepalive,
                        preshared_key,
                    );
                    if res.is_err() {
                        return EINVAL;
                    }
                    replace_ips = false;
                    endpoint = None;
                    keepalive = None;
                    preshared_key = None;
                    remove = false;
                    update_only = false; // Reset update only
                    allowed_ips.clear(); //clear the vector content after update
                    match val.parse::<KeyBytes>() {
                        Ok(key_bytes) => public_key = key_bytes.0.into(),
                        Err(_) => return EINVAL,
                    }
                }
                "protocol_version" => match val.parse::<u32>() {
                    Ok(1) => {} // Only version 1 is legal
                    _ => return EINVAL,
                },
                _ => return EINVAL,
            }
        }
        cmd.clear();
    }
    0
}
