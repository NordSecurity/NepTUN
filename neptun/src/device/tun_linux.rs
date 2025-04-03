// Copyright (c) 2024 Nord Security. All rights reserved.
// Copyright (c) 2019-2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::Error;
use libc::{
    self, __c_anonymous_ifr_ifru, c_char, c_short, close, fcntl, ifreq, open, read, socket, write,
    AF_INET, F_GETFL, F_SETFL, IFF_MULTI_QUEUE, IFF_NO_PI, IFF_TUN, IFNAMSIZ, IF_NAMESIZE,
    IPPROTO_IP, O_NONBLOCK, O_RDWR, SIOCGIFMTU, SOCK_STREAM,
};
use nix::{ioctl_read_bad, ioctl_write_ptr_bad};
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use tracing::error;

#[cfg(target_os = "linux")]
mod tun_interface_flags {
    use super::*;
    use libc::{TUNGETIFF, TUNSETIFF};
    ioctl_read_bad!(get, TUNGETIFF, ifreq);
    ioctl_write_ptr_bad!(set, TUNSETIFF, ifreq);
}

#[cfg(target_os = "android")]
mod tun_interface_flags {
    use super::*;
    const TUNGETIFF: u64 = 0x8004_54D2;
    ioctl_read_bad!(get, TUNGETIFF, ifreq);
}

ioctl_read_bad!(get_interface_mtu, SIOCGIFMTU, ifreq);

#[derive(Default, Debug)]
pub struct TunSocket {
    fd: RawFd,
    name: String,
}

impl Drop for TunSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

impl AsRawFd for TunSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl TunSocket {
    fn write(&self, src: &[u8]) -> usize {
        match unsafe { write(self.fd, src.as_ptr() as _, src.len()) } {
            -1 => 0,
            n => n as usize,
        }
    }

    pub fn new(name: &str) -> Result<TunSocket, Error> {
        // If the provided name appears to be a FD, use that.
        let provided_fd = name.parse::<i32>();
        if let Ok(fd) = provided_fd {
            return Ok(TunSocket {
                fd,
                name: name.to_string(),
            });
        }

        let fd = match unsafe { open(b"/dev/net/tun\0".as_ptr() as _, O_RDWR) } {
            -1 => return Err(Error::Socket(io::Error::last_os_error())),
            fd => fd,
        };

        #[cfg(target_os = "linux")]
        {
            if !name.is_ascii() {
                return Err(Error::InvalidTunnelName);
            }

            let mut ifr = ifreq {
                ifr_name: [0; IFNAMSIZ],
                ifr_ifru: __c_anonymous_ifr_ifru {
                    ifru_flags: (IFF_TUN | IFF_MULTI_QUEUE | IFF_NO_PI) as _,
                },
            };

            if name.len() >= ifr.ifr_name.len() {
                return Err(Error::InvalidTunnelName);
            }

            ifr.ifr_name
                .iter_mut()
                .zip(name.as_bytes().iter())
                .for_each(|(slot, char)| *slot = *char as c_char);

            if unsafe { tun_interface_flags::set(fd, &ifr) }.is_err() {
                let error = Error::IOCtl(io::Error::last_os_error());
                let flags = unsafe { format!("{:x}", ifr.ifr_ifru.ifru_flags) };
                error!(
                    ?error,
                    op = "TUNSETIFF",
                    name,
                    flags,
                    "Failed to configure tunnel"
                );
                return Err(error);
            }
        }

        let name = name.to_string();
        Ok(TunSocket { fd, name })
    }

    pub fn new_from_fd(fd: RawFd) -> Result<TunSocket, Error> {
        let mut ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: __c_anonymous_ifr_ifru { ifru_ifindex: 0 },
        };

        if unsafe { tun_interface_flags::get(fd, &mut ifr) }.is_err() {
            let error = Error::IOCtl(io::Error::last_os_error());
            error!(?error, op = "TUNGETIFF", "Failed to get tunnel info");
            return Err(error);
        }
        let flags = unsafe { ifr.ifr_ifru.ifru_flags };
        if flags & IFF_TUN as c_short == 0 {
            return Err(Error::InvalidTunnelName);
        }
        let name = std::ffi::CStr::from_bytes_until_nul(&ifr.ifr_name.map(|c| c as u8))
            .map_err(|_| Error::InvalidTunnelName)?
            .to_str()
            .map_err(|_| Error::InvalidTunnelName)?
            .to_owned();
        Ok(TunSocket { fd, name })
    }

    pub fn set_non_blocking(self) -> Result<TunSocket, Error> {
        match unsafe { fcntl(self.fd, F_GETFL) } {
            -1 => Err(Error::FCntl(io::Error::last_os_error())),
            flags => match unsafe { fcntl(self.fd, F_SETFL, flags | O_NONBLOCK) } {
                -1 => Err(Error::FCntl(io::Error::last_os_error())),
                _ => Ok(self),
            },
        }
    }

    pub fn name(&self) -> Result<String, Error> {
        Ok(self.name.clone())
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> Result<usize, Error> {
        let provided_fd = self.name.parse::<i32>();
        if provided_fd.is_ok() {
            return Ok(1500);
        }

        let fd = match unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) } {
            -1 => return Err(Error::Socket(io::Error::last_os_error())),
            fd => fd,
        };

        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: __c_anonymous_ifr_ifru { ifru_mtu: 0 },
        };

        ifr.ifr_name
            .iter_mut()
            .zip(self.name.as_bytes().iter())
            .for_each(|(slot, char)| *slot = *char as c_char);

        if unsafe { get_interface_mtu(fd, &mut ifr) }.is_err() {
            let error = Error::IOCtl(io::Error::last_os_error());
            error!(
                ?error,
                op = "SIOCGIFMTU",
                self.name,
                "Failed to get mtu for tunnel"
            );
            return Err(error);
        }

        unsafe { close(fd) };

        Ok(unsafe { ifr.ifr_ifru.ifru_mtu } as _)
    }

    pub fn write4(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    pub fn write6(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    pub fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        match unsafe { read(self.fd, dst.as_mut_ptr() as _, dst.len()) } {
            -1 => Err(Error::IfaceRead(io::Error::last_os_error())),
            n => Ok(&mut dst[..n as usize]),
        }
    }
}
