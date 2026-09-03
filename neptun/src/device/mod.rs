// Copyright (c) 2024 Nord Security. All rights reserved.
// Copyright (c) 2019-2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod control;
mod inbound;
mod outbound;

pub mod allowed_ips;
pub mod api;
mod dev_lock;
pub mod drop_privileges;
pub mod peer;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "kqueue.rs"]
pub mod poll;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "epoll.rs"]
pub mod poll;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "tun_darwin.rs"]
pub mod tun;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "tun_linux.rs"]
pub mod tun;

pub mod waker;

use crate::device::control::Control;
use crate::device::inbound::Inbound;
use crate::device::outbound::Outbound;
use crate::device::peer::DATA_SOCKET_READ_TIMEOUT;
use crate::device::waker::Waker;
use crate::noise::errors::WireGuardError;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Tunn, TunnResult};
use crate::x25519;
use allowed_ips::AllowedIps;
use dev_lock::{Lock, LockReadGuard};
use peer::{AllowedIP, Peer};
use poll::{EventPoll, EventRef, WaitResult};
use rand_core::{OsRng, RngCore};
use socket2::{Domain, Protocol, Type};
use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter};
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
use std::mem::swap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::RawFd;
#[cfg(not(target_os = "windows"))]
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tun::TunSocket;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
use dispatch2::{
    DispatchGroup, DispatchQueue, DispatchQueueGlobalPriority, DispatchRetained, DispatchTime,
    GlobalQueueIdentifier,
};

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
use {
    nix::sys::socket as NixSocket,
    std::os::fd::{AsFd, BorrowedFd},
    std::thread::{self, JoinHandle},
};

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

// Max packet size of 1550 because packets are limited by the MTU sizes
// used in wild networks.
const MAX_PKT_SIZE: usize = 1550;
const MAX_ITR: usize = 100;
const WG_HEADER_OFFSET: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),
    #[error("Socket creation error: {0}")]
    Socket(io::Error),
    #[error("Socket bind error: {0}")]
    Bind(String),
    #[error("FCntl error: {0}")]
    FCntl(io::Error),
    #[error("Event queue error: {0}")]
    EventQueue(io::Error),
    #[error("IOCtl error: {0}")]
    IOCtl(io::Error),
    #[error("Connect error: {0}")]
    Connect(String),
    #[error("Set sockopt error: {0}")]
    SetSockOpt(String),
    #[error("Invalid tunnel name")]
    InvalidTunnelName,
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    #[error("Get sockopt error: {0}")]
    GetSockOpt(io::Error),
    #[error("Get socket error: {0}")]
    GetSockName(String),
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[error("Timer error: {0}")]
    Timer(io::Error),
    #[error("iface read: {0}")]
    IfaceRead(io::Error),
    #[error("Failed to drop privileges: {0}")]
    DropPrivileges(String),
    #[error("API socket error: {0}")]
    ApiSocket(io::Error),
    #[error("Set tunnel error: Failed to get device lock when setting tunnel")]
    SetTunnel,
    #[error("Internal error occured: {0}")]
    InternalError(String),
    #[error("Poll error: {0}")]
    Poll(io::Error),
}

// What the event loop should do after a handler returns
enum Action {
    Continue, // Continue the loop
    Yield,    // Yield the read lock and acquire it again
    Exit,     // Stop the loop
}

// Event handler function
type Handler = Box<dyn Fn(&mut LockReadGuard<Device>, &mut ThreadData) -> Action + Send + Sync>;

pub trait MakeExternalNeptun: Send + Sync {
    fn make_external(&self, socket: RawFd);
}

pub struct MakeExternalNeptunNoop;

impl MakeExternalNeptun for MakeExternalNeptunNoop {
    fn make_external(&self, _socket: std::os::fd::RawFd) {}
}

pub struct DeviceHandle {
    pub device: Arc<Lock<Device>>, // The interface this handle owns
    control: Option<Control>,
    data: Option<DataPlane>,
    sockets_to_close: Arc<Lock<Vec<Arc<TunSocket>>>>,
}

#[derive(Clone)]
pub struct DeviceConfig {
    pub n_threads: usize,
    /// On Apple platform, packets are always handled through an unconnected UDP socket.
    /// Hence, setting this value has no effect when used on Apple platform.
    pub use_connected_socket: bool,
    #[cfg(target_os = "linux")]
    pub use_multi_queue: bool,
    pub open_uapi_socket: bool,
    pub protect: Arc<dyn MakeExternalNeptun>,
    pub firewall_process_inbound_callback:
        Option<Arc<dyn Fn(&[u8; 32], &mut [u8]) -> bool + Send + Sync>>,
    pub firewall_process_outbound_callback:
        Option<Arc<dyn Fn(&[u8; 32], &mut [u8], &mut dyn std::io::Write) -> bool + Send + Sync>>,
    pub skt_buffer_size: Option<usize>,
    pub inter_thread_channel_size: Option<usize>,
    pub max_inter_thread_batched_pkts: Option<usize>,
}

pub struct Device {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    queue: Arc<EventPoll<Handler>>,

    listen_port: u16,
    fwmark: Option<u32>,
    update_seq: u32,

    iface: Arc<TunSocket>,
    closed: bool,
    udp4: Option<Arc<socket2::Socket>>,
    udp6: Option<Arc<socket2::Socket>>,

    yield_notice: Option<EventRef>,
    exit_notice: Option<EventRef>,

    peers: HashMap<x25519::PublicKey, Arc<Peer>>,
    peers_by_ip: AllowedIps<Arc<Peer>>,
    peers_by_idx: HashMap<u32, Arc<Peer>>,
    next_index: IndexLfsr,

    config: DeviceConfig,

    cleanup_paths: Vec<String>,

    mtu: Arc<AtomicUsize>,

    rate_limiter: Option<Arc<RateLimiter>>,

    /// Set to stop the data plane threads.
    data_stop: Arc<AtomicBool>,
    out_waker: Arc<Waker>,
    in_waker: Arc<Waker>,
}

struct ThreadData {
    iface: Arc<TunSocket>,
    src_buf: [u8; MAX_PKT_SIZE],
    dst_buf: [u8; MAX_PKT_SIZE],
    update_seq: u32,
}

enum IfaceReadResult<'a> {
    Packet {
        payload: &'a mut [u8],
        peer: Arc<Peer>,
    },
    Exhausted,
    Fatal(Error),
    Skip,
}

pub struct DataPlane {
    outbound: Outbound,
    inbound: Inbound,
}

impl DataPlane {
    fn start(device: &Arc<Lock<Device>>) -> Result<Self, Error> {
        let (stop, out_waker, in_waker) = {
            let d = device.read();
            (d.data_stop.clone(), d.out_waker.clone(), d.in_waker.clone())
        };

        Ok(Self {
            outbound: Outbound::start(device.clone(), stop.clone(), out_waker)?,
            inbound: Inbound::start(device.clone(), stop, in_waker)?,
        })
    }

    pub fn join(self) {
        self.outbound.join();
        self.inbound.join();
    }

    pub(crate) fn close_device(device: &Arc<Lock<Device>>, err: Error) {
        tracing::error!(message = "Critical data plane failure, closing device", error = ?err);

        // TODO: ensure stopping control plane's event loop
        let mut d = device.read();
        d.try_writeable(|dev| dev.trigger_yield(), |dev| dev.closed = true);
        d.trigger_exit();
    }
}

impl DeviceHandle {
    pub fn new(name: &str, config: DeviceConfig) -> Result<DeviceHandle, Error> {
        tracing::info!("NepTUN starting up. GIT_SHA: {}", env!("GIT_SHA"));
        Self::new_with_tun(TunSocket::new(name)?, config)
    }

    pub fn new_with_tun(tun: TunSocket, config: DeviceConfig) -> Result<DeviceHandle, Error> {
        let mut wg_interface = Device::new_with_tun(tun, config)?;
        wg_interface.open_listen_socket(0)?; // Start listening on a random port

        let interface_lock = Arc::new(Lock::new(wg_interface));

        let (control, sockets) = Control::start(interface_lock.clone());

        let data = DataPlane::start(&interface_lock)?;

        Ok(DeviceHandle {
            device: interface_lock,
            control: Some(control),
            data: Some(data),
            sockets_to_close: sockets,
        })
    }

    // fn start_event_loop_threads(
    //     n_threads: usize,
    //     interface_lock: Arc<Lock<Device>>,
    // ) -> EventLoopThreads {
    //     let sockets_to_close = Arc::new(Lock::new(vec![]));
    //     #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    //     let threads = {
    //         let group = DispatchGroup::new();
    //         // `global_queue` returns a shared singleton, so fetch it once.
    //         let queue = DispatchQueue::global_queue(GlobalQueueIdentifier::Priority(
    //             DispatchQueueGlobalPriority::High,
    //         ));
    //         for i in 0..n_threads {
    //             let dev = Arc::clone(&interface_lock);
    //             let thread_local = DeviceHandle::new_thread_local(i, &dev.read())?;
    //             sockets_to_close
    //                 .read()
    //                 .try_writeable(|_| {}, |fds| fds.push(thread_local.iface.clone()));
    //             group.exec_async(&queue, move || DeviceHandle::event_loop(thread_local, &dev));
    //         }
    //         group
    //     };

    //     #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
    //     let threads = {
    //         let mut threads = vec![];
    //         for i in 0..n_threads {
    //             threads.push({
    //                 let dev = Arc::clone(&interface_lock);
    //                 let thread_local = DeviceHandle::new_thread_local(i, &dev.read())?;
    //                 sockets_to_close
    //                     .read()
    //                     .try_writeable(|_| {}, |fds| fds.push(thread_local.iface.clone()));
    //                 thread::Builder::new()
    //                     .name("neptun".to_string())
    //                     .spawn(move || DeviceHandle::event_loop(thread_local, &dev))?
    //             });
    //         }
    //         threads
    //     };

    //     Ok((threads, sockets_to_close))
    // }

    pub fn send_uapi_cmd(&self, cmd: &str) -> String {
        let mut response = Vec::<u8>::new();
        {
            let mut reader = BufReader::new(cmd.as_bytes());
            let mut writer = BufWriter::new(&mut response);
            api::api_exec(&mut self.device.read(), &mut reader, &mut writer);
        }
        std::str::from_utf8(&response)
            .unwrap_or_else(|_| {
                tracing::warn!("Malformed response string");
                ""
            })
            .to_owned()
    }

    pub fn trigger_exit(&self) {
        self.device.read().trigger_exit();
    }

    pub fn drop_connected_sockets(&self) {
        self.device.read().drop_connected_sockets();
    }

    pub fn wait(&mut self) {
        if let Some(data) = self.data.take() {
            data.join();
        }
        if let Some(control) = self.control.take() {
            control.join();
        }
    }

    #[cfg(all(feature = "docker-tests", target_os = "macos"))]
    pub fn is_event_loop_active(&self) -> bool {
        // A zero-timeout wait succeeds only once the group is empty, so a
        // timeout means event loop tasks are still running.
        self.control.wait(DispatchTime::NOW).is_err()
    }

    pub fn clean(&mut self) {
        for path in &self.device.read().cleanup_paths {
            // attempt to remove any file we created in the work dir
            let _ = std::fs::remove_file(path);
        }
    }

    pub fn set_iface(&mut self, new_iface: TunSocket) -> Result<(), Error> {
        // Even though device struct is not being written to, we still take a write lock on device to stop the event loop
        // The event loop must be stopped so that the old iface event handler can be safely cleared.
        // See clear_event_by_fd() function description
        self.device
            .read()
            .try_writeable(
                |device| device.trigger_yield(),
                |device| -> Result<(), Error> {
                    let sockets_to_close = self.sockets_to_close.read().clone();
                    for tun_socket in sockets_to_close {
                        // Because the event loop is stopped now, this is safe (see clear_event_by_fd() comment)
                        let unregister_ok: bool =
                            unsafe { device.queue.clear_event_by_fd(tun_socket.as_raw_fd()) };
                        if !unregister_ok {
                            tracing::warn!(
                                "Failed to clear events handler for fd {tun_socket:?} and name: {:?}",
                                device.iface.name()
                            )
                        }

                        // This will trigger the exit condition in the event_loop running on a different thread
                        // for this file descriptor.
                        tun_socket.force_close();
                    }

                    (device.update_seq, _) = device.update_seq.overflowing_add(1);
                    device.iface = Arc::new(new_iface.set_non_blocking()?);
                    // device.register_read_iface_handler(device.iface.clone())?;
                    device.cancel_yield();

                    Ok(())
                },
            )
            .ok_or(Error::SetTunnel)??;
        let (control, sockets) = Control::start(self.device.clone());
        self.control = Some(control);
        self.sockets_to_close = sockets;
        self.restart_data_plane()
    }

    fn event_loop(mut thread_local: ThreadData, device: &Lock<Device>) {
        loop {
            let mut device_lock = device.read();

            if device_lock.update_seq != thread_local.update_seq {
                // New threads are started when the tun interface is changed, so this
                // thread that was started for an older tun should end.
                return;
            }

            // The event loop keeps a read lock on the device, because we assume write access is rarely needed
            let queue = Arc::clone(&device_lock.queue);

            loop {
                match queue.wait() {
                    WaitResult::Ok(handler) => {
                        let action = (*handler)(&mut device_lock, &mut thread_local);
                        match action {
                            Action::Continue => {}
                            Action::Yield => {
                                tracing::info!("Yielding from inner event loop...");
                                break;
                            }
                            Action::Exit => {
                                tracing::info!("Exiting event loop...");
                                device_lock.try_writeable(
                                    |dev| dev.trigger_yield(),
                                    |dev| dev.closed = true,
                                );
                                device_lock.trigger_exit();
                                return;
                            }
                        }
                    }
                    WaitResult::EoF(handler) => {
                        handler.cancel();
                    }
                    WaitResult::Error(e) => {
                        if e.contains("Interrupted system call") {
                            // Interrupts happening while we are waiting in a syscall (epoll_wait, kevent)
                            // are a normal situation, and not an error condition.
                            tracing::trace!(message = "Poll interrupt", error = ?e)
                        } else {
                            tracing::error!(message = "Poll error", error = ?e)
                        }
                    }
                }
            }
        }
    }

    // fn new_thread_local(
    //     _thread_id: usize,
    //     device_lock: &LockReadGuard<Device>,
    // ) -> Result<ThreadData, Error> {
    //     let t_local = ThreadData {
    //         src_buf: [0u8; MAX_PKT_SIZE],
    //         dst_buf: [0u8; MAX_PKT_SIZE],
    //         iface: Arc::clone(&device_lock.iface),
    //         update_seq: device_lock.update_seq,
    //     };

    //     Ok(t_local)
    // }

    fn restart_data_plane(&mut self) -> Result<(), Error> {
        self.device.read().stop_data_plane();

        if let Some(data) = self.data.take() {
            // Lock must not be held across the join
            data.join();
        }

        let data = DataPlane::start(&self.device)?;

        self.device.read().resume_data_plane();
        self.data = Some(data);

        Ok(())
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.device.read().trigger_exit();
        self.clean();
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
fn set_sock_opt<T: NixSocket::SetSockOpt<Val = usize>>(
    socket: BorrowedFd<'_>,
    buffer: T,
    buffer_size: usize,
    buffer_name: &str,
) {
    match NixSocket::setsockopt(&socket, buffer, &buffer_size) {
        Ok(()) => tracing::info!("Socket buffer {buffer_name:?} set with value {buffer_size}"),
        Err(e) => tracing::warn!("Socket buffer {buffer_name:?} failed with {e}"),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
fn modify_skt_buffer_size(socket: BorrowedFd<'_>, buffer_size: usize) {
    set_sock_opt(socket, NixSocket::sockopt::RcvBuf, buffer_size, "RcvBuf");
    set_sock_opt(socket, NixSocket::sockopt::SndBuf, buffer_size, "SndBuf");
}

impl Device {
    fn next_index(&mut self) -> u32 {
        self.next_index.next()
    }

    fn remove_peer(&mut self, pub_key: &x25519::PublicKey) {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Found a peer to remove, now purge all references to it:
            {
                peer.shutdown_endpoint(); // close open udp socket and free the closure
                self.peers_by_idx.remove(&peer.index());
            }
            self.peers_by_ip
                .remove(&|p: &Arc<Peer>| Arc::ptr_eq(&peer, p));

            tracing::info!("Peer removed");
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn update_peer(
        &mut self,
        pub_key: x25519::PublicKey,
        update_only: bool,
        remove: bool,
        replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) -> Result<(), Error> {
        if remove {
            self.remove_peer(&pub_key);

            return Ok(());
        }

        if let Some(peer) = self.peers.get(&pub_key) {
            if let Some(endpoint) = endpoint {
                peer.set_endpoint(endpoint);
            }

            if replace_ips {
                self.peers_by_ip.remove(&|p| Arc::ptr_eq(peer, p));
                peer.set_allowed_ips(allowed_ips);
            } else {
                peer.add_allowed_ips(allowed_ips);
            }

            if let Some(keepalive) = keepalive {
                peer.tunnel.lock().set_persistent_keepalive(keepalive);
            }

            if let Some(preshared_key) = preshared_key {
                peer.set_preshared_key(preshared_key);
            }

            for AllowedIP { addr, cidr } in allowed_ips {
                self.peers_by_ip.insert(*addr, *cidr as _, Arc::clone(peer));
            }
        } else {
            if update_only {
                return Ok(());
            }

            return self
                .new_peer(pub_key, endpoint, allowed_ips, keepalive, preshared_key)
                .and(Ok(()));
        }

        Ok(())
    }

    fn new_peer(
        &mut self,
        pub_key: x25519_dalek::PublicKey,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) -> Result<Arc<Peer>, Error> {
        let next_index = self.next_index();
        let device_key_pair = self.key_pair.as_ref().ok_or_else(|| {
            tracing::error!("No device keypair specified for a peer");
            Error::InternalError("No device keypair specified for a peer".to_owned())
        })?;

        let tunn = Tunn::new(
            device_key_pair.0.clone(),
            pub_key,
            preshared_key,
            keepalive,
            next_index,
            None,
        )
        .map_err(|e| {
            tracing::error!("Failed to create state for peer {}", e);
            Error::InternalError(format!("Failed to create state for peer {}", e))
        })?;

        let peer = Arc::new(Peer::new(
            tunn,
            next_index,
            endpoint,
            allowed_ips,
            preshared_key,
            self.config.protect.clone(),
        ));

        self.peers.insert(pub_key, Arc::clone(&peer));
        self.peers_by_idx.insert(next_index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip
                .insert(*addr, *cidr as _, Arc::clone(&peer));
        }

        tracing::info!("Peer added");

        Ok(peer)
    }

    pub fn new(name: &str, config: DeviceConfig) -> Result<Device, Error> {
        Self::new_with_tun(TunSocket::new(name)?, config)
    }

    pub fn new_with_tun(tun: TunSocket, config: DeviceConfig) -> Result<Device, Error> {
        // Create a tunnel device
        let iface = Arc::new(tun.set_non_blocking()?);
        let mtu = iface.mtu()?;
        Self::new_with_iface(iface, mtu, config)
    }

    #[cfg(all(test, any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
    pub(crate) fn new_with_mock_tun(
        tun: TunSocket,
        mtu: usize,
        config: DeviceConfig,
    ) -> Result<Device, Error> {
        let iface = Arc::new(tun.set_non_blocking()?);
        Self::new_with_iface(iface, mtu, config)
    }

    fn new_with_iface(
        iface: Arc<TunSocket>,
        mtu: usize,
        config: DeviceConfig,
    ) -> Result<Device, Error> {
        let poll = EventPoll::<Handler>::new()?;

        let mut device = Device {
            queue: Arc::new(poll),
            iface,
            closed: false,
            config,
            exit_notice: Default::default(),
            yield_notice: Default::default(),
            fwmark: Default::default(),
            key_pair: Default::default(),
            listen_port: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            udp4: Default::default(),
            udp6: Default::default(),
            cleanup_paths: Default::default(),
            mtu: Arc::new(AtomicUsize::new(mtu)),
            rate_limiter: None,
            update_seq: 0,
            data_stop: Arc::new(AtomicBool::new(false)),
            out_waker: Arc::new(Waker::new().map_err(Error::from)?),
            in_waker: Arc::new(Waker::new().map_err(Error::from)?),
        };

        if device.config.open_uapi_socket {
            device.register_api_handler()?;
        }
        // device.register_read_iface_handler(Arc::clone(&device.iface))?;
        device.register_notifiers()?;
        device.register_timers()?;

        #[cfg(target_os = "macos")]
        {
            // Only for macOS write the actual socket name into WG_TUN_NAME_FILE
            if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE") {
                std::fs::write(
                    &name_file,
                    device
                        .iface
                        .name()
                        .map_err(|_| Error::InvalidTunnelName)?
                        .as_bytes(),
                )?;
                device.cleanup_paths.push(name_file);
            }
        }

        Ok(device)
    }

    fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
        // Binds the network facing interfaces
        // First close any existing open socket
        if let Some(_) = self.udp4.take() {};

        if let Some(_) = self.udp6.take() {}

        for peer in self.peers.values() {
            peer.shutdown_endpoint();
        }

        // Then open new sockets and bind to the port
        let udp_sock4 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock4.set_reuse_address(true)?;
        udp_sock4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        udp_sock4.set_nonblocking(false)?;
        udp_sock4.set_read_timeout(Some(DATA_SOCKET_READ_TIMEOUT))?;
        self.config.protect.make_external(udp_sock4.as_raw_fd());

        if port == 0 {
            // Random port was assigned
            if let Some(socket) = udp_sock4.local_addr()?.as_socket() {
                port = socket.port();
            }
        }

        let udp_sock6 = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock6.set_reuse_address(true)?;
        udp_sock6.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        udp_sock6.set_nonblocking(false)?;
        udp_sock6.set_read_timeout(Some(DATA_SOCKET_READ_TIMEOUT))?;
        self.config.protect.make_external(udp_sock6.as_raw_fd());

        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
        if let Some(buffer_size) = self.config.skt_buffer_size {
            // Modify IPv4 IPv6 snd and recv buffers
            modify_skt_buffer_size(udp_sock4.as_fd(), buffer_size);
            modify_skt_buffer_size(udp_sock6.as_fd(), buffer_size);
        }

        let udp4 = Arc::new(udp_sock4);
        let udp6 = Arc::new(udp_sock6);
        self.udp4 = Some(udp4.clone());
        self.udp6 = Some(udp6.clone());

        self.notify_data_plane();

        let _ = (&udp4, &udp6);

        self.listen_port = port;

        Ok(())
    }

    fn set_key(&mut self, private_key: x25519::StaticSecret) {
        let mut bad_peers = vec![];

        let public_key = x25519::PublicKey::from(&private_key);
        let key_pair = Some((private_key.clone(), public_key));

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&public_key) == self.key_pair.as_ref().map(|p| &p.1) {
            return;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.values_mut() {
            if peer
                .tunnel
                .lock()
                .set_static_private(
                    private_key.clone(),
                    public_key,
                    Some(Arc::clone(&rate_limiter)),
                )
                .is_err()
            {
                // In case we encounter an error, we will remove that peer
                // An error will be a result of bad public key/secret key combination
                bad_peers.push(Arc::clone(peer));
            }
        }

        self.key_pair = key_pair;
        self.rate_limiter = Some(rate_limiter);
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        // First set fwmark on listeners
        if let Some(ref sock) = self.udp4 {
            sock.set_mark(mark)?;
        }

        if let Some(ref sock) = self.udp6 {
            sock.set_mark(mark)?;
        }

        // Then on all currently connected sockets
        for peer in self.peers.values() {
            if let Some(ref sock) = peer.endpoint().conn {
                sock.set_mark(mark)?
            }
        }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }

    fn register_notifiers(&mut self) -> Result<(), Error> {
        let yield_ev = self
            .queue
            // The notification event handler simply returns Action::Yield
            .new_notifier(Box::new(|_, _| Action::Yield))?;
        self.yield_notice = Some(yield_ev);

        let exit_ev = self
            .queue
            // The exit event handler simply returns Action::Exit
            .new_notifier(Box::new(|_, _| Action::Exit))?;
        self.exit_notice = Some(exit_ev);
        Ok(())
    }

    fn register_timers(&self) -> Result<(), Error> {
        self.queue.new_periodic_event(
            // Reset the rate limiter every second give or take
            Box::new(|d, _| {
                if let Some(r) = d.rate_limiter.as_ref() {
                    r.reset_count()
                }
                Action::Continue
            }),
            std::time::Duration::from_secs(1),
        )?;

        self.queue.new_periodic_event(
            // Execute the timed function of every peer in the list
            Box::new(|d, t| {
                let peer_map = &d.peers;

                let (udp4, udp6) = match (d.udp4.as_ref(), d.udp6.as_ref()) {
                    (Some(udp4), Some(udp6)) => (udp4, udp6),
                    _ => return Action::Continue,
                };

                // Go over each peer and invoke the timer function
                for peer in peer_map.values() {
                    let endpoint_addr = match peer.endpoint().addr {
                        Some(addr) => addr,
                        None => continue,
                    };

                    let res = {
                        let mut tun = peer.tunnel.lock();
                        tun.update_timers(&mut t.dst_buf[..])
                    };
                    match res {
                        TunnResult::Done => {}
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            peer.shutdown_endpoint(); // close open udp socket
                        }
                        TunnResult::Err(e) => tracing::error!(message = "Timer error", error = ?e),
                        TunnResult::WriteToNetwork(packet) => {
                            let res = match endpoint_addr {
                                SocketAddr::V4(_) => {
                                    udp4.send_to(packet, &endpoint_addr.into())
                                }
                                SocketAddr::V6(_) => {
                                    udp6.send_to(packet, &endpoint_addr.into())
                                }
                            };

                            if let Err(err) = res {
                                tracing::warn!(message = "Failed to send timers request", error = ?err, dst = ?endpoint_addr);
                            }
                        }
                        _ => tracing::error!("Unexpected result from update_timers"),
                    };

                    if peer.take_handshake_request() {
                        let res = {
                            let mut tun = peer.tunnel.lock();
                            tun.format_handshake_initiation(&mut t.dst_buf[..], false)
                        };
                        if let TunnResult::WriteToNetwork(packet) = res {
                            let r = match endpoint_addr {
                                SocketAddr::V4(_) => udp4.send_to(packet, &endpoint_addr.into()),
                                SocketAddr::V6(_) => udp6.send_to(packet, &endpoint_addr.into()),
                            };
                            if let Err(e) = r {
                                tracing::warn!(message = "Failed to send handshake init", error = ?e, dst = ?endpoint_addr);
                            }
                        }
                    }
                }
                Action::Continue
            }),
            std::time::Duration::from_millis(250),
        )?;
        Ok(())
    }

    pub fn trigger_yield(&self) {
        match self.yield_notice.as_ref() {
            Some(notice) => self.queue.trigger_notification(notice),
            None => tracing::error!("Notification requested while there is no notice"),
        }
    }

    pub(crate) fn trigger_exit(&self) {
        self.stop_data_plane();

        match self.exit_notice.as_ref() {
            Some(notice) => self.queue.trigger_notification(notice),
            None => tracing::error!("Exit requested while there is no notice"),
        }
    }

    pub(crate) fn drop_connected_sockets(&self) {
        for peer in self.peers.values() {
            let endpoint = peer.endpoint();
            if endpoint.conn.is_some() {
                drop(endpoint);
                peer.shutdown_endpoint();
            }
        }
    }

    pub fn cancel_yield(&self) {
        match self.yield_notice.as_ref() {
            Some(notice) => self.queue.stop_notification(notice),
            None => tracing::error!("Cancellation requested while there is no notice"),
        }
    }

    pub fn iface(&self) -> &TunSocket {
        &self.iface
    }

    pub(crate) fn notify_data_plane(&self) {
        self.out_waker.wake();
        self.in_waker.wake();
    }

    pub(crate) fn stop_data_plane(&self) {
        self.data_stop.store(true, Ordering::Relaxed);
        self.notify_data_plane();
    }

    pub(crate) fn resume_data_plane(&self) {
        self.data_stop.store(false, Ordering::Relaxed);
    }
}

/// A basic linear-feedback shift register implemented as xorshift, used to
/// distribute peer indexes across the 24-bit address space reserved for peer
/// identification.
/// The purpose is to obscure the total number of peers using the system and to
/// ensure it requires a non-trivial amount of processing power and/or samples
/// to guess other peers' indices. Anything more ambitious than this is wasted
/// with only 24 bits of space.
struct IndexLfsr {
    initial: u32,
    lfsr: u32,
    mask: u32,
}

impl IndexLfsr {
    /// Generate a random 24-bit nonzero integer
    fn random_index() -> u32 {
        const LFSR_MAX: u32 = 0xffffff; // 24-bit seed
        loop {
            let i = OsRng.next_u32() & LFSR_MAX;
            if i > 0 {
                // LFSR seed must be non-zero
                return i;
            }
        }
    }

    /// Generate the next value in the pseudorandom sequence
    fn next(&mut self) -> u32 {
        // 24-bit polynomial for randomness. This is arbitrarily chosen to
        // inject bitflips into the value.
        const LFSR_POLY: u32 = 0xd80000; // 24-bit polynomial
        let value = self.lfsr - 1; // lfsr will never have value of 0
        self.lfsr = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1u32)) & LFSR_POLY);
        assert!(self.lfsr != self.initial, "Too many peers created");
        value ^ self.mask
    }
}

impl Default for IndexLfsr {
    fn default() -> Self {
        let seed = Self::random_index();
        IndexLfsr {
            initial: seed,
            lfsr: seed,
            mask: Self::random_index(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_setting_skt_buffers() {
        let socket = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        let _res = socket.set_reuse_address(true);
        let _res = socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into());

        const BUFFER_SIZE: usize = 11111;
        modify_skt_buffer_size(socket.as_fd(), BUFFER_SIZE);

        let get_buf = NixSocket::getsockopt(&socket.as_fd(), NixSocket::sockopt::RcvBuf).unwrap();

        // According to `man 7 socket` linux doubles the buffer size
        // internally as it assumes half is for internal kernel structures
        assert!(get_buf == (BUFFER_SIZE * 2) as usize);
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    fn start_event_loop_threads_starts_one_loop_per_thread() {
        use std::convert::TryFrom;
        use std::os::unix::io::IntoRawFd;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        const N_THREADS: usize = 4;
        const MOCK_MTU: usize = 1420;

        // `_far` keeps the socket's peer end open; `near` backs the TunSocket.
        let (near, _far) = UnixStream::pair().unwrap();
        let tun = TunSocket::new_from_fd(near.into_raw_fd()).unwrap();

        let config = DeviceConfig {
            n_threads: N_THREADS,
            use_connected_socket: false,
            open_uapi_socket: false,
            protect: Arc::new(MakeExternalNeptunNoop),
            firewall_process_inbound_callback: None,
            firewall_process_outbound_callback: None,
            skt_buffer_size: None,
            inter_thread_channel_size: None,
            max_inter_thread_batched_pkts: None,
        };

        let device = Device::new_with_mock_tun(tun, MOCK_MTU, config).unwrap();
        let interface_lock = Arc::new(Lock::new(device));

        let (threads, sockets_to_close) =
            DeviceHandle::start_event_loop_threads(N_THREADS, Arc::clone(&interface_lock)).unwrap();

        // One `sockets_to_close` entry per thread confirms all loops started.
        assert_eq!(sockets_to_close.read().len(), N_THREADS);

        // Bounded wait: a regression fails the assertion instead of hanging.
        interface_lock.read().trigger_exit();
        assert!(
            threads
                .wait(DispatchTime::try_from(Duration::from_secs(10)).unwrap())
                .is_ok(),
            "event loops did not exit"
        );
    }
}
