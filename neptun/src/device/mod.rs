// Copyright (c) 2024 Nord Security. All rights reserved.
// Copyright (c) 2019-2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod allowed_ips;
pub mod api;
mod dev_lock;
pub mod drop_privileges;
#[cfg(test)]
mod integration_tests;
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

use nix::sys::socket as NixSocket;
use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter, Write};
use std::mem::{swap, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsFd, BorrowedFd, RawFd};
#[cfg(not(target_os = "windows"))]
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};
use crate::x25519;
use allowed_ips::AllowedIps;
use crossbeam_channel::{Receiver, Sender};
use num_cpus;
use peer::{AllowedIP, Peer};
use poll::{EventPoll, EventRef, WaitResult};
use rand_core::{OsRng, RngCore};
use socket2::{Domain, Protocol, Type};
use tun::TunSocket;

use dev_lock::{Lock, LockReadGuard};
use thiserror::Error;

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

// Max packet size of 1550 because packets are limited by the MTU sizes
// used in wild networks.
const MAX_PKT_SIZE: usize = 1550;
const MAX_ITR: usize = 100;
const CHANNEL_SIZE: usize = 500;
const WG_HEADER_OFFSET: usize = 16;
const MAX_INTERTHREAD_BATCHED_PKTS: usize = 50;

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
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
    threads: Vec<thread::JoinHandle<()>>,
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    threads: (dispatch::Group, Vec<dispatch::Queue>),
    sockets_to_close: Arc<Lock<Vec<Arc<TunSocket>>>>,
}

#[derive(Clone)]
pub struct DeviceConfig {
    pub n_threads: usize,
    pub use_connected_socket: bool,
    #[cfg(target_os = "linux")]
    pub use_multi_queue: bool,
    pub open_uapi_socket: bool,
    pub protect: Arc<dyn MakeExternalNeptun>,
    pub firewall_process_inbound_callback:
        Option<Arc<dyn Fn(&[u8; 32], &[u8]) -> bool + Send + Sync>>,
    pub firewall_process_outbound_callback:
        Option<Arc<dyn Fn(&[u8; 32], &[u8], &mut dyn std::io::Write) -> bool + Send + Sync>>,
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

    mtu: AtomicUsize,

    rate_limiter: Option<Arc<RateLimiter>>,

    close_network_worker_tx: Sender<()>,
    close_network_worker_rx: Receiver<()>,

    tunnel_to_socket_rx: Receiver<Vec<NetworkTaskData>>,
    tunnel_to_socket_tx: Sender<Vec<NetworkTaskData>>,

    // UDP socket -> processing -> socket_to_tunnel_tx ->
    // [thread boundary] -> socket_to_tunnel_rx -> -> write to tunnel
    socket_to_tunnel_rx: Receiver<Vec<TunnelWorkerData>>,
    socket_to_tunnel_tx: Sender<Vec<TunnelWorkerData>>,
}

struct ThreadData {
    iface: Arc<TunSocket>,
    src_buf: [u8; MAX_PKT_SIZE],
    dst_buf: [u8; MAX_PKT_SIZE],
    update_seq: u32,
}

struct NetworkTaskData {
    data: [u8; MAX_PKT_SIZE],
    buf_len: usize,
    peer: Arc<Peer>,
    iface: Arc<TunSocket>,
}

struct TunnelWorkerData {
    buffer: [u8; MAX_PKT_SIZE],
    peer: Arc<Peer>,
    iface: Arc<TunSocket>,
    addr: IpAddr,
    buf_len: usize,
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
type EventLoopThreads = Result<(Vec<JoinHandle<()>>, Arc<Lock<Vec<Arc<TunSocket>>>>), Error>;
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
type EventLoopThreads = Result<
    (
        (dispatch::Group, Vec<dispatch::Queue>),
        Arc<Lock<Vec<Arc<TunSocket>>>>,
    ),
    Error,
>;

impl DeviceHandle {
    pub fn new(name: &str, config: DeviceConfig) -> Result<DeviceHandle, Error> {
        tracing::info!("NepTUN starting up. GIT_SHA: {}", env!("GIT_SHA"));
        Self::new_with_tun(TunSocket::new(name)?, config)
    }

    pub fn new_with_tun(tun: TunSocket, config: DeviceConfig) -> Result<DeviceHandle, Error> {
        let n_threads = config.n_threads;
        let mut wg_interface = Device::new_with_tun(tun, config)?;
        wg_interface.open_listen_socket(0)?; // Start listening on a random port

        let interface_lock = Arc::new(Lock::new(wg_interface));

        let (threads, sockets_to_close) =
            Self::start_event_loop_threads(n_threads, interface_lock.clone())?;

        Ok(DeviceHandle {
            device: interface_lock,
            threads,
            sockets_to_close,
        })
    }

    fn start_event_loop_threads(
        n_threads: usize,
        interface_lock: Arc<Lock<Device>>,
    ) -> EventLoopThreads {
        let sockets_to_close = Arc::new(Lock::new(vec![]));
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        let threads = {
            let group = dispatch::Group::create();
            let mut queues = vec![];
            for i in 0..n_threads {
                queues.push({
                    let dev = Arc::clone(&interface_lock);
                    let thread_local = DeviceHandle::new_thread_local(i, &dev.read());
                    sockets_to_close
                        .read()
                        .try_writeable(|_| {}, |fds| fds.push(thread_local.iface.clone()));
                    let group_clone = group.clone();
                    let queue = dispatch::Queue::global(dispatch::QueuePriority::High);
                    queue.exec_async(move || {
                        group_clone.enter();
                        DeviceHandle::event_loop(thread_local, &dev)
                    });
                    queue
                });
            }
            (group, queues)
        };

        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
        let threads = {
            let mut threads = vec![];
            for i in 0..n_threads {
                threads.push({
                    let dev = Arc::clone(&interface_lock);
                    let thread_local = DeviceHandle::new_thread_local(i, &dev.read());
                    sockets_to_close
                        .read()
                        .try_writeable(|_| {}, |fds| fds.push(thread_local.iface.clone()));
                    thread::Builder::new()
                        .name(format!("neptun"))
                        .spawn(move || DeviceHandle::event_loop(thread_local, &dev))?
                });
            }
            threads
        };

        Ok((threads, sockets_to_close))
    }

    pub fn send_uapi_cmd(&self, cmd: &str) -> String {
        let mut response = Vec::<u8>::new();
        {
            let mut reader = BufReader::new(cmd.as_bytes());
            let mut writer = BufWriter::new(&mut response);
            api::api_exec(&mut self.device.read(), &mut reader, &mut writer);
        }
        std::str::from_utf8(&response).unwrap().to_owned()
    }

    pub fn trigger_exit(&self) {
        self.device.read().trigger_exit();
    }

    pub fn drop_connected_sockets(&self) {
        self.device.read().drop_connected_sockets();
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
    pub fn wait(&mut self) {
        while let Some(thread) = self.threads.pop() {
            if let Err(e) = thread.join() {
                tracing::error!("Unable to gracefully close thread. {:?}", e);
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    pub fn wait(&mut self) {
        self.threads.0.wait();
    }

    pub fn clean(&mut self) {
        for path in &self.device.read().cleanup_paths {
            // attempt to remove any file we created in the work dir
            let _ = std::fs::remove_file(path);
        }
    }

    pub fn set_iface(&mut self, new_iface: TunSocket) -> Result<(), Error> {
        // Even though device struct is not being written to, we still take a write lock on device to stop the event loop
        // The event loop must be stopped so that the old iface event handler can be safelly cleared.
        // See clear_event_by_fd() function description
        let mut threads = vec![];
        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
        swap(&mut threads, &mut self.threads);
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        swap(&mut threads, &mut self.threads.1);
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
                    device.register_read_iface_handler(device.iface.clone())?;
                    device.cancel_yield();

                    Ok(())
                },
            )
            .ok_or(Error::SetTunnel)??;
        let (threads, sockets_to_close) = DeviceHandle::start_event_loop_threads(
            self.device.read().config.n_threads,
            self.device.clone(),
        )?;
        self.threads = threads;
        self.sockets_to_close = sockets_to_close;
        Ok(())
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
                            Action::Yield => break,
                            Action::Exit => {
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

    fn new_thread_local(_thread_id: usize, device_lock: &LockReadGuard<Device>) -> ThreadData {
        #[cfg(target_os = "linux")]
        let t_local = ThreadData {
            src_buf: [0u8; MAX_PKT_SIZE],
            dst_buf: [0u8; MAX_PKT_SIZE],
            iface: if _thread_id == 0 || !device_lock.config.use_multi_queue {
                // For the first thread use the original iface
                Arc::clone(&device_lock.iface)
            } else {
                // For for the rest create a new iface queue
                let iface_local = Arc::new(
                    TunSocket::new(&device_lock.iface.name().unwrap())
                        .unwrap()
                        .set_non_blocking()
                        .unwrap(),
                );

                device_lock
                    .register_read_iface_handler(Arc::clone(&iface_local))
                    .ok();

                iface_local
            },
            update_seq: device_lock.update_seq,
        };

        #[cfg(not(target_os = "linux"))]
        let t_local = ThreadData {
            src_buf: [0u8; MAX_PKT_SIZE],
            dst_buf: [0u8; MAX_PKT_SIZE],
            iface: Arc::clone(&device_lock.iface),
            update_seq: device_lock.update_seq,
        };

        t_local
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.device.read().trigger_exit();
        self.clean();
    }
}

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
                self.peers_by_ip.remove(&|p| Arc::ptr_eq(&peer, p));
                peer.set_allowed_ips(&allowed_ips);
            } else {
                peer.add_allowed_ips(&allowed_ips);
            }

            if let Some(keepalive) = keepalive {
                peer.tunnel.lock().set_persistent_keepalive(keepalive);
            }

            if let Some(preshared_key) = preshared_key {
                peer.set_preshared_key(preshared_key);
            }

            for AllowedIP { addr, cidr } in allowed_ips {
                self.peers_by_ip
                    .insert(*addr, *cidr as _, Arc::clone(&peer));
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
            pub_key.clone(),
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
            &allowed_ips,
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
        let poll = EventPoll::<Handler>::new()?;

        // Create a tunnel device
        let iface = Arc::new(tun.set_non_blocking()?);
        let mtu = iface.mtu()?;
        let channel_size = config.inter_thread_channel_size.unwrap_or(CHANNEL_SIZE);
        let (tunnel_to_socket_tx, tunnel_to_socket_rx) = crossbeam_channel::bounded(channel_size);
        let (socket_to_tunnel_tx, socket_to_tunnel_rx) = crossbeam_channel::bounded(channel_size);
        let (close_network_worker_tx, close_network_worker_rx) =
            crossbeam_channel::bounded(num_cpus::get_physical());

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
            mtu: AtomicUsize::new(mtu),
            rate_limiter: None,
            tunnel_to_socket_tx,
            tunnel_to_socket_rx,
            close_network_worker_tx,
            close_network_worker_rx,
            socket_to_tunnel_tx,
            socket_to_tunnel_rx,
            update_seq: 0,
        };

        if device.config.open_uapi_socket {
            device.register_api_handler()?;
        }
        device.register_read_iface_handler(Arc::clone(&device.iface))?;
        device.register_notifiers()?;
        device.register_timers()?;

        #[cfg(target_os = "macos")]
        {
            // Only for macOS write the actual socket name into WG_TUN_NAME_FILE
            if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE") {
                std::fs::write(&name_file, device.iface.name().unwrap().as_bytes()).unwrap();
                device.cleanup_paths.push(name_file);
            }
        }

        Ok(device)
    }

    fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
        // Binds the network facing interfaces
        // First close any existing open socket, and remove them from the event loop
        if let Some(s) = self.udp4.take() {
            for _ in 0..num_cpus::get_physical() {
                if let Err(e) = self.close_network_worker_tx.send(()) {
                    tracing::error!("Unable to close network thread {e}");
                }
            }
            unsafe {
                // This is safe because the event loop is not running yet
                self.queue.clear_event_by_fd(s.as_raw_fd());
            }
        };

        if let Some(s) = self.udp6.take() {
            unsafe { self.queue.clear_event_by_fd(s.as_raw_fd()) };
        }

        for peer in self.peers.values() {
            peer.shutdown_endpoint();
        }

        // Then open new sockets and bind to the port
        let udp_sock4 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock4.set_reuse_address(true)?;
        udp_sock4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        udp_sock4.set_nonblocking(true)?;
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
        udp_sock6.set_nonblocking(true)?;
        self.config.protect.make_external(udp_sock6.as_raw_fd());

        if let Some(buffer_size) = self.config.skt_buffer_size {
            // Modify IPv4 IPv6 snd and recv buffers
            modify_skt_buffer_size(udp_sock4.as_fd(), buffer_size);
            modify_skt_buffer_size(udp_sock6.as_fd(), buffer_size);
        }

        self.register_udp_handler(udp_sock4.try_clone().unwrap())?;
        self.register_udp_handler(udp_sock6.try_clone().unwrap())?;

        let udp4 = Arc::new(udp_sock4);
        let udp6 = Arc::new(udp_sock6);
        self.udp4 = Some(udp4.clone());
        self.udp6 = Some(udp6.clone());

        // Process packet in a seperate thread
        for _ in 0..num_cpus::get_physical() {
            let rx_clone = self.tunnel_to_socket_rx.clone();
            let close_chan_clone = self.close_network_worker_rx.clone();
            let udp4_c = udp4.clone();
            let udp6_c = udp6.clone();
            let fw_callback = if let Some(f) = &self.config.firewall_process_outbound_callback {
                Some(f.clone())
            } else {
                None
            };
            thread::spawn(move || {
                write_to_socket_worker(rx_clone, close_chan_clone, udp4_c, udp6_c, fw_callback)
            });
        }

        let rx_clone = self.socket_to_tunnel_rx.clone();
        let fw_callback = self.config.firewall_process_inbound_callback.clone();
        thread::spawn(move || write_to_tun_worker(rx_clone, fw_callback));

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

        // Remove all the bad peers
        for _ in bad_peers {
            unimplemented!();
        }
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
                        _ => panic!("Unexpected result from update_timers"),
                    };
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

    fn register_udp_handler(&self, udp: socket2::Socket) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // Handler that handles anonymous packets over UDP
                let mut iter = MAX_ITR;
                let (private_key, public_key) = d.key_pair.as_ref().expect("Key not set");

                let rate_limiter = d.rate_limiter.as_ref();

                // Loop while we have packets on the anonymous connection

                // Safety: the `recv_from` implementation promises not to write uninitialised
                // bytes to the buffer, so this casting is safe.
                let src_buf =
                    unsafe { &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
                while let Ok((packet_len, addr)) = udp.recv_from(src_buf) {
                    let packet = &t.src_buf[..packet_len];

                    // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
                    let parsed_packet = match rate_limiter {
                        Some(rate_limiter) => {
                            match rate_limiter.verify_packet(Some(addr.as_socket().unwrap().ip()), packet, &mut t.dst_buf) {
                                Ok(packet) => packet,
                                Err(TunnResult::WriteToNetwork(cookie)) => {
                                    if let Err(err) = udp.send_to(cookie, &addr) {
                                        tracing::warn!(message = "Failed to send cookie", error = ?err, dst = ?addr);
                                    }
                                    continue;
                                }
                                Err(_) => continue,
                            }
                        },
                        None => {
                            match Tunn::parse_incoming_packet(packet) {
                                Ok(packet) => packet,
                                Err(_) => continue,
                            }
                        }
                    };

                    let peer = match &parsed_packet {
                        Packet::HandshakeInit(p) => {
                            parse_handshake_anon(private_key, public_key, p)
                                .ok()
                                .and_then(|hh| {
                                    d.peers.get(&x25519::PublicKey::from(hh.peer_static_public))
                                })
                        }
                        Packet::HandshakeResponse(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketCookieReply(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketData(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                    };

                    let peer = match peer {
                        None => continue,
                        Some(peer) => peer,
                    };

                    let mut flush = false; // Are there packets to send from the queue?
                    let res = {
                        let mut tun = peer.tunnel.lock();
                        tun.handle_verified_packet(parsed_packet, &mut t.dst_buf[..])
                    };
                    match res {
                        TunnResult::Done => {}
                        TunnResult::Err(err) => {
                            tracing::warn!(message = "Failed to handle packet", error = ?err);
                            continue;
                        },
                        TunnResult::WriteToNetwork(packet) => {
                            flush = true;
                            if let Err(err) = udp.send_to(packet, &addr) {
                                tracing::warn!(message = "Failed to send packet", error = ?err, dst = ?addr);
                            }
                        }
                        TunnResult::WriteToTunnel(packet, addr) => {
                            if let Some(callback) = &d.config.firewall_process_inbound_callback {
                                if !callback(&peer.public_key.0, packet) {
                                    continue;
                                }
                            }

                            if peer.is_allowed_ip(addr) {
                                _ = t.iface.as_ref().write(packet);
                                tracing::trace!(
                                    message = "Writing packet to tunnel",
                                    interface = ?t.iface.name(),
                                    packet_length = packet.len(),
                                    src_addr = ?addr,
                                    public_key = peer.public_key.1
                                );
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        loop {
                            let res = {
                                let mut tun = peer.tunnel.lock();
                                tun.decapsulate(None, &[], &mut t.dst_buf[..])
                            };

                            let TunnResult::WriteToNetwork(packet) = res else {
                                break;
                            };

                            if let Err(err) = udp.send_to(packet, &addr) {
                                tracing::warn!(message = "Failed to flush queue", error = ?err, dst = ?addr);
                            }
                        }
                    }

                    // This packet was OK, that means we want to create a connected socket for this peer
                    let addr = addr.as_socket().unwrap();
                    let ip_addr = addr.ip();
                    peer.set_endpoint(addr);
                    if d.config.use_connected_socket {
                        // No need for aditional checking, as from this point all packets will arive to connected socket handler
                        if let Ok(sock) = peer.connect_endpoint(d.listen_port, d.config.skt_buffer_size) {
                            if let Err(e) = d.register_read_conn_skt_handler(Arc::clone(peer), sock, ip_addr) {
                                tracing::error!("Failed to register connected socket handler {}", e);
                                peer.shutdown_endpoint();
                            }
                        }
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_read_conn_skt_handler(
        &self,
        peer: Arc<Peer>,
        udp: socket2::Socket,
        peer_addr: IpAddr,
    ) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // The conn_handler handles packet received from a connected UDP socket, associated
                // with a known peer, this saves us the hustle of finding the right peer. If another
                // peer gets the same ip, it will be ignored until the socket does not expire.
                let max_batched_pkts = d.config.max_inter_thread_batched_pkts.unwrap_or(MAX_INTERTHREAD_BATCHED_PKTS);
                loop {
                    let mut batched_pkts = Vec::with_capacity(max_batched_pkts);
                    let mut socket_buffer_exhausted = false;
                    for _ in 0..batched_pkts.capacity() {
                        // Safety: the `recv_from` implementation promises not to write uninitialised
                        // bytes to the buffer, so this casting is safe.
                        let src_buf = unsafe {
                            &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>])
                        };

                        if let Ok(read_bytes) = udp.recv(src_buf) {
                            let mut flush = false;
                            let mut buffer = [0u8; MAX_PKT_SIZE];
                            let res = {
                                let mut tun = peer.tunnel.lock();
                                tun.decapsulate(
                                    Some(peer_addr),
                                    t.src_buf[..read_bytes].as_ref(),
                                    &mut buffer[..],
                                )
                            };

                            match res {
                                TunnResult::Done => {}
                                TunnResult::Err(e) => match e {
                                    WireGuardError::DuplicateCounter => {
                                        // TODO(LLT-6071): revert back to having error level for all error types
                                        tracing::debug!(message="Decapsulate error",
                                            error=?e,
                                            public_key=peer.public_key.1)
                                    }
                                    _ => {
                                        tracing::error!(message="Decapsulate error",
                                            error=?e,
                                            public_key = peer.public_key.1)
                                    }
                                },
                                TunnResult::WriteToNetwork(packet) => {
                                    // Respond to handshake packets
                                    flush = true;
                                    if let Err(err) = udp.send(packet) {
                                        tracing::warn!(message="Failed to write packet", error = ?err);
                                    }
                                }
                                TunnResult::WriteToTunnel(packet, addr) => {
                                    let worker_data = TunnelWorkerData {
                                        buf_len: packet.len(),
                                        addr,
                                        buffer,
                                        iface: t.iface.clone(),
                                        peer: peer.clone(),
                                    };
                                    batched_pkts.push(worker_data);
                                }
                            }

                            if flush {
                                // Flush pending queue
                                loop {
                                    let mut dst_buf = [0u8; MAX_PKT_SIZE];
                                    let res = {
                                        let mut tun = peer.tunnel.lock();
                                        tun.decapsulate(None, &[], &mut dst_buf[..])
                                    };
                                    let TunnResult::WriteToNetwork(packet) = res else {
                                        break;
                                    };
                                    if let Err(err) = udp.send(packet) {
                                        tracing::warn!(message="Failed to flush queue", error = ?err);
                                    }
                                }
                            }
                        } else {
                            // If the queue is empty break out of the loop
                            socket_buffer_exhausted = true;
                            break;
                        }
                    }
                    if let Err(e) = d.socket_to_tunnel_tx.send(batched_pkts) {
                        tracing::warn!("Unable to forward data onto tunnel worker {e}");
                    }
                    if socket_buffer_exhausted {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_read_iface_handler(&self, iface: Arc<TunSocket>) -> Result<(), Error> {
        self.queue.new_event(
            iface.as_raw_fd(),
            Box::new(move |d, _t| {
                // The iface_handler handles packets received from the WireGuard virtual network
                // interface. The flow is as follows:
                // * Read a packet
                // * Determine peer based on packet destination ip
                // * Encapsulate the packet for the given peer
                // * Send encapsulated packet to the peer's endpoint
                let mtu = d.mtu.load(Ordering::Relaxed);

                let peers = &d.peers_by_ip;
                let max_batched_pkts = d
                    .config
                    .max_inter_thread_batched_pkts
                    .unwrap_or(MAX_INTERTHREAD_BATCHED_PKTS);
                loop {
                    let mut batched_pkts = Vec::with_capacity(max_batched_pkts);
                    let mut tunnel_buffer_exhausted = false;
                    for _ in 0..batched_pkts.capacity() {
                        let mut buffer = [0u8; MAX_PKT_SIZE];
                        let len = match iface
                            .read(&mut buffer[WG_HEADER_OFFSET..mtu + WG_HEADER_OFFSET])
                        {
                            Ok(src) => src.len(),
                            Err(Error::IfaceRead(e)) => {
                                let ek = e.kind();
                                if ek == io::ErrorKind::Interrupted
                                    || ek == io::ErrorKind::WouldBlock
                                {
                                    tunnel_buffer_exhausted = true;
                                    break;
                                }
                                tracing::error!(
                                    message="Fatal read error on tun interface: errno", error=?e
                                );
                                return Action::Exit;
                            }
                            Err(e) => {
                                tracing::error!(
                                    message="Unexpected error on tun interface", error=?e
                                );
                                return Action::Exit;
                            }
                        };

                        let dst_addr = match Tunn::dst_address(
                            &buffer[WG_HEADER_OFFSET..len + WG_HEADER_OFFSET],
                        ) {
                            Some(addr) => addr,
                            None => continue,
                        };

                        let peer = match peers.find(dst_addr) {
                            Some(peer) => peer,
                            None => continue,
                        };
                        batched_pkts.push(NetworkTaskData {
                            data: buffer,
                            buf_len: len,
                            peer: peer.clone(),
                            iface: iface.clone(),
                        });
                    }
                    if let Err(e) = d.tunnel_to_socket_tx.send(batched_pkts) {
                        tracing::warn!("Unable to forward data onto network worker {e}");
                    }
                    if tunnel_buffer_exhausted {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    pub fn iface(&self) -> &TunSocket {
        &self.iface
    }
}

fn write_to_socket_worker(
    tunnel_to_socket_rx: Receiver<Vec<NetworkTaskData>>,
    close_chan: Receiver<()>,
    udp4: Arc<socket2::Socket>,
    udp6: Arc<socket2::Socket>,
    firewall_process_outbound_callback: Option<
        Arc<dyn Fn(&[u8; 32], &[u8], &mut dyn std::io::Write) -> bool + Send + Sync>,
    >,
) {
    loop {
        crossbeam_channel::select! {
            recv(tunnel_to_socket_rx) -> element => {
                if let Ok(mut batched_pkts) = element {
                    for element in batched_pkts.iter_mut() {
                        let len = element.buf_len;

                        if let Some(callback) = &firewall_process_outbound_callback {
                                if !callback(&element.peer.public_key.0, &element.data[WG_HEADER_OFFSET..len + WG_HEADER_OFFSET], &mut element.iface.as_ref()) {
                                    continue;
                                }
                        }

                        let res = {
                            let mut tun = element.peer.tunnel.lock();
                            tun.encapsulate_in_place(len, &mut element.data[..])
                        };
                        match res {
                            TunnResult::Done => {}
                            TunnResult::Err(e) => {
                                tracing::error!(message = "Encapsulate error",
                                    error = ?e,
                                    public_key = element.peer.public_key.1)
                            }
                            TunnResult::WriteToNetwork(packet) => {
                                let endpoint = element.peer.endpoint();
                                if let Some(conn) = endpoint.conn.as_ref() {
                                    // Prefer to send using the connected socket
                                    if let Err(err) = conn.send(packet) {
                                        tracing::debug!(message = "Failed to send packet with the connected socket", error = ?err);
                                        drop(endpoint);
                                        element.peer.shutdown_endpoint();
                                    } else {
                                        tracing::trace!(
                                            "Pkt -> ConnSock ({:?}), len: {}",
                                            endpoint.addr,
                                            packet.len(),
                                        );
                                    }
                                } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
                                    if let Err(err) = udp4.send_to(packet, &addr.into()) {
                                        tracing::warn!(message = "Failed to write packet to network v4", error = ?err, dst = ?addr);
                                    } else {
                                        tracing::trace!(
                                            message = "Writing packet to network v4",
                                            packet_length = packet.len(),
                                            src_addr = ?addr,
                                            public_key = element.peer.public_key.1
                                        );
                                    }
                                } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
                                    if let Err(err) = udp6.send_to(packet, &addr.into()) {
                                        tracing::warn!(message = "Failed to write packet to network v6", error = ?err, dst = ?addr);
                                    } else {
                                        tracing::trace!(
                                            message = "Writing packet to network v6",
                                            packet_length = packet.len(),
                                            src_addr = ?addr,
                                            public_key = element.peer.public_key.1
                                        );
                                    }
                                } else {
                                    tracing::error!("No endpoint");
                                }
                            }
                            _ => panic!("Unexpected result from encapsulate"),
                        };
                    }
                }
            }
            recv(close_chan) -> _n => {
                break;
            }
        }
    }
}

fn write_to_tun_worker(
    socket_to_tunnel_rx: Receiver<Vec<TunnelWorkerData>>,
    firewall_process_inbound_callback: Option<Arc<dyn Fn(&[u8; 32], &[u8]) -> bool + Send + Sync>>,
) {
    loop {
        if let Ok(batched_pkts) = socket_to_tunnel_rx.recv() {
            for t in batched_pkts {
                let peer = t.peer;

                if let Some(callback) = &firewall_process_inbound_callback {
                    if !callback(&peer.public_key.0, &t.buffer[..t.buf_len]) {
                        continue;
                    }
                }
                if peer.is_allowed_ip(t.addr) {
                    _ = t.iface.as_ref().write(&t.buffer[..t.buf_len]);
                    tracing::trace!(
                        message = "Writing packet to tunnel",
                        packet_length = t.buf_len,
                        src_addr = ?t.addr,
                        public_key = peer.public_key.1
                    );
                }
            }
        };
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

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
}
