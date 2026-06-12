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

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};
use crate::x25519;
use allowed_ips::AllowedIps;
use crossbeam_channel::{Receiver, Sender};
use nix::sys::socket as NixSocket;
use num_cpus;
use peer::{AllowedIP, Peer};
use poll::{EventPoll, EventRef, WaitResult};
use rand_core::{OsRng, RngCore};
use socket2::{Domain, Protocol, Type};
use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter, Write};
use std::mem::{swap, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsFd, BorrowedFd, RawFd};
#[cfg(not(target_os = "windows"))]
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
use std::thread::JoinHandle;
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

// PoC Step 2: number of datagrams a single recvmmsg/sendmmsg syscall handles. The OUT thread
// drains the TUN fd up to this many packets (or until EWOULDBLOCK) before one sendmmsg; the IN
// thread receives up to this many datagrams per recvmmsg. Tunable after profiling.
const MMSG_BATCH: usize = 16;

/// `AtomicU64::fetch_min` is unstable on the pinned toolchain, so do a CAS loop.
fn atomic_min(a: &AtomicU64, v: u64) {
    let mut cur = a.load(Ordering::Relaxed);
    while v < cur {
        match a.compare_exchange_weak(cur, v, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(x) => cur = x,
        }
    }
}

/// `AtomicU64::fetch_max` counterpart of [`atomic_min`].
fn atomic_max(a: &AtomicU64, v: u64) {
    let mut cur = a.load(Ordering::Relaxed);
    while v > cur {
        match a.compare_exchange_weak(cur, v, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(x) => cur = x,
        }
    }
}

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
        Option<Arc<dyn Fn(&[u8; 32], &mut [u8]) -> bool + Send + Sync>>,
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

    close_network_worker_tx: Option<Sender<()>>,
    close_tun_worker_tx: Option<Sender<()>>,

    tunnel_to_socket_rx: Receiver<Vec<NetworkTaskData>>,
    tunnel_to_socket_tx: Sender<Vec<NetworkTaskData>>,

    // UDP socket -> processing -> socket_to_tunnel_tx ->
    // [thread boundary] -> socket_to_tunnel_rx -> -> write to tunnel
    socket_to_tunnel_rx: Receiver<Vec<TunnelWorkerData>>,
    socket_to_tunnel_tx: Sender<Vec<TunnelWorkerData>>,

    /// PoC two-thread data plane: set to stop the OUT/IN data threads (see out_data_thread /
    /// in_data_thread). The epoll control plane stops via its exit notifier.
    data_stop: Arc<AtomicBool>,
    /// PoC two-thread data plane packet/byte counters, logged every 10s.
    data_stats: Arc<DataStats>,
}

/// PoC two-thread data plane counters, logged periodically (see register_timers). `out_*` is
/// the OUT/encrypt thread (TUN→net), `in_*` is the IN/decrypt thread (net→TUN). `prev_*` hold
/// the last logged values so the logger can report a per-interval delta.
///
/// Step 2 adds per-direction batch stats: `*_batches` counts recvmmsg/sendmmsg calls that moved
/// ≥1 packet (monotonic, delta'd against `prev_*_batches` for a per-interval average), and
/// `*_batch_min`/`*_batch_max` track the per-interval extremes of packets-per-batch (the logger
/// resets them each interval: min→u64::MAX, max→0).
struct DataStats {
    out_pkts: AtomicU64,
    out_bytes: AtomicU64,
    in_pkts: AtomicU64,
    in_bytes: AtomicU64,
    prev_out_pkts: AtomicU64,
    prev_out_bytes: AtomicU64,
    prev_in_pkts: AtomicU64,
    prev_in_bytes: AtomicU64,
    out_batches: AtomicU64,
    in_batches: AtomicU64,
    prev_out_batches: AtomicU64,
    prev_in_batches: AtomicU64,
    out_batch_min: AtomicU64,
    out_batch_max: AtomicU64,
    in_batch_min: AtomicU64,
    in_batch_max: AtomicU64,
    /// Packets read from the TUN but never sent (sendmmsg short/error, encrypt failure).
    out_drops: AtomicU64,
    /// Datagrams received but never written to the TUN (write EAGAIN, decrypt fail, no session).
    in_drops: AtomicU64,
    prev_out_drops: AtomicU64,
    prev_in_drops: AtomicU64,
}

impl Default for DataStats {
    fn default() -> Self {
        // Manual impl (not derive): the two `*_batch_min` fields must start at u64::MAX so the
        // first observed batch wins the min; everything else starts at 0.
        DataStats {
            out_pkts: AtomicU64::new(0),
            out_bytes: AtomicU64::new(0),
            in_pkts: AtomicU64::new(0),
            in_bytes: AtomicU64::new(0),
            prev_out_pkts: AtomicU64::new(0),
            prev_out_bytes: AtomicU64::new(0),
            prev_in_pkts: AtomicU64::new(0),
            prev_in_bytes: AtomicU64::new(0),
            out_batches: AtomicU64::new(0),
            in_batches: AtomicU64::new(0),
            prev_out_batches: AtomicU64::new(0),
            prev_in_batches: AtomicU64::new(0),
            out_batch_min: AtomicU64::new(u64::MAX),
            out_batch_max: AtomicU64::new(0),
            in_batch_min: AtomicU64::new(u64::MAX),
            in_batch_max: AtomicU64::new(0),
            out_drops: AtomicU64::new(0),
            in_drops: AtomicU64::new(0),
            prev_out_drops: AtomicU64::new(0),
            prev_in_drops: AtomicU64::new(0),
        }
    }
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
        // PoC two-thread model: the epoll loop is only the control plane (timers, notifiers,
        // udp bootstrap), so a single epoll thread is enough. Forcing 1 also avoids the
        // multi-queue per-thread TUN creation (we dropped IFF_MULTI_QUEUE; unavailable on
        // Android). The data plane is the two dedicated OUT/IN threads.
        let n_threads = 1;
        let mut wg_interface = Device::new_with_tun(tun, config)?;
        wg_interface.open_listen_socket(0)?; // Start listening on a random port

        let interface_lock = Arc::new(Lock::new(wg_interface));

        #[allow(unused_mut)]
        let (mut threads, sockets_to_close) =
            Self::start_event_loop_threads(n_threads, interface_lock.clone())?;

        // PoC two-thread data plane: one thread per direction, on blocking fds.
        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "tvos")))]
        {
            let stop = interface_lock.read().data_stop.clone();
            let dev_out = interface_lock.clone();
            let dev_in = interface_lock.clone();
            let stop_in = stop.clone();
            threads.push(
                thread::Builder::new()
                    .name("neptun-out".to_string())
                    .spawn(move || out_data_thread(dev_out, stop))?,
            );
            threads.push(
                thread::Builder::new()
                    .name("neptun-in".to_string())
                    .spawn(move || in_data_thread(dev_in, stop_in))?,
            );
        }

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
                    let thread_local = DeviceHandle::new_thread_local(i, &dev.read())?;
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
                    let thread_local = DeviceHandle::new_thread_local(i, &dev.read())?;
                    sockets_to_close
                        .read()
                        .try_writeable(|_| {}, |fds| fds.push(thread_local.iface.clone()));
                    thread::Builder::new()
                        .name("neptun".to_string())
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

    fn new_thread_local(
        _thread_id: usize,
        device_lock: &LockReadGuard<Device>,
    ) -> Result<ThreadData, Error> {
        #[cfg(target_os = "linux")]
        let t_local = ThreadData {
            src_buf: [0u8; MAX_PKT_SIZE],
            dst_buf: [0u8; MAX_PKT_SIZE],
            iface: if _thread_id == 0 || !device_lock.config.use_multi_queue {
                // For the first thread use the original iface
                Arc::clone(&device_lock.iface)
            } else {
                // For for the rest create a new iface queue
                let iface_local =
                    Arc::new(TunSocket::new(&device_lock.iface.name()?)?.set_non_blocking()?);

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

        Ok(t_local)
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.device.read().trigger_exit();
        self.clean();
    }
}

fn set_sock_opt<T>(socket: BorrowedFd<'_>, buffer: T, buffer_size: usize, buffer_name: &str)
where
    T: NixSocket::SetSockOpt<Val = usize> + NixSocket::GetSockOpt<Val = usize> + Copy,
{
    match NixSocket::setsockopt(&socket, buffer, &buffer_size) {
        Ok(()) => {
            // Read back the EFFECTIVE size: the kernel clamps SO_RCVBUF/SO_SNDBUF to
            // net.core.{r,w}mem_max (an unprivileged app can't exceed it), so the requested
            // value alone is misleading. Linux reports ~2x the usable size here (bookkeeping
            // overhead), so `effective` well below 2*requested means it was clamped.
            let effective = NixSocket::getsockopt(&socket, buffer).unwrap_or(0);
            tracing::info!(
                "Socket buffer {buffer_name:?}: requested {buffer_size}, effective {effective} (kernel reports ~2x; if << 2x requested it was clamped to net.core.{{r,w}}mem_max)"
            );
        }
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
        let poll = EventPoll::<Handler>::new()?;

        // Create a tunnel device. PoC two-thread model: the OUT thread waits for TUN
        // readiness with poll() (timeout) and then read()s, so the fd is left in its inherited
        // (non-blocking, on Android VpnService) state — poll handles the wait + stop-check.
        let iface = Arc::new(tun);
        let mtu = iface.mtu()?;
        let channel_size = config.inter_thread_channel_size.unwrap_or(CHANNEL_SIZE);
        let (tunnel_to_socket_tx, tunnel_to_socket_rx) = crossbeam_channel::bounded(channel_size);
        let (socket_to_tunnel_tx, socket_to_tunnel_rx) = crossbeam_channel::bounded(channel_size);

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
            close_network_worker_tx: None,
            socket_to_tunnel_tx,
            socket_to_tunnel_rx,
            close_tun_worker_tx: None,
            update_seq: 0,
            data_stop: Arc::new(AtomicBool::new(false)),
            data_stats: Arc::new(DataStats::default()),
        };

        if device.config.open_uapi_socket {
            device.register_api_handler()?;
        }
        // NOTE: the TUN read handler is intentionally NOT registered — the OUT data thread
        // owns the TUN fd. The epoll loop is kept only as the control plane (timers,
        // notifiers, udp bootstrap handler).
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
        // First close any existing open socket, and remove them from the event loop
        if let Some(s) = self.udp4.take() {
            if let Some(close_network_worker_tx) = &self.close_network_worker_tx {
                for _ in 0..num_cpus::get_physical() {
                    if let Err(e) = close_network_worker_tx.try_send(()) {
                        tracing::error!("Unable to close network thread {e}");
                    }
                }
            }
            if let Some(close_tun_worker_tx) = &self.close_tun_worker_tx {
                if let Err(e) = close_tun_worker_tx.try_send(()) {
                    tracing::error!("Unable to close tun thread {e}");
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

        self.register_udp_handler(udp_sock4.try_clone()?)?;
        self.register_udp_handler(udp_sock6.try_clone()?)?;

        let udp4 = Arc::new(udp_sock4);
        let udp6 = Arc::new(udp_sock6);
        self.udp4 = Some(udp4.clone());
        self.udp6 = Some(udp6.clone());

        // PoC two-thread model: the legacy encrypt/decrypt worker pool is NOT spawned. The
        // data plane runs on the dedicated OUT/IN threads (see out_data_thread/in_data_thread).
        // udp4/udp6 are kept for handshake bootstrap; the connected socket carries data.
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

        // PoC: log the two-thread data-plane packet/byte counters every 10s (delta + totals).
        self.queue.new_periodic_event(
            Box::new(|d, _| {
                let s = &d.data_stats;
                let out_p = s.out_pkts.load(Ordering::Relaxed);
                let out_b = s.out_bytes.load(Ordering::Relaxed);
                let in_p = s.in_pkts.load(Ordering::Relaxed);
                let in_b = s.in_bytes.load(Ordering::Relaxed);
                let d_out_p = out_p.wrapping_sub(s.prev_out_pkts.swap(out_p, Ordering::Relaxed));
                let d_out_b = out_b.wrapping_sub(s.prev_out_bytes.swap(out_b, Ordering::Relaxed));
                let d_in_p = in_p.wrapping_sub(s.prev_in_pkts.swap(in_p, Ordering::Relaxed));
                let d_in_b = in_b.wrapping_sub(s.prev_in_bytes.swap(in_b, Ordering::Relaxed));

                // Batch stats: per-interval packets-per-batch min/avg/max, per direction.
                // Read + RESET the min/max every interval (unconditionally, before the idle
                // guard, so a stale extreme can't linger). avg = interval pkts / interval batches.
                let out_batches = s.out_batches.load(Ordering::Relaxed);
                let in_batches = s.in_batches.load(Ordering::Relaxed);
                let d_out_batches =
                    out_batches.wrapping_sub(s.prev_out_batches.swap(out_batches, Ordering::Relaxed));
                let d_in_batches =
                    in_batches.wrapping_sub(s.prev_in_batches.swap(in_batches, Ordering::Relaxed));
                let out_min = s.out_batch_min.swap(u64::MAX, Ordering::Relaxed);
                let out_max = s.out_batch_max.swap(0, Ordering::Relaxed);
                let in_min = s.in_batch_min.swap(u64::MAX, Ordering::Relaxed);
                let in_max = s.in_batch_max.swap(0, Ordering::Relaxed);
                // Display the u64::MAX sentinel (no batches this interval) as 0.
                let out_min = if out_min == u64::MAX { 0 } else { out_min };
                let in_min = if in_min == u64::MAX { 0 } else { in_min };
                let out_avg = if d_out_batches > 0 { d_out_p as f64 / d_out_batches as f64 } else { 0.0 };
                let in_avg = if d_in_batches > 0 { d_in_p as f64 / d_in_batches as f64 } else { 0.0 };

                // Dropped packets per interval (sendmmsg short/error/encrypt fail on OUT;
                // tun-write EAGAIN / decrypt fail / no session on IN). Nonzero here explains
                // TCP retransmissions / throughput shortfall.
                let out_drops = s.out_drops.load(Ordering::Relaxed);
                let in_drops = s.in_drops.load(Ordering::Relaxed);
                let d_out_drops = out_drops.wrapping_sub(s.prev_out_drops.swap(out_drops, Ordering::Relaxed));
                let d_in_drops = in_drops.wrapping_sub(s.prev_in_drops.swap(in_drops, Ordering::Relaxed));

                // Skip the line entirely when idle to avoid log spam.
                if d_out_p != 0 || d_in_p != 0 {
                    tracing::info!(
                        "neptun data-plane (last 10s): OUT +{d_out_p} pkts (+{d_out_b} B) [batch {d_out_batches}x min/avg/max {out_min}/{out_avg:.1}/{out_max}] drops {d_out_drops} | IN +{d_in_p} pkts (+{d_in_b} B) [batch {d_in_batches}x min/avg/max {in_min}/{in_avg:.1}/{in_max}] drops {d_in_drops} || totals OUT {out_p} pkts / {out_b} B ({out_drops} drop), IN {in_p} pkts / {in_b} B ({in_drops} drop)"
                    );
                }
                Action::Continue
            }),
            std::time::Duration::from_secs(10),
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

                    // PoC: the OUT data thread can't initiate handshakes (it does no Tunn
                    // handshake work). When it has data but no session it sets want_handshake;
                    // the control plane initiates here.
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
                            if let Err(err) = r {
                                tracing::warn!(message = "Failed to send handshake init", error = ?err, dst = ?endpoint_addr);
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
        // Stop the data-plane threads (they poll this flag on their I/O timeouts)...
        self.data_stop.store(true, Ordering::Relaxed);
        // ...and the epoll control-plane loop via its exit notifier.
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
                let (private_key, public_key) = if let Some((sk, pk)) = d.key_pair.as_ref() {
                    (sk, pk)
                } else {
                    tracing::error!("Empty key pair");
                    return Action::Exit;
                };

                let rate_limiter = d.rate_limiter.as_ref();

                // Loop while we have packets on the anonymous connection

                // Safety: the `recv_from` implementation promises not to write uninitialised
                // bytes to the buffer, so this casting is safe.
                let src_buf =
                    unsafe { &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
                while let Ok((packet_len, addr)) = udp.recv_from(src_buf) {
                    let packet = match t.src_buf.get(..packet_len) {
                        Some(p) => p,
                        None => {tracing::error!("Buffer size different from packet length"); continue;},
                    };

                    let sock = match addr.as_socket() {
                        Some(s) => s,
                        None => {tracing::warn!("Invalid socket address family"); continue;}
                    };
                    // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
                    let parsed_packet = match rate_limiter {
                        Some(rate_limiter) => {
                            match rate_limiter.verify_packet(Some(sock.ip()), packet, &mut t.dst_buf) {
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
                            // PoC: firewall callbacks dropped.
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

                    // This packet was OK, that means we want to create a connected socket for
                    // this peer. PoC: we DON'T register an epoll handler for it — the IN data
                    // thread owns the connected socket recv, and the OUT thread sends on it.
                    //
                    // PoC: roaming DISABLED on udp4/udp6. We only *learn* the endpoint once (if
                    // it was never configured); we never update it from a packet's source
                    // address. Roaming could move the peer endpoint and desync it from the
                    // connected data socket (`conn` is bound + connected once), making the peer
                    // flip between source ports. (See NepTUN/notes.md.)
                    if peer.endpoint().addr.is_none() {
                        peer.set_endpoint(sock);
                    }
                    if d.config.use_connected_socket {
                        if let Err(e) = peer.connect_endpoint(d.listen_port, d.config.skt_buffer_size)
                        {
                            tracing::error!("Failed to create connected socket {}", e);
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
                                #[allow(clippy::indexing_slicing)]
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

                if mtu + WG_HEADER_OFFSET > MAX_PKT_SIZE {
                    tracing::error!("Insufficient packet buffer size");
                    return Action::Exit;
                }

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
                        #[allow(clippy::indexing_slicing)] // Size already checked above
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

                        #[allow(clippy::indexing_slicing)] // Size already checked above
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
                                let buffer = match element.data.get(WG_HEADER_OFFSET..len + WG_HEADER_OFFSET) {
                                    Some(b) => b,
                                    None => continue,
                                };
                                if !callback(&element.peer.public_key.0, buffer, &mut element.iface.as_ref()) {
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
                            _ => {
                                tracing::error!("Unexpected result from encapsulate");
                                continue;
                            },
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
    close_chan: Receiver<()>,
    firewall_process_inbound_callback: Option<
        Arc<dyn Fn(&[u8; 32], &mut [u8]) -> bool + Send + Sync>,
    >,
) {
    loop {
        crossbeam_channel::select! {
            recv(socket_to_tunnel_rx) -> batched_pkts => {
                if let Ok(batched_pkts) = batched_pkts {
                    for mut t in batched_pkts {
                        let peer = t.peer;

                        let buffer = match t.buffer.get_mut(..t.buf_len) {
                            Some(b) => b,
                            None => {tracing::warn!("Length is greater than buffer space"); continue},
                        };
                        if let Some(callback) = &firewall_process_inbound_callback {
                            if !callback(&peer.public_key.0, buffer) {
                                continue;
                            }
                        }
                        if peer.is_allowed_ip(t.addr) {
                            _ = t.iface.as_ref().write(buffer);
                            tracing::trace!(
                                message = "Writing packet to tunnel",
                                packet_length = t.buf_len,
                                src_addr = ?t.addr,
                                public_key = peer.public_key.1
                            );
                        }
                    }
                }
            }
            recv(close_chan) -> _n => {
                break;
            }
        }
    }
}

/// PoC two-thread data plane, OUT direction: TUN read -> encrypt -> connected-socket send.
/// Crypto runs on a cloned `Arc<Session>` with no `Tunn` lock held (only a short lock to
/// clone the session out). Single peer. No handshake/timer work here — if there is no
/// session yet, it asks the control plane (epoll timers) to initiate a handshake.
fn out_data_thread(device: Arc<Lock<Device>>, stop: Arc<AtomicBool>) {
    let (iface, stats) = {
        let d = device.read();
        (d.iface.clone(), d.data_stats.clone())
    };
    let tun_fd = iface.as_raw_fd();

    // Per-thread batch buffers (boxed: ~99 KB; Android thread stacks can be small). Each slot
    // holds one raw IP packet read into [WG_HEADER_OFFSET..] and is encrypted IN PLACE; the
    // resulting WireGuard data packet to send then starts at slot offset 0.
    let mut bufs: Box<[[u8; MAX_PKT_SIZE]; MMSG_BATCH]> =
        Box::new([[0u8; MAX_PKT_SIZE]; MMSG_BATCH]);
    // Per-slot length: during drain it holds the plaintext length; after encrypt it is replaced
    // with the full WG-packet length (0 == skip this slot in sendmmsg).
    let mut lens = [0usize; MMSG_BATCH];
    // Cached clone of the peer's connected socket (appears after the first handshake).
    let mut conn: Option<socket2::Socket> = None;

    while !stop.load(Ordering::Relaxed) {
        // Wait for TUN readiness with a timeout so we periodically re-check `stop` (the TUN
        // char device has no SO_RCVTIMEO). The fd is non-blocking, so the drain read below
        // returns EWOULDBLOCK once the queue empties.
        let mut pfd = libc::pollfd {
            fd: tun_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let pr = unsafe { libc::poll(&mut pfd, 1, 250) };
        if pr <= 0 {
            continue; // timeout (re-check stop) or error
        }

        // Drain the TUN fd into the batch: read until EWOULDBLOCK or the batch is full, so one
        // sendmmsg can take the whole batch.
        let mtu = device.read().mtu.load(Ordering::Relaxed).min(MAX_PKT_SIZE - WG_HEADER_OFFSET);
        let mut count = 0usize;
        while count < MMSG_BATCH {
            match iface.read(&mut bufs[count][WG_HEADER_OFFSET..WG_HEADER_OFFSET + mtu]) {
                Ok(s) => {
                    let n = s.len();
                    if n == 0 {
                        break;
                    }
                    lens[count] = n; // plaintext length (replaced by encrypt below)
                    count += 1;
                }
                // Non-blocking TUN drained: stop the batch.
                Err(Error::IfaceRead(ref e)) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    tracing::info!(message = "OUT: tun read error", error = ?e);
                    break;
                }
            }
        }
        if count == 0 {
            continue;
        }

        // Single-peer PoC: every TUN packet goes to the one peer, so fetch the peer + its
        // current session + connected socket ONCE per batch (short lock), then crypt off-lock.
        // NOTE: multi-peer would require per-packet dst routing + grouping by destination here.
        let session = {
            let d = device.read();
            let peer = match d.peers.values().next() {
                Some(p) => p,
                None => {
                    tracing::info!("OUT: no peer configured; dropping batch");
                    continue;
                }
            };
            if conn.is_none() {
                conn = peer
                    .endpoint()
                    .conn
                    .as_ref()
                    .and_then(|c| c.try_clone().ok());
                tracing::info!(message = "OUT: connected-socket fetch", acquired = conn.is_some());
            }
            // Bind to a local so the tunnel MutexGuard temporary drops before the device guard.
            let current = peer.tunnel.lock().current_session();
            match current {
                Some(s) => s,
                None => {
                    // No session yet: ask the control plane to handshake; drop this batch (the
                    // fd was already drained, so poll() won't hot-loop on the same packets).
                    tracing::info!("OUT: no current session; requesting handshake, dropping batch");
                    peer.request_handshake();
                    continue;
                }
            }
        };

        let sock_fd = match conn.as_ref() {
            Some(c) => c.as_raw_fd(),
            None => {
                tracing::info!("OUT: have session but no connected socket yet; dropping batch");
                continue;
            }
        };

        // Encrypt each drained packet in place; record the full WG-packet length per slot.
        for i in 0..count {
            let plain_len = lens[i];
            match session.encrypt(plain_len, &mut bufs[i][..]) {
                Ok(packet) => lens[i] = packet.len(),
                Err(e) => {
                    tracing::warn!(message = "OUT: encrypt failed", error = ?e);
                    lens[i] = 0; // skip this slot in sendmmsg
                    stats.out_drops.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // Build the sendmmsg vector from slots that encrypted successfully. iovec/mmsghdr hold
        // raw pointers into `bufs`; no live Rust reference into the buffers is kept across the
        // syscall.
        let mut iovecs: [libc::iovec; MMSG_BATCH] = unsafe { std::mem::zeroed() };
        let mut msgs: [libc::mmsghdr; MMSG_BATCH] = unsafe { std::mem::zeroed() };
        let mut vlen = 0usize;
        for i in 0..count {
            if lens[i] == 0 {
                continue;
            }
            iovecs[vlen].iov_base = bufs[i].as_mut_ptr() as *mut libc::c_void;
            iovecs[vlen].iov_len = lens[i] as _;
            msgs[vlen].msg_hdr.msg_iov = &mut iovecs[vlen] as *mut libc::iovec;
            msgs[vlen].msg_hdr.msg_iovlen = 1 as _;
            vlen += 1;
        }
        if vlen == 0 {
            continue;
        }

        // SAFETY: msgs/iovecs are valid for `vlen` entries and point into live `bufs`; the
        // connected socket needs no addresses. The kernel only reads the buffers.
        let sent = unsafe { libc::sendmmsg(sock_fd, msgs.as_mut_ptr(), vlen as _, 0) };
        if sent < 0 {
            let err = io::Error::last_os_error();
            // The whole drained batch is lost here (read from TUN, never sent).
            stats.out_drops.fetch_add(vlen as u64, Ordering::Relaxed);
            match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => {} // transient; drop
                _ => {
                    tracing::warn!(message = "OUT: sendmmsg failed", error = ?err);
                    conn = None; // re-fetch the socket (e.g. endpoint reset/roam)
                }
            }
            continue;
        }
        let sent = sent as usize;
        // sendmmsg may stop early (e.g. ENOBUFS): the unsent tail is dropped — count it.
        if sent < vlen {
            stats.out_drops.fetch_add((vlen - sent) as u64, Ordering::Relaxed);
        }
        if sent == 0 {
            continue;
        }
        // Count only actually-sent messages so throughput stats aren't inflated. After
        // sendmmsg each msg_len holds the bytes transmitted for that datagram.
        let mut sent_bytes = 0u64;
        for v in 0..sent {
            sent_bytes += msgs[v].msg_len as u64;
        }
        stats.out_pkts.fetch_add(sent as u64, Ordering::Relaxed);
        stats.out_bytes.fetch_add(sent_bytes, Ordering::Relaxed);
        stats.out_batches.fetch_add(1, Ordering::Relaxed);
        atomic_min(&stats.out_batch_min, sent as u64);
        atomic_max(&stats.out_batch_max, sent as u64);
    }
}

/// PoC two-thread data plane, IN direction: connected-socket recv -> decrypt -> TUN write.
/// Data packets are decrypted on a cloned `Arc<Session>` off the `Tunn` lock. Rare
/// handshake/cookie packets (e.g. rekey) are handled inline via the existing `decapsulate`
/// under the lock. Single peer.
fn in_data_thread(device: Arc<Lock<Device>>, stop: Arc<AtomicBool>) {
    let (iface, stats) = {
        let d = device.read();
        (d.iface.clone(), d.data_stats.clone())
    };

    // Per-thread batch buffers (boxed: ~99 KB; Android thread stacks can be small). recvmmsg
    // fills up to MMSG_BATCH datagrams in one syscall. The iovec/mmsghdr arrays point into
    // `rbufs` and are set up ONCE (the boxed buffers never move); the kernel only rewrites
    // each `msg_len` (and msg_flags) per call. A single reused `dbuf` holds each decrypted IP
    // packet (which is then written to the TUN one at a time — TUN can't batch writes).
    let mut rbufs: Box<[[u8; MAX_PKT_SIZE]; MMSG_BATCH]> =
        Box::new([[0u8; MAX_PKT_SIZE]; MMSG_BATCH]);
    let mut dbuf = [0u8; MAX_PKT_SIZE];
    let mut iovecs: [libc::iovec; MMSG_BATCH] = unsafe { std::mem::zeroed() };
    let mut msgs: [libc::mmsghdr; MMSG_BATCH] = unsafe { std::mem::zeroed() };
    for i in 0..MMSG_BATCH {
        iovecs[i].iov_base = rbufs[i].as_mut_ptr() as *mut libc::c_void;
        iovecs[i].iov_len = MAX_PKT_SIZE as _;
        msgs[i].msg_hdr.msg_iov = &mut iovecs[i] as *mut libc::iovec;
        msgs[i].msg_hdr.msg_iovlen = 1 as _;
    }

    // The single peer + a clone of its connected socket, established after the handshake.
    let mut bound: Option<(Arc<Peer>, socket2::Socket)> = None;

    while !stop.load(Ordering::Relaxed) {
        if bound.is_none() {
            bound = {
                let d = device.read();
                d.peers.values().next().and_then(|p| {
                    p.endpoint()
                        .conn
                        .as_ref()
                        .and_then(|c| c.try_clone().ok())
                        .map(|c| (p.clone(), c))
                })
            };
            if bound.is_none() {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            tracing::info!("IN: acquired peer + connected socket; starting recv loop");
        }

        let mut reset = false;
        {
            let (peer, conn) = match bound.as_ref() {
                Some(b) => b,
                None => continue,
            };
            let sock_fd = conn.as_raw_fd();

            // MSG_WAITFORONE is REQUIRED: without it recvmmsg blocks (per recvmsg, bounded by
            // SO_RCVTIMEO) trying to fill the whole batch, so a single datagram would return
            // ~250 ms late (kills ping latency under sparse traffic). With MSG_WAITFORONE the
            // first datagram blocks (bounded by SO_RCVTIMEO so we still wake to check `stop`),
            // then MSG_DONTWAIT is turned on and it returns all immediately-available datagrams
            // (1..=MMSG_BATCH) at once — low latency when sparse, real batching under load.
            // SAFETY: msgs/iovecs are valid for MMSG_BATCH entries pointing into the live boxed
            // `rbufs`; no live Rust reference into `rbufs` is held across the call.
            let rc = unsafe {
                libc::recvmmsg(
                    sock_fd,
                    msgs.as_mut_ptr(),
                    MMSG_BATCH as _,
                    libc::MSG_WAITFORONE,
                    std::ptr::null_mut(),
                )
            };
            let n_msgs = if rc < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::WouldBlock
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted => 0, // re-check `stop`
                    _ => {
                        tracing::warn!(message = "IN: recvmmsg error; re-acquiring socket", error = ?e);
                        reset = true;
                        0
                    }
                }
            } else {
                rc as usize
            };

            if n_msgs > 0 {
                // tracing::info!(message = "IN: recvmmsg batch", n = n_msgs); // per-batch: off for perf
                stats.in_batches.fetch_add(1, Ordering::Relaxed);
                atomic_min(&stats.in_batch_min, n_msgs as u64);
                atomic_max(&stats.in_batch_max, n_msgs as u64);
            }

            // Cache the session within the batch: all data packets in a batch share the same
            // receiver_idx (constant within a session), so look it up once under the Tunn lock
            // and reuse it for the rest of the batch — mirrors OUT's once-per-batch fetch
            // instead of locking Tunn per datagram (the one gratuitous IN/OUT asymmetry).
            // u32::MAX is never a valid (24-bit) receiver_idx, so it's a safe "empty" sentinel;
            // cached_session's type (Option<Arc<Session>>) is inferred from the assignment below
            // (the `session` module is private, so the type can't be named here).
            let mut cached_idx: u32 = u32::MAX;
            let mut cached_session = None;

            // Dispatch each received datagram by type — a single batch may mix data packets and
            // a handshake/cookie (e.g. rekey), so we must not assume all-data.
            for mi in 0..n_msgs {
                let len = msgs[mi].msg_len as usize;
                if len == 0 {
                    continue;
                }
                let datagram = &rbufs[mi][..len];
                match Tunn::parse_incoming_packet(datagram) {
                    Ok(Packet::PacketData(p)) => {
                        let r_idx = p.receiver_idx;
                        // Off-lock data decrypt: reuse the cached session, else fetch it under a
                        // short lock and cache it for the rest of the batch.
                        let session = if cached_idx == r_idx {
                            cached_session.clone()
                        } else {
                            let s = peer.tunnel.lock().session_for_index(r_idx);
                            cached_session = s.clone();
                            cached_idx = r_idx;
                            s
                        };
                        match session {
                            Some(session) => match session.decrypt(p, &mut dbuf) {
                                // Empty payload == keepalive: nothing to write.
                                Ok(plain) if !plain.is_empty() => {
                                    // Trim WireGuard padding to the real IP length before
                                    // writing to the TUN (peers like kernel WireGuard pad data
                                    // packets to a 16-byte boundary).
                                    if let Some(len) = Tunn::decapsulated_packet_len(plain) {
                                        match iface.as_ref().write(&plain[..len]) {
                                            Ok(_) => {
                                                // tracing::info!(message = "IN: decrypted + wrote to tun", receiver_idx = r_idx, len); // per-packet: off for perf
                                                stats.in_pkts.fetch_add(1, Ordering::Relaxed);
                                                stats.in_bytes.fetch_add(len as u64, Ordering::Relaxed);
                                            }
                                            // TUN fd is non-blocking: a full TUN queue (EAGAIN)
                                            // means the decrypted packet is dropped — download loss.
                                            Err(e) => {
                                                tracing::warn!(message = "IN: tun write failed; packet dropped", error = ?e);
                                                stats.in_drops.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    } else {
                                        tracing::info!("IN: decrypted packet has unrecognised IP header; dropped");
                                        stats.in_drops.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                Ok(_) => tracing::info!("IN: decrypted keepalive (empty); not written"),
                                Err(e) => {
                                    tracing::warn!(message = "IN: decrypt failed", error = ?e);
                                    stats.in_drops.fetch_add(1, Ordering::Relaxed);
                                }
                            },
                            None => {
                                tracing::info!(message = "IN: no session for receiver_idx", receiver_idx = r_idx);
                                stats.in_drops.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    // Handshake / cookie: handle on the control path (under the Tunn lock).
                    Ok(_) => {
                        tracing::info!("IN: non-data (handshake/cookie) packet -> decapsulate");
                        let res = {
                            let mut tun = peer.tunnel.lock();
                            tun.decapsulate(None, datagram, &mut dbuf)
                        };
                        match res {
                            TunnResult::WriteToNetwork(packet) => {
                                tracing::info!(message = "IN: handshake reply -> send on conn", len = packet.len());
                                let _ = conn.send(packet);
                                // Drain any queued packets the handshake completion released.
                                loop {
                                    let mut out = [0u8; MAX_PKT_SIZE];
                                    let r = {
                                        let mut tun = peer.tunnel.lock();
                                        tun.decapsulate(None, &[], &mut out)
                                    };
                                    match r {
                                        TunnResult::WriteToNetwork(p2) => {
                                            let _ = conn.send(p2);
                                        }
                                        _ => break,
                                    }
                                }
                            }
                            TunnResult::WriteToTunnel(packet, _addr) => {
                                tracing::info!(message = "IN: control path produced tun packet", len = packet.len());
                                let _ = iface.as_ref().write(packet);
                            }
                            other => {
                                tracing::info!(message = "IN: control path result", result = ?std::mem::discriminant(&other));
                            }
                        }
                    }
                    Err(e) => tracing::info!(message = "IN: parse_incoming_packet failed", error = ?e),
                }
            }
        }
        if reset {
            bound = None;
        }
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
