# NepTUN-AEGIS PoC — branch notes

Branch: `neptun-aegis-poc-two-thread-model` (off neptun v2.3.0).

This branch is a **proof of concept**, not production code. Step 1 of the PoC replaces the
epoll event loop + worker pool with a **two-thread, blocking-fd data plane**. The wider PoC
also targets `sendmmsg`/`recvmmsg` (Step 2) and the AEGIS-256 cipher (Step 3).

## Step 1 architecture (current)

Three threads instead of the previous epoll-threads + worker-pool:

- **OUT thread** (`device/mod.rs::out_data_thread`) — TUN read → encrypt → connected-socket
  send. Pure data path; does no handshake/timer work.
- **IN thread** (`device/mod.rs::in_data_thread`) — connected-socket recv → decrypt → TUN
  write. Decrypts data packets off-lock; handles the rare handshake/cookie packet inline via
  `Tunn::decapsulate` (under the lock).
- **Control plane = the existing epoll loop**, forced to a single thread. Runs `register_timers`
  (→ `Tunn::update_timers`: keepalive/rekey, and handshake initiation when the OUT thread sets
  `want_handshake`), `register_notifiers` (shutdown), and the udp4/udp6 **bootstrap** handler.

Crypto runs on a cloned `Arc<Session>` (sessions ring is now `[Option<Arc<Session>>; N]`); the
`Mutex<Tunn>` is taken only for a tiny critical section to clone the session out, so the two
directions encrypt/decrypt in parallel on two cores. The connected socket is set **blocking**
with `SO_RCVTIMEO` (~250 ms) so the IN thread wakes to check the stop flag; the OUT thread
`poll()`s the TUN fd with the same timeout. Shutdown: `Device::trigger_exit` sets `data_stop`
and triggers the epoll exit notifier; `DeviceHandle::wait` joins all three threads.

## Limitations (PoC scope)

- **Single peer only.** The data threads assume one peer/tunnel (they take `peers.values().next()`
  / route the one peer). Multi-peer would need per-peer routing/threads.
- **IPv4 / connected-socket data path.** Data flows over the per-peer **connected** UDP socket,
  established after the first handshake. The model assumes the endpoint is known and the
  connected socket stays up for the session (initiator-style, true for the measurement). The
  unconnected udp4/udp6 sockets remain only for handshake **bootstrap**.
- **No `IFF_MULTI_QUEUE`.** Dropped (unavailable on Android); single shared TUN fd. The epoll
  control plane is pinned to **1 thread** (`n_threads` is ignored) to avoid multi-queue
  per-thread TUN creation.
- **Handshake initiation latency.** The OUT thread can't initiate handshakes; when it has data
  but no session it sets `want_handshake` and drops the packet — the control plane initiates on
  its next ~250 ms tick (upper layer retransmits).
- **No `recvmmsg`/`sendmmsg` batching yet** — one packet per syscall (Step 2).
- **No firewall callbacks.** `firewall_process_inbound/outbound_callback` are no longer invoked
  (the `DeviceConfig` fields remain for API compatibility with libtelio but are ignored).
- **Per-packet timer ticks skipped on the data path.** The data threads don't call
  `timer_tick` per packet; session expiry/rekey is still driven time-based by the control plane,
  which is fine for short measurement runs.
- **No inbound allowed-IPs check** on the off-lock data path (the AEAD tag authenticates the
  peer). Acceptable for the single-peer PoC.
- **TUN readiness via `poll()`.** The TUN char device has no `SO_RCVTIMEO`, so the OUT
  (encrypt) thread `poll()`s the (non-blocking) TUN fd with a ~250 ms timeout, then `read()`s.
  The timeout lets it re-check the `stop` flag for clean shutdown. (The IN thread uses
  `SO_RCVTIMEO ~250ms` on its UDP socket for the same purpose.)
- **Roaming is disabled.** The udp4/udp6 handler no longer updates the peer endpoint from
  incoming packet source addresses — it only *learns* the endpoint once (if it was never
  configured). The data plane uses a per-peer **connected** UDP socket (`Endpoint.conn`) bound
  + connected once; if roaming moved the endpoint, `conn` would desync and the peer would see
  the phone at two different source ports (udp4 vs conn), flip-flopping its replies between the
  epoll handler and the IN thread. So the PoC assumes a single, stable peer endpoint. `conn`
  itself never roams (only the udp4/udp6 handler ever called `set_endpoint`; the IN/OUT data
  threads do not). `connect_endpoint` logs a warning if the connected socket's local port does
  not match `listen_port` (= udp4's port).
- **`set_iface` (tun reset) is not supported** in the two-thread model — it would re-register the
  epoll TUN handler and not respawn the data threads. The measurement path uses
  `DeviceHandle::new_with_tun` once; libtelio's `set_tun` is not exercised.
- **Legacy dead code** (`register_read_conn_skt_handler`, `write_to_socket_worker`,
  `write_to_tun_worker`, the inter-thread channels) is left in place but unused.
