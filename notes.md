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
- **OUT thread shutdown needs a TUN packet.** The OUT (encrypt) thread does a plain **blocking
  `read()` on the TUN fd with no timeout** (the TUN char device has no `SO_RCVTIMEO`, and the
  `poll()` was removed for simplicity). It therefore only notices the `stop` flag *after the next
  packet arrives* from the TUN — so `DeviceHandle::wait` can hang on the OUT thread if the
  tunnel is fully idle at shutdown. Acceptable for the PoC since traffic always flows during a
  measurement. (The IN thread is unaffected — its UDP socket uses `SO_RCVTIMEO ~250ms`.)
- **`set_iface` (tun reset) is not supported** in the two-thread model — it would re-register the
  epoll TUN handler and not respawn the data threads. The measurement path uses
  `DeviceHandle::new_with_tun` once; libtelio's `set_tun` is not exercised.
- **Legacy dead code** (`register_read_conn_skt_handler`, `write_to_socket_worker`,
  `write_to_tun_worker`, the inter-thread channels) is left in place but unused.
