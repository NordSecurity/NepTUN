# NepTUN-AEGIS PoC — branch notes

Branch: `neptun-aegis-poc-two-thread-model` (off neptun v2.3.0).

This branch is a **proof of concept**, not production code. Step 1 of the PoC replaces the
epoll event loop + worker pool with a **two-thread, blocking-fd data plane**. The wider PoC
also targets `sendmmsg`/`recvmmsg` (Step 2) and the AEGIS-256 cipher (Step 3).

## Step 3: AEGIS-256 (replaces ChaCha20Poly1305)

This build speaks **AEGIS-256 only** (no cipher negotiation/abstraction), wire-compatible with the
NordLynx kernel module's `WG_CRYPTO_SUITE_AEGIS256` (suite id `1`). Cipher = the `aegis` crate
(`aegis::aegis256::Aegis256::<16>`, 16-byte tag), which is byte-identical to the kernel's bundled
zinc AEGIS-256 (both implement IETF draft-irtf-cfrg-aegis-aead — proven by the KAT test
`session::tests::aegis256_matches_kernel_ietf_vectors`).

- **Handshake** (`noise/handshake.rs`): the Noise protocol name is
  `"Noise_IKpsk2_25519_AEGIS256_BLAKE2s"` (not the ChaChaPoly name), so the initial chaining
  key/hash are recomputed (`initial_chain_key`/`initial_chain_hash`). The handshake *message
  fields* (`encrypted_static`/`timestamp`/`nothing`) are sealed with AEGIS-256 too — 32-byte
  all-zero nonce (WG handshake counter is always 0), AAD = the current Noise `hash`, 16-byte tag.
- **Transport** (`noise/session.rs`): data packets use AEGIS-256 — 32-byte nonce = LE64 counter at
  offset 0 (zeros after), empty AAD, 16-byte tag appended inline. `Session` stores the raw 32-byte
  keys; a fresh `Aegis256` state is built per packet (so the off-lock `&self` data path is
  unchanged). Packet layout/overhead identical to ChaCha (tag is 16 B either way).
- **Header suite byte**: carried **only on handshake** messages (init/response, byte 1 = 1) — that's
  where the kernel negotiates the suite. **DATA packets have NO suite byte** (`04 00 00 00`): the
  kernel's `send.c` writes only `type = MESSAGE_DATA` and decrypts using the negotiated keypair's
  suite, ignoring the data header. So `parse_incoming_packet` enforces byte 1 == 1 (+ reserved 0)
  **only for init/response**, and never rejects DATA on the reserved bytes — otherwise it would drop
  the kernel's `04 00 00 00` data packets (this was the "handshake works in AEGIS, then traffic
  stops" bug). (The old code read all 4 bytes as the LE32 type, which any nonzero byte 1 broke.)
- **Cookies** stay XChaCha20Poly1305 (kernel cookie path is suite-independent).
- **Build note:** the `aegis` crate defaults to its **C backend** (`cc`), giving hardware AES on
  the Pixel's ARM crypto extensions. If the Android cross-build (`./build.sh`) trips on the `cc`
  step, switch to `aegis = { version = "0.9", default-features = false, features = ["pure-rust"] }`
  (software AES — correct, just slower). Both backends produce identical output.
- **Interop:** requires the peer to also speak AEGIS-256 (set the NordLynx kernel default at its
  `noise.c:42`, or another AEGIS NepTUN). Verified internally by the NepTUN↔NepTUN handshake+data
  unit tests; the kernel KAT confirms the on-wire cipher matches.

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
- **UDP GRO (receive) + UDP GSO (send) offload on the data socket.** The download ceiling was
  proven to be single-core kernel `NET_RX` softirq on CPU 0 (a little core; the wired link is a
  single-queue USB-C ethernet adapter, phone unrooted so no RPS/IRQ-affinity). WireGuard is UDP on
  the wire, so each datagram hit per-packet softirq. Fix (raw `libc`, gated to linux/android):
  - **RX:** `connect_endpoint` sets `UDP_GRO` on the connected socket; `in_data_thread` uses
    `recvmsg` into a **64 KB** buffer + a control buffer, reads the `UDP_GRO` cmsg for the segment
    size (`c_int`), and **splits the coalesced super-buffer into gso_size segments**, decrypting
    each and writing it to the TUN one at a time (TUN can't batch). `MSG_TRUNC` is logged + counted.
    No cmsg ⇒ treat the read as one datagram. Session is cached by `receiver_idx` within the read.
  - **TX:** `out_data_thread` drains the TUN coalescing **consecutive equal-size** packets into one
    GSO batch (cap = 64 segments / 64 KB), encrypts each in place, and sends with one `sendmsg` +
    `UDP_SEGMENT` cmsg (gso_size = WG byte size, a `u16`). GSO requires every segment == gso_size
    except the last (≤): a shorter packet is appended as the final segment then flushed; a larger
    packet is **carried over** (in a separate `carry` buffer, preserving order) to seed the next
    batch. 1-packet batches send without the cmsg. Single-peer (multi-peer would need per-packet
    routing + per-destination grouping).
  - The **`UDP offload probe`** at startup confirms the app process can set these sockopts (logs
    `udp_gro_set_ok`/`udp_segment_set_ok`). The 10 s `data-plane` stats line reports per-direction
    **segments-per-syscall min/avg/max** (coalescing factor) and **drop** counters.
  - The **`IFF_VNET_HDR` TUN-side equivalent is unavailable** on an Android VpnService fd (the
    framework pre-creates the tun without it), so the TUN side stays one `read`/`write` per packet.
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
- **CPU-affinity pinning and thread-priority (`nice`) tuning were both tried and reverted** —
  no measurable impact, since the data threads already run on the performance cores (4-8) by
  default. Left out to keep the PoC simple.
- **`set_iface` (tun reset) is not supported** in the two-thread model — it would re-register the
  epoll TUN handler and not respawn the data threads. The measurement path uses
  `DeviceHandle::new_with_tun` once; libtelio's `set_tun` is not exercised.
- **Legacy dead code** (`register_read_conn_skt_handler`, `write_to_socket_worker`,
  `write_to_tun_worker`, the inter-thread channels) is left in place but unused.
