# Track E — Live Session Viewing

**Status:** Design approved 2026-04-14
**Predecessors:** Tracks A–D merged to main
**Scope:** epitropos (proxy + new `live/` member + collector changes) + theatron

Real-time session viewing through the collector, fully optional
per-host. The live stream is best-effort and ephemeral — the
recording pipeline handles durability independently.

## 1. Goals

1. Operators can watch active sessions in real-time via theatron.
2. Completely optional at every layer — default is OFF everywhere.
   An operator who never touches `[live]` gets zero sockets, zero
   daemons, zero WebSocket routes, zero UI elements.
3. Secure: reuses existing mTLS enrollment, no new keys or trust
   boundaries. Live data never touches disk.
4. Best-effort delivery: if the live daemon crashes or disconnects,
   the recording pipeline continues unaffected.

**Non-goals:**
- Per-session access control (watch-only gating per user)
- Recording the live stream (ephemeral only)
- Live input injection (watch-only)
- Guaranteed delivery of every frame (best-effort is fine for
  real-time viewing)

## 2. Data flow

```
epitropos (recording host)
    │
    │ kgv1 lines via unix socket
    │ /var/run/epitropos/live.<session_id>.sock
    ▼
epitropos-live (recording host)
    │
    │ mTLS WebSocket to collector
    │ wss://collector:8443/v1/live/push
    │ multiplexed: {session_id, line}
    ▼
epitropos-collector
    │
    │ fan-out WebSocket per session
    │ ws://localhost:8443/v1/live/<session_id>
    ▼
theatron (browser)
    │
    │ xterm.js real-time rendering
    ▼
operator's screen
```

## 3. Epitropos proxy: unix socket writer

New backend writer `LiveSocketWriter` in `proxy/src/backend.rs`.

When `config.live.enabled = true`:
- On session start: create
  `/var/run/epitropos/live.<session_id>.sock` as a `SOCK_STREAM`
  unix listener. Mode 0700, owned `session-proxy:session-proxy`.
- Accept up to 1 connection (the `epitropos-live` daemon).
- On each `write_output` / `write_input` / `write_resize` call:
  forward the serialized kgv1 JSON line to the connected client.
- On session end: close the socket, unlink the file.
- If no client connects: writes are silently dropped. No
  backpressure on the recording pipeline.
- If the client disconnects mid-session: subsequent writes are
  silently dropped. Recording continues.

When `config.live.enabled = false` (default): `LiveSocketWriter`
is never constructed. The event loop code path for live is
completely absent.

Config addition:

```toml
[live]
enabled = false
```

## 4. `epitropos-live` daemon

New workspace member (4th alongside proxy, collector, sentinel).

```
epitropos/
├── live/
│   ├── Cargo.toml
│   ├── build.rs
│   └── src/
│       ├── main.rs
│       ├── lib.rs
│       ├── config.rs         # TOML config
│       ├── error.rs          # LiveError + sysexits
│       ├── socket_reader.rs  # connect to unix sockets, read lines
│       ├── ws_client.rs      # mTLS WebSocket client to collector
│       └── watcher.rs        # inotify: discover new live.*.sock
```

### 4.1 Behavior

1. Starts as a long-lived systemd service.
2. Watches `/var/run/epitropos/` for `live.*.sock` files via
   inotify.
3. When a socket appears: connects as a client, reads kgv1 lines.
4. Maintains a single mTLS WebSocket to the collector at
   `wss://<collector>:8443/v1/live/push`.
5. Multiplexes all active sessions over one connection:
   `{"session_id":"...","line":"<kgv1 json>"}\n`
6. When a socket disappears (session ended): sends
   `{"session_id":"...","ended":true}\n`
7. On collector disconnect: reconnect with exponential backoff.
   Lines during disconnection are dropped.

### 4.2 TLS

Reuses epitropos-forward's enrolled certs:
- `/var/lib/epitropos-forward/cert.pem` (sender TLS cert)
- `/var/lib/epitropos-forward/key.pem` (sender TLS key)
- `/var/lib/epitropos-forward/collector.pem` (pinned collector cert)

No new enrollment needed. The `epitropos-live` user must be in the
same group as `epitropos-forward` to read the cert files, OR share
the same user. NixOS module handles this.

### 4.3 Config

`/etc/epitropos-live/live.toml`:

```toml
[collector]
address = "nyx.tailnet:8443"

[tls]
sender_cert = "/var/lib/epitropos-forward/cert.pem"
sender_key = "/var/lib/epitropos-forward/key.pem"
collector_cert = "/var/lib/epitropos-forward/collector.pem"

[source]
socket_dir = "/var/run/epitropos"
```

### 4.4 Dependencies

```toml
tokio = { version = "1", features = ["rt-multi-thread", "net", "io-util", "fs", "macros", "signal"] }
tokio-tungstenite = "0.24"
rustls = { version = "0.23", default-features = false, features = ["std", "tls12", "ring"] }
tokio-rustls = "0.26"
rustls-pemfile = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
thiserror = "1"
inotify = "0.11"
libc = "0.2"
```

## 5. Collector: WebSocket endpoints

Three new routes on the existing axum server. All gated behind
`config.live.enable` (default true if the collector is enabled;
but no data flows unless an `epitropos-live` daemon connects).

### 5.1 `GET /v1/live/sessions`

Returns the currently-active live sessions:

```json
{
  "sessions": [
    {
      "session_id": "abc-123",
      "user": "alice",
      "host": "prod-web-01",
      "sender": "alice-laptop",
      "started": 1712534400.0
    }
  ]
}
```

The collector tracks active sessions in:

```rust
Arc<RwLock<HashMap<String, LiveSessionState>>>
```

Updated by the push WebSocket handler.

### 5.2 `GET /v1/live/{session_id}` (WebSocket upgrade)

Upgrades to WebSocket. Collector relays kgv1 lines from the push
connection for the requested session to this viewer.

Multiple viewers can watch the same session (fan-out: one push
sender → N viewer WebSockets via `tokio::sync::broadcast` or
per-viewer `mpsc` channels).

If the session doesn't exist or isn't live: returns 404 before
upgrading.

When the session ends (push sender sends `ended:true`): collector
sends a final `{"kind":"end","reason":"live_ended"}` frame to all
viewers and closes the WebSocket.

### 5.3 `POST /v1/live/push` (WebSocket upgrade, mTLS required)

The `epitropos-live` daemon connects here. mTLS is required (same
pinned-cert verifier as the push endpoint). Sends multiplexed
frames, one per line:

```json
{"session_id":"abc-123","line":"{\"kind\":\"out\",\"t\":1.23,\"b\":\"aGk=\"}"}
{"session_id":"abc-123","ended":true}
```

The collector demultiplexes by `session_id`:
- New `session_id` → create `LiveSessionState`, parse `user` and
  `host` from the first `header` line
- Existing `session_id` → fan out to viewers
- `ended:true` → notify viewers, remove from the map

### 5.4 State management

```rust
struct LiveSessionState {
    user: String,
    host: String,
    sender: String,
    started: f64,
    viewers: Vec<tokio::sync::mpsc::UnboundedSender<String>>,
}
```

Each viewer WebSocket gets an `mpsc::UnboundedReceiver`. The push
handler iterates `viewers` and sends to each. Dropped senders
(viewer disconnected) are detected by `send()` returning `Err`
and removed from the list.

`UnboundedSender` is used because live viewing is best-effort —
if a viewer can't keep up, messages queue in the channel until
the viewer reads them. Backpressure from a slow viewer does NOT
slow down the push handler (and therefore does not slow down the
recording pipeline).

### 5.5 Config addition

In collector's `collector.toml`:

```toml
[live]
enable = true   # default: true (routes are registered but idle)
```

When `enable = false`: the three `/v1/live/*` routes are not
registered. Push WebSocket connections are rejected at the HTTP
level (404). No `LiveSessionState` map is created.

## 6. Theatron: live viewer

### 6.1 Active session detection

When the session browser screen is active, poll
`GET /v1/live/sessions` every 5 seconds. Cache the result.

For each session in the browser table:
- If the session ID is in the live set: show a green pulsing dot
  + "WATCH" button (links to `#/viewer/<session_id>?live=1`)
- Otherwise: show "PLAYBACK_" as today

Poll stops when the user navigates away from the sessions screen.

If `/v1/live/sessions` returns 404 or network error: live features
are silently disabled (no WATCH buttons). This handles the case
where the collector has `live.enable = false`.

### 6.2 Live viewer mode

When navigating to `#/viewer/<session_id>` with `?live=1` (or if
the session is detected as live):

1. Open `ws://<host>/v1/live/<session_id>` (same host as theatron,
   since both go through the same collector or localhost)
2. Each WebSocket message is a kgv1 JSON line
3. Parse: `out` → base64-decode → write to xterm.js immediately
   (no delay, no buffering)
4. `resize` → `xterm.resize(cols, rows)`
5. `header` → populate session properties panel
6. Show a "LIVE" badge with pulsing green dot in the top bar
7. Hide seek slider and speed controls (not applicable in live mode)
8. Show play/pause only: pause = stop rendering but keep receiving;
   resume = catch up instantly by flushing the accumulated buffer

When the server sends `end` or the WebSocket closes:
- Show "SESSION_ENDED" overlay
- Fetch the session manifest from `/api/sessions/<id>` (now
  finalized and indexed)
- Offer "REPLAY" button that switches to recorded-playback mode

### 6.3 No age key required for live

Live data is plaintext kgv1 (never encrypted). The operator does
NOT need to paste an age identity to watch live. This is consistent
with the trust model: live data flows only over localhost between
the collector and theatron, same as the `/api/stream` endpoint
(which does require a key because it decrypts recordings at rest).

## 7. Opt-out at every layer

| Layer | Config | Default | Effect when disabled |
|---|---|---|---|
| epitropos proxy | `[live] enabled = false` | **off** | No unix socket. Zero live code. |
| epitropos-live | `services.epitropos.live.enable` | **false** | Service not installed. |
| collector | `[live] enable = false` | **true** | Routes not registered. Push rejected. |
| theatron | automatic | follows collector | 404 from live/sessions → no WATCH buttons. |

An operator who never sets `[live] enabled = true` in their
epitropos config gets:
- No unix sockets on recording hosts
- No epitropos-live daemon running
- No WebSocket routes on the collector (they exist but no data
  flows since no daemon pushes)
- No WATCH buttons in theatron (live sessions list is always empty)

## 8. Security model

- **Unix socket**: mode 0700, owned `session-proxy`. Only the
  proxy and the live daemon (via group) can access. The recorded
  user cannot reach it (different UID, PID namespace).
- **mTLS to collector**: reuses forward's enrolled cert. Same
  trust boundary. Collector verifies via `PinnedClientVerifier`.
- **Collector → theatron**: localhost WebSocket, no auth (same
  as all theatron API endpoints).
- **No new keys, no new enrollment, no new trust boundaries.**
- **Data in transit**: unix socket = local IPC. mTLS WebSocket =
  encrypted. Collector to theatron = localhost plaintext.
- **Data at rest**: live data is NEVER written to disk. It exists
  only in memory buffers. When the session ends, all buffers are
  freed. The recording pipeline handles persistence independently.

## 9. NixOS modules

### 9.1 Proxy config extension

In `nixos-module.nix`, add to the config TOML generator:

```nix
live = {
  enabled = cfg.live.enable;
};
```

With option:

```nix
live.enable = mkOption {
  type = types.bool;
  default = false;
  description = "Enable live session viewing unix socket.";
};
```

### 9.2 `epitropos-live` module

New sub-option in the existing epitropos NixOS module:

```nix
services.epitropos.live = {
  enable = mkOption { type = types.bool; default = false; };
  collector = mkOption { type = types.str; };
};
```

When enabled:
- Creates systemd service `epitropos-live` running as
  `epitropos-forward` user (reuses certs)
- `Type=simple`, `Restart=on-failure`
- Same hardening as epitropos-forward (ProtectSystem, etc.)
- `ReadOnlyPaths = [ /var/run/epitropos /var/lib/epitropos-forward ]`

### 9.3 Collector live config

In `nixos-module-collector.nix`, add:

```nix
live.enable = mkOption {
  type = types.bool;
  default = true;
  description = "Enable live session WebSocket endpoints.";
};
```

## 10. Testing

- Unit: `LiveSocketWriter` creates socket, accepts connection,
  delivers lines, silently drops on no client, cleans up on drop
- Unit: collector `LiveSessionState` fan-out delivers to multiple
  receivers, handles dropped receivers
- Unit: collector `live/sessions` endpoint returns correct set
- Integration: fake epitropos writes to unix socket → epitropos-live
  connects → collector receives → theatron WebSocket client receives
- NixOS VM test: two-node. Node A: proxy + live enabled. Node B:
  collector + theatron. SSH into A, verify theatron shows WATCH,
  view live output.

## 11. Acceptance criteria

1. `[live] enabled = false` (default) → no unix socket, `ls
   /var/run/epitropos/live.*` empty
2. `[live] enabled = true` → socket appears on session start,
   disappears on session end
3. `epitropos-live` connects to socket, forwards to collector
   via mTLS WebSocket
4. `GET /v1/live/sessions` returns active sessions
5. `GET /v1/live/{session_id}` upgrades to WebSocket and streams
   kgv1 lines in real-time
6. Theatron shows WATCH button with green dot for live sessions
7. Theatron viewer renders live terminal output via xterm.js with
   sub-second latency
8. Session end → viewer shows SESSION_ENDED + REPLAY button
9. Multiple viewers on same session all receive same data
10. epitropos-live crash → recordings continue normally
11. Collector with `live.enable = false` → 404 on `/v1/live/*`
12. All existing tests pass (zero regression)
