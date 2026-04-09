# Track C — Off-Host Collector + Real `epitropos-forward`

**Status:** Design approved 2026-04-07
**Predecessors:** Track A + Track B (both on `main` for epitropos and katagrapho)
**Scope:** `epitropos/` (converted to a cargo workspace) + `katagrapho/` (ownership + group changes only)

Track C replaces the `epitropos-forward` refusal stub with a real
shipper that pushes signed manifests and age-encrypted recordings to
a new off-host service, `epitropos-collector`. The collector
re-verifies signatures on arrival, maintains a per-sender append-only
head chain, and stores received files under its own privileged user.

Transport is HTTP/1.1 over mutual TLS. Trust is established once per
sender via a one-time enrollment token plus out-of-band collector
certificate fingerprint — no private CA, no manual fingerprint
distribution at scale, no MITM window on first connect.

## 1. Goals

1. **Off-host content preservation.** Survive origin-host disk loss,
   root compromise, or deliberate wipe by shipping every finalized
   part to a separate machine.
2. **Tamper-evident ingestion.** Every push is re-validated at the
   collector: signature check against the sender's pinned pubkey,
   SHA-256 check against the manifest's claimed recording hash,
   strict `prev_manifest_hash` chain continuity.
3. **Zero-CA deployment.** No operator-run PKI. Bootstrap via a
   short-lived enrollment token + fingerprint pin. Works on any
   network (Tailscale, WireGuard, plain internet, LAN).
4. **Minimal privilege coupling.** The shipper runs as a dedicated
   non-privileged user with read-only access to katagrapho's
   recording and log files via a new group. The setuid signing key
   is never reachable by the shipper process.
5. **Future-web-UI-ready.** Protocol is HTTP so a browser/UI can
   extend it later without replacing the wire format.

**Non-goals (deferred):**

- `sd_journal` / syslog structured sinks → **Track D**
- Central search/index backend → **Track D**
- Web UI → **Track D** (the HTTP protocol chosen here is additive)
- Multi-collector replication and off-host witness for the
  collector's own head chain → future
- Automated enrollment without operator interaction → future

## 2. Workspace restructure

`epitropos/` becomes a cargo workspace with two members:

```
epitropos/
├── Cargo.toml                  # [workspace] root, no [package]
├── flake.nix                   # packages.proxy, packages.collector
├── proxy/                      # RENAMED from the current flat layout
│   ├── Cargo.toml              # name = "epitropos"
│   ├── build.rs
│   ├── rust-toolchain.toml
│   ├── src/                    # existing modules (main, event_loop, ...)
│   └── tests/                  # existing test modules
├── collector/                  # NEW
│   ├── Cargo.toml              # name = "epitropos-collector"
│   ├── build.rs                # emits EPITROPOS_COLLECTOR_GIT_COMMIT
│   ├── src/
│   │   ├── main.rs             # binary entry + CLI dispatcher
│   │   ├── lib.rs              # re-exports for integration tests
│   │   ├── config.rs           # TOML config, deny_unknown_fields
│   │   ├── error.rs            # CollectorError + sysexits exit codes
│   │   ├── server.rs           # axum router and handlers
│   │   ├── tls.rs              # rustls server setup + client-cert validation
│   │   ├── enroll.rs           # token generate / validate / burn
│   │   ├── storage.rs          # per-sender directory layout, atomic writes
│   │   ├── chain.rs            # per-sender head pointer, strict mode
│   │   ├── verify.rs           # incoming manifest signature check
│   │   └── cli.rs              # `enroll`, `rotate-cert`, `list`, `serve`
│   └── tests/
│       └── e2e.rs              # in-process axum + hyper client round trips
├── nixos-module.nix            # existing proxy module (extended with .forward.*)
├── nixos-module-collector.nix  # NEW collector module
└── tests/
    ├── vm-proxy.nix            # RENAMED from vm-test.nix
    └── vm-collector.nix        # NEW two-node test
```

The top-level `Cargo.toml`:

```toml
[workspace]
members = ["proxy", "collector"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"
```

Per-member `Cargo.toml`s inherit `version` and `edition` from the
workspace. The proxy member's dependency tree is unchanged from
Track B — no new runtime deps on the setuid side. The collector
member gets its own independent dep tree.

The flake exposes `packages.x86_64-linux.epitropos-proxy` and
`packages.x86_64-linux.epitropos-collector` as separate outputs.
Deploying either on a host pulls in only that crate's closure.

## 3. Protocol

HTTP/1.1 over TLS (rustls). Default port 8443. No HTTP/2 in v1.

### 3.1 Endpoints

```
POST /v1/enroll
  Auth:    none (token in body authenticates)
  Body:    JSON, see §3.2
  200:     JSON { collector_tls_cert_pem, collector_fingerprint_sha256 }
  400:     malformed body
  401:     invalid, expired, or already-burned token
  409:     sender_name already enrolled with a different cert
  413:     body exceeds 64 KiB

POST /v1/sessions/{session_id}/parts/{part}
  Auth:    mTLS; client cert must equal the pinned cert for some
           enrolled sender
  Body:    binary framing, see §3.3
  Content-Type: application/octet-stream
  200:     JSON { stored: true, head_hash: "<hex>" }
  401:     mTLS handshake failed or client cert not in pinned set
  409:     (session_id, part) already stored and payload matches —
           idempotent success
  412:     prev_manifest_hash does not match this sender's current head
  413:     body exceeds max_upload_bytes (default 1 GiB)
  422:     manifest signature invalid, OR
           computed recording SHA-256 != manifest.recording_sha256, OR
           url part != manifest.part, OR
           url session_id != manifest.session_id

GET  /v1/health
  Auth:    none
  200:     "ok"
```

No other endpoints in v1. Playback endpoints (`GET /v1/sessions/...`)
are reserved for Track D.

### 3.2 Enrollment request body

```json
{
  "sender_name": "alice-laptop",
  "token": "epitropos-enroll:AABBCCDDEEFFGG...",
  "tls_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
  "signing_pub_hex": "a1b2c3d4...64-hex-chars..."
}
```

- `sender_name` — operator-chosen, unique, matches the name the token
  was minted for. 1–64 chars from `[a-z0-9._-]`.
- `token` — the single-use token generated by the collector via
  `epitropos-collector enroll <sender_name>`.
- `tls_cert_pem` — the sender's freshly-generated self-signed X.509
  cert that will be pinned for future mTLS. 10-year validity.
- `signing_pub_hex` — the raw 32-byte ed25519 public key from
  katagrapho's `signing.pub`, hex-encoded. Used by the collector to
  verify manifest signatures on push.

The **two keys are distinct by design** (see §9).

Enrollment response body:

```json
{
  "collector_tls_cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "collector_fingerprint_sha256": "c39f3a...a821"
}
```

The sender verifies the fingerprint matches the value the operator
passed via `--expect-fingerprint` before trusting the response.

### 3.3 Push request framing

The body of `POST /v1/sessions/.../parts/...` is a raw binary frame:

```
[  4 bytes  ] u32 BE manifest_len (must be <= 65536)
[  N bytes  ] manifest JSON (bytes of the sidecar file, verbatim)
[  rest     ] encrypted recording bytes until Content-Length
```

The collector reads the 4-byte length header, reads the manifest
(with an upper bound on `manifest_len` of 64 KiB), parses it as JSON,
then streams the remaining body into a temp file while computing
SHA-256. On EOF:

1. Verify manifest signature using the sender's pinned
   `signing.pub` (hex-decoded to 32 bytes then passed to the existing
   `katagrapho::manifest::Manifest::verify` logic, copied into the
   collector crate).
2. Verify `manifest.session_id` matches the URL.
3. Verify `manifest.part` matches the URL.
4. Verify `manifest.prev_manifest_hash == current_head(sender)`.
5. Verify computed SHA-256 == `manifest.recording_sha256`.
6. Under a per-sender flock: `rename(tmp, final)`, write sidecar,
   advance head, append head log.

Any failure unlinks the temp file and returns the appropriate status.
Concurrent pushes from the same sender serialize on the flock.

### 3.4 Authentication

Two modes:

- **Enrollment**: TLS with server cert only (collector's self-signed).
  No client cert requested. The token in the request body is the
  authenticator; the sender verifies the server's cert fingerprint
  out-of-band via `--expect-fingerprint`.
- **Push / health**: full mTLS. The rustls server config requires a
  client certificate (`with_client_cert_verifier`). The custom
  verifier accepts any cert whose DER SHA-256 is in the pinned
  sender table. If no match, the TLS handshake fails with a clear
  alert.

The authenticated sender identity is threaded through request state
so the push handler knows which sender it's talking to.

## 4. Enrollment tokens

### 4.1 Format

Tokens are ASCII, prefixed with `epitropos-enroll:`, body is
base32 (RFC 4648) of:

```
HMAC-SHA256(enroll.secret, sender_name || nonce || expires_at_be8)[..16]
  || nonce (16 bytes)
  || expires_at_be8 (8 bytes)
```

Total 40 bytes before base32, 64 chars after. The HMAC is truncated
to 128 bits (sufficient for single-use short-TTL credentials).

### 4.2 State

Tokens are **stateless under HMAC** for validation (the collector
can recompute the HMAC to verify authenticity) but **stateful for
single-use** via a burn list at
`/var/lib/epitropos-collector/enrollments/burned/<sha256(token)>`.

Pending tokens are also recorded at
`/var/lib/epitropos-collector/enrollments/pending/<sha256(token)>.json`
with the intended `sender_name`. This lets `epitropos-collector list`
show what's outstanding.

### 4.3 Lifecycle

1. Operator runs `epitropos-collector enroll alice-laptop`. Collector:
   - Generates a fresh 16-byte nonce
   - Computes `expires_at = now + 15 min` (configurable)
   - HMACs the tuple → forms the token
   - Writes `enrollments/pending/<token_hash>.json` with `sender_name`,
     `expires_at`, `issued_by` (uid of the operator)
   - Prints the token + current collector fingerprint + copy-paste
     hint
2. Operator transports the token + fingerprint to the sender
   out-of-band. Fingerprint is the MITM defense.
3. Sender runs `epitropos-forward enroll ...`. On the wire:
   - Opens TLS to the collector
   - Reads the server cert from the TLS handshake
   - Computes its SHA-256 fingerprint, compares to
     `--expect-fingerprint`. Mismatch → abort, no data sent.
   - POSTs the enrollment body.
4. Collector `/v1/enroll` handler:
   - Parses the token, verifies HMAC
   - Checks burn list → if present, 401
   - Checks pending list → if absent, 401
   - Checks `expires_at > now` → if not, 401
   - Checks `sender_name` matches pending entry → if not, 401
   - Validates the tls_cert_pem parses as a single X.509 cert
   - Validates `signing_pub_hex` is 64 hex chars
   - Under a global enrollment flock:
     - Check `senders/<sender_name>/` → if exists with a different
       cert, 409
     - Create `senders/<sender_name>/`
     - Write `cert.pem`, `cert.fingerprint`, `signing.pub`
     - Add the cert fingerprint to the in-memory pinned set (for
       TLS handshake validation)
     - Move token from `pending/` to `burned/`
   - Return 200 with collector cert + fingerprint

### 4.4 Failure modes

- **Wrong fingerprint** → sender aborts before sending the token; no
  collector state changes.
- **Token expired** → 401; pending entry is garbage-collected at
  next `enroll` call or on service startup.
- **Token reused** → 401; burn list blocks the second attempt.
- **Sender name collision** → 409; operator must choose a different
  name or delete the existing enrollment with
  `epitropos-collector revoke <name>` (see §10 CLI).

## 5. Collector storage layout

```
/var/lib/epitropos-collector/
├── tls/
│   ├── cert.pem                 # self-signed, 10 years
│   ├── key.pem                  # mode 0400
│   └── enroll.secret            # 32 random bytes, mode 0400
├── senders/
│   └── <sender-name>/           # mode 0750 (owned by collector user)
│       ├── cert.pem             # pinned sender TLS cert
│       ├── cert.fingerprint     # hex SHA-256 of DER
│       ├── signing.pub          # raw 32-byte ed25519 pubkey
│       ├── enrolled_at          # ISO timestamp
│       ├── head.hash            # current chain head for this sender
│       ├── head.hash.lock       # flock file
│       ├── head.hash.log        # append-only, mode 0640
│       └── recordings/
│           └── <user>/
│               ├── <session>.part0.kgv1.age
│               ├── <session>.part0.kgv1.age.manifest.json
│               └── ...
├── enrollments/
│   ├── pending/
│   │   └── <sha256>.json
│   ├── burned/
│   │   └── <sha256>             # empty files, name is the token hash
│   └── lock                     # flock target for enrollment serialization
├── collector.log                # operator log (distinct from chain log)
└── state/                       # reserved for future bookkeeping
```

All paths created by the collector user. Parent dir owned
`epitropos-collector:epitropos-collector` mode 0750. No world
access anywhere.

Recording files land at 0640 (readable by collector user + group).
Access control for auditors: add them to `epitropos-collector`
group, or run `epitropos-play` via a controlled sudo target. Left
to the operator in v1.

## 6. Sender: `epitropos-forward` rewrite

The current stub binary in the proxy crate is replaced with a real
CLI. It still lives in the proxy crate (for co-location with its
only input — katagrapho state and epitropos recording files) but
gains new modules.

### 6.1 CLI surface

```
epitropos-forward enroll --collector <addr:port> \
                         --token <t> \
                         --expect-fingerprint <hex>
epitropos-forward push   [--once] [--config <path>]
epitropos-forward status [--config <path>]
epitropos-forward --version
```

### 6.2 `enroll` flow

1. Parse args. Validate fingerprint format (64 hex chars).
2. Generate sender TLS keypair + self-signed cert if
   `/var/lib/epitropos-forward/cert.pem` does not exist. 10-year
   validity, subject CN = hostname.
3. Read katagrapho's `signing.pub` (requires group membership, see
   §8). Hex-encode.
4. Open TLS to `--collector`. Capture the server's leaf cert.
5. Compute server cert SHA-256 fingerprint. Compare to
   `--expect-fingerprint`. Mismatch → print error, exit 1, **do not
   send the token**.
6. POST `/v1/enroll` with the JSON body from §3.2.
7. On 200: parse response, verify `collector_fingerprint_sha256`
   matches what we computed in step 5. Write
   `collector.pem` to state dir.
8. Print summary and exit 0.

### 6.3 `push` flow

1. Parse args, load config, load state.
2. Read `last_shipped.hash` from state dir. Default `"0" * 64`
   (genesis) if absent.
3. Open katagrapho's `head.hash.log` read-only. Walk line by line
   until finding the line whose hash equals `last_shipped.hash`;
   start shipping from the next line. If `last_shipped.hash` is
   genesis, ship from the first line.
4. For each line to ship (up to `batch_size`):
   a. Parse `<ts> <user> <session_id> <part> <hash>`.
   b. Locate recording at
      `<recording_root>/<user>/<session>.part<N>.kgv1.age`.
   c. Locate sidecar at `<recording>.manifest.json`.
   d. Open TLS connection to collector (mTLS with sender cert +
      pinned collector cert).
   e. Read sidecar file entirely (bounded at 64 KiB by
      the collector). Compute `u32 BE len`.
   f. `POST /v1/sessions/<session>/parts/<N>` with framed body:
      `len | sidecar_bytes | stream(recording_file)`.
   g. On 200: update `last_shipped.hash` to this manifest's hash
      atomically (tmp + rename). Advance to next line.
   h. On 409 (already stored, payload matches): treat as success,
      advance.
   i. On 412, 422, 5xx, network error: log, exit non-zero, retry
      next run.
5. Report summary.

The state file `last_shipped.hash` is advanced ONLY after the
collector returns 200 or 409. Crash-during-push means the same
manifest is re-shipped next run; the collector's 409 handling makes
this idempotent. No progress is lost, no duplicates are committed.

### 6.4 `status` flow

Prints:

- Whether enrollment files exist
- Collector address from config
- Last shipped hash
- Count of lines in the head log
- Count of pending (not yet shipped) lines
- Collector reachability (GET /v1/health)

Exit 0 if everything is healthy, non-zero otherwise.

### 6.5 Sender state layout

```
/var/lib/epitropos-forward/
├── cert.pem                # sender TLS cert, mode 0444
├── key.pem                 # sender TLS private key, mode 0400
├── collector.pem           # pinned collector TLS cert, mode 0444
├── last_shipped.hash       # hex, mode 0600
└── last_shipped.hash.tmp   # transient (rename target)
```

Owner `epitropos-forward:epitropos-forward`, dir mode 0750.
`epitropos-forward` user is also in group `katagrapho-readers`
(see §8) to read katagrapho's logs + recordings.

## 7. Configuration

Both configs use TOML with `#[serde(deny_unknown_fields)]`.

### 7.1 Collector — `/etc/epitropos-collector/collector.toml`

```toml
[listen]
address = "0.0.0.0"
port = 8443

[storage]
dir = "/var/lib/epitropos-collector"
max_upload_bytes = 1073741824   # 1 GiB per part

[enrollment]
token_ttl_seconds = 900         # 15 minutes
max_pending_tokens = 1000       # safety cap

[tls]
cert_path = "/var/lib/epitropos-collector/tls/cert.pem"
key_path  = "/var/lib/epitropos-collector/tls/key.pem"

[log]
level = "info"                  # "debug"|"info"|"warn"|"error"
```

### 7.2 Sender — `/etc/epitropos-forward/forward.toml`

```toml
[collector]
address = "nyx.tailnet:8443"

[tls]
sender_cert  = "/var/lib/epitropos-forward/cert.pem"
sender_key   = "/var/lib/epitropos-forward/key.pem"
collector_cert_pinned = "/var/lib/epitropos-forward/collector.pem"

[source]
head_log_path = "/var/lib/katagrapho/head.hash.log"
recording_root = "/var/log/ssh-sessions"

[state]
last_shipped = "/var/lib/epitropos-forward/last_shipped.hash"

[push]
batch_size = 16
timeout_seconds = 30
```

## 8. Privilege separation

### 8.1 Two keys, two processes

- **`/var/lib/katagrapho/signing.key`** — owned `session-writer`,
  mode 0400. Only accessible to katagrapho via setuid. Signs
  manifests. **Never** readable by `epitropos-forward`.
- **`/var/lib/epitropos-forward/key.pem`** — owned
  `epitropos-forward`, mode 0400. Only accessible to the shipper.
  Used for mTLS only. Cannot sign manifests.

A compromise of `epitropos-forward` (buffer overflow in the HTTP
stack, misconfigured systemd, local privesc into that user) gives
the attacker the ability to stop shipping new data or leak the
recordings to a third party — but **not** to forge manifests. The
katagrapho chain remains tamper-evident even in that scenario.

### 8.2 New group: `katagrapho-readers`

A system group dedicated to "daemons that need read access to
katagrapho state". Created by the katagrapho NixOS module.

File ownership changes on the katagrapho side:

| Path | Before | After |
|---|---|---|
| `/var/lib/katagrapho/head.hash.log` | 0640 session-writer:ssh-sessions | 0640 session-writer:`katagrapho-readers` |
| `/var/lib/katagrapho/signing.pub` | 0444 session-writer:ssh-sessions | 0640 session-writer:`katagrapho-readers` (still world-readable? — see note) |
| `/var/log/ssh-sessions/<user>/*.kgv1.age` | 0440 session-writer:ssh-sessions | 0440 session-writer:`katagrapho-readers` |
| `/var/log/ssh-sessions/<user>/*.manifest.json` | 0440 session-writer:ssh-sessions | 0440 session-writer:`katagrapho-readers` |

Note on `signing.pub`: it is public-key material, genuinely safe
to world-read, but tightening to 0640 keeps the ownership story
consistent. The pubkey is also distributed explicitly to collectors
via enrollment, so no external consumer relies on reading the on-
disk file.

`/var/lib/katagrapho/head.hash` stays 0600 session-writer only —
forward reads the *log*, not the pointer.

### 8.3 Group membership

- `epitropos-forward` is added to `katagrapho-readers` by its NixOS
  module
- Operators who need to run `epitropos-play` can be added manually
- `ssh-sessions` group is **kept** as a no-op compatibility handle
  for any external scripts. It has no file perms in this layout.
  Cleanup deferred to Track D.

## 9. NixOS modules

### 9.1 Katagrapho module changes (ownership + group)

Add to `katagrapho/nixos-module.nix`:

```nix
users.groups.katagrapho-readers = {};

systemd.tmpfiles.rules = [
  # existing rules kept
  "z /var/lib/katagrapho/head.hash.log 0640 ${cfg.user} katagrapho-readers -"
  "z /var/log/ssh-sessions 2750 ${cfg.user} katagrapho-readers -"
];
```

(Existing `d` rules create the dirs; the `z` rules set ownership +
mode on every boot so the group fix applies even on upgrades.)

Recording files created by katagrapho at runtime still use the
group bit from the parent dir inheritance, so a chgrp of the
storage dir propagates to new files. Existing files from before
this change need a one-shot `chgrp -R katagrapho-readers
/var/log/ssh-sessions` documented in the upgrade notes.

### 9.2 Epitropos forward submodule

Extends the existing `services.epitropos` module with a `.forward`
sub-block (per §C.8.2 decision):

```nix
services.epitropos.forward = {
  enable = mkOption { type = types.bool; default = false; };
  collector = mkOption {
    type = types.str;
    example = "nyx.tailnet:8443";
    description = "Collector address and port.";
  };
  pushIntervalSeconds = mkOption {
    type = types.int;
    default = 300;
  };
  batchSize = mkOption {
    type = types.int;
    default = 16;
  };
};
```

When `enable = true`:

- Creates `epitropos-forward` system user + group
- Adds the user to `katagrapho-readers`
- Writes `/etc/epitropos-forward/forward.toml` from options
- Creates `/var/lib/epitropos-forward` via `systemd.tmpfiles`,
  mode 0750 owned `epitropos-forward:epitropos-forward`
- `systemd.services.epitropos-forward-push`: `Type=oneshot`, runs
  `epitropos-forward push --once`, hardened (no network capabilities
  beyond what mTLS needs, `ProtectSystem=strict`, `NoNewPrivileges`,
  `PrivateTmp`, seccomp)
- `systemd.timers.epitropos-forward-push`: `OnUnitActiveSec=${cfg.forward.pushIntervalSeconds}s`
- **Initial enrollment is NOT automated** — operator runs
  `epitropos-forward enroll` once on the host

### 9.3 Collector module — new file `nixos-module-collector.nix`

```nix
services.epitropos-collector = {
  enable = mkEnableOption "epitropos collector service";
  package = mkOption { /* from flake output */ };
  listenAddress = mkOption { type = types.str; default = "0.0.0.0"; };
  listenPort = mkOption { type = types.port; default = 8443; };
  openFirewall = mkOption { type = types.bool; default = false; };
  storageDir = mkOption { type = types.path; default = "/var/lib/epitropos-collector"; readOnly = true; };
  maxUploadBytes = mkOption { type = types.int; default = 1073741824; };
  tokenTtlSeconds = mkOption { type = types.int; default = 900; };
};
```

Generates:

- `epitropos-collector` system user + group
- `systemd.tmpfiles` for the storage dir tree with correct modes
- `epitropos-collector-keygen.service`: systemd oneshot with
  `ConditionPathExists=!${storageDir}/tls/cert.pem`. Generates TLS
  cert (ed25519 via rcgen), 10-year validity, CN = hostname.
  Generates 32-byte `enroll.secret` from `/dev/urandom`. Chowns to
  the collector user.
- `epitropos-collector.service`: `Type=simple`, `ExecStart=${package}/bin/epitropos-collector serve --config /etc/epitropos-collector/collector.toml`, `User=epitropos-collector`, `Group=epitropos-collector`, `ProtectSystem=strict`, `ReadWritePaths=${storageDir}`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `ProtectHome=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`, `RestrictAddressFamilies=AF_INET AF_INET6`, `RestrictNamespaces=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, `SystemCallArchitectures=native`, seccomp filter allowing network + fs. Depends on `keygen.service`.
- Writes `/etc/epitropos-collector/collector.toml` from options
- Optional firewall rule for `listenPort`

The collector module lives in `epitropos/nixos-module-collector.nix`
and the flake exposes it as `nixosModules.collector`. Operators who
run only the collector on a box import just that module; operators
running both proxy and collector import both.

## 10. Collector CLI subcommands

`epitropos-collector` is one binary with subcommands:

```
epitropos-collector serve [--config PATH]
  Run the HTTP server. Default config path
  /etc/epitropos-collector/collector.toml.

epitropos-collector enroll <sender-name> [--ttl-seconds N]
  Generate an enrollment token for the given sender name. Prints
  the token + the collector's current TLS fingerprint + deployment
  hint. Must run as the collector user (or root).

epitropos-collector revoke <sender-name>
  Remove the sender from the pinned set. Does NOT delete their
  existing recordings or chain log — those remain for audit. Moves
  the sender dir to `senders-revoked/<name>.<timestamp>/`. Requires
  operator confirmation unless --force.

epitropos-collector list [--format=table|json]
  List enrolled senders, their enrollment timestamps, current head,
  and last activity.

epitropos-collector rotate-cert
  Generate a new collector TLS cert. Prints a checklist: every
  sender must re-enroll against the new fingerprint. The old cert
  is saved at tls/cert.pem.old for reference.

epitropos-collector verify <path>
  Validate a manifest sidecar signature against the stored
  signing.pub for whatever sender the sidecar refers to. Similar
  to katagrapho-verify but uses the collector's pubkey store.

epitropos-collector --version
  Print version + git commit and exit 0.
```

## 11. Dependencies

### 11.1 Collector member

```toml
[dependencies]
axum = { version = "0.8", default-features = false, features = ["http1", "tokio", "macros"] }
tokio = { version = "1", features = ["rt-multi-thread", "net", "io-util", "fs", "macros", "signal"] }
tower = "0.5"
tower-http = { version = "0.6", features = ["limit"] }
rustls = { version = "0.23", default-features = false, features = ["std", "tls12", "ring"] }
tokio-rustls = "0.26"
rustls-pemfile = "2"
rcgen = "0.13"
sha2 = "0.10"
hex = "0.4"
hmac = "0.12"
base32 = "0.5"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
thiserror = "1"
ed25519-dalek = { version = "2", default-features = false, features = ["std"] }

[dev-dependencies]
tempfile = "3"
hyper = { version = "1", features = ["client", "http1"] }
hyper-util = { version = "0.1", features = ["client-legacy", "tokio"] }
```

### 11.2 Forward side (existing proxy crate)

Add (minimal blocking client, no tokio):

```toml
ureq = { version = "2", default-features = false, features = ["tls", "json"] }
rustls = { version = "0.23", default-features = false, features = ["std", "tls12", "ring"] }
rcgen = "0.13"   # for sender cert generation
base32 = "0.5"
```

`ureq` is a blocking HTTP client with rustls support; it keeps the
forward binary off the tokio runtime. The proxy itself (the setuid
binary) is unchanged — these deps are only reached from
`epitropos-forward`, which lives in the same crate but is a separate
`[[bin]]` target. The setuid binary still has the same minimal dep
closure at runtime.

## 12. Testing

### 12.1 Unit tests (collector)

- `enroll::generate_token` + `enroll::validate_token` round-trip
- `enroll::validate_token` rejects expired
- `enroll::validate_token` rejects burned (second attempt)
- `enroll::validate_token` rejects wrong HMAC
- `chain::read_head` + `chain::advance` under flock (reuses pattern)
- `chain::advance` rejects non-matching `prev_manifest_hash`
- `storage::put_atomic` writes tmp, renames, handles existing file
- `storage::put_atomic` refuses paths outside the sender's dir
  (path-traversal check)
- `verify::verify_manifest` against a known signing pubkey —
  accepts valid, rejects tampered user field, rejects tampered
  signature
- `server::read_framed_body` parses `u32 BE len | manifest | bytes`
  correctly, rejects `manifest_len > 65536`, rejects truncated input
- `tls::pin_verifier` accepts pinned fingerprint, rejects everything
  else

### 12.2 Integration tests (collector in-process)

In-process `axum::Router` wrapped in a `tokio::net::TcpListener`
bound to 127.0.0.1:0, tests use `hyper` client with a pre-configured
rustls:

1. `/v1/health` returns 200
2. `/v1/enroll` with valid token returns 200, writes state, burns token
3. `/v1/enroll` with invalid token returns 401
4. `/v1/enroll` with expired token returns 401
5. `/v1/enroll` with reused token returns 401
6. `/v1/enroll` with duplicate sender_name returns 409
7. `/v1/sessions/.../parts/0` without mTLS returns 401 (handshake fails)
8. `/v1/sessions/.../parts/0` with wrong client cert returns 401
9. `/v1/sessions/.../parts/0` with correct cert + valid manifest +
   matching chain returns 200, advances head, writes files
10. Same as 9 with a chain gap (wrong `prev_manifest_hash`) returns 412
11. Same as 9 with a tampered manifest signature returns 422
12. Same as 9 with a recording whose SHA-256 doesn't match the manifest
    returns 422
13. Duplicate push of the same (session, part) returns 409 idempotent
14. Push with body > `max_upload_bytes` returns 413

### 12.3 Unit tests (forward side)

- `enroll::compute_expected_fingerprint` matches rustls cert
- `push::walk_head_log_from_position` returns the expected tail
- State file atomic update: write, rename, read back
- Framing: local helper that builds the `u32 BE len | manifest | bytes`
  body matches what the collector test fixture produces

### 12.4 NixOS VM test — `tests/vm-collector.nix`

Two-node test:

- **Node A (proxy)**: runs katagrapho + epitropos proxy + forward
  submodule enabled, collector pointing at B
- **Node B (collector)**: runs epitropos-collector

Test script:

1. Wait for both services
2. On B: generate an enrollment token for node A via
   `epitropos-collector enroll nodeA`
3. Capture the token + fingerprint from the command output
4. On A: run `epitropos-forward enroll` with the token and fingerprint
5. Assert `/var/lib/epitropos-forward/cert.pem`,
   `/var/lib/epitropos-forward/collector.pem` exist
6. On B: assert `/var/lib/epitropos-collector/senders/nodeA/` exists
   with `cert.pem` and `signing.pub`
7. On A: SSH into self as a recorded user, run `echo collector-test`,
   exit
8. On A: run `epitropos-forward push --once`, exit 0
9. On B: assert
   `/var/lib/epitropos-collector/senders/nodeA/recordings/<user>/*.kgv1.age`
   exists
10. On B: assert the sidecar exists and
    `epitropos-collector verify <sidecar>` exits 0
11. On B: assert `head.hash.log` has one line
12. On A: SSH again, run another command
13. On A: `push --once` again
14. On B: assert a second recording landed, chain has advanced
15. Tamper test: on B, corrupt one byte in a sidecar, run
    `epitropos-collector verify <sidecar>` — assert exit 1
16. Revoke test: on B, `epitropos-collector revoke nodeA` — sender
    dir moved to `senders-revoked/`, future pushes from A fail

## 13. Risks and mitigations

1. **Enrollment token interception + fingerprint interception.** If
   an attacker captures both, they can enroll as the sender.
   Mitigation: 15-minute TTL, single-use, deploy via NixOS secret
   file rather than chat/email. Operators are told not to paste tokens
   into shared chat.
2. **Collector TLS key loss.** Means every sender must re-enroll
   against a new fingerprint. Mitigation: `rotate-cert` command
   prints a checklist. Losing the key is intentionally a significant
   event — it IS the root of trust.
3. **Collector compromise.** An attacker with full collector
   control can see all recordings (still age-encrypted to the
   configured recipients), can forge future chain entries (they
   control the head), can serve a MITM to new enrollments.
   Detection: off-host replication of the collector's own
   `head.hash.log` — not in scope for Track C; flagged as a future
   track. Mitigation in Track C: run the collector on a hardened,
   network-isolated host.
4. **Collector disk full.** Uploads fail with 500; sender retries
   indefinitely. Mitigation: systemd `StorageMax` + monitoring
   (external, not in scope); documented in ops notes.
5. **Head log out of sync with `last_shipped.hash`.** If the
   katagrapho log is rotated, truncated, or the sender state file
   is deleted, the next push might re-ship everything or skip some
   entries. Mitigation: never rotate `head.hash.log` (append-only
   by design); if state is lost, the collector's idempotent 409
   handles duplicates, and the strict chain check ensures no
   entries are skipped silently.
6. **Clock skew.** Tokens are absolute-time bound. Severe skew can
   cause spurious enrollment failures. Mitigation: 15-minute TTL
   absorbs normal skew; docs require NTP.
7. **Crash during push.** State file is advanced AFTER a successful
   collector response. Crash in the middle = same manifest re-shipped
   next run = 409 idempotent success. No data loss, no duplication.
8. **Path traversal in sender_name / session_id.** Validated at
   both URL parse time and inside `storage::put_atomic` against the
   expected sender root. Defense in depth against typo'd sender
   names or malicious push bodies.
9. **rustls cert-verifier panic.** Custom client-cert verifier is
   small and takes only `&[u8]` DER input; unit-tested against
   random garbage inputs.
10. **Race on enrollment with concurrent clients.** All enrollment
    state transitions go through a single per-collector flock at
    `enrollments/lock`. Push handlers use per-sender flocks.

## 14. Acceptance criteria

1. `cargo build --release` succeeds at the workspace root for both
   members on the pinned toolchain
2. `epitropos/proxy` tests still pass (no regression in the proxy
   side after the workspace split)
3. `cargo test -p epitropos-collector` passes with the unit + in-
   process integration tests from §12.1–12.2
4. `cargo clippy --all-targets --workspace -- -D warnings` is clean
5. First-boot of the collector (via NixOS module) generates
   `tls/cert.pem` (mode 0400), `tls/key.pem` (0400), `enroll.secret`
   (0400), all owned `epitropos-collector:epitropos-collector`
6. `epitropos-collector enroll nodeA` prints a token and the
   collector's cert fingerprint
7. `epitropos-forward enroll` with a wrong `--expect-fingerprint`
   aborts before sending the token (unit test + VM test)
8. `epitropos-forward enroll` with correct token + fingerprint
   completes and writes `cert.pem`, `key.pem`, `collector.pem` to
   `/var/lib/epitropos-forward/`
9. Expired token returns 401 at the collector
10. Reused token returns 401 at the collector
11. `epitropos-forward push --once` ships any pending entries and
    advances `last_shipped.hash`
12. Chain-gap push returns 412 and the state does not advance on
    either side
13. Tampered manifest push returns 422
14. Tampered recording bytes push returns 422
15. Duplicate (session, part) push returns 409 idempotent and the
    sender treats it as success
16. Collector storage ends up with the expected per-sender layout
    + correct modes + correct ownership
17. `epitropos-collector verify <sidecar>` validates a pushed
    manifest using the stored sender pubkey
18. `epitropos-collector revoke <sender-name>` moves the sender
    to `senders-revoked/` and causes future mTLS handshakes from
    that sender to fail
19. NixOS VM test (2-node) passes
20. `katagrapho-readers` group is created by the katagrapho module,
    file ownership is updated, `epitropos-forward` is a member, and
    `ssh-sessions` still exists as a no-op handle

---

## Appendix A: Protocol wire example

Enrollment:

```
POST /v1/enroll HTTP/1.1
Host: nyx.tailnet:8443
Content-Type: application/json
Content-Length: 1248

{
  "sender_name": "alice-laptop",
  "token": "epitropos-enroll:OBSXG2DBNZTQWZDPOIXHIIBKMVRXSYLDNFSGK3TXEBSHK4TCOQWHG3LB",
  "tls_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIBk...\n-----END CERTIFICATE-----\n",
  "signing_pub_hex": "a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef"
}

HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 512

{
  "collector_tls_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
  "collector_fingerprint_sha256": "c39f3a2b18e4d9c7...a821"
}
```

Push:

```
POST /v1/sessions/abc-123/parts/0 HTTP/1.1
Host: nyx.tailnet:8443
Content-Type: application/octet-stream
Content-Length: 4196

\x00\x00\x03\xe4{"v":"katagrapho-manifest-v1","session_id":"abc-123",...}(age-blob-bytes-here)

HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 96

{
  "stored": true,
  "head_hash": "7f3c1b2a..."
}
```
