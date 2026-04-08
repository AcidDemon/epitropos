# Track B — Audit Trail, Manifest Chain, Format, Rotation

**Status:** Design approved 2026-04-07
**Predecessor:** Track A (`2026-04-07-track-a-correctness-and-hardening.md`) — **must be merged first**
**Scope:** `/home/acid/Workspace/repos/katagrapho/` and `/home/acid/Workspace/repos/epitropos/`

Track B replaces the asciicast v2 recording format with a new
`katagrapho-v1` JSONL format that carries per-chunk SHA-256 hashes,
adds a signed JSON manifest sidecar, chains manifests across sessions
via a per-host head pointer, propagates available PAM/SSH metadata,
and introduces in-session file rotation with a total-size ceiling.
The format is intentionally incompatible with asciicast v2; legacy
`.cast.age` files remain readable by the existing playback path for
one release.

## 1. Goals

1. **Tamper-evident storage at rest** — every chunk of recording
   content is committed by a SHA-256 hash embedded in-stream, and
   the set of chunks per file is committed by a signed manifest.
2. **Corpus completeness** — a per-host manifest chain (`prev_manifest_hash`)
   detects session deletion or insertion, not just per-session tampering.
3. **Signature verification without the decryption key** — the manifest
   sidecar is plaintext and signed, so an audit team that is not an
   age recipient can still verify integrity of the recording corpus.
4. **Rotation without data loss** — long sessions rotate across
   multiple files, chain-linked, without interrupting the shell.
5. **Denial-of-disk protection** — a total-size-per-session ceiling
   prevents a user from filling the disk with a `yes`-in-a-loop.
6. **Audit fidelity** — the header records all SSH/PAM-adjacent
   metadata available without a custom PAM module (Track D).

**Non-goals (deferred):**

- Real `pam_epitropos.so` module — **Track D**
- Off-host witness/replication of `head.hash.log` — **Track C**
- TPM2 / HSM-backed signing key — **Track D**
- BLAKE3 secondary hash for fast dedup — optional, not required
- In-place migration tool from asciicast to v1 — not needed;
  legacy files stay legacy

## 2. Format — `katagrapho-v1`

### 2.1 Filenames

Per part:

```
<session-id>.part<N>.kgv1.age           # encrypted recording
<session-id>.part<N>.kgv1.manifest.json # plaintext signed manifest
```

`N` starts at 0 and increments on rotation. For sessions that never
rotate, only `part0` exists.

### 2.2 Stream schema

Newline-delimited JSON inside the (age-encrypted) recording file.
One record per line. Record kinds:

**`header`** — first line of every part, including part > 0:

```jsonc
{
  "kind": "header",
  "v": "katagrapho-v1",
  "session_id": "<string>",
  "user": "<username>",
  "host": "<hostname>",
  "boot_id": "<kernel boot_id>",
  "part": 0,
  "prev_manifest_hash_link": "<hex of previous part's this_manifest_hash, or null for part 0>",
  "started": 1712534400.123,
  "cols": 80,
  "rows": 24,
  "shell": "/bin/bash",
  "epitropos_version": "0.1.0",
  "epitropos_commit":  "1a89e30",
  "katagrapho_version": "0.3.0",
  "katagrapho_commit":  "0f58ff0",
  "audit_session_id": 42,
  "ppid": 12345,
  "ssh_client": "203.0.113.5 54321 22",
  "ssh_connection": "203.0.113.5 54321 10.0.0.2 22",
  "ssh_original_command": null,
  "parent_comm": "sshd",
  "parent_cmdline": "sshd: alice [priv]",
  "pam_rhost": null,
  "pam_service": null
}
```

`pam_rhost` and `pam_service` are reserved. Track D's PAM module
fills them in; Track B always writes `null`.

**`out`** / **`in`** — one record per PTY output/input write:

```jsonc
{"kind": "out", "t": 0.123, "b": "aGVsbG8K"}
```

- `t` — monotonic seconds since `header.started`
- `b` — base64-encoded bytes (lossless for non-UTF-8)

**`resize`** — one record per SIGWINCH:

```jsonc
{"kind": "resize", "t": 1.789, "cols": 100, "rows": 30}
```

**`chunk`** — emitted by the epitropos flush buffer at every chunk
boundary:

```jsonc
{
  "kind": "chunk",
  "seq": 0,
  "bytes": 65310,
  "messages": 412,
  "elapsed": 9.87,
  "sha256": "<hex>"
}
```

`sha256` is computed over all non-`chunk` records emitted since the
previous `chunk` boundary (or since the `header` for `seq = 0`),
concatenated with `\n` between records and ending in `\n`. The
`chunk` record itself is **not** included in its own hash.

**`rotate`** — emitted by katagrapho immediately before finalizing
the current part:

```jsonc
{"kind": "rotate", "t": 123.45, "next_part": 1}
```

**`end`** — terminator, always emitted before `encryptor.finish()`:

```jsonc
{"kind": "end", "t": 118.42, "reason": "eof", "exit_code": 0}
```

`reason` values: `"eof"`, `"signal"`, `"shell_exited"`,
`"size_limit"`, `"session_size_limit"`, `"writer_error"`,
`"rotated"`.

### 2.3 Who emits which records

- **epitropos** emits `header`, `out`, `in`, `resize`, `chunk`.
- **katagrapho** emits `rotate`, `end` (because it owns the file and
  decides when to rotate).
- Chunk boundaries are decided by epitropos (via `FlushBuffer`)
  because the timing/byte/message counters live there.
- Chunk SHA-256 is computed in epitropos and mirrored verbatim into
  the manifest by katagrapho.

## 3. Manifest sidecar

Path: `<recording-dir>/<session-id>.part<N>.kgv1.manifest.json`
Mode: 0444 owned `session-writer:ssh-sessions`.
Encoding: UTF-8 JSON. Canonicalization: field order fixed by a
shared schema module so sign/verify agree byte-for-byte.

```jsonc
{
  "v": "katagrapho-manifest-v1",
  "session_id": "<string>",
  "part": 0,
  "user": "alice",
  "host": "nyx",
  "boot_id": "<kernel boot_id>",
  "audit_session_id": 42,
  "started": 1712534400.123,
  "ended":   1712534518.551,
  "katagrapho_version": "0.3.0",
  "katagrapho_commit":  "0f58ff0",
  "epitropos_version":  "0.1.0",
  "epitropos_commit":   "1a89e30",
  "recording_file": "alice-42-abc.part0.kgv1.age",
  "recording_size": 524288,
  "recording_sha256": "<hex of SHA-256 over the encrypted file on disk>",
  "chunks": [
    {"seq": 0, "bytes": 65310, "messages": 412, "elapsed":  9.87, "sha256": "<hex>"},
    {"seq": 1, "bytes": 63988, "messages": 398, "elapsed":  9.92, "sha256": "<hex>"}
  ],
  "end_reason": "eof",
  "exit_code":  0,
  "prev_manifest_hash": "<hex of SHA-256 of previous host manifest's this_manifest_hash, or 64 zeros for genesis>",
  "this_manifest_hash": "<hex of SHA-256 over canonicalized manifest fields EXCLUDING signature and this_manifest_hash itself>",
  "key_id": "<hex of SHA-256 of the ed25519 pubkey>",
  "signature": "<base64 ed25519 signature over this_manifest_hash>"
}
```

### 3.1 Canonicalization rules

1. Field order is fixed exactly as shown above.
2. Floats use `f64` with JSON's default serialization (no trailing
   zeros, no exponent unless needed).
3. `chunks` array preserves insertion order (which is chronological).
4. Strings are UTF-8, no BOM.
5. No trailing newline.
6. `this_manifest_hash` and `signature` are **omitted** during the
   hashing pass; the hash is computed over the canonical bytes of
   the manifest minus those two fields. The verifier reconstructs
   the same byte sequence by dropping those fields and re-serializing.

Canonicalization is implemented once, in `katagrapho/src/manifest.rs`,
and is used by both sign and verify paths.

### 3.2 Sign/verify

Signing algorithm: Ed25519 (`ed25519-dalek` 2.x).

Signing steps:

1. Assemble manifest with all fields except `this_manifest_hash` and
   `signature` populated.
2. Serialize canonically, producing `bytes_to_hash`.
3. `this_manifest_hash = SHA256(bytes_to_hash)`.
4. `signature = ed25519_sign(private_key, this_manifest_hash)`.
5. Write the final JSON with `this_manifest_hash` and `signature`
   inserted at their canonical positions.

Verification:

1. Parse sidecar.
2. Extract `this_manifest_hash` and `signature`.
3. Re-serialize canonically without those two fields.
4. Recompute `SHA256(bytes_to_hash)`; compare to `this_manifest_hash`.
   Mismatch → tampered → exit 1.
5. `ed25519_verify(pubkey, this_manifest_hash, signature)`. Failure
   → forged or wrong key → exit 1.
6. If `--with-key <age-identity>` also given: decrypt the recording,
   walk chunk records, confirm each `chunk.sha256` matches the
   SHA-256 over the records between it and the previous chunk.
   Mismatch → exit 2.

## 4. Head pointer and per-host chain

### 4.1 Files

```
/var/lib/katagrapho/
├── head.hash             # mode 0600 session-writer — current head (hex, no newline)
├── head.hash.lock        # mode 0600 session-writer — flock target, empty
├── head.hash.log         # mode 0640 session-writer:ssh-sessions — append-only log
├── signing.key           # mode 0400 session-writer — ed25519 seed
└── signing.pub           # mode 0444 world-readable — ed25519 pubkey
```

On a fresh install, `head.hash` does not exist. First finalize
treats a missing file as `"0" * 64` (genesis).

### 4.2 head.hash.log format

Append-only, one line per finalized manifest:

```
<iso8601 timestamp> <user> <session_id> <part> <this_manifest_hash>
```

Lines are fsynced individually. This file is the witness-ready
structure Track C will replicate off-host.

### 4.3 Finalize protocol (katagrapho, per part)

```
1. flock(head.hash.lock, LOCK_EX)                   # blocking
2. prev = read(head.hash) or "0"*64 if missing
3. manifest.prev_manifest_hash = prev
4. manifest.this_manifest_hash = SHA256(canonicalize(manifest))
5. manifest.signature = ed25519_sign(key, this_manifest_hash)
6. write(sidecar.tmp, json)
   fsync(sidecar.tmp)
   rename(sidecar.tmp, sidecar)
7. write(head.hash.tmp, this_manifest_hash)
   fsync(head.hash.tmp)
   rename(head.hash.tmp, head.hash)
8. append(head.hash.log, "<ts> <user> <session> <part> <hash>\n")
   fsync(head.hash.log)
9. flock(LOCK_UN)
```

Crash recovery:

- Crash between 6 and 7: sidecar exists, head not updated. Next
  finalize detects that the on-disk sidecar for the prior session
  exists but is not pointed at by head; logs a warning, treats the
  stale head as `prev_manifest_hash`. The detection logic is:
  if there is a sidecar newer than `head.hash`'s mtime, emit a
  warning to syslog. No automatic repair.
- Crash between 7 and 8: head updated, log not appended. Next
  finalize detects log is behind head, appends a `<recovered>` line
  pointing at the current head to resync.
- Crash before 6: nothing on disk. Clean state.

## 5. Signing key

- Generated once at install time by a NixOS `systemd` oneshot unit
  `katagrapho-keygen.service` with
  `ConditionPathExists=!/var/lib/katagrapho/signing.key`. Runs as
  root, writes `signing.key` owned by `session-writer` mode 0400 and
  `signing.pub` mode 0444.
- Key type: Ed25519. Algorithm label in manifest: implicit via
  `v: "katagrapho-manifest-v1"` (no agility in Track B).
- `key_id` in manifest is the hex SHA-256 of the raw 32-byte public
  key. Lets future key rotation and a Track D two-tier cert model
  slot in without a format version bump.
- Katagrapho loads the key once at startup, after privilege drop,
  into memory. `mlock`ed (best effort; no hard fail).
- Dependency: `ed25519-dalek = "2"`.

## 6. Chunking (hybrid rule)

Chunk boundary fires when **any** of:

- `bytes_since_last_chunk >= cfg.chunk.max_bytes` (default 65536)
- `messages_since_last_chunk >= cfg.chunk.max_messages` (default 256)
- `elapsed_since_last_chunk >= cfg.chunk.max_seconds` (default 10.0)
- `end` or `rotate` about to be written

Implementation: `epitropos/src/buffer.rs::FlushBuffer` gains a
`ChunkTracker` struct holding a running SHA-256 (via `sha2::Sha256`),
a byte counter, a message counter, and an epoch for elapsed. On
boundary, it finalizes the SHA-256, emits the `chunk` record, and
resets.

Non-goal: computing chunk hashes in katagrapho. Epitropos is the
authoritative producer.

## 7. Rotation and size limits

### 7.1 Config

New katagrapho config file. Katagrapho currently has only CLI args;
Track B adds `--config /etc/katagrapho/katagrapho.toml`, optional,
falls back to built-in defaults.

```toml
[storage]
max_file_bytes    = 536870912    # 512 MiB per part
max_session_bytes = 4294967296   # 4 GiB per session (hard fail)

[signing]
key_path = "/var/lib/katagrapho/signing.key"
pub_path = "/var/lib/katagrapho/signing.pub"

[chain]
head_path = "/var/lib/katagrapho/head.hash"
log_path  = "/var/lib/katagrapho/head.hash.log"
lock_path = "/var/lib/katagrapho/head.hash.lock"
```

Epitropos config gains:

```toml
[chunk]
max_bytes    = 65536
max_messages = 256
max_seconds  = 10.0
```

### 7.2 Rotation flow (katagrapho)

Rotation is checked only at **chunk boundaries**, never mid-record.

```
when (current_file_bytes + next_chunk_bytes > max_file_bytes):
    emit {"kind":"rotate","t":now,"next_part":N+1}  # inside current stream
    emit {"kind":"end","t":now,"reason":"rotated","exit_code":0}
    encryptor.finish()
    write_manifest(part=N, end_reason="rotated")
    advance_head_chain()
    open <session>.part<N+1>.kgv1.age
    write_header(part=N+1, prev_manifest_hash_link=part_N.this_manifest_hash)
    resume streaming
```

### 7.3 Session size ceiling

```
when (total_session_bytes >= max_session_bytes):
    emit {"kind":"end","t":now,"reason":"session_size_limit","exit_code":0}
    encryptor.finish()
    write_manifest(..., end_reason="session_size_limit")
    advance_head_chain()
    exit(EX_IOERR)
```

The SIGCHLD path in epitropos's event loop (Track A) then tears down
the shell the same way any other writer exit does.

## 8. Auth metadata scraping

New module `epitropos/src/auth_meta.rs`:

```rust
pub struct AuthMeta {
    pub ssh_client:            Option<String>,
    pub ssh_connection:        Option<String>,
    pub ssh_original_command:  Option<String>,
    pub ppid:                  libc::pid_t,
    pub parent_comm:           Option<String>,
    pub parent_cmdline:        Option<String>,
    pub pam_rhost:             Option<String>,  // always None in Track B
    pub pam_service:           Option<String>,  // always None in Track B
}

impl AuthMeta {
    pub fn capture() -> Self;
}
```

`capture()` reads environment variables **before** `env::sanitize()`
is called, plus `/proc/<ppid>/comm` and `/proc/<ppid>/cmdline`
(truncated at 4 KiB, NUL-separated args joined by space). Never
panics, never errors — missing fields become `None`.

Call site: `main.rs::run()`, immediately after `env::stash_shell_vars()`
and before `env::sanitize()`. Value is injected into the `header`
record of every part.

## 9. Binaries and playback

### 9.1 New binary: `katagrapho-verify`

```
katagrapho-verify [--with-key <age-identity-file>] [--check-chain] <path>
```

Inputs:
- `<path>` can be a single manifest sidecar, a recording file (infers
  sidecar path), or a directory (recurses and verifies every manifest
  found).
- `--with-key` also decrypts each recording and verifies chunk hashes.
- `--check-chain` walks `prev_manifest_hash` backward across the
  supplied set, confirming all links resolve to a signed predecessor
  in the set (genesis is a valid terminator).

Exit codes (sysexits + verify-specific):
- 0 — verified
- 1 — signature mismatch
- 2 — chunk hash mismatch (only with `--with-key`)
- 3 — chain broken
- 4 — manifest malformed
- 64 (`EX_USAGE`) — bad CLI args
- 66 (`EX_NOINPUT`) — path or key file missing
- 77 (`EX_NOPERM`) — permission denied

### 9.2 `epitropos-play` extension

Add a format detection step: the first decrypted line is inspected.

- `{"version":2,...}` → legacy asciicast path (preserved for ≥1 release)
- `{"kind":"header","v":"katagrapho-v1",...}` → new path

On the new path, before playback, `epitropos-play` locates the
sidecar manifest (same basename, `.manifest.json` suffix), verifies
the signature using `/var/lib/katagrapho/signing.pub`, and refuses
playback on mismatch unless `--force` is passed (with a loud stderr
warning).

## 10. File layout changes

### 10.1 Katagrapho — new files

```
src/manifest.rs        ~180  build, canonicalize, hash, sign, write, load, verify
src/chain.rs           ~100  head.hash + head.hash.log append with flock
src/signing.rs         ~80   load ed25519 key from disk, wrap dalek
src/verify.rs          ~150  verify logic used by the new binary
src/stream.rs          ~220  parse katagrapho-v1 stream, rotation detection
src/kata_config.rs     ~120  TOML config parsing + defaults
bin/katagrapho-verify.rs ~80 CLI entry
```

### 10.2 Katagrapho — modified files

```
src/main.rs           switch from raw byte-through pipe to v1 stream
                      parser; rotation loop; manifest finalize per part
src/finalize.rs       unchanged behaviour; still owns age finalization
Cargo.toml            + ed25519-dalek, + sha2, + hex, [[bin]] for verify
nixos-module.nix      keygen oneshot; /var/lib/katagrapho tmpfiles;
                      /etc/katagrapho/katagrapho.toml deployment
```

### 10.3 Epitropos — new files

```
src/auth_meta.rs      ~60   AuthMeta::capture()
src/kgv1.rs           ~180  emit katagrapho-v1 records (replaces asciicinema.rs
                            for write path; legacy reader stays in asciicinema.rs)
```

### 10.4 Epitropos — modified files

```
src/main.rs           capture AuthMeta before env::sanitize; inject into header;
                      switch writer from asciicinema to kgv1
src/buffer.rs         add ChunkTracker; emit chunk record at flush
src/config.rs         new [chunk] section
src/asciicinema.rs    kept as read-only legacy parser for epitropos-play;
                      write functions deleted
```

## 11. Testing strategy

### 11.1 Unit tests (both crates)

- `manifest::canonicalize` produces byte-identical output for logically
  equal manifests built with different field-insertion order
- `manifest::sign` + `manifest::verify` round-trip with a fresh key
- `manifest::verify` fails on tampered sidecar (flip 1 byte)
- `manifest::verify --with-key` fails on tampered recording (flip 1 byte
  in the encrypted file after sidecar was written)
- `chain::advance` updates head.hash atomically, logs to head.hash.log
- `chain::walk` correctly traverses 3 manifests
- `chain::walk` detects a break in the middle
- `ChunkTracker` fires on each of byte / message / elapsed triggers
  independently
- `AuthMeta::capture` with synthetic env populates expected fields
- Rotation: simulated `max_file_bytes = 1024`, feed 3 KiB → 3 parts,
  chain links correct
- Session ceiling: `max_session_bytes = 2048`, feed 2049 → session ends
  with `reason=session_size_limit`

### 11.2 Integration tests

- End-to-end katagrapho: pipe synthetic kgv1 stream in, assert sidecar
  + head.hash + head.hash.log all correct
- `katagrapho-verify` on valid / tampered / broken-chain inputs —
  exit codes match §9.1
- `epitropos-play --force` on a tampered recording prints warning
  and continues; without `--force` refuses

### 11.3 NixOS VM test update

Extend the existing `session-recording` VM test (epitropos repo) to:

- Verify `signing.key` is generated at first boot
- Record a session, confirm sidecar exists with correct owner/mode
- Run `katagrapho-verify` on the sidecar inside the VM
- Verify `head.hash.log` gained a line

## 12. Migration and compatibility

Track A format (asciicast v2) remains readable by `epitropos-play`
via the legacy branch of its format-detection dispatch. Track A
recordings have no manifest and no chain membership; they remain
standalone.

Track B flips the recording writer to `kgv1.rs` as soon as the
updated epitropos is deployed. Mixed deployments (new epitropos, old
katagrapho) are not supported — operators must roll both together.

No in-place migration tool. Track A files stay as they are.

## 13. Risks and mitigations

1. **Format churn in epitropos-play** — legacy and v1 parsers live
   alongside. Mitigation: explicit format detection on the first
   decrypted line; exhaustive unit tests for both branches.
2. **Ed25519 key loss** — private key loss invalidates all future
   manifest verification. Mitigation: `signing.pub` is world-readable
   and should be backed up into the NixOS system closure so the
   pubkey is recoverable from machine state. Private key is
   host-state; document that losing it means starting a new chain
   with a new `key_id`, old manifests remain verifiable with the old
   pubkey.
3. **head.hash race** — mitigated by flock on `head.hash.lock` and
   the append-only log. Crash recovery rules in §4.3 cover the
   documented failure windows.
4. **Encrypted-stream chunk hash forgery** — epitropos computes the
   hashes before the stream hits katagrapho. Compromise of katagrapho
   cannot rewrite chunk records without also compromising epitropos.
   The two run under different UIDs.
5. **Rotation mid-record** — forbidden by construction: rotation
   checks fire only at chunk boundaries, which are record boundaries.
6. **Keygen race** — `ConditionPathExists=!` on the oneshot makes
   re-runs no-ops. First boot is atomic.
7. **Disk-full during finalize** — sidecar write is the critical
   path. `write(tmp) → fsync → rename` gives atomicity. If the
   sidecar write fails, head pointer is not advanced, the chain is
   intact, the recording file exists unverified. Audit sees a
   sidecar-missing warning via `katagrapho-verify`.
8. **Manifest signature over plaintext sidecar** — anyone with
   `signing.pub` can verify; the signing key is the authoritative
   secret. Signing-key compromise = forgery after compromise but
   not retroactively, because already-distributed sidecars are
   fixed (an attacker rewriting on-host sidecars is detected by any
   off-host copy).

## 14. Acceptance criteria

1. Fresh install of the NixOS module generates
   `/var/lib/katagrapho/signing.key` mode 0400 owned `session-writer`
   and `/var/lib/katagrapho/signing.pub` mode 0444.
2. A session produces `<id>.part0.kgv1.age` + `<id>.part0.kgv1.manifest.json`
   with the expected owners and modes (0440 and 0444 respectively).
3. The sidecar contains `prev_manifest_hash` equal to the pre-session
   value of `head.hash` (or 64 zeros if this is the first session).
4. After the session, `head.hash` contains the session's
   `this_manifest_hash`.
5. `head.hash.log` has gained one line for the session.
6. `katagrapho-verify <sidecar>` exits 0 on the fresh session.
7. Flipping one byte anywhere in the sidecar causes
   `katagrapho-verify` to exit 1.
8. `katagrapho-verify --with-key <age-identity> <sidecar>` decrypts
   the recording, walks all chunk records, confirms each chunk's
   `sha256` matches the in-stream hash, and exits 0.
9. Flipping one byte in the encrypted recording after the fact
   causes `katagrapho-verify --with-key` to exit 2.
10. A session that writes more than `max_file_bytes` bytes produces
    multiple parts (`part0`, `part1`, ...), each with its own
    sidecar, and each header's `prev_manifest_hash_link` points at
    the previous part's `this_manifest_hash`.
11. A session that writes more than `max_session_bytes` total
    triggers an `end` record with `reason = session_size_limit`
    and the shell is torn down.
12. `AuthMeta::capture()` populates `ssh_client`, `ssh_connection`,
    and `parent_comm` when called under an SSH login (verified in the
    VM test) and returns `None` for all fields when run outside SSH
    (verified in a unit test with a scrubbed env).
13. `epitropos-play` on a v1 recording verifies the sidecar signature
    before replay and refuses to proceed on mismatch unless `--force`
    is passed.
14. `katagrapho-verify --check-chain /var/log/ssh-sessions/<user>/`
    walks every manifest in the directory, verifies each signature
    individually, verifies every `prev_manifest_hash` resolves to a
    manifest in the set (or genesis), and exits 0 on a clean corpus.
15. Legacy `.cast.age` files from Track A remain playable via
    `epitropos-play`'s legacy branch for at least one release after
    Track B lands.
