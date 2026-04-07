# Track A — Correctness, Build, and Hardening

**Status:** Design approved 2026-04-07
**Scope:** `/home/acid/Workspace/repos/katagrapho/` and `/home/acid/Workspace/repos/epitropos/`
**Out of scope:** `session-writer/` (dead, will be deleted separately)

This is the first of four planned tracks (A → B → C → D) that bring the
katagrapho + epitropos session-recording stack to feature parity with — and
beyond — Scribery/tlog. Track A is "make it correct, make it build, close
the audit gaps an operator can fall into." It introduces no new format, no
new sinks, no hash chain.

## 1. Goals

1. Eliminate the high-severity correctness bugs surfaced by the 2026-04-07
   security audit (encryption finalization, fsync, RAII terminal restore,
   SIGCHLD reap, fail-closed nesting).
2. Make both binaries build cleanly on rustc edition 2024.
3. Replace `Result<_, String>` everywhere with `thiserror` enums and map
   them to sysexits.h-style exit codes so sysadmins can triage failures
   without grepping syslog.
4. Close operator-misconfiguration footguns (`failPolicy = open` reaching
   root, `serde` silently dropping unknown config keys).
5. Backfill test coverage on the unverified hot paths
   (`event_loop::run`, `HookRunner`, katagrapho `run()`,
   `decode_shell_from_argv0`).
6. Add `--version` to every binary.
7. Defuse `epitropos-forward` so it cannot lie about delivery; real
   forwarder lands in Track C.

Non-goals: format changes, hash chain, PAM field propagation, sinks,
central collector, configurable file size, rotation. All deferred to
Tracks B/C/D.

## 2. Fix list (canonical, dependency order)

### 2.1 Cross-cutting

**F1 — Error type overhaul.** Replace every `Result<_, String>` in both
crates with `thiserror`-derived per-module enums. Top-level
`run() -> Result<(), TopError>` in each binary. `TopError` carries
`fn exit_code(&self) -> i32` mapping to sysexits.h:

| Variant class           | Code | Constant       |
|-------------------------|------|----------------|
| argv parse / mutex flag | 64   | `EX_USAGE`     |
| validation failure      | 65   | `EX_DATAERR`   |
| missing file (recipient/config) | 66 | `EX_NOINPUT` |
| stub refusal            | 69   | `EX_UNAVAILABLE` |
| unreachable / invariant | 70   | `EX_SOFTWARE`  |
| read/write/fsync/finalize | 74 | `EX_IOERR`     |
| transient (lock, kernel) | 75  | `EX_TEMPFAIL`  |
| privilege drop / EACCES | 77   | `EX_NOPERM`    |
| TOML / unknown field    | 78   | `EX_CONFIG`    |

**F2 — `--version` flag** in every binary (`katagrapho`, `epitropos`,
`epitropos-play`, `epitropos-forward`, `epitropos-ns-exec`). Prints
`name version (commit)` from `env!("CARGO_PKG_VERSION")` plus
`option_env!("KATAGRAPHO_GIT_COMMIT")` (and the epitropos analogue)
populated by a new `build.rs` in each crate. `build.rs` calls
`git rev-parse --short HEAD`; falls back to `"unknown"` outside a
git checkout.

### 2.2 Katagrapho

**F3 — Encryption finalization invariant.** Refactor `run()` so
`encryptor.finish()` is **always** called when an encryptor was
constructed, regardless of `stream_stdin` outcome or signal. New
`struct EncryptionFinalizer<'a, W: Write>` (in `src/finalize.rs`)
holds an `Option<age::stream::StreamWriter<W>>`. `Drop` consumes the
inner writer, calls `finish()`, stores the result in a shared cell
the caller reads after drop. Termination marker is written through
the finalizer (so it always lands inside the encrypted stream and
before `finish()`). Plaintext path keeps current behavior.

**F4 — fsync on every exit path.** Move `file.sync_all()` into a
`Drop` guard on the `File` wrapper, surface its result through the
top-level error so disk-full mid-stream returns `EX_IOERR` instead of
being silently swallowed.

**F5 — `build.rs`** as per F2.

**F6 — Tests added in Track A:**

- `run()` end-to-end smoke test: spawn the binary in a tempdir with
  a fake `STORAGE_DIR` (override via env? — see §6 risks), drive
  stdin, assert file content, perms (`0440`), and exit code.
  Currently `run()` has zero coverage.
- Encryption finalization on signal: spawn katagrapho, send asciicast
  bytes, send `SIGTERM`, decrypt the file with a known identity,
  assert it parses and contains the termination marker.
- `validate_directory` symlink-trap case (only happy-path tested today).
- `lock_privileges` is a no-op when `euid == uid` (sanity).

### 2.3 Epitropos

**F7 — Edition-2024 unsafe-env wrap.** `process.rs:309-314`
`set_var`/`remove_var` wrapped in `unsafe { }` blocks with SAFETY
comments noting the single-threaded post-fork invariant. Verifies
the crate builds cleanly on stable rustc with `edition = "2024"`.
A `rust-toolchain.toml` is added pinning to a known-good stable.

**F8 — RAII terminal-restore guard.** New
`src/term_guard.rs::TerminalGuard { saved: termios }` whose `Drop`
calls `tcsetattr(STDIN, TCSANOW, &self.saved)`. Constructed
immediately after `set_raw_mode` in `main.rs:453`; replaces the
manual `restore_terminal` call. Panic-safe by construction. Test:
trigger a panic inside `run()` after raw mode is set (using a slave
PTY in the test harness) and assert the termios is restored.

**F9 — SIGCHLD reap of katagrapho in event loop.** New
`src/sigchld.rs` registering a SIGCHLD handler against the **same**
self-pipe `signals.rs` already uses, distinguished in the consumer
by `waitpid(WNOHANG)`. The event loop polls the resulting flag each
iteration; if katagrapho's pid has exited, the session is torn down
immediately as `recording_failed`. Closes the up-to-`latency`-second
gap where buffered output hides the writer's death. Test: spawn a
fake katagrapho child that exits immediately; assert the event loop
terminates within one poll tick, not after `latency` seconds.

**F10 — Fail-closed on `is_nested_session` lock errors.**
`process.rs:64-73` returns `Result<bool, NestingError>`;
`main.rs:175-189` treats `Err` as `EX_TEMPFAIL` and refuses the
login. Operator sees a clear "nesting check failed, refusing
session" log line.

**F11 — Hardcoded always-closed identities.** New constants in
`config.rs`:

```rust
const ALWAYS_CLOSED_GROUPS: &[&str] = &["root", "wheel", "sudo", "admin"];
const ALWAYS_CLOSED_UIDS: &[u32] = &[0];
```

The fail-policy resolver unions these with operator config — operator
can *add* to the always-closed set but never *remove* an entry. Group
names not present on the host are silently ignored. Test: synthesize
a config with `default = "open"` and an empty `closedForGroups`;
assert that a uid-0 caller and a `wheel`-member caller both resolve
to `closed`. Documented escape hatch for emergency recovery: boot
single-user, edit config, restart. There is no CLI override.

**F12 — `#[serde(deny_unknown_fields)]`** on every struct in
`config.rs`. Removes the silent-ignore footgun for unknown sections
(`[nesting]` in the existing test). The `parse_minimal_config` test
is updated to use only declared fields; a new test asserts unknown-
field rejection produces a clear error mapped to `EX_CONFIG`.

**F13 — `epitropos-forward` becomes a refusal stub.** All real logic
in `forward.rs` is deleted. The binary prints
`epitropos-forward: not implemented (Track C)` to stderr and exits
with `EX_UNAVAILABLE` (69). The NixOS module still installs it so
dependent paths resolve. Test: invoke binary, assert exit code 69
and stderr message.

**F14 — Hook-runner reason hardening.** `main.rs:85-101` already caps
the reason at 256 bytes. Add a comment noting why, and a test
asserting non-UTF8 reasons round-trip via `OsStr` (today they
`unwrap_or_default()` and silently empty).

**F15 — Tests added in Track A** (the audit's gap list):

- `event_loop::run`: happy path + EOF + SIGCHLD-from-writer + SIGWINCH
  propagation.
- `HookRunner`: exec + arg passing + reason truncation + non-UTF8
  reason.
- `decode_shell_from_argv0`: allowlist enforcement, `..` rejection,
  every shell in the allowlist round-trips.

## 3. Architecture deltas

Two new tiny modules per crate. Each is small enough to hold in one
head, with one clear purpose and one clear interface.

### Katagrapho

```
src/error.rs       // ~80 lines: KatagraphoError + exit_code()
src/finalize.rs    // ~60 lines: EncryptionFinalizer<W>, Drop-driven
build.rs           // ~30 lines: KATAGRAPHO_GIT_COMMIT
tests/integration.rs  // end-to-end smoke + finalization-on-signal
```

`src/main.rs` shrinks: error helpers and the encryption
construction-and-finalize block move out.

### Epitropos

```
src/error.rs       // ~80 lines: EpitroposError + exit_code()
src/term_guard.rs  // ~40 lines: TerminalGuard
src/sigchld.rs     // ~50 lines: handler + flag, fed by signals.rs self-pipe
build.rs           // ~30 lines: EPITROPOS_GIT_COMMIT
tests/event_loop_smoke.rs
tests/hook_runner.rs
tests/decode_shell.rs
tests/fail_policy.rs
tests/term_guard_panic.rs
```

No existing-module boundaries move beyond import-and-replace.

## 4. Files touched (estimate)

**katagrapho** (~6 files):
`Cargo.toml`, `build.rs`, `src/main.rs`, `src/error.rs`,
`src/finalize.rs`, `tests/integration.rs`

**epitropos** (~14 files):
`Cargo.toml`, `build.rs`, `src/main.rs`, `src/process.rs`,
`src/event_loop.rs`, `src/config.rs`, `src/forward.rs`,
`src/error.rs`, `src/term_guard.rs`, `src/sigchld.rs`,
`tests/event_loop_smoke.rs`, `tests/hook_runner.rs`,
`tests/decode_shell.rs`, `tests/fail_policy.rs`,
`tests/term_guard_panic.rs`

NixOS modules (`nixos-module.nix`) are not modified by Track A. The
existing epitropos VM test (`vm-test-run-epitropos-session-recording`)
must still pass.

## 5. Testing strategy

- Unit tests live next to code (`#[cfg(test)] mod tests`) as today.
- Integration tests live in `tests/` per crate, using `assert_cmd`
  and `tempfile` (new dev-deps).
- One end-to-end smoke test per crate spawns the real binary in a
  tempdir sandbox.
- The existing epitropos NixOS VM test is not modified by Track A;
  if it still passes, behavior is preserved.

## 6. Risks

- **Edition-2024 build verification** depends on the installed rustc.
  Mitigation: `rust-toolchain.toml` pins to a known-good stable so
  CI and dev environments agree.
- **`thiserror` full conversion is a wide diff.** Mechanical but
  touches every file that returns `Result`. Mitigation: land it in
  one focused commit per crate, separate from the bug fixes, to
  keep review tractable.
- **SIGCHLD handler must coexist with `signals.rs`'s self-pipe.**
  Risk: double-handling or lost signals. Mitigation: register
  SIGCHLD against the same self-pipe and distinguish in the consumer
  by `waitpid(WNOHANG)`.
- **Hardcoded always-closed groups could lock out emergency recovery.**
  Mitigation: documented escape hatch is single-user boot + config
  edit + restart. No CLI override on purpose.
- **Katagrapho integration test needs to override `STORAGE_DIR`.**
  Today it is a `const`. Options: (a) make it a build-time `option_env!`
  with `/var/log/ssh-sessions` as default, (b) gate on `cfg(test)` and
  read from an env var, (c) accept a `--storage-dir` flag rejected
  outside tests. Decision: **(a)** — single source of truth, no test-
  only code in production paths.

## 7. Out of scope (deferred)

- Hash chain, per-message envelope, PAM field propagation → **Track B**
- Configurable `MAX_FILE_SIZE` and rotation → **Track B**
- Real `epitropos-forward` (TLS, mutual auth) → **Track C**
- `sd_journal` / syslog sinks → **Track C**
- Central collector, search, real PAM module → **Track D**

## 8. Acceptance criteria

Track A is done when:

1. `cargo build --release` succeeds in both crates on the pinned
   stable rustc.
2. `cargo test` passes in both crates, including the new tests
   listed in §2.
3. `cargo clippy -- -D warnings` is clean in both crates.
4. The existing epitropos NixOS VM test still passes.
5. Sending `SIGTERM` to a running katagrapho mid-session produces a
   decryptable file containing a termination marker.
6. Setting `failPolicy.default = "open"` with no `closedForGroups`
   in epitropos config and logging in as a `wheel` member with a
   broken katagrapho results in a refused session (not an unrecorded
   shell).
7. A typo'd config key in `epitropos.toml` produces an error message
   naming the unknown key and exit code 78.
8. `katagrapho --version` and `epitropos --version` print
   `name version (commit)`.
9. `epitropos-forward` exits 69 with the documented stderr message.
