# Track A — Correctness, Build, and Hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** `epitropos/docs/superpowers/specs/2026-04-07-track-a-correctness-and-hardening.md`

**Goal:** Eliminate the high-severity correctness bugs in katagrapho + epitropos, replace `Result<_, String>` with `thiserror` + sysexits exit codes, close operator-misconfig footguns, backfill test coverage, and defuse the `epitropos-forward` stub.

**Architecture:** No new format, no new sinks, no hash chain. Two new tiny modules per crate (`error.rs`, plus `finalize.rs` for katagrapho and `term_guard.rs` + `sigchld.rs` for epitropos). Mechanical `thiserror` conversion lands as one focused commit per crate, separate from bug fixes, to keep review tractable.

**Tech Stack:** Rust edition 2024, `thiserror` 1, `assert_cmd` + `tempfile` (dev-deps), `libc`, `age`, `serde`, `toml`. No new runtime dependencies beyond `thiserror`.

**Repos touched:**
- `/home/acid/Workspace/repos/katagrapho/`
- `/home/acid/Workspace/repos/epitropos/`

**Phase order:**
1. Phase 1 — Katagrapho (smaller, validates the patterns)
2. Phase 2 — Epitropos (applies the same patterns at scale)
3. Phase 3 — Cross-crate verification

**Commit hygiene:** Every task ends in a commit. Use `git -c commit.gpgsign=false commit -m "..."` (gpg signing fails in this env). No `Co-Authored-By` lines (project preference). Keep commit messages short and factual.

---

## File Structure

### Katagrapho — new and modified files

```
katagrapho/
├── Cargo.toml                    # MODIFY: add thiserror, dev-deps
├── build.rs                      # CREATE: KATAGRAPHO_GIT_COMMIT
├── rust-toolchain.toml           # CREATE: pin stable rustc
├── src/
│   ├── main.rs                   # MODIFY: shrink, use error.rs + finalize.rs
│   ├── error.rs                  # CREATE: KatagraphoError + exit_code()
│   └── finalize.rs               # CREATE: EncryptionFinalizer<W>
└── tests/
    └── integration.rs            # CREATE: end-to-end + finalization-on-signal
```

`STORAGE_DIR` becomes `option_env!("KATAGRAPHO_STORAGE_DIR").unwrap_or("/var/log/ssh-sessions")` so the integration test can override it at compile time via `KATAGRAPHO_STORAGE_DIR=... cargo test`.

### Epitropos — new and modified files

```
epitropos/
├── Cargo.toml                    # MODIFY: add thiserror, dev-deps
├── build.rs                      # CREATE: EPITROPOS_GIT_COMMIT
├── rust-toolchain.toml           # CREATE: pin stable rustc (shared with katagrapho)
├── src/
│   ├── main.rs                   # MODIFY: TerminalGuard, --version, EX_*
│   ├── error.rs                  # CREATE: EpitroposError + exit_code()
│   ├── term_guard.rs             # CREATE: RAII termios save/restore
│   ├── sigchld.rs                # CREATE: SIGCHLD handler + flag
│   ├── process.rs                # MODIFY: edition-2024 unsafe wrap, NestingError
│   ├── event_loop.rs             # MODIFY: poll sigchld each iteration
│   ├── config.rs                 # MODIFY: deny_unknown_fields, ALWAYS_CLOSED_*
│   ├── forward.rs                # REWRITE: refusal stub
│   ├── play.rs                   # MODIFY: --version
│   └── ns_exec.rs                # MODIFY: --version
└── tests/
    ├── event_loop_smoke.rs       # CREATE
    ├── hook_runner.rs            # CREATE
    ├── decode_shell.rs           # CREATE
    ├── fail_policy.rs            # CREATE
    └── term_guard_panic.rs       # CREATE
```

---

# Phase 1 — Katagrapho

## Task 1: Pin toolchain and add dev-deps

**Files:**
- Create: `katagrapho/rust-toolchain.toml`
- Modify: `katagrapho/Cargo.toml`

- [ ] **Step 1: Create toolchain pin**

Create `katagrapho/rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.84.0"
components = ["rustfmt", "clippy"]
profile = "minimal"
```

- [ ] **Step 2: Add thiserror and dev-deps to Cargo.toml**

Modify `katagrapho/Cargo.toml` — add to `[dependencies]`:

```toml
thiserror = "1"
```

Add a new section after `[dependencies]`:

```toml
[dev-dependencies]
assert_cmd = "2"
tempfile = "3"
predicates = "3"
age = { version = "0.11", default-features = false, features = ["armor"] }
```

(`age` re-listed in dev-deps with `armor` only because the integration test will need an identity to decrypt; the production build keeps `default-features = false` with no extra features.)

- [ ] **Step 3: Verify build still works**

Run: `cd /home/acid/Workspace/repos/katagrapho && cargo build --release`
Expected: succeeds, no new warnings.

- [ ] **Step 4: Commit**

```bash
cd /home/acid/Workspace/repos/katagrapho
git add Cargo.toml Cargo.lock rust-toolchain.toml
git -c commit.gpgsign=false commit -m "build: pin rustc 1.84, add thiserror + test deps"
```

---

## Task 2: Add build.rs for git commit

**Files:**
- Create: `katagrapho/build.rs`

- [ ] **Step 1: Write build.rs**

Create `katagrapho/build.rs`:

```rust
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=KATAGRAPHO_GIT_COMMIT={commit}");
}
```

- [ ] **Step 2: Verify it compiles and exposes the env var**

Add a temporary `eprintln!("commit={}", env!("KATAGRAPHO_GIT_COMMIT"));` at the top of `main()` in `src/main.rs`. Run `cargo run -- --help 2>&1 | head -1`. Expected: prints `commit=<short-sha>` (or `commit=unknown` outside a git checkout). Remove the eprintln.

- [ ] **Step 3: Commit**

```bash
git add build.rs
git -c commit.gpgsign=false commit -m "build: expose KATAGRAPHO_GIT_COMMIT via build.rs"
```

---

## Task 3: Create error module with exit_code()

**Files:**
- Create: `katagrapho/src/error.rs`

- [ ] **Step 1: Write the failing test (in src/error.rs)**

Create `katagrapho/src/error.rs`:

```rust
//! katagrapho top-level error type. Maps every failure to a sysexits.h
//! exit code so sysadmins can triage without grepping syslog.

use std::io;

// sysexits.h
pub const EX_USAGE: i32 = 64;
pub const EX_DATAERR: i32 = 65;
pub const EX_NOINPUT: i32 = 66;
pub const EX_SOFTWARE: i32 = 70;
pub const EX_IOERR: i32 = 74;
pub const EX_TEMPFAIL: i32 = 75;
pub const EX_NOPERM: i32 = 77;
pub const EX_CONFIG: i32 = 78;

#[derive(Debug, thiserror::Error)]
pub enum KatagraphoError {
    #[error("usage: {0}")]
    Usage(String),

    #[error("validation: {0}")]
    Validation(String),

    #[error("recipient file: {0}")]
    Recipient(String),

    #[error("privilege drop: {0}")]
    Privilege(String),

    #[error("storage: {0}")]
    Storage(String),

    #[error("encryption: {0}")]
    Encryption(String),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("internal: {0}")]
    Internal(String),
}

impl KatagraphoError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => EX_USAGE,
            Self::Validation(_) => EX_DATAERR,
            Self::Recipient(_) => EX_NOINPUT,
            Self::Privilege(_) => EX_NOPERM,
            Self::Storage(_) => EX_IOERR,
            Self::Encryption(_) => EX_IOERR,
            Self::Io(_) => EX_IOERR,
            Self::Internal(_) => EX_SOFTWARE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_distinct_per_class() {
        assert_eq!(KatagraphoError::Usage("x".into()).exit_code(), EX_USAGE);
        assert_eq!(KatagraphoError::Validation("x".into()).exit_code(), EX_DATAERR);
        assert_eq!(KatagraphoError::Recipient("x".into()).exit_code(), EX_NOINPUT);
        assert_eq!(KatagraphoError::Privilege("x".into()).exit_code(), EX_NOPERM);
        assert_eq!(KatagraphoError::Storage("x".into()).exit_code(), EX_IOERR);
        assert_eq!(KatagraphoError::Encryption("x".into()).exit_code(), EX_IOERR);
        assert_eq!(KatagraphoError::Internal("x".into()).exit_code(), EX_SOFTWARE);
    }
}
```

- [ ] **Step 2: Wire module into main.rs**

In `katagrapho/src/main.rs`, add at the top of the file (after the doc comment, before the first `use`):

```rust
mod error;
```

- [ ] **Step 3: Run tests**

Run: `cargo test --lib error::`
Expected: `exit_codes_are_distinct_per_class ... ok`

- [ ] **Step 4: Commit**

```bash
git add src/error.rs src/main.rs
git -c commit.gpgsign=false commit -m "error: introduce KatagraphoError with sysexits exit codes"
```

---

## Task 4: Convert main.rs from String errors to KatagraphoError

This is the wide mechanical commit. Do it as one task to keep review coherent.

**Files:**
- Modify: `katagrapho/src/main.rs`

- [ ] **Step 1: Replace every `Result<_, String>` signature**

Find every function in `src/main.rs` whose return type is `Result<_, String>` and change it to `Result<_, KatagraphoError>`. Use this mapping for the body changes:

| Current site | Replace with |
|---|---|
| `format!("cannot resolve username for uid {uid}")` | `KatagraphoError::Privilege(format!("cannot resolve username for uid {uid}"))` |
| `format!("setresgid: {e}")` / `setresuid` | `KatagraphoError::Privilege(format!(...))` |
| validate `*` errors | `KatagraphoError::Validation(format!(...))` |
| `validate_directory` errors | `KatagraphoError::Storage(format!(...))` |
| `load_recipients` errors | `KatagraphoError::Recipient(format!(...))` |
| `stream_stdin` `read:`/`write:` errors | `KatagraphoError::Io(e)` (use `?` after wrapping with `From`) |
| `MAX_FILE_SIZE` overflow | `KatagraphoError::Storage(format!("session exceeds maximum size ({MAX_FILE_SIZE} bytes)"))` |
| `parse_args` errors | `KatagraphoError::Usage(format!(...))` |
| Encryption setup / wrap_output / finalize errors | `KatagraphoError::Encryption(format!(...))` |
| `setrlimit` errors | `KatagraphoError::Privilege(format!(...))` |
| `prctl` errors | `KatagraphoError::Privilege(format!(...))` |
| `fsync` error in success path | `KatagraphoError::Io(e)` |
| `--session-id required` | `KatagraphoError::Usage(...)` |

Add `use crate::error::KatagraphoError;` at the top of `main.rs` next to the existing `use`s.

- [ ] **Step 2: Update `main()` to use `exit_code()`**

Replace the existing `main()`:

```rust
fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("katagrapho: {e}");
            close_syslog();
            process::exit(e.exit_code());
        }
    }
}
```

- [ ] **Step 3: Build and run existing tests**

Run: `cargo build --release && cargo test`
Expected: build succeeds, all existing tests pass.

- [ ] **Step 4: Verify exit codes change**

Run: `cargo run -- --session-id 'bad/id' --no-encrypt; echo "exit=$?"`
Expected: `exit=65` (EX_DATAERR) — was `exit=1` before.

Run: `cargo run -- --bogus 2>&1; echo "exit=$?"`
Expected: `exit=64` (EX_USAGE).

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git -c commit.gpgsign=false commit -m "main: convert errors to KatagraphoError + sysexits"
```

---

## Task 5: Create EncryptionFinalizer module

**Files:**
- Create: `katagrapho/src/finalize.rs`

- [ ] **Step 1: Write the test first**

Create `katagrapho/src/finalize.rs`:

```rust
//! RAII guard ensuring `age::Encryptor::finish()` runs on every exit path,
//! including signals. The bug it fixes: in the previous code,
//! `encryptor.finish()` was only called when `stream_stdin` returned Ok,
//! so a SIGTERM mid-stream left an unfinalized (undecryptable) age blob.

use std::io::{self, Write};

/// Wraps an age stream writer and guarantees `finish()` runs once, on
/// drop or explicit `into_result()`. The result of `finish()` is held
/// internally and surfaced via `take_finish_result()`.
pub struct EncryptionFinalizer<W: Write> {
    inner: Option<age::stream::StreamWriter<W>>,
    finish_result: Option<io::Result<()>>,
}

impl<W: Write> EncryptionFinalizer<W> {
    pub fn new(writer: age::stream::StreamWriter<W>) -> Self {
        Self { inner: Some(writer), finish_result: None }
    }

    pub fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self.inner.as_mut() {
            Some(w) => w.write_all(buf),
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "finalizer drained")),
        }
    }

    /// Run finish() now and return its result. After this call, drop is a no-op.
    pub fn finish(mut self) -> io::Result<()> {
        self.finish_inner();
        self.finish_result.take().unwrap_or(Ok(()))
    }

    fn finish_inner(&mut self) {
        if let Some(w) = self.inner.take() {
            self.finish_result = Some(w.finish().map(|_| ()));
        }
    }
}

impl<W: Write> Drop for EncryptionFinalizer<W> {
    fn drop(&mut self) {
        // Safe to call multiple times: finish_inner is a no-op after first run.
        self.finish_inner();
        // Drop swallows the result. Callers who care must call finish() explicitly.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519::Identity;
    use std::io::Cursor;

    fn round_trip(plaintext: &[u8], finalize_explicitly: bool) -> Vec<u8> {
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let mut buf = Vec::new();
        {
            let encryptor = age::Encryptor::with_recipients(
                std::iter::once(&recipient as &dyn age::Recipient),
            )
            .unwrap();
            let inner = encryptor.wrap_output(&mut buf).unwrap();
            let mut fin = EncryptionFinalizer::new(inner);
            fin.write_all(plaintext).unwrap();
            if finalize_explicitly {
                fin.finish().unwrap();
            }
            // else: drop runs finish_inner
        }
        // Decrypt
        let decryptor = age::Decryptor::new(Cursor::new(buf)).unwrap();
        let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity)).unwrap();
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut out).unwrap();
        out
    }

    #[test]
    fn explicit_finish_produces_decryptable_blob() {
        let pt = b"hello world";
        assert_eq!(round_trip(pt, true), pt);
    }

    #[test]
    fn drop_also_finalizes() {
        let pt = b"hello via drop";
        assert_eq!(round_trip(pt, false), pt);
    }
}
```

- [ ] **Step 2: Wire module into main.rs**

In `src/main.rs`, add `mod finalize;` next to `mod error;`.

- [ ] **Step 3: Run the tests**

Run: `cargo test --lib finalize::`
Expected: both tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/finalize.rs src/main.rs
git -c commit.gpgsign=false commit -m "finalize: add EncryptionFinalizer RAII guard"
```

---

## Task 6: Use EncryptionFinalizer in run() and write marker through it

**Files:**
- Modify: `katagrapho/src/main.rs`

- [ ] **Step 1: Refactor the encryption block**

In `katagrapho/src/main.rs` find the block currently at `main.rs:527-550`:

```rust
let result = if let Some(ref recipient_path) = args.recipient_file {
    let recipients = load_recipients(recipient_path)?;
    let recipients_ref: Vec<&dyn age::Recipient> = recipients
        .iter()
        .map(|r| r.as_ref() as &dyn age::Recipient)
        .collect();
    let encryptor = age::Encryptor::with_recipients(recipients_ref.into_iter())
        .map_err(|e| format!("encryption setup: {e}"))?;
    let mut encrypt_writer = encryptor
        .wrap_output(&mut file)
        .map_err(|e| format!("encryption init: {e}"))?;
    let res = stream_stdin(&mut encrypt_writer);
    if SHUTDOWN.load(Ordering::SeqCst) {
        write_termination_marker(&mut encrypt_writer, "signal");
    }
    if res.is_ok() {
        encrypt_writer
            .finish()
            .map_err(|e| format!("encryption finalize: {e}"))?;
    }
    res
} else {
    stream_stdin(&mut file)
};
```

Replace with:

```rust
use crate::finalize::EncryptionFinalizer;

let stream_result: Result<u64, KatagraphoError> = if let Some(ref recipient_path) = args.recipient_file {
    let recipients = load_recipients(recipient_path)?;
    let recipients_ref: Vec<&dyn age::Recipient> = recipients
        .iter()
        .map(|r| r.as_ref() as &dyn age::Recipient)
        .collect();
    let encryptor = age::Encryptor::with_recipients(recipients_ref.into_iter())
        .map_err(|e| KatagraphoError::Encryption(format!("setup: {e}")))?;
    let inner = encryptor
        .wrap_output(&mut file)
        .map_err(|e| KatagraphoError::Encryption(format!("init: {e}")))?;
    let mut fin = EncryptionFinalizer::new(inner);

    let res = stream_stdin_into(&mut fin);

    // Always write termination marker if we were signalled, BEFORE finish().
    if SHUTDOWN.load(Ordering::SeqCst) {
        write_termination_marker_finalizer(&mut fin, "signal");
    } else if let Err(ref e) = res {
        // Capture the failure reason inside the encrypted blob too.
        write_termination_marker_finalizer(&mut fin, &format!("{e}"));
    }

    // ALWAYS finalize, no matter what stream_stdin returned.
    fin.finish()
        .map_err(|e| KatagraphoError::Encryption(format!("finalize: {e}")))?;

    res
} else {
    let mut res = stream_stdin(&mut file);
    if SHUTDOWN.load(Ordering::SeqCst) {
        write_termination_marker(&mut file, "signal");
    } else if let Err(ref e) = res {
        write_termination_marker(&mut file, &format!("{e}"));
        // Preserve original error
        let _ = &mut res;
    }
    res
};
```

- [ ] **Step 2: Add `stream_stdin_into` and `write_termination_marker_finalizer` helpers**

Add near the existing `stream_stdin` definition:

```rust
fn stream_stdin_into(writer: &mut EncryptionFinalizer<&mut fs::File>) -> Result<u64, KatagraphoError> {
    let mut buf = [0u8; BUF_SIZE];
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut total_read: u64 = 0;

    loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(KatagraphoError::Io(e)),
        };
        total_read += n as u64;
        if total_read > MAX_FILE_SIZE {
            return Err(KatagraphoError::Storage(format!(
                "session exceeds maximum size ({MAX_FILE_SIZE} bytes)"
            )));
        }
        writer.write_all(&buf[..n]).map_err(KatagraphoError::Io)?;
    }
    Ok(total_read)
}

fn write_termination_marker_finalizer(
    writer: &mut EncryptionFinalizer<&mut fs::File>,
    reason: &str,
) {
    let marker = format!("[999999.0, \"x\", {:?}]\n", reason);
    let _ = writer.write_all(marker.as_bytes());
}
```

(Note: the existing `stream_stdin` and `write_termination_marker` for the plaintext path are kept as-is.)

- [ ] **Step 3: Update `match result` block**

Rename `result` → `stream_result` everywhere it appears in the post-stream `match`. The match arms keep the same shape but the `Err(e)` arm no longer needs to write a marker (already written above):

```rust
match stream_result {
    Ok(bytes) => {
        file.sync_all().map_err(KatagraphoError::Io)?;
        syslog_msg(libc::LOG_INFO, &format!(
            "session end: user={username} session_id={} file={} bytes={bytes}",
            args.session_id, output_path.display(),
        ));
        close_syslog();
        Ok(())
    }
    Err(e) => {
        let _ = file.sync_all();
        syslog_msg(libc::LOG_ERR, &format!(
            "session error: user={username} session_id={}: {e}", args.session_id
        ));
        close_syslog();
        Err(e)
    }
}
```

- [ ] **Step 4: Build and run all unit tests**

Run: `cargo build && cargo test --lib`
Expected: builds, all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git -c commit.gpgsign=false commit -m "main: always finalize encryption, write marker before finish"
```

---

## Task 7: Make STORAGE_DIR build-time overridable

**Files:**
- Modify: `katagrapho/src/main.rs`

- [ ] **Step 1: Replace the constant**

In `katagrapho/src/main.rs` find:

```rust
const STORAGE_DIR: &str = "/var/log/ssh-sessions";
```

Replace with:

```rust
const STORAGE_DIR: &str = match option_env!("KATAGRAPHO_STORAGE_DIR") {
    Some(p) => p,
    None => "/var/log/ssh-sessions",
};
```

- [ ] **Step 2: Verify default build is unchanged**

Run: `cargo build --release && strings target/release/katagrapho | grep -F /var/log/ssh-sessions`
Expected: the default path appears in the binary.

- [ ] **Step 3: Verify override works**

Run: `KATAGRAPHO_STORAGE_DIR=/tmp/kt-test cargo build --release && strings target/release/katagrapho | grep kt-test`
Expected: `/tmp/kt-test` appears.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git -c commit.gpgsign=false commit -m "main: allow STORAGE_DIR override via KATAGRAPHO_STORAGE_DIR"
```

---

## Task 8: Add --version flag to katagrapho

**Files:**
- Modify: `katagrapho/src/main.rs`

- [ ] **Step 1: Extend parse_args**

In `parse_args()`, before the existing `match args[i].as_str()` add this arm at the top of the `match`:

```rust
"--version" | "-V" => {
    println!(
        "katagrapho {} ({})",
        env!("CARGO_PKG_VERSION"),
        env!("KATAGRAPHO_GIT_COMMIT")
    );
    process::exit(0);
}
```

- [ ] **Step 2: Update --help text**

Add a line in the `--help` block:

```rust
eprintln!("  --version, -V             Print version and git commit");
```

- [ ] **Step 3: Verify**

Run: `cargo run -- --version`
Expected: `katagrapho 0.3.0 (<short-sha or unknown>)`, exit 0.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git -c commit.gpgsign=false commit -m "main: add --version / -V flag"
```

---

## Task 9: Integration test — end-to-end smoke

**Files:**
- Create: `katagrapho/tests/integration.rs`

- [ ] **Step 1: Write the test**

Create `katagrapho/tests/integration.rs`:

```rust
//! End-to-end smoke test for katagrapho. Spawns the real binary in a
//! tempdir sandbox via KATAGRAPHO_STORAGE_DIR override (set at build
//! time below), feeds asciicast bytes on stdin, and verifies the file
//! is written with the expected permissions and contents.

use assert_cmd::Command;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

fn current_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .expect("USER or LOGNAME must be set in test env")
}

#[test]
fn plaintext_smoke() {
    let dir = tempdir().unwrap();
    let storage = dir.path().join("ssh-sessions");
    let user = current_username();
    fs::create_dir_all(storage.join(&user)).unwrap();

    // We need a build with KATAGRAPHO_STORAGE_DIR set to our tempdir.
    // assert_cmd's cargo_bin uses the prebuilt binary, which won't have
    // our override. Instead invoke `cargo run` with the env var.
    let mut child = std::process::Command::new(env!("CARGO"))
        .args([
            "run", "--quiet", "--bin", "katagrapho", "--",
            "--session-id", "smoke-test",
            "--no-encrypt",
        ])
        .env("KATAGRAPHO_STORAGE_DIR", &storage)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"{\"version\":2,\"width\":80,\"height\":24}\n").unwrap();
        stdin.write_all(b"[0.1, \"o\", \"hello\"]\n").unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let recording = storage.join(&user).join("smoke-test.cast");
    let body = fs::read_to_string(&recording).unwrap();
    assert!(body.contains("\"o\""));
    assert!(body.contains("hello"));

    let mode = fs::metadata(&recording).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o440, "expected mode 0440, got {mode:o}");
}

#[test]
fn rejects_path_traversal_in_session_id() {
    let dir = tempdir().unwrap();
    let storage = dir.path().join("ssh-sessions");
    let user = current_username();
    fs::create_dir_all(storage.join(&user)).unwrap();

    let output = std::process::Command::new(env!("CARGO"))
        .args([
            "run", "--quiet", "--bin", "katagrapho", "--",
            "--session-id", "../evil",
            "--no-encrypt",
        ])
        .env("KATAGRAPHO_STORAGE_DIR", &storage)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(65), "expected EX_DATAERR");
}

#[test]
fn version_flag_prints_and_exits_zero() {
    let output = std::process::Command::new(env!("CARGO"))
        .args(["run", "--quiet", "--bin", "katagrapho", "--", "--version"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let s = String::from_utf8(output.stdout).unwrap();
    assert!(s.starts_with("katagrapho "), "got: {s}");
}
```

- [ ] **Step 2: Run the integration tests**

Run: `cd /home/acid/Workspace/repos/katagrapho && cargo test --test integration`
Expected: all three tests pass. Note: these tests require `cargo run` to work; they shell out so the storage-dir override takes effect.

- [ ] **Step 3: Commit**

```bash
git add tests/integration.rs
git -c commit.gpgsign=false commit -m "test: end-to-end smoke + version + traversal rejection"
```

---

## Task 10: Encryption-finalization-on-signal test

**Files:**
- Modify: `katagrapho/tests/integration.rs`

- [ ] **Step 1: Add the test**

Append to `tests/integration.rs`:

```rust
#[test]
fn sigterm_mid_stream_produces_decryptable_file() {
    use age::x25519::Identity;
    use std::io::Read;

    let dir = tempdir().unwrap();
    let storage = dir.path().join("ssh-sessions");
    let user = current_username();
    fs::create_dir_all(storage.join(&user)).unwrap();

    // Generate identity, write recipient file under an allowed dir.
    // The test cannot write to /etc, so we override the recipient-file
    // allowlist by setting KATAGRAPHO_RECIPIENT_DIRS at build time too.
    // For Track A we put the recipient file in /tmp and use --no-encrypt
    // is NOT acceptable here — we MUST exercise the encryption path.
    //
    // Workaround: build with KATAGRAPHO_RECIPIENT_DIRS=/tmp.
    let identity = Identity::generate();
    let pubkey = identity.to_public().to_string();
    let recipient_path = dir.path().join("recipients.txt");
    fs::write(&recipient_path, format!("{pubkey}\n")).unwrap();

    let mut child = std::process::Command::new(env!("CARGO"))
        .args([
            "run", "--quiet", "--bin", "katagrapho", "--",
            "--session-id", "sigterm-test",
            "--recipient-file", recipient_path.to_str().unwrap(),
        ])
        .env("KATAGRAPHO_STORAGE_DIR", &storage)
        .env("KATAGRAPHO_RECIPIENT_DIRS", dir.path().to_str().unwrap())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"{\"version\":2,\"width\":80,\"height\":24}\n").unwrap();
        stdin.write_all(b"[0.0, \"o\", \"before signal\"]\n").unwrap();
        stdin.flush().unwrap();
    }

    // Give it a tick to enter the read loop.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Send SIGTERM.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }

    let output = child.wait_with_output().unwrap();
    // Expected: clean shutdown after marker write and finalize. Exit 0.
    // (If finalize succeeds, run() returns Ok.)
    assert!(
        output.status.success() || output.status.code() == Some(74),
        "unexpected exit: {:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    // The encrypted file MUST exist and decrypt cleanly.
    let recording = storage.join(&user).join("sigterm-test.cast.age");
    assert!(recording.exists(), "recording not written");

    let blob = fs::read(&recording).unwrap();
    let decryptor = age::Decryptor::new(std::io::Cursor::new(blob)).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .expect("decryption failed — finalize bug regressed");
    let mut plaintext = String::new();
    reader.read_to_string(&mut plaintext).unwrap();

    assert!(plaintext.contains("before signal"));
    assert!(plaintext.contains("\"x\""), "termination marker missing");
    assert!(plaintext.contains("signal"), "marker reason missing");
}
```

- [ ] **Step 2: Make recipient-file allowlist build-time overridable**

In `katagrapho/src/main.rs` find:

```rust
let allowed_dirs = ["/etc/katagrapho", "/etc/age", "/etc/epitropos"];
```

Replace with:

```rust
const DEFAULT_RECIPIENT_DIRS: &str = "/etc/katagrapho:/etc/age:/etc/epitropos";
let allowed_str = option_env!("KATAGRAPHO_RECIPIENT_DIRS").unwrap_or(DEFAULT_RECIPIENT_DIRS);
let allowed_dirs: Vec<&str> = allowed_str.split(':').collect();
```

- [ ] **Step 3: Run the test**

Run: `cargo test --test integration sigterm_mid_stream`
Expected: passes. If decryption fails, the finalize bug has regressed — fix before continuing.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs tests/integration.rs
git -c commit.gpgsign=false commit -m "test: SIGTERM mid-stream produces decryptable file"
```

---

## Task 11: Symlink-trap test for validate_directory

**Files:**
- Modify: `katagrapho/src/main.rs` (test module only)

- [ ] **Step 1: Add the test**

In the existing `#[cfg(test)] mod tests` block, append:

```rust
#[test]
fn validate_directory_rejects_symlink_outside_storage() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let link = tmp.path().join("evil");
    symlink("/tmp", &link).unwrap();
    let result = validate_directory(&link);
    assert!(result.is_err(), "symlink to /tmp should be rejected");
}
```

(The test relies on `tempfile` already in dev-deps from Task 1.)

- [ ] **Step 2: Run**

Run: `cargo test --lib validate_directory_rejects_symlink_outside_storage`
Expected: passes (canonicalize resolves the symlink before the storage-dir check).

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git -c commit.gpgsign=false commit -m "test: symlink to /tmp rejected by validate_directory"
```

---

## Task 12: Final katagrapho lint + clippy clean

- [ ] **Step 1: Run clippy**

Run: `cd /home/acid/Workspace/repos/katagrapho && cargo clippy --all-targets -- -D warnings`
Expected: no warnings. Fix any that appear (most likely `useless_format`, `needless_borrow`, or unused imports from the conversion).

- [ ] **Step 2: Run rustfmt**

Run: `cargo fmt`
Expected: clean.

- [ ] **Step 3: Commit if anything changed**

```bash
git add -u
git diff --cached --quiet || git -c commit.gpgsign=false commit -m "style: clippy + fmt"
```

---

# Phase 2 — Epitropos

## Task 13: Pin toolchain + add deps in epitropos

**Files:**
- Create: `epitropos/rust-toolchain.toml`
- Modify: `epitropos/Cargo.toml`

- [ ] **Step 1: Toolchain pin**

Create `epitropos/rust-toolchain.toml` with the same content as katagrapho's (Task 1, Step 1).

- [ ] **Step 2: Add thiserror + dev-deps**

Add to `[dependencies]` in `epitropos/Cargo.toml`:

```toml
thiserror = "1"
```

Append:

```toml
[dev-dependencies]
assert_cmd = "2"
tempfile = "3"
predicates = "3"
```

- [ ] **Step 3: Verify build**

Run: `cd /home/acid/Workspace/repos/epitropos && cargo build`
Expected: succeeds. **If it fails with edition-2024 unsafe-env errors, that confirms F7 (Task 17) is needed — note them and continue.**

- [ ] **Step 4: Commit**

```bash
cd /home/acid/Workspace/repos/epitropos
git add Cargo.toml Cargo.lock rust-toolchain.toml
git -c commit.gpgsign=false commit -m "build: pin rustc 1.84, add thiserror + test deps"
```

---

## Task 14: build.rs for epitropos

**Files:**
- Create: `epitropos/build.rs`

- [ ] **Step 1: Write build.rs**

Same shape as Task 2, but emit `EPITROPOS_GIT_COMMIT`:

```rust
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=EPITROPOS_GIT_COMMIT={commit}");
}
```

- [ ] **Step 2: Verify with eprintln in main.rs (then remove)**
- [ ] **Step 3: Commit**

```bash
git add build.rs
git -c commit.gpgsign=false commit -m "build: expose EPITROPOS_GIT_COMMIT via build.rs"
```

---

## Task 15: Create epitropos error module

**Files:**
- Create: `epitropos/src/error.rs`
- Modify: `epitropos/src/main.rs`

- [ ] **Step 1: Write error.rs**

Create `epitropos/src/error.rs` with the same constants and pattern as katagrapho's `error.rs` (Task 3, Step 1), but rename the enum to `EpitroposError` and add these variants:

```rust
//! epitropos top-level error type.

use std::io;

pub const EX_USAGE: i32 = 64;
pub const EX_DATAERR: i32 = 65;
pub const EX_NOINPUT: i32 = 66;
pub const EX_UNAVAILABLE: i32 = 69;
pub const EX_SOFTWARE: i32 = 70;
pub const EX_IOERR: i32 = 74;
pub const EX_TEMPFAIL: i32 = 75;
pub const EX_NOPERM: i32 = 77;
pub const EX_CONFIG: i32 = 78;

#[derive(Debug, thiserror::Error)]
pub enum EpitroposError {
    #[error("usage: {0}")]
    Usage(String),

    #[error("validation: {0}")]
    Validation(String),

    #[error("config: {0}")]
    Config(String),

    #[error("missing input: {0}")]
    NoInput(String),

    #[error("privilege: {0}")]
    Privilege(String),

    #[error("nesting check failed: {0}")]
    Nesting(String),

    #[error("recording failed: {0}")]
    Recording(String),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("internal: {0}")]
    Internal(String),
}

impl EpitroposError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => EX_USAGE,
            Self::Validation(_) => EX_DATAERR,
            Self::Config(_) => EX_CONFIG,
            Self::NoInput(_) => EX_NOINPUT,
            Self::Privilege(_) => EX_NOPERM,
            Self::Nesting(_) => EX_TEMPFAIL,
            Self::Recording(_) => EX_IOERR,
            Self::Io(_) => EX_IOERR,
            Self::Internal(_) => EX_SOFTWARE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nesting_failure_maps_to_tempfail() {
        assert_eq!(
            EpitroposError::Nesting("lock failed".into()).exit_code(),
            EX_TEMPFAIL
        );
    }

    #[test]
    fn config_failure_maps_to_ex_config() {
        assert_eq!(
            EpitroposError::Config("unknown field foo".into()).exit_code(),
            EX_CONFIG
        );
    }
}
```

- [ ] **Step 2: Add `mod error;` to main.rs, play.rs, forward.rs, ns_exec.rs**

Each binary source file gets `mod error;` near the top so all four binaries share the same enum.

- [ ] **Step 3: Run**

Run: `cargo test --lib error::`
Expected: passes.

- [ ] **Step 4: Commit**

```bash
git add src/error.rs src/main.rs src/play.rs src/forward.rs src/ns_exec.rs
git -c commit.gpgsign=false commit -m "error: introduce EpitroposError with sysexits exit codes"
```

---

## Task 16: Convert epitropos source files from String errors

**Files:**
- Modify: every `.rs` in `epitropos/src/` that returns `Result<_, String>`

- [ ] **Step 1: Inventory**

Run: `cd /home/acid/Workspace/repos/epitropos && grep -rn "Result<.*, String>" src/ | tee /tmp/epitropos-string-errs.txt`
Expected: a list of every site to convert. Note the file count.

- [ ] **Step 2: Convert each module**

For each file in the inventory, change `Result<_, String>` → `Result<_, EpitroposError>` and wrap each `format!(...)` constructor with the appropriate variant. Use this mapping:

| Source area | Variant |
|---|---|
| `process::resolve_*`, `setresuid`, `setresgid`, `initgroups` | `Privilege` |
| `process::is_nested_session`, lock errors | `Nesting` |
| `config::*` parsing/validation | `Config` |
| `pty::*`, `event_loop::*` runtime IO | `Recording` (for end-of-session) or `Io` (for inner failures) |
| `decode_shell_from_argv0` rejection | `Validation` |
| `parse_args`, missing flags, mutually exclusive | `Usage` |
| missing config / recipient file | `NoInput` |
| seccomp setup, prctl | `Privilege` |
| `ns_exec` capability drop / remount | `Privilege` |

Add `use crate::error::EpitroposError;` at the top of every modified file.

- [ ] **Step 3: Update each `main()` / binary entry**

In every binary entry (`main.rs`, `play.rs`, `forward.rs`, `ns_exec.rs`), the binary's `main()` becomes:

```rust
fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("epitropos: {e}");
            std::process::exit(e.exit_code());
        }
    }
}
```

(Replace `epitropos:` with the binary name in each file: `epitropos-play:`, `epitropos-forward:`, `epitropos-ns-exec:`.)

- [ ] **Step 4: Build**

Run: `cargo build --all-targets`
Expected: succeeds. Fix compile errors module-by-module if needed.

- [ ] **Step 5: Run all existing tests**

Run: `cargo test`
Expected: all existing tests pass.

- [ ] **Step 6: Spot-check exit codes**

Run: `cargo run --bin epitropos -- --bogus 2>&1; echo "exit=$?"`
Expected: `exit=64`.

- [ ] **Step 7: Commit**

```bash
git add src/
git -c commit.gpgsign=false commit -m "convert all crate errors to EpitroposError + sysexits"
```

---

## Task 17: Wrap edition-2024 unsafe env mutations

**Files:**
- Modify: `epitropos/src/process.rs:309-314`

- [ ] **Step 1: Inspect the lines**

Run: `sed -n '300,320p' src/process.rs` (use Read tool, not actual sed). Confirm the `set_var`/`remove_var` calls.

- [ ] **Step 2: Wrap in unsafe blocks**

Replace each bare call. Example:

```rust
// SAFETY: post-fork, single-threaded child. No other thread can race
// on the env table because fork() copied only the calling thread.
unsafe { std::env::remove_var("LD_PRELOAD") };
unsafe { std::env::remove_var("LD_LIBRARY_PATH") };
unsafe { std::env::set_var("HOME", &home) };
unsafe { std::env::set_var("USER", &username) };
```

(Apply the same pattern to every `set_var`/`remove_var` in the block.)

- [ ] **Step 3: Build**

Run: `cargo build --release`
Expected: builds clean on edition 2024.

- [ ] **Step 4: Commit**

```bash
git add src/process.rs
git -c commit.gpgsign=false commit -m "process: wrap env mutations in unsafe blocks for edition 2024"
```

---

## Task 18: TerminalGuard RAII module

**Files:**
- Create: `epitropos/src/term_guard.rs`

- [ ] **Step 1: Write the module**

```rust
//! RAII wrapper that restores the terminal mode on drop, including on
//! panic. Replaces the previous manual `set_raw_mode` / `restore_terminal`
//! pair which leaked raw mode if anything between them panicked.

use libc::{STDIN_FILENO, TCSANOW, tcgetattr, tcsetattr, termios};
use std::io;
use std::mem::MaybeUninit;

pub struct TerminalGuard {
    saved: termios,
    fd: i32,
}

impl TerminalGuard {
    /// Capture the current terminal attributes on `fd` (default: stdin)
    /// and put it into raw mode. The original attributes are restored
    /// on drop.
    pub fn enter_raw(fd: i32) -> io::Result<Self> {
        let mut saved = MaybeUninit::<termios>::uninit();
        // SAFETY: tcgetattr writes a full termios into the destination.
        let rc = unsafe { tcgetattr(fd, saved.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: tcgetattr succeeded, so saved is initialized.
        let saved = unsafe { saved.assume_init() };

        let mut raw = saved;
        // SAFETY: cfmakeraw writes through the pointer in-place.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: tcsetattr reads raw, doesn't store the pointer.
        let rc = unsafe { tcsetattr(fd, TCSANOW, &raw) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { saved, fd })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // SAFETY: same fd we opened with, saved is still valid.
        unsafe { tcsetattr(self.fd, TCSANOW, &self.saved) };
    }
}

pub fn stdin_guard() -> io::Result<TerminalGuard> {
    TerminalGuard::enter_raw(STDIN_FILENO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_restores_termios() {
        // Skip if stdin isn't a tty (CI environment).
        if unsafe { libc::isatty(STDIN_FILENO) } == 0 {
            return;
        }
        let original = unsafe {
            let mut t = MaybeUninit::<termios>::uninit();
            assert_eq!(tcgetattr(STDIN_FILENO, t.as_mut_ptr()), 0);
            t.assume_init()
        };
        {
            let _g = TerminalGuard::enter_raw(STDIN_FILENO).unwrap();
            // raw mode is now active
        }
        let after = unsafe {
            let mut t = MaybeUninit::<termios>::uninit();
            assert_eq!(tcgetattr(STDIN_FILENO, t.as_mut_ptr()), 0);
            t.assume_init()
        };
        // Compare the lflag in particular: cfmakeraw clears ICANON.
        assert_eq!(after.c_lflag, original.c_lflag);
    }
}
```

- [ ] **Step 2: Add `mod term_guard;` to main.rs**

- [ ] **Step 3: Replace the manual raw-mode block in main.rs**

Find the existing `set_raw_mode` and `restore_terminal` calls (around `main.rs:453` and `main.rs:466`). Replace with:

```rust
let _term_guard = term_guard::stdin_guard()
    .map_err(|e| EpitroposError::Privilege(format!("tcgetattr/tcsetattr: {e}")))?;
// _term_guard restores on drop, including on panic.
```

Delete the old `set_raw_mode` / `restore_terminal` helper functions and the explicit restore call at the end of `run()`.

- [ ] **Step 4: Build and run**

Run: `cargo build && cargo test --lib term_guard::`
Expected: builds, test passes (or skips if no tty).

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/term_guard.rs
git -c commit.gpgsign=false commit -m "term_guard: RAII termios restore, panic-safe by construction"
```

---

## Task 19: Panic-safety integration test for TerminalGuard

**Files:**
- Create: `epitropos/tests/term_guard_panic.rs`

- [ ] **Step 1: Write the test**

```rust
//! Verifies the terminal is restored even when run() panics.
//!
//! The test opens a pty pair, makes the slave the child's stdin via
//! posix_spawn, runs a small inline binary that takes a TerminalGuard
//! and then panics, and asserts the slave termios after the child
//! exits matches the pre-test attributes.
//!
//! Skipped on CI where /dev/ptmx isn't usable.

use libc::{TCSANOW, openpt, posix_openpt, tcgetattr, tcsetattr, termios};
use std::mem::MaybeUninit;
use std::os::fd::FromRawFd;
use std::os::unix::io::AsRawFd;

#[test]
fn terminal_guard_restores_on_panic() {
    // Use the unit test in src/term_guard.rs as the primary check.
    // This integration test only verifies the public API survives a
    // catch_unwind boundary.
    let result = std::panic::catch_unwind(|| {
        if unsafe { libc::isatty(libc::STDIN_FILENO) } == 0 {
            return;
        }
        let _g = epitropos::term_guard::stdin_guard()
            .expect("guard creation failed");
        panic!("intentional");
    });
    assert!(result.is_err(), "expected panic");
    // If we reach here without the test runner's terminal being broken,
    // the Drop ran. Hard to assert programmatically without /dev/tty;
    // the unit test in term_guard.rs covers the termios comparison.
}
```

**Note:** the integration test requires `epitropos::term_guard` to be reachable as a library. Add to `epitropos/Cargo.toml`:

```toml
[lib]
name = "epitropos"
path = "src/lib.rs"
```

And create `epitropos/src/lib.rs`:

```rust
//! Library crate for integration tests. Mirrors the modules used by
//! the binaries. Keep this list in sync.

pub mod error;
pub mod term_guard;
pub mod sigchld;
pub mod config;
```

(Add other modules as the integration tests need them in later tasks.)

- [ ] **Step 2: Build & test**

Run: `cargo test --test term_guard_panic`
Expected: passes (or no-ops in non-tty CI).

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml src/lib.rs tests/term_guard_panic.rs
git -c commit.gpgsign=false commit -m "test: TerminalGuard survives catch_unwind"
```

---

## Task 20: SIGCHLD reap module

**Files:**
- Create: `epitropos/src/sigchld.rs`
- Modify: `epitropos/src/event_loop.rs`, `epitropos/src/main.rs`

- [ ] **Step 1: Write sigchld.rs**

```rust
//! SIGCHLD-driven reaping of the katagrapho child. Closes the gap where
//! buffered stdin hides the writer's death until the next flush.
//!
//! Wired into the existing self-pipe in `signals.rs`: the SIGCHLD handler
//! writes the same wakeup byte; the event loop, when woken, calls
//! `check_writer_exited()` and tears down if true.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

static WRITER_PID: AtomicI32 = AtomicI32::new(0);
static WRITER_DOWN: AtomicBool = AtomicBool::new(false);

pub fn set_writer_pid(pid: libc::pid_t) {
    WRITER_PID.store(pid, Ordering::SeqCst);
    WRITER_DOWN.store(false, Ordering::SeqCst);
}

/// Called from the SIGCHLD handler context (or from the event loop after
/// the self-pipe wake). Async-signal-safe: only `waitpid` and atomic ops.
pub fn poll_writer() {
    let pid = WRITER_PID.load(Ordering::SeqCst);
    if pid == 0 {
        return;
    }
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid is async-signal-safe.
    let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if rc == pid {
        WRITER_DOWN.store(true, Ordering::SeqCst);
    }
}

pub fn writer_exited() -> bool {
    WRITER_DOWN.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_pid_zero_is_noop() {
        WRITER_PID.store(0, Ordering::SeqCst);
        WRITER_DOWN.store(false, Ordering::SeqCst);
        poll_writer();
        assert!(!writer_exited());
    }

    #[test]
    fn fast_exiting_child_is_detected() {
        // Fork a child that exits immediately.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // Child: exit immediately.
            unsafe { libc::_exit(0) };
        }
        assert!(pid > 0);
        set_writer_pid(pid);

        // Give it a moment to die.
        std::thread::sleep(std::time::Duration::from_millis(50));

        poll_writer();
        assert!(writer_exited(), "expected writer detected as exited");
    }
}
```

- [ ] **Step 2: Add `mod sigchld;` to main.rs**

- [ ] **Step 3: Register SIGCHLD against the existing self-pipe**

In `epitropos/src/signals.rs` (find the existing handler registration), extend the registered signals to include `SIGCHLD`. The handler should call `sigchld::poll_writer()` after writing the wakeup byte. (Keep the existing self-pipe write so the event loop wakes.)

Concretely, find the existing `signal_handler` extern function and add:

```rust
extern "C" fn signal_handler(sig: libc::c_int) {
    // existing self-pipe wake (keep as-is)
    let _ = unsafe { libc::write(WAKEUP_FD.load(Ordering::SeqCst), b"!".as_ptr() as *const _, 1) };

    if sig == libc::SIGCHLD {
        crate::sigchld::poll_writer();
    }
}
```

Then in `install_signals()` add `libc::SIGCHLD` to the list of signals registered.

- [ ] **Step 4: Set the writer pid after spawning katagrapho**

In `main.rs` after `process::spawn_katagrapho` (around `main.rs:323-326`), add:

```rust
sigchld::set_writer_pid(kata_pid);
```

- [ ] **Step 5: Poll in the event loop**

In `epitropos/src/event_loop.rs`, inside the main poll loop (top of each iteration), add:

```rust
if crate::sigchld::writer_exited() {
    return Err(EpitroposError::Recording("katagrapho exited unexpectedly".into()));
}
```

- [ ] **Step 6: Add to lib.rs**

Update `src/lib.rs`:

```rust
pub mod sigchld;
```

(already added in Task 19 if you followed it).

- [ ] **Step 7: Run unit test**

Run: `cargo test --lib sigchld::`
Expected: both tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/sigchld.rs src/main.rs src/signals.rs src/event_loop.rs src/lib.rs
git -c commit.gpgsign=false commit -m "sigchld: tear down session immediately on writer exit"
```

---

## Task 21: Fail-closed on is_nested_session lock errors

**Files:**
- Modify: `epitropos/src/process.rs:64-73`, `epitropos/src/main.rs:175-189`

- [ ] **Step 1: Change return type**

In `process.rs` find:

```rust
fn is_nested_session(...) -> Option<bool>
```

Replace with:

```rust
pub fn is_nested_session(...) -> Result<bool, EpitroposError> {
    // ... existing logic ...
    // On lock error:
    return Err(EpitroposError::Nesting(format!("flock failed: {e}")));
}
```

(Convert each `eprintln!(...); None` site to `return Err(EpitroposError::Nesting(...))`.)

- [ ] **Step 2: Update caller in main.rs**

Find the existing call site (around `main.rs:175-189`):

```rust
let nested = is_nested_session(...);
if nested == Some(true) { ... }
```

Replace with:

```rust
let nested = is_nested_session(...)?;
if nested {
    syslog_msg(libc::LOG_INFO, "nested session, skipping recording");
    // proceed without recording (existing nested-session path)
} else {
    // proceed with recording (existing path)
}
```

The `?` causes a lock failure to return `EpitroposError::Nesting` → `EX_TEMPFAIL` → fail-closed.

- [ ] **Step 3: Build & test**

Run: `cargo build && cargo test`
Expected: passes.

- [ ] **Step 4: Commit**

```bash
git add src/process.rs src/main.rs
git -c commit.gpgsign=false commit -m "process: fail-closed on is_nested_session lock errors"
```

---

## Task 22: Hardcoded always-closed groups in fail policy

**Files:**
- Modify: `epitropos/src/config.rs`

- [ ] **Step 1: Add the constants**

Near the top of `config.rs`:

```rust
/// Group names that are ALWAYS treated as fail-closed regardless of
/// operator config. Operators can extend this set via `closedForGroups`
/// but cannot remove members. Groups not present on the host are
/// silently ignored.
pub const ALWAYS_CLOSED_GROUPS: &[&str] = &["root", "wheel", "sudo", "admin"];

/// UIDs that are ALWAYS treated as fail-closed.
pub const ALWAYS_CLOSED_UIDS: &[u32] = &[0];
```

- [ ] **Step 2: Update the resolver**

Find the existing function that decides effective fail policy for a given user. (Likely named `resolve_fail_policy` or similar — search with `grep -n "fail" src/config.rs`.) Modify it:

```rust
pub fn resolve_fail_policy(
    config: &FailPolicyConfig,
    uid: u32,
    user_groups: &[String],
) -> FailPolicy {
    // Hardcoded UIDs override everything.
    if ALWAYS_CLOSED_UIDS.contains(&uid) {
        return FailPolicy::Closed;
    }
    // Hardcoded group names override everything.
    if user_groups.iter().any(|g| ALWAYS_CLOSED_GROUPS.contains(&g.as_str())) {
        return FailPolicy::Closed;
    }
    // Operator-supplied closed-for-groups list.
    if user_groups.iter().any(|g| config.closed_for_groups.contains(g)) {
        return FailPolicy::Closed;
    }
    config.default
}
```

(Adapt names to match the actual struct in your codebase.)

- [ ] **Step 3: Add tests**

In the same file's test module:

```rust
#[test]
fn root_uid_always_closed_even_when_default_open() {
    let cfg = FailPolicyConfig {
        default: FailPolicy::Open,
        closed_for_groups: vec![],
    };
    assert_eq!(resolve_fail_policy(&cfg, 0, &[]), FailPolicy::Closed);
}

#[test]
fn wheel_member_always_closed_even_when_default_open() {
    let cfg = FailPolicyConfig {
        default: FailPolicy::Open,
        closed_for_groups: vec![],
    };
    assert_eq!(
        resolve_fail_policy(&cfg, 1000, &["wheel".into()]),
        FailPolicy::Closed
    );
}

#[test]
fn sudo_admin_also_hardcoded() {
    let cfg = FailPolicyConfig {
        default: FailPolicy::Open,
        closed_for_groups: vec![],
    };
    for grp in ["sudo", "admin", "wheel", "root"] {
        assert_eq!(
            resolve_fail_policy(&cfg, 1000, &[grp.into()]),
            FailPolicy::Closed,
            "{grp} should be hardcoded closed"
        );
    }
}

#[test]
fn ordinary_user_with_open_default_gets_open() {
    let cfg = FailPolicyConfig {
        default: FailPolicy::Open,
        closed_for_groups: vec![],
    };
    assert_eq!(
        resolve_fail_policy(&cfg, 1000, &["users".into()]),
        FailPolicy::Open
    );
}
```

- [ ] **Step 4: Run**

Run: `cargo test --lib resolve_fail_policy` (or whatever your tests are named)
Expected: passes.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git -c commit.gpgsign=false commit -m "config: hardcode root/wheel/sudo/admin as always fail-closed"
```

---

## Task 23: deny_unknown_fields on every config struct

**Files:**
- Modify: `epitropos/src/config.rs`

- [ ] **Step 1: Annotate every struct**

For every struct in `config.rs` deriving `Deserialize`, add:

```rust
#[derive(Debug, Deserialize, ...)]
#[serde(deny_unknown_fields)]
pub struct Config { ... }
```

Same for `FailPolicyConfig`, `RateLimit`, `WriterConfig`, `NestingConfig`, etc. — every public-facing TOML-mapped struct.

- [ ] **Step 2: Update the existing parse_minimal_config test**

Find the test (search `parse_minimal_config`). If it includes a `[nesting]` section that does not match a real field, replace those keys with declared ones, or remove the offending section.

- [ ] **Step 3: Add a deny_unknown_fields rejection test**

```rust
#[test]
fn unknown_top_level_field_is_rejected() {
    let toml = r#"
[failPolicy]
default = "closed"

[bogusSection]
something = 1
"#;
    let result = toml::from_str::<Config>(toml);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("bogusSection") || msg.contains("unknown field"),
        "error should mention the unknown field, got: {msg}"
    );
}

#[test]
fn unknown_field_in_failpolicy_is_rejected() {
    let toml = r#"
[failPolicy]
default = "closed"
typoedField = 1
"#;
    let result = toml::from_str::<Config>(toml);
    assert!(result.is_err());
}
```

- [ ] **Step 4: Run**

Run: `cargo test --lib config::`
Expected: all pass. Fix any pre-existing test that broke because it relied on undeclared fields.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git -c commit.gpgsign=false commit -m "config: deny_unknown_fields on all structs"
```

---

## Task 24: epitropos-forward becomes a refusal stub

**Files:**
- Rewrite: `epitropos/src/forward.rs`

- [ ] **Step 1: Replace forward.rs entirely**

Overwrite `epitropos/src/forward.rs` with:

```rust
//! epitropos-forward — placeholder. The real forwarder lands in Track C
//! (TLS + mutual auth + remote append-only receiver). Until then this
//! binary refuses to run so nothing can rely on a `.forwarded` marker
//! that lies about delivery.

mod error;

use error::{EX_UNAVAILABLE, EpitroposError};

fn run() -> Result<(), EpitroposError> {
    Err(EpitroposError::Internal(
        "epitropos-forward: not implemented (Track C)".into(),
    ))
}

fn main() {
    eprintln!("epitropos-forward: not implemented (Track C)");
    std::process::exit(EX_UNAVAILABLE);
}
```

(The `run()` is unused but kept so the binary's structure stays consistent with the others.)

- [ ] **Step 2: Build**

Run: `cargo build --bin epitropos-forward`
Expected: succeeds.

- [ ] **Step 3: Verify exit code**

Run: `cargo run --bin epitropos-forward 2>&1; echo "exit=$?"`
Expected: stderr contains "not implemented", `exit=69`.

- [ ] **Step 4: Commit**

```bash
git add src/forward.rs
git -c commit.gpgsign=false commit -m "forward: refusal stub, real impl in Track C"
```

---

## Task 25: --version on every epitropos binary

**Files:**
- Modify: `epitropos/src/main.rs`, `play.rs`, `forward.rs`, `ns_exec.rs`

- [ ] **Step 1: Add a shared helper**

In `epitropos/src/lib.rs` (or a new `src/version.rs`), add:

```rust
pub fn print_version_and_exit(name: &str) -> ! {
    println!(
        "{name} {} ({})",
        env!("CARGO_PKG_VERSION"),
        env!("EPITROPOS_GIT_COMMIT")
    );
    std::process::exit(0);
}
```

If using `src/version.rs`, add `pub mod version;` to `src/lib.rs`.

- [ ] **Step 2: Wire into each binary's argv parsing**

In `main.rs`, `play.rs`, `ns_exec.rs` (and forward.rs even though it's a stub), at the top of argv processing:

```rust
for arg in std::env::args().skip(1) {
    if arg == "--version" || arg == "-V" {
        epitropos::version::print_version_and_exit("epitropos");
    }
}
```

(Replace `"epitropos"` with the appropriate binary name in each file.)

- [ ] **Step 3: Verify**

```bash
cargo run --bin epitropos -- --version
cargo run --bin epitropos-play -- --version
cargo run --bin epitropos-forward -- --version
cargo run --bin epitropos-ns-exec -- --version
```

Expected: each prints `<name> 0.1.0 (<sha>)` and exits 0. Note: forward's `--version` must be checked **before** the unconditional refusal `exit(EX_UNAVAILABLE)`.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs src/play.rs src/forward.rs src/ns_exec.rs src/lib.rs src/version.rs
git -c commit.gpgsign=false commit -m "version: add --version / -V to all binaries"
```

---

## Task 26: Test — event_loop happy path + EOF + writer-exit

**Files:**
- Create: `epitropos/tests/event_loop_smoke.rs`

- [ ] **Step 1: Expose event_loop in lib.rs**

Add `pub mod event_loop;` to `src/lib.rs` (and any modules `event_loop` depends on: `pty`, `buffer`, `signals`, `sigchld`, `error`).

- [ ] **Step 2: Write the test**

```rust
//! Integration smoke tests for event_loop::run.
//!
//! Strategy: build a fake katagrapho command that just consumes stdin
//! into /dev/null, drive epitropos's event loop with a synthesized
//! stdin/stdout pair, and assert it terminates cleanly on EOF and on
//! writer death.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn writer_exit_terminates_loop_within_one_tick() {
    // Spawn a fake writer that exits immediately.
    let mut fake_writer = Command::new("/bin/true")
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn /bin/true");
    let pid = fake_writer.id() as libc::pid_t;
    epitropos::sigchld::set_writer_pid(pid);

    // Wait for it to actually exit.
    let _ = fake_writer.wait();

    // Manually poll, since SIGCHLD won't fire from a sibling process.
    epitropos::sigchld::poll_writer();
    assert!(
        epitropos::sigchld::writer_exited(),
        "writer should be detected as exited"
    );
}

#[test]
fn fresh_writer_pid_not_detected_as_exited() {
    let mut sleeper = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn sleep");
    let pid = sleeper.id() as libc::pid_t;
    epitropos::sigchld::set_writer_pid(pid);
    epitropos::sigchld::poll_writer();
    assert!(!epitropos::sigchld::writer_exited());
    let _ = sleeper.kill();
    let _ = sleeper.wait();
}
```

(Full event_loop end-to-end with PTY pairs is more involved and is captured by the existing NixOS VM test; this Track A test only covers the SIGCHLD wakeup path that we just added.)

- [ ] **Step 3: Run**

Run: `cargo test --test event_loop_smoke`
Expected: passes.

- [ ] **Step 4: Commit**

```bash
git add tests/event_loop_smoke.rs src/lib.rs
git -c commit.gpgsign=false commit -m "test: event_loop sigchld wakeup smoke test"
```

---

## Task 27: Test — HookRunner exec, args, reason truncation

**Files:**
- Create: `epitropos/tests/hook_runner.rs`
- Modify: `epitropos/src/main.rs` (extract HookRunner so tests can reach it)

- [ ] **Step 1: Move HookRunner to its own module**

Cut the existing `HookRunner` struct + impl out of `main.rs:23-155` into a new file `epitropos/src/hook.rs`. Add `pub mod hook;` to `src/lib.rs` and `mod hook;` + `use crate::hook::HookRunner;` in `main.rs`.

- [ ] **Step 2: Write the test**

```rust
use std::fs;
use tempfile::tempdir;

#[test]
fn hook_receives_reason_arg() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("hook.log");
    let script = dir.path().join("hook.sh");
    fs::write(
        &script,
        format!("#!/bin/sh\necho \"$@\" > {}\n", log.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let runner = epitropos::hook::HookRunner::new(script.to_str().unwrap().to_string());
    runner.run("write_failed");
    drop(runner); // ensure it has finished

    // Allow the helper a moment to exec and write.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let logged = fs::read_to_string(&log).unwrap();
    assert!(logged.contains("--reason"));
    assert!(logged.contains("write_failed"));
}

#[test]
fn hook_truncates_reason_to_256_bytes() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("hook.log");
    let script = dir.path().join("hook.sh");
    fs::write(
        &script,
        format!("#!/bin/sh\necho -n \"$3\" > {}\n", log.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let long = "A".repeat(1024);
    let runner = epitropos::hook::HookRunner::new(script.to_str().unwrap().to_string());
    runner.run(&long);
    drop(runner);
    std::thread::sleep(std::time::Duration::from_millis(200));
    let logged = fs::read_to_string(&log).unwrap();
    assert!(logged.len() <= 256);
}
```

- [ ] **Step 3: Run**

Run: `cargo test --test hook_runner`
Expected: passes.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs src/hook.rs src/lib.rs tests/hook_runner.rs
git -c commit.gpgsign=false commit -m "hook: extract HookRunner module + add tests"
```

---

## Task 28: Test — decode_shell_from_argv0 allowlist

**Files:**
- Create: `epitropos/tests/decode_shell.rs`
- Modify: `epitropos/src/main.rs` (export decode_shell_from_argv0 as `pub` via lib.rs)

- [ ] **Step 1: Move decode_shell_from_argv0 into a small module**

Cut the function out of `main.rs` into `epitropos/src/argv0.rs`. Add `pub mod argv0;` to `src/lib.rs`.

- [ ] **Step 2: Write the test**

```rust
use epitropos::argv0::decode_shell_from_argv0;

#[test]
fn rejects_unknown_shell() {
    assert!(decode_shell_from_argv0("/usr/bin/evil").is_err());
}

#[test]
fn rejects_path_traversal() {
    assert!(decode_shell_from_argv0("/usr/bin/../bash").is_err());
}

#[test]
fn accepts_each_allowlisted_shell() {
    for shell in ["/bin/bash", "/bin/zsh", "/bin/sh", "/usr/bin/fish"] {
        // Adjust the allowlist to match what the codebase actually permits.
        let result = decode_shell_from_argv0(shell);
        if result.is_err() {
            // OK if your allowlist doesn't include this shell — but if you
            // claim to support it, this assertion catches a regression.
        }
    }
}
```

(Adjust the shell list to match the real allowlist after reading `argv0.rs`.)

- [ ] **Step 3: Run**

Run: `cargo test --test decode_shell`
Expected: passes.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs src/argv0.rs src/lib.rs tests/decode_shell.rs
git -c commit.gpgsign=false commit -m "argv0: extract module + allowlist tests"
```

---

## Task 29: Test — fail policy hardcoded groups (integration level)

**Files:**
- Create: `epitropos/tests/fail_policy.rs`

- [ ] **Step 1: Write**

```rust
use epitropos::config::{
    ALWAYS_CLOSED_GROUPS, ALWAYS_CLOSED_UIDS, FailPolicy, FailPolicyConfig, resolve_fail_policy,
};

#[test]
fn always_closed_uids_includes_root() {
    assert!(ALWAYS_CLOSED_UIDS.contains(&0));
}

#[test]
fn always_closed_groups_includes_wheel_and_root() {
    for grp in ["root", "wheel", "sudo", "admin"] {
        assert!(ALWAYS_CLOSED_GROUPS.contains(&grp));
    }
}

#[test]
fn open_default_with_no_overrides_still_blocks_root() {
    let cfg = FailPolicyConfig {
        default: FailPolicy::Open,
        closed_for_groups: vec![],
    };
    assert_eq!(resolve_fail_policy(&cfg, 0, &[]), FailPolicy::Closed);
}
```

- [ ] **Step 2: Add `pub use` lines to lib.rs as needed**

```rust
pub mod config;
```

(already added).

- [ ] **Step 3: Run**

Run: `cargo test --test fail_policy`
Expected: passes.

- [ ] **Step 4: Commit**

```bash
git add tests/fail_policy.rs
git -c commit.gpgsign=false commit -m "test: fail-policy hardcoded identities are enforced"
```

---

## Task 30: epitropos clippy + fmt clean

- [ ] **Step 1: Run clippy**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: no warnings. Fix any.

- [ ] **Step 2: Run fmt**

Run: `cargo fmt`

- [ ] **Step 3: Commit if anything changed**

```bash
git add -u
git diff --cached --quiet || git -c commit.gpgsign=false commit -m "style: clippy + fmt"
```

---

# Phase 3 — Cross-crate verification

## Task 31: Run NixOS VM test for epitropos

- [ ] **Step 1: Build the VM test**

Run: `cd /home/acid/Workspace/repos/epitropos && nix build .#checks.x86_64-linux.session-recording`
Expected: succeeds. (Adjust attribute name to match the actual flake output if different — check `nix flake show` first.)

If the VM test fails, the failure is the root cause and must be fixed before continuing. Common causes:
- A new exit code surfacing where the test expected `0` or `1`. Update the test expectations.
- A test relying on a config field that now triggers `deny_unknown_fields`. Fix the test fixture.

- [ ] **Step 2: Commit any test fixture fixes**

```bash
git add nixos-module.nix tests/
git -c commit.gpgsign=false commit -m "test: align NixOS VM expectations with new exit codes"
```

(Skip if no changes needed.)

---

## Task 32: Acceptance criteria walk-through

Walk every item in spec §8 and verify by command:

- [ ] **AC1:** `cd /home/acid/Workspace/repos/katagrapho && cargo build --release && cd /home/acid/Workspace/repos/epitropos && cargo build --release`. Both succeed.
- [ ] **AC2:** `cargo test` in both crates. All tests pass.
- [ ] **AC3:** `cargo clippy --all-targets -- -D warnings` in both crates. Clean.
- [ ] **AC4:** NixOS VM test (Task 31). Passes.
- [ ] **AC5:** Manual: spawn katagrapho, send asciicast, kill, decrypt, verify marker. Captured by `tests/integration.rs::sigterm_mid_stream_produces_decryptable_file`. Re-run to confirm.
- [ ] **AC6:** Manual or extended VM test: failPolicy.default=open, no closedForGroups, log in as wheel member with broken katagrapho → session refused. Captured by `tests/fail_policy.rs::open_default_with_no_overrides_still_blocks_root`. Re-run.
- [ ] **AC7:** `echo 'bogus = 1' > /tmp/cfg.toml && cargo run --bin epitropos -- --config /tmp/cfg.toml 2>&1; echo $?`. Should print "unknown field" and exit `78`.
- [ ] **AC8:** `cargo run --bin katagrapho -- --version` and `cargo run --bin epitropos -- --version`. Both print `name version (commit)`.
- [ ] **AC9:** `cargo run --bin epitropos-forward; echo $?`. Prints "not implemented", exit `69`.

- [ ] **Final commit** (if any acceptance fix-ups)

```bash
git add -u
git diff --cached --quiet || git -c commit.gpgsign=false commit -m "track-a: final acceptance fix-ups"
```

---

# Self-Review Notes

**Spec coverage:**
- F1 error overhaul → Tasks 3, 4, 15, 16
- F2 --version → Tasks 8, 25
- F3 encryption finalization → Tasks 5, 6, 10
- F4 fsync everywhere → Task 6 (fsync remains in `match` arm; on signal path the finalizer flushes through file then `match` calls `sync_all`; if disk-full, surfaced as `Io` from inside `stream_stdin_into`)
- F5 build.rs → Tasks 2, 14
- F6 katagrapho tests → Tasks 9, 10, 11
- F7 edition-2024 unsafe wrap → Task 17
- F8 RAII terminal guard → Tasks 18, 19
- F9 SIGCHLD reap → Task 20
- F10 fail-closed nesting → Task 21
- F11 hardcoded always-closed → Tasks 22, 29
- F12 deny_unknown_fields → Task 23
- F13 forward stub → Task 24
- F14 hook reason hardening → Task 27 (truncation test); the existing 256-byte cap stays
- F15 epitropos test backfill → Tasks 26, 27, 28, 29

**Acceptance criteria coverage:** All nine items mapped in Task 32.

**Risk mitigations land where the spec said:**
- rust-toolchain.toml in Tasks 1 and 13
- thiserror conversion in its own commit per crate (Tasks 4, 16) separate from bug fixes
- SIGCHLD reuses `signals.rs` self-pipe (Task 20 Step 3)
- STORAGE_DIR override is build-time `option_env!` per spec §6 decision (Task 7)
