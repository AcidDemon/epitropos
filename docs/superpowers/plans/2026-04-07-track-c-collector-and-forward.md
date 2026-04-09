# Track C — Collector + Forward — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** `epitropos/docs/superpowers/specs/2026-04-07-track-c-collector-and-forward.md`

**Goal:** Replace the `epitropos-forward` refusal stub with a real HTTP/mTLS shipper, introduce a new `epitropos-collector` workspace member that accepts and verifies signed recordings, and add a `katagrapho-readers` group that decouples shipping daemons from the legacy `ssh-sessions` handle.

**Architecture:** Convert `epitropos/` into a cargo workspace with `proxy/` (existing setuid code, unchanged deps) and `collector/` (new, axum+tokio+rustls). Enrollment is a single-use HMAC'd token plus out-of-band TLS fingerprint pin — no CA. Push is one streaming POST per part, with strict chain-gap rejection and SHA-256 content verification.

**Tech Stack:** Rust edition 2024, `axum` + `tokio` + `tokio-rustls` + `rcgen` (collector only), `ureq` + `rustls` + `rcgen` (forward only), `ed25519-dalek` (shared for signature verification). Proxy crate's setuid runtime dependency tree is unchanged.

**Repos touched:**
- `/home/acid/Workspace/repos/epitropos/` — workspace restructure + new collector member + forward rewrite
- `/home/acid/Workspace/repos/katagrapho/` — group + ownership changes only

**Predecessors:** Track A + Track B merged to `main` on both repos.

**Phase order:**
1. Phase 1 — Workspace restructure (scaffolding; no logic changes)
2. Phase 2 — katagrapho `katagrapho-readers` group + ownership
3. Phase 3 — Collector pure-logic modules (error, config, chain, storage, verify, enroll)
4. Phase 4 — Collector TLS + HTTP server
5. Phase 5 — Collector CLI subcommands
6. Phase 6 — NixOS collector module
7. Phase 7 — Forward rewrite (enroll + push + status)
8. Phase 8 — Forward NixOS submodule
9. Phase 9 — Two-node VM test + acceptance

**Commit hygiene:** `git -c commit.gpgsign=false commit`, no Co-Authored-By, one task = one commit unless noted.

Because the plan is long, individual phases will be committed via this plan's execution then re-written as a single file on disk. The executing agent should treat phases 1–9 as strict ordering — each phase produces a green build that can be merged to `main` if the plan is paused.

---

## File structure (target)

```
epitropos/
├── Cargo.toml                     # NEW workspace root
├── flake.nix                      # MODIFY: two package outputs
├── proxy/                         # RENAMED from src/ (all proxy files move here)
│   ├── Cargo.toml                 # MOVED, name stays "epitropos"
│   ├── build.rs                   # MOVED
│   ├── rust-toolchain.toml        # MOVED
│   ├── src/
│   └── tests/
├── collector/                     # NEW workspace member
│   ├── Cargo.toml                 # CREATE
│   ├── build.rs                   # CREATE
│   ├── src/
│   │   ├── main.rs                # CREATE
│   │   ├── lib.rs                 # CREATE
│   │   ├── error.rs               # CREATE
│   │   ├── config.rs              # CREATE
│   │   ├── storage.rs             # CREATE
│   │   ├── chain.rs               # CREATE
│   │   ├── verify.rs              # CREATE
│   │   ├── enroll.rs              # CREATE
│   │   ├── tls.rs                 # CREATE
│   │   ├── server.rs              # CREATE
│   │   └── cli.rs                 # CREATE
│   └── tests/
│       └── e2e.rs                 # CREATE
├── nixos-module.nix               # MODIFY: add services.epitropos.forward.*
├── nixos-module-collector.nix     # CREATE
└── tests/
    ├── vm-proxy.nix               # RENAMED from vm-test.nix
    └── vm-collector.nix           # CREATE

katagrapho/
├── nixos-module.nix               # MODIFY: add katagrapho-readers group + chown
```

---

# Phase 1 — Workspace restructure

## Task 1: Create `track-c` worktrees

**Files:**
- Create: `epitropos/.worktrees/track-c`
- Create: `katagrapho/.worktrees/track-c`

- [ ] **Step 1: Worktrees + baseline**

```bash
cd /home/acid/Workspace/repos/epitropos
git worktree add .worktrees/track-c -b track-c main
cd .worktrees/track-c && cargo test --quiet 2>&1 | tail -5

cd /home/acid/Workspace/repos/katagrapho
git worktree add .worktrees/track-c -b track-c main
cd .worktrees/track-c && cargo test --quiet 2>&1 | tail -5
```

Expected: both baselines green (40+7 epitropos, 41+7 katagrapho).

## Task 2: Move proxy files into `proxy/` subdir

**Files:**
- Move: every file under `epitropos/.worktrees/track-c/` top-level into `proxy/` except `docs/`, `flake.nix`, `flake.lock`, `nixos-module.nix`, `LICENSE`, `README.md`, and the `tests/*.nix` files.

- [ ] **Step 1: Inventory current top-level**

```bash
cd /home/acid/Workspace/repos/epitropos/.worktrees/track-c
ls -A
```

Expected inventory: `Cargo.toml`, `Cargo.lock`, `build.rs`, `rust-toolchain.toml`, `src/`, `tests/` (rust tests), `nixos-module.nix`, `flake.nix`, `flake.lock`, `docs/`, `LICENSE`, `README.md`, `.gitignore`.

- [ ] **Step 2: Create `proxy/` and `git mv` the crate files**

```bash
mkdir -p proxy
git mv Cargo.toml proxy/Cargo.toml
git mv build.rs proxy/build.rs
git mv rust-toolchain.toml proxy/rust-toolchain.toml
git mv src proxy/src
```

If there was a top-level `tests/` that contained Rust integration tests (not the `.nix` VM test), move it too:

```bash
test -d tests && {
  mkdir -p proxy/tests
  for f in tests/*.rs; do [ -f "$f" ] && git mv "$f" proxy/tests/; done
}
```

(Leave `.nix` test files at the repo top-level.)

Move `Cargo.lock` under `proxy/` temporarily — the workspace root will get its own:

```bash
git mv Cargo.lock proxy/Cargo.lock 2>/dev/null || true
```

- [ ] **Step 3: Create workspace root `Cargo.toml`**

Create `epitropos/.worktrees/track-c/Cargo.toml`:

```toml
[workspace]
members = ["proxy", "collector"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"
```

- [ ] **Step 4: Create minimal `collector/Cargo.toml` so the workspace resolves**

Create `epitropos/.worktrees/track-c/collector/Cargo.toml`:

```toml
[package]
name = "epitropos-collector"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "Off-host collector for epitropos session recordings"

[dependencies]
```

Create `epitropos/.worktrees/track-c/collector/src/main.rs`:

```rust
fn main() {
    eprintln!("epitropos-collector: not yet implemented");
    std::process::exit(69);
}
```

- [ ] **Step 5: Edit `proxy/Cargo.toml` to inherit workspace version**

At the top of `proxy/Cargo.toml` replace:

```toml
version = "0.1.0"
edition = "2024"
license = "MIT"
```

with:

```toml
version.workspace = true
edition.workspace = true
license.workspace = true
```

- [ ] **Step 6: Build the workspace**

From the worktree root:

```bash
cd /home/acid/Workspace/repos/epitropos/.worktrees/track-c
rm -f proxy/Cargo.lock
cargo build --workspace 2>&1 | tail -10
```

Expected: both members build. A single `Cargo.lock` lands at the workspace root.

- [ ] **Step 7: Run proxy tests to confirm no regression**

```bash
cargo test -p epitropos 2>&1 | grep "test result" | tail -5
```

Expected: all existing proxy tests pass.

- [ ] **Step 8: Commit**

```bash
git add -A
git -c commit.gpgsign=false commit -m "workspace: move proxy into proxy/ subdir, add collector skeleton"
```

## Task 3: Update flake to expose two package outputs

**Files:**
- Modify: `epitropos/.worktrees/track-c/flake.nix`

- [ ] **Step 1: Inspect existing flake**

```bash
grep -n "packages\|buildRustPackage\|naersk\|crane" flake.nix | head
```

- [ ] **Step 2: Replace the single package output with two**

The exact edit depends on the build framework (naersk/crane/buildRustPackage). The plan is: wherever the existing flake defines `packages.${system}.epitropos`, keep that entry but make it build the `proxy` member (e.g., `cargoExtraArgs = "-p epitropos"` or equivalent), and add a new entry `packages.${system}.epitropos-collector` that builds the `collector` member (`-p epitropos-collector`).

If the flake currently does `cargoBuildFlags = [ ]`, change it to `cargoBuildFlags = [ "-p" "epitropos" ]` for the existing package and add:

```nix
epitropos-collector = pkgs.rustPlatform.buildRustPackage {
  pname = "epitropos-collector";
  version = (lib.importTOML ./Cargo.toml).workspace.package.version;
  src = ./.;
  cargoLock.lockFile = ./Cargo.lock;
  cargoBuildFlags = [ "-p" "epitropos-collector" ];
};
```

Adapt to the existing framework.

- [ ] **Step 3: Verify the flake builds**

```bash
nix build .#epitropos 2>&1 | tail -5
nix build .#epitropos-collector 2>&1 | tail -5
```

Expected: both succeed. If `nix build` isn't reachable in the dev environment, skip this verification and note it for the VM test later.

- [ ] **Step 4: Commit**

```bash
git add flake.nix
git -c commit.gpgsign=false commit -m "flake: expose proxy and collector as separate packages"
```

## Task 4: Rename VM test file

**Files:**
- Move: `epitropos/.worktrees/track-c/tests/vm-test.nix` → `tests/vm-proxy.nix`

- [ ] **Step 1: Rename + update flake references**

```bash
git mv tests/vm-test.nix tests/vm-proxy.nix
grep -rn "vm-test.nix" flake.nix nixos-module.nix || true
```

Update any `flake.nix` reference to `./tests/vm-test.nix` to `./tests/vm-proxy.nix`.

- [ ] **Step 2: Commit**

```bash
git add -A
git -c commit.gpgsign=false commit -m "test: rename vm-test.nix to vm-proxy.nix"
```

---

# Phase 2 — katagrapho `katagrapho-readers` group

## Task 5: Add the group and chown rules to katagrapho NixOS module

**Files:**
- Modify: `katagrapho/.worktrees/track-c/nixos-module.nix`

- [ ] **Step 1: Read the current module**

```bash
cd /home/acid/Workspace/repos/katagrapho/.worktrees/track-c
grep -n "users.groups\|tmpfiles.rules\|storageDir" nixos-module.nix
```

- [ ] **Step 2: Add the new group**

Near the existing `users.groups.${cfg.group}` block, add:

```nix
users.groups.katagrapho-readers = {};
```

- [ ] **Step 3: Add tmpfiles z-rules to fix ownership on existing state**

In the `systemd.tmpfiles.rules` list, append:

```nix
# Ensure katagrapho state is group-readable by katagrapho-readers.
"z /var/lib/katagrapho/head.hash.log 0640 ${cfg.user} katagrapho-readers -"
"z /var/lib/katagrapho/signing.pub  0640 ${cfg.user} katagrapho-readers -"
"z ${cfg.storageDir}                 2750 ${cfg.user} katagrapho-readers -"
```

The `z` type chowns + chmods on every boot (idempotent). Recording files created at runtime inherit the group via the setgid bit on the parent dir.

- [ ] **Step 4: Commit**

```bash
git add nixos-module.nix
git -c commit.gpgsign=false commit -m "nixos: add katagrapho-readers group + chown state on boot"
```

---

# Phase 3 — Collector pure-logic modules

Each task in this phase adds one module plus its unit tests. The module tree is wired incrementally; every task produces a green `cargo build -p epitropos-collector`.

## Task 6: Collector Cargo.toml with real dependencies

**Files:**
- Modify: `epitropos/.worktrees/track-c/collector/Cargo.toml`

- [ ] **Step 1: Replace with full dep list**

```toml
[package]
name = "epitropos-collector"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "Off-host collector for epitropos session recordings"

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
libc = "0.2"

[dev-dependencies]
tempfile = "3"
hyper = { version = "1", features = ["client", "http1"] }
hyper-util = { version = "0.1", features = ["client-legacy", "tokio"] }
```

- [ ] **Step 2: Make `main.rs` import a `lib.rs` stub**

Create `collector/src/lib.rs`:

```rust
pub mod error;
```

Create `collector/src/error.rs`:

```rust
use std::io;

pub const EX_USAGE: i32 = 64;
pub const EX_DATAERR: i32 = 65;
pub const EX_NOINPUT: i32 = 66;
pub const EX_UNAVAILABLE: i32 = 69;
pub const EX_SOFTWARE: i32 = 70;
pub const EX_IOERR: i32 = 74;
pub const EX_TEMPFAIL: i32 = 75;
pub const EX_CONFIG: i32 = 78;

#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("usage: {0}")]
    Usage(String),

    #[error("config: {0}")]
    Config(String),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("tls: {0}")]
    Tls(String),

    #[error("enroll: {0}")]
    Enroll(String),

    #[error("storage: {0}")]
    Storage(String),

    #[error("chain: {0}")]
    Chain(String),

    #[error("verify: {0}")]
    Verify(String),

    #[error("internal: {0}")]
    Internal(String),
}

impl CollectorError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => EX_USAGE,
            Self::Config(_) => EX_CONFIG,
            Self::Io(_) => EX_IOERR,
            Self::Tls(_) => EX_UNAVAILABLE,
            Self::Enroll(_) => EX_DATAERR,
            Self::Storage(_) => EX_IOERR,
            Self::Chain(_) => EX_IOERR,
            Self::Verify(_) => EX_DATAERR,
            Self::Internal(_) => EX_SOFTWARE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_distinct() {
        assert_eq!(CollectorError::Usage("x".into()).exit_code(), EX_USAGE);
        assert_eq!(CollectorError::Config("x".into()).exit_code(), EX_CONFIG);
        assert_eq!(CollectorError::Verify("x".into()).exit_code(), EX_DATAERR);
        assert_eq!(CollectorError::Chain("x".into()).exit_code(), EX_IOERR);
    }
}
```

Update `collector/src/main.rs`:

```rust
use epitropos_collector::error::CollectorError;

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("epitropos-collector: {e}");
            std::process::exit(e.exit_code());
        }
    }
}

fn run() -> Result<(), CollectorError> {
    // Placeholder — filled in by Task 25 (CLI dispatcher).
    eprintln!("epitropos-collector: not yet implemented");
    std::process::exit(69);
}
```

- [ ] **Step 3: Build + test**

```bash
cd /home/acid/Workspace/repos/epitropos/.worktrees/track-c
cargo build -p epitropos-collector 2>&1 | tail -5
cargo test -p epitropos-collector 2>&1 | tail -5
```

Expected: builds; 1 test passes.

- [ ] **Step 4: Commit**

```bash
git add collector/
git -c commit.gpgsign=false commit -m "collector: add deps + error type + sysexits exit codes"
```

## Task 7: `config.rs` — TOML config with deny_unknown_fields

**Files:**
- Create: `collector/src/config.rs`
- Modify: `collector/src/lib.rs`

- [ ] **Step 1: Write config.rs**

```rust
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::CollectorError;

const DEFAULT_STORAGE_DIR: &str = "/var/lib/epitropos-collector";
const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0";
const DEFAULT_LISTEN_PORT: u16 = 8443;
const DEFAULT_MAX_UPLOAD_BYTES: u64 = 1 << 30; // 1 GiB
const DEFAULT_TOKEN_TTL_SECONDS: u64 = 900;
const DEFAULT_MAX_PENDING_TOKENS: usize = 1000;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub listen: Listen,
    #[serde(default)]
    pub storage: Storage,
    #[serde(default)]
    pub enrollment: Enrollment,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub log: Log,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    #[serde(default = "Listen::default_address")]
    pub address: String,
    #[serde(default = "Listen::default_port")]
    pub port: u16,
}
impl Listen {
    fn default_address() -> String { DEFAULT_LISTEN_ADDRESS.into() }
    fn default_port() -> u16 { DEFAULT_LISTEN_PORT }
}
impl Default for Listen {
    fn default() -> Self { Self { address: Self::default_address(), port: Self::default_port() } }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    #[serde(default = "Storage::default_dir")]
    pub dir: PathBuf,
    #[serde(default = "Storage::default_max_upload")]
    pub max_upload_bytes: u64,
}
impl Storage {
    fn default_dir() -> PathBuf { PathBuf::from(DEFAULT_STORAGE_DIR) }
    fn default_max_upload() -> u64 { DEFAULT_MAX_UPLOAD_BYTES }
}
impl Default for Storage {
    fn default() -> Self { Self { dir: Self::default_dir(), max_upload_bytes: Self::default_max_upload() } }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    #[serde(default = "Enrollment::default_ttl")]
    pub token_ttl_seconds: u64,
    #[serde(default = "Enrollment::default_max_pending")]
    pub max_pending_tokens: usize,
}
impl Enrollment {
    fn default_ttl() -> u64 { DEFAULT_TOKEN_TTL_SECONDS }
    fn default_max_pending() -> usize { DEFAULT_MAX_PENDING_TOKENS }
}
impl Default for Enrollment {
    fn default() -> Self { Self { token_ttl_seconds: Self::default_ttl(), max_pending_tokens: Self::default_max_pending() } }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Log {
    #[serde(default = "Log::default_level")]
    pub level: String,
}
impl Log {
    fn default_level() -> String { "info".into() }
}
impl Default for Log {
    fn default() -> Self { Self { level: Self::default_level() } }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: Listen::default(),
            storage: Storage::default(),
            enrollment: Enrollment::default(),
            tls: Tls::default(),
            log: Log::default(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, CollectorError> {
        let s = fs::read_to_string(path)
            .map_err(|e| CollectorError::Config(format!("read {}: {e}", path.display())))?;
        toml::from_str(&s).map_err(|e| CollectorError::Config(format!("parse: {e}")))
    }

    pub fn tls_cert_path(&self) -> PathBuf {
        self.tls.cert_path.clone().unwrap_or_else(|| self.storage.dir.join("tls/cert.pem"))
    }

    pub fn tls_key_path(&self) -> PathBuf {
        self.tls.key_path.clone().unwrap_or_else(|| self.storage.dir.join("tls/key.pem"))
    }

    pub fn enroll_secret_path(&self) -> PathBuf {
        self.storage.dir.join("tls/enroll.secret")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_when_empty() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.listen.port, DEFAULT_LISTEN_PORT);
        assert_eq!(cfg.storage.dir, PathBuf::from(DEFAULT_STORAGE_DIR));
        assert_eq!(cfg.enrollment.token_ttl_seconds, DEFAULT_TOKEN_TTL_SECONDS);
    }

    #[test]
    fn rejects_unknown_top_level() {
        let toml_str = r#"
[bogus]
key = 1
"#;
        assert!(toml::from_str::<Config>(toml_str).is_err());
    }

    #[test]
    fn rejects_unknown_subkey() {
        let toml_str = r#"
[storage]
dir = "/tmp/foo"
bogus = 1
"#;
        assert!(toml::from_str::<Config>(toml_str).is_err());
    }

    #[test]
    fn overrides_apply() {
        let toml_str = r#"
[listen]
port = 9999

[enrollment]
token_ttl_seconds = 60
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.listen.port, 9999);
        assert_eq!(cfg.enrollment.token_ttl_seconds, 60);
    }
}
```

- [ ] **Step 2: Wire into lib.rs**

Update `collector/src/lib.rs`:

```rust
pub mod config;
pub mod error;
```

- [ ] **Step 3: Test + commit**

```bash
cargo test -p epitropos-collector config 2>&1 | tail -10
git add collector/src/config.rs collector/src/lib.rs
git -c commit.gpgsign=false commit -m "collector: TOML config with deny_unknown_fields"
```

## Task 8: `chain.rs` — per-sender head pointer (strict mode)

**Files:**
- Create: `collector/src/chain.rs`

- [ ] **Step 1: Write chain.rs**

```rust
//! Per-sender head pointer + append-only log. Strict mode: advance
//! only if the supplied prev_manifest_hash equals the current head.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::error::CollectorError;

pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub struct SenderChain {
    pub head: PathBuf,
    pub log: PathBuf,
    pub lock: PathBuf,
}

impl SenderChain {
    pub fn under(sender_dir: &Path) -> Self {
        Self {
            head: sender_dir.join("head.hash"),
            log: sender_dir.join("head.hash.log"),
            lock: sender_dir.join("head.hash.lock"),
        }
    }
}

pub struct ChainLock {
    file: fs::File,
}

impl ChainLock {
    pub fn acquire(chain: &SenderChain) -> Result<Self, CollectorError> {
        if let Some(parent) = chain.lock.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| CollectorError::Chain(format!("mkdir {}: {e}", parent.display())))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&chain.lock)
            .map_err(|e| CollectorError::Chain(format!("open lock: {e}")))?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(CollectorError::Chain(format!(
                "flock: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self { file })
    }
}

impl Drop for ChainLock {
    fn drop(&mut self) {
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub fn read_head(chain: &SenderChain) -> Result<String, CollectorError> {
    if !chain.head.exists() {
        return Ok(GENESIS_PREV.to_string());
    }
    let s = fs::read_to_string(&chain.head)
        .map_err(|e| CollectorError::Chain(format!("read head: {e}")))?;
    let trimmed = s.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CollectorError::Chain(format!(
            "head.hash not 64 hex: {trimmed:?}"
        )));
    }
    Ok(trimmed.to_string())
}

pub fn write_head(chain: &SenderChain, hex_hash: &str) -> Result<(), CollectorError> {
    if hex_hash.len() != 64 {
        return Err(CollectorError::Chain("hash must be 64 hex chars".into()));
    }
    let tmp = chain.head.with_extension("tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| CollectorError::Chain(format!("open head tmp: {e}")))?;
    f.write_all(hex_hash.as_bytes())
        .map_err(|e| CollectorError::Chain(format!("write head: {e}")))?;
    f.sync_all()
        .map_err(|e| CollectorError::Chain(format!("fsync head: {e}")))?;
    drop(f);
    fs::rename(&tmp, &chain.head)
        .map_err(|e| CollectorError::Chain(format!("rename head: {e}")))?;
    Ok(())
}

pub fn append_log(
    chain: &SenderChain,
    iso_ts: &str,
    user: &str,
    session_id: &str,
    part: u32,
    hex_hash: &str,
) -> Result<(), CollectorError> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .open(&chain.log)
        .map_err(|e| CollectorError::Chain(format!("open log: {e}")))?;
    let line = format!("{iso_ts} {user} {session_id} {part} {hex_hash}\n");
    f.write_all(line.as_bytes())
        .map_err(|e| CollectorError::Chain(format!("write log: {e}")))?;
    f.sync_all()
        .map_err(|e| CollectorError::Chain(format!("fsync log: {e}")))?;
    Ok(())
}

/// Strict advance: fails if `prev` does not match the current head.
/// Must be called with `ChainLock` held.
pub fn strict_advance(
    chain: &SenderChain,
    prev: &str,
    new_head: &str,
) -> Result<(), CollectorError> {
    let current = read_head(chain)?;
    if current != prev {
        return Err(CollectorError::Chain(format!(
            "chain gap: expected prev={current} but manifest said {prev}"
        )));
    }
    write_head(chain, new_head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn genesis_when_missing() {
        let dir = tempdir().unwrap();
        let c = SenderChain::under(dir.path());
        assert_eq!(read_head(&c).unwrap(), GENESIS_PREV);
    }

    #[test]
    fn advance_once_from_genesis() {
        let dir = tempdir().unwrap();
        let c = SenderChain::under(dir.path());
        let _g = ChainLock::acquire(&c).unwrap();
        let new_hash = "a".repeat(64);
        strict_advance(&c, GENESIS_PREV, &new_hash).unwrap();
        assert_eq!(read_head(&c).unwrap(), new_hash);
    }

    #[test]
    fn advance_with_wrong_prev_fails() {
        let dir = tempdir().unwrap();
        let c = SenderChain::under(dir.path());
        let _g = ChainLock::acquire(&c).unwrap();
        strict_advance(&c, GENESIS_PREV, &"a".repeat(64)).unwrap();
        // Now try to advance from an unrelated prev.
        let wrong_prev = "b".repeat(64);
        assert!(strict_advance(&c, &wrong_prev, &"c".repeat(64)).is_err());
    }

    #[test]
    fn append_log_appends_lines() {
        let dir = tempdir().unwrap();
        let c = SenderChain::under(dir.path());
        append_log(&c, "2026-04-07T12:00:00Z", "alice", "s1", 0, &"a".repeat(64)).unwrap();
        append_log(&c, "2026-04-07T12:01:00Z", "alice", "s1", 1, &"b".repeat(64)).unwrap();
        let content = fs::read_to_string(&c.log).unwrap();
        assert_eq!(content.lines().count(), 2);
        assert!(content.contains("alice s1 0"));
        assert!(content.contains("alice s1 1"));
    }
}
```

- [ ] **Step 2: Wire into lib.rs**

Add `pub mod chain;` to `collector/src/lib.rs`.

- [ ] **Step 3: Test + commit**

```bash
cargo test -p epitropos-collector chain 2>&1 | tail -10
git add collector/src/chain.rs collector/src/lib.rs
git -c commit.gpgsign=false commit -m "collector: per-sender head pointer with strict chain advance"
```

## Task 9: `verify.rs` — manifest signature verification against stored pubkey

**Files:**
- Create: `collector/src/verify.rs`

- [ ] **Step 1: Write verify.rs**

```rust
//! Verify incoming manifest signatures against a sender's pinned
//! ed25519 signing.pub. Canonicalization MUST match what katagrapho
//! produces — we mirror the field order here.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::CollectorError;

#[derive(Debug, Deserialize, Clone)]
pub struct Chunk {
    pub seq: u64,
    pub bytes: u64,
    pub messages: u64,
    pub elapsed: f64,
    pub sha256: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Manifest {
    pub v: String,
    pub session_id: String,
    pub part: u32,
    pub user: String,
    pub host: String,
    pub boot_id: String,
    pub audit_session_id: Option<u32>,
    pub started: f64,
    pub ended: f64,
    pub katagrapho_version: String,
    pub katagrapho_commit: String,
    pub epitropos_version: String,
    pub epitropos_commit: String,
    pub recording_file: String,
    pub recording_size: u64,
    pub recording_sha256: String,
    pub chunks: Vec<Chunk>,
    pub end_reason: String,
    pub exit_code: i32,
    pub prev_manifest_hash: String,
    #[serde(default)]
    pub this_manifest_hash: String,
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub signature: String,
}

impl Manifest {
    fn canonical_bytes_for_hashing(&self) -> Result<Vec<u8>, CollectorError> {
        let json = serde_json::to_string(&serde_json::json!({
            "v": self.v,
            "session_id": self.session_id,
            "part": self.part,
            "user": self.user,
            "host": self.host,
            "boot_id": self.boot_id,
            "audit_session_id": self.audit_session_id,
            "started": self.started,
            "ended": self.ended,
            "katagrapho_version": self.katagrapho_version,
            "katagrapho_commit": self.katagrapho_commit,
            "epitropos_version": self.epitropos_version,
            "epitropos_commit": self.epitropos_commit,
            "recording_file": self.recording_file,
            "recording_size": self.recording_size,
            "recording_sha256": self.recording_sha256,
            "chunks": self.chunks,
            "end_reason": self.end_reason,
            "exit_code": self.exit_code,
            "prev_manifest_hash": self.prev_manifest_hash,
        }))
        .map_err(|e| CollectorError::Verify(format!("canonical: {e}")))?;
        Ok(json.into_bytes())
    }

    pub fn compute_hash(&self) -> Result<[u8; 32], CollectorError> {
        let bytes = self.canonical_bytes_for_hashing()?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(hasher.finalize().into())
    }

    /// Verify signature and internal hash binding using a raw 32-byte
    /// ed25519 pubkey (the sender's signing.pub).
    pub fn verify(&self, signing_pub: &[u8; 32]) -> Result<(), CollectorError> {
        let recomputed = self.compute_hash()?;
        let stored = hex::decode(&self.this_manifest_hash)
            .map_err(|e| CollectorError::Verify(format!("hex decode hash: {e}")))?;
        if stored.len() != 32 || recomputed[..] != stored[..] {
            return Err(CollectorError::Verify(
                "manifest content != this_manifest_hash".into(),
            ));
        }
        let sig_bytes = base64_decode(&self.signature)
            .map_err(|e| CollectorError::Verify(format!("sig base64: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(CollectorError::Verify("signature wrong length".into()));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        let vk = VerifyingKey::from_bytes(signing_pub)
            .map_err(|e| CollectorError::Verify(format!("pubkey: {e}")))?;
        let signature = Signature::from_bytes(&sig);
        vk.verify(&recomputed, &signature)
            .map_err(|e| CollectorError::Verify(format!("signature: {e}")))
    }
}

pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, CollectorError> {
    serde_json::from_slice(bytes)
        .map_err(|e| CollectorError::Verify(format!("parse manifest: {e}")))
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 char: {c}")),
        }
    }
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 length not multiple of 4".into());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&b| b == b'=').count();
        let v0 = val(chunk[0])?;
        let v1 = val(chunk[1])?;
        let v2 = if pad < 2 { val(chunk[2])? } else { 0 };
        let v3 = if pad < 1 { val(chunk[3])? } else { 0 };
        out.push((v0 << 2) | (v1 >> 4));
        if pad < 2 { out.push((v1 << 4) | (v2 >> 2)); }
        if pad < 1 { out.push((v2 << 6) | v3); }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn sample() -> Manifest {
        Manifest {
            v: "katagrapho-manifest-v1".into(),
            session_id: "abc".into(),
            part: 0,
            user: "alice".into(),
            host: "nyx".into(),
            boot_id: "00000000-0000-0000-0000-000000000000".into(),
            audit_session_id: Some(42),
            started: 1.0,
            ended: 2.0,
            katagrapho_version: "0.3.0".into(),
            katagrapho_commit: "deadbee".into(),
            epitropos_version: "0.1.0".into(),
            epitropos_commit: "cafebab".into(),
            recording_file: "abc.part0.kgv1.age".into(),
            recording_size: 1024,
            recording_sha256: "00".repeat(32),
            chunks: vec![],
            end_reason: "eof".into(),
            exit_code: 0,
            prev_manifest_hash: "0".repeat(64),
            this_manifest_hash: String::new(),
            key_id: String::new(),
            signature: String::new(),
        }
    }

    fn sign_in_place(m: &mut Manifest, sk: &SigningKey) {
        let digest = m.compute_hash().unwrap();
        let sig = sk.sign(&digest).to_bytes();
        m.this_manifest_hash = hex::encode(digest);
        let mut out = String::new();
        // Inline base64 encode
        const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for chunk in sig.chunks(3) {
            let b0 = chunk[0];
            let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
            out.push(ALPH[(b0 >> 2) as usize] as char);
            out.push(ALPH[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);
            if chunk.len() > 1 { out.push(ALPH[((b1 & 0x0F) << 2 | b2 >> 6) as usize] as char); } else { out.push('='); }
            if chunk.len() > 2 { out.push(ALPH[(b2 & 0x3F) as usize] as char); } else { out.push('='); }
        }
        m.signature = out;
    }

    #[test]
    fn valid_manifest_verifies() {
        let sk = SigningKey::generate(&mut OsRng);
        let pub_bytes: [u8; 32] = sk.verifying_key().to_bytes();
        let mut m = sample();
        sign_in_place(&mut m, &sk);
        m.verify(&pub_bytes).unwrap();
    }

    #[test]
    fn tampered_user_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let pub_bytes: [u8; 32] = sk.verifying_key().to_bytes();
        let mut m = sample();
        sign_in_place(&mut m, &sk);
        m.user = "mallory".into();
        assert!(m.verify(&pub_bytes).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut m = sample();
        sign_in_place(&mut m, &sk);
        let other = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        assert!(m.verify(&other).is_err());
    }
}
```

- [ ] **Step 2: Add `rand` to dev-dependencies**

In `collector/Cargo.toml` add to `[dev-dependencies]`:

```toml
rand = "0.8"
```

- [ ] **Step 3: Wire into lib.rs**

Add `pub mod verify;` to `collector/src/lib.rs`.

- [ ] **Step 4: Test + commit**

```bash
cargo test -p epitropos-collector verify 2>&1 | tail -10
git add collector/src/verify.rs collector/src/lib.rs collector/Cargo.toml
git -c commit.gpgsign=false commit -m "collector: manifest signature verification with canonical JSON"
```

## Task 10: `storage.rs` — per-sender dirs + atomic writes + path-traversal guards

**Files:**
- Create: `collector/src/storage.rs`

- [ ] **Step 1: Write storage.rs**

```rust
//! Storage layout under the collector's root directory.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::CollectorError;

const SAFE_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";

pub fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.chars().all(|c| SAFE_CHARS.contains(c))
        && !name.starts_with('.')
}

pub struct SenderDirs {
    pub root: PathBuf,
    pub cert_pem: PathBuf,
    pub cert_fingerprint: PathBuf,
    pub signing_pub: PathBuf,
    pub enrolled_at: PathBuf,
    pub recordings: PathBuf,
}

impl SenderDirs {
    pub fn under(storage_dir: &Path, sender_name: &str) -> Result<Self, CollectorError> {
        if !is_safe_name(sender_name) {
            return Err(CollectorError::Storage(format!(
                "unsafe sender name: {sender_name:?}"
            )));
        }
        let root = storage_dir.join("senders").join(sender_name);
        Ok(Self {
            cert_pem: root.join("cert.pem"),
            cert_fingerprint: root.join("cert.fingerprint"),
            signing_pub: root.join("signing.pub"),
            enrolled_at: root.join("enrolled_at"),
            recordings: root.join("recordings"),
            root,
        })
    }

    pub fn ensure_created(&self) -> Result<(), CollectorError> {
        fs::create_dir_all(&self.root)
            .map_err(|e| CollectorError::Storage(format!("mkdir {}: {e}", self.root.display())))?;
        fs::create_dir_all(&self.recordings)
            .map_err(|e| CollectorError::Storage(format!("mkdir {}: {e}", self.recordings.display())))?;
        let mut perms = fs::metadata(&self.root)
            .map_err(|e| CollectorError::Storage(format!("stat: {e}")))?
            .permissions();
        perms.set_mode(0o750);
        let _ = fs::set_permissions(&self.root, perms);
        Ok(())
    }
}

/// Compute the final path for a recording part within a sender dir.
/// Rejects unsafe user / session / part values.
pub fn recording_paths(
    sender: &SenderDirs,
    user: &str,
    session_id: &str,
    part: u32,
) -> Result<(PathBuf, PathBuf), CollectorError> {
    if !is_safe_name(user) {
        return Err(CollectorError::Storage(format!("unsafe user: {user:?}")));
    }
    if !is_safe_name(session_id) {
        return Err(CollectorError::Storage(format!(
            "unsafe session_id: {session_id:?}"
        )));
    }
    let dir = sender.recordings.join(user);
    let rec = dir.join(format!("{session_id}.part{part}.kgv1.age"));
    let sidecar = dir.join(format!("{session_id}.part{part}.kgv1.age.manifest.json"));
    // Defense in depth: ensure paths don't escape the sender root.
    if !rec.starts_with(&sender.root) || !sidecar.starts_with(&sender.root) {
        return Err(CollectorError::Storage("path escapes sender root".into()));
    }
    Ok((rec, sidecar))
}

/// Atomic write: tmp file + fsync + rename. Mode 0640.
pub fn put_atomic(path: &Path, data: &[u8]) -> Result<(), CollectorError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| CollectorError::Storage(format!("mkdir {}: {e}", parent.display())))?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o640)
        .open(&tmp)
        .map_err(|e| CollectorError::Storage(format!("open tmp: {e}")))?;
    f.write_all(data)
        .map_err(|e| CollectorError::Storage(format!("write: {e}")))?;
    f.sync_all()
        .map_err(|e| CollectorError::Storage(format!("fsync: {e}")))?;
    drop(f);
    fs::rename(&tmp, path)
        .map_err(|e| CollectorError::Storage(format!("rename: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn safe_name_rejects_slashes() {
        assert!(!is_safe_name("foo/bar"));
        assert!(!is_safe_name(".hidden"));
        assert!(!is_safe_name(""));
        assert!(is_safe_name("alice-laptop"));
        assert!(is_safe_name("node01.nyx"));
    }

    #[test]
    fn sender_dirs_rejects_bad_name() {
        let dir = tempdir().unwrap();
        assert!(SenderDirs::under(dir.path(), "../evil").is_err());
        assert!(SenderDirs::under(dir.path(), "good").is_ok());
    }

    #[test]
    fn recording_paths_rejects_bad_input() {
        let dir = tempdir().unwrap();
        let s = SenderDirs::under(dir.path(), "alice").unwrap();
        assert!(recording_paths(&s, "../etc", "s1", 0).is_err());
        assert!(recording_paths(&s, "alice", "s/1", 0).is_err());
        let (rec, sc) = recording_paths(&s, "alice", "s1", 0).unwrap();
        assert!(rec.starts_with(&s.root));
        assert!(sc.starts_with(&s.root));
    }

    #[test]
    fn put_atomic_creates_parent_and_writes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sub/file.bin");
        put_atomic(&path, b"hello").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"hello");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }
}
```

- [ ] **Step 2: Wire + test + commit**

```bash
# add pub mod storage; to lib.rs
cargo test -p epitropos-collector storage 2>&1 | tail -10
git add collector/src/storage.rs collector/src/lib.rs
git -c commit.gpgsign=false commit -m "collector: per-sender storage layout with path-traversal guards"
```

## Task 11: `enroll.rs` — HMAC tokens + pending/burned state

**Files:**
- Create: `collector/src/enroll.rs`

- [ ] **Step 1: Write enroll.rs**

```rust
//! Enrollment tokens: HMAC-SHA256 construction, stateful single-use.
//!
//! Wire format (base32 of 40 bytes, 64 chars):
//!   HMAC(enroll.secret, sender_name || nonce || expires_at_be)[..16]
//!   || nonce (16 bytes)
//!   || expires_at_be (8 bytes)

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::CollectorError;

type HmacSha256 = Hmac<Sha256>;
const TOKEN_PREFIX: &str = "epitropos-enroll:";
const BODY_LEN: usize = 16 + 16 + 8; // 40

pub struct EnrollmentDir {
    pub pending: PathBuf,
    pub burned: PathBuf,
    pub lock: PathBuf,
}

impl EnrollmentDir {
    pub fn under(storage_dir: &Path) -> Self {
        let base = storage_dir.join("enrollments");
        Self {
            pending: base.join("pending"),
            burned: base.join("burned"),
            lock: base.join("lock"),
        }
    }

    pub fn ensure_created(&self) -> Result<(), CollectorError> {
        for p in [&self.pending, &self.burned] {
            fs::create_dir_all(p)
                .map_err(|e| CollectorError::Enroll(format!("mkdir {}: {e}", p.display())))?;
        }
        Ok(())
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random_nonce() -> [u8; 16] {
    let mut buf = [0u8; 16];
    let bytes = fs::read("/dev/urandom").ok();
    if let Some(b) = bytes {
        if b.len() >= 16 {
            buf.copy_from_slice(&b[..16]);
            return buf;
        }
    }
    // Fallback — mix in current time if urandom unavailable.
    let t = now_secs().to_be_bytes();
    buf[..8].copy_from_slice(&t);
    buf
}

pub fn load_secret(path: &Path) -> Result<Vec<u8>, CollectorError> {
    let bytes = fs::read(path)
        .map_err(|e| CollectorError::Enroll(format!("read secret: {e}")))?;
    if bytes.len() < 32 {
        return Err(CollectorError::Enroll("secret < 32 bytes".into()));
    }
    Ok(bytes)
}

pub fn generate_secret(path: &Path) -> Result<(), CollectorError> {
    let bytes = fs::read("/dev/urandom")
        .map_err(|e| CollectorError::Enroll(format!("urandom: {e}")))?;
    if bytes.len() < 32 {
        return Err(CollectorError::Enroll("urandom returned <32 bytes".into()));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| CollectorError::Enroll(format!("mkdir: {e}")))?;
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o400)
        .open(path)
        .map_err(|e| CollectorError::Enroll(format!("open secret: {e}")))?;
    f.write_all(&bytes[..32])
        .map_err(|e| CollectorError::Enroll(format!("write: {e}")))?;
    f.sync_all()
        .map_err(|e| CollectorError::Enroll(format!("fsync: {e}")))?;
    Ok(())
}

fn hmac_body(secret: &[u8], sender_name: &str, nonce: &[u8; 16], expires_at: u64) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key len");
    mac.update(sender_name.as_bytes());
    mac.update(nonce);
    mac.update(&expires_at.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&out[..16]);
    truncated
}

pub struct GeneratedToken {
    pub token: String,
    pub token_hash_hex: String,
    pub expires_at: u64,
}

pub fn generate_token(
    secret: &[u8],
    sender_name: &str,
    ttl_seconds: u64,
) -> Result<GeneratedToken, CollectorError> {
    let nonce = random_nonce();
    let expires_at = now_secs() + ttl_seconds;
    let mac = hmac_body(secret, sender_name, &nonce, expires_at);
    let mut body = [0u8; BODY_LEN];
    body[..16].copy_from_slice(&mac);
    body[16..32].copy_from_slice(&nonce);
    body[32..].copy_from_slice(&expires_at.to_be_bytes());
    let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &body);
    let token = format!("{TOKEN_PREFIX}{encoded}");

    let mut hasher = <Sha256 as sha2::Digest>::new();
    <Sha256 as sha2::Digest>::update(&mut hasher, token.as_bytes());
    let hash_hex = hex::encode(<Sha256 as sha2::Digest>::finalize(hasher));

    Ok(GeneratedToken { token, token_hash_hex: hash_hex, expires_at })
}

pub fn write_pending(
    dir: &EnrollmentDir,
    token_hash_hex: &str,
    sender_name: &str,
    expires_at: u64,
) -> Result<(), CollectorError> {
    dir.ensure_created()?;
    let path = dir.pending.join(format!("{token_hash_hex}.json"));
    let body = serde_json::json!({
        "sender_name": sender_name,
        "expires_at": expires_at,
    });
    let s = serde_json::to_string(&body)
        .map_err(|e| CollectorError::Enroll(format!("serialize: {e}")))?;
    crate::storage::put_atomic(&path, s.as_bytes())
}

pub enum ValidateResult {
    Ok { sender_name: String },
    Expired,
    AlreadyBurned,
    NotPending,
    BadMac,
    Malformed,
}

pub fn validate_token(
    secret: &[u8],
    dir: &EnrollmentDir,
    token: &str,
) -> Result<ValidateResult, CollectorError> {
    let body = match token.strip_prefix(TOKEN_PREFIX) {
        Some(b) => b,
        None => return Ok(ValidateResult::Malformed),
    };
    let raw = match base32::decode(base32::Alphabet::Rfc4648 { padding: false }, body) {
        Some(r) if r.len() == BODY_LEN => r,
        _ => return Ok(ValidateResult::Malformed),
    };

    let mut mac = [0u8; 16];
    mac.copy_from_slice(&raw[..16]);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&raw[16..32]);
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&raw[32..]);
    let expires_at = u64::from_be_bytes(ts);

    if expires_at < now_secs() {
        return Ok(ValidateResult::Expired);
    }

    let mut hasher = <Sha256 as sha2::Digest>::new();
    <Sha256 as sha2::Digest>::update(&mut hasher, token.as_bytes());
    let hash_hex = hex::encode(<Sha256 as sha2::Digest>::finalize(hasher));

    if dir.burned.join(&hash_hex).exists() {
        return Ok(ValidateResult::AlreadyBurned);
    }
    let pending_path = dir.pending.join(format!("{hash_hex}.json"));
    if !pending_path.exists() {
        return Ok(ValidateResult::NotPending);
    }
    let pending_json = fs::read(&pending_path)
        .map_err(|e| CollectorError::Enroll(format!("read pending: {e}")))?;
    let pending: serde_json::Value = serde_json::from_slice(&pending_json)
        .map_err(|e| CollectorError::Enroll(format!("parse pending: {e}")))?;
    let sender_name = pending["sender_name"].as_str().unwrap_or("").to_string();
    if sender_name.is_empty() {
        return Ok(ValidateResult::Malformed);
    }

    // Recompute MAC against the stored sender name.
    let expected = hmac_body(secret, &sender_name, &nonce, expires_at);
    let mut match_bytes: u8 = 0;
    for (a, b) in expected.iter().zip(mac.iter()) {
        match_bytes |= a ^ b;
    }
    if match_bytes != 0 {
        return Ok(ValidateResult::BadMac);
    }

    Ok(ValidateResult::Ok { sender_name })
}

pub fn burn(dir: &EnrollmentDir, token_hash_hex: &str) -> Result<(), CollectorError> {
    dir.ensure_created()?;
    let burn_path = dir.burned.join(token_hash_hex);
    fs::write(&burn_path, b"")
        .map_err(|e| CollectorError::Enroll(format!("write burn: {e}")))?;
    let _ = fs::remove_file(dir.pending.join(format!("{token_hash_hex}.json")));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn setup() -> (tempfile::TempDir, Vec<u8>, EnrollmentDir) {
        let dir = tempdir().unwrap();
        let secret_path = dir.path().join("enroll.secret");
        generate_secret(&secret_path).unwrap();
        let secret = load_secret(&secret_path).unwrap();
        let edir = EnrollmentDir::under(dir.path());
        edir.ensure_created().unwrap();
        (dir, secret, edir)
    }

    #[test]
    fn generate_and_validate_round_trip() {
        let (_dir, secret, edir) = setup();
        let gen = generate_token(&secret, "alice", 60).unwrap();
        write_pending(&edir, &gen.token_hash_hex, "alice", gen.expires_at).unwrap();
        match validate_token(&secret, &edir, &gen.token).unwrap() {
            ValidateResult::Ok { sender_name } => assert_eq!(sender_name, "alice"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn burned_token_rejected() {
        let (_dir, secret, edir) = setup();
        let gen = generate_token(&secret, "alice", 60).unwrap();
        write_pending(&edir, &gen.token_hash_hex, "alice", gen.expires_at).unwrap();
        burn(&edir, &gen.token_hash_hex).unwrap();
        matches!(validate_token(&secret, &edir, &gen.token).unwrap(), ValidateResult::AlreadyBurned);
    }

    #[test]
    fn expired_token_rejected() {
        let (_dir, secret, edir) = setup();
        // TTL 0 → expires immediately.
        let gen = generate_token(&secret, "alice", 0).unwrap();
        write_pending(&edir, &gen.token_hash_hex, "alice", gen.expires_at).unwrap();
        // Sleep 1s to push past the boundary.
        std::thread::sleep(std::time::Duration::from_secs(1));
        matches!(validate_token(&secret, &edir, &gen.token).unwrap(), ValidateResult::Expired);
    }

    #[test]
    fn malformed_token_rejected() {
        let (_dir, secret, edir) = setup();
        matches!(validate_token(&secret, &edir, "not-a-token").unwrap(), ValidateResult::Malformed);
    }

    #[test]
    fn wrong_secret_rejected() {
        let (dir, _secret, edir) = setup();
        // Generate with one secret, validate with another.
        let mut other = vec![0u8; 32];
        other[0] = 0xFF;
        let gen = generate_token(&other, "alice", 60).unwrap();
        write_pending(&edir, &gen.token_hash_hex, "alice", gen.expires_at).unwrap();
        let secret_path = dir.path().join("enroll.secret");
        let good = load_secret(&secret_path).unwrap();
        matches!(validate_token(&good, &edir, &gen.token).unwrap(), ValidateResult::BadMac);
    }
}
```

Note: the test prints `other` in `matches!` debug — `ValidateResult` needs `Debug`. Add `#[derive(Debug)]` to the enum.

- [ ] **Step 2: Add Debug derive**

In the enum definition, add:

```rust
#[derive(Debug)]
pub enum ValidateResult { ... }
```

- [ ] **Step 3: Wire + test + commit**

```bash
# add pub mod enroll; to lib.rs
cargo test -p epitropos-collector enroll 2>&1 | tail -15
git add collector/src/enroll.rs collector/src/lib.rs
git -c commit.gpgsign=false commit -m "collector: HMAC enrollment tokens with single-use burn list"
```

---

# Phase 4 — Collector TLS + HTTP server

## Task 12: `tls.rs` — rustls server config + pinned client-cert verifier

**Files:**
- Create: `collector/src/tls.rs`

- [ ] **Step 1: Write tls.rs**

```rust
//! rustls server configuration with a custom client-certificate
//! verifier that checks the presented cert's DER SHA-256 against a
//! pinned set loaded from on-disk sender state.

use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{DigitallySignedStruct, DistinguishedName, Error as RustlsError, SignatureScheme};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::error::CollectorError;

pub fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, CollectorError> {
    let bytes = fs::read(path)
        .map_err(|e| CollectorError::Tls(format!("read cert {}: {e}", path.display())))?;
    rustls_pemfile::certs(&mut &bytes[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CollectorError::Tls(format!("parse cert: {e}")))
}

pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, CollectorError> {
    let bytes = fs::read(path)
        .map_err(|e| CollectorError::Tls(format!("read key {}: {e}", path.display())))?;
    let mut reader = &bytes[..];
    if let Some(k) = rustls_pemfile::pkcs8_private_keys(&mut reader).next() {
        return k
            .map(PrivateKeyDer::Pkcs8)
            .map_err(|e| CollectorError::Tls(format!("parse pkcs8: {e}")));
    }
    let mut reader = &bytes[..];
    if let Some(k) = rustls_pemfile::rsa_private_keys(&mut reader).next() {
        return k
            .map(PrivateKeyDer::Pkcs1)
            .map_err(|e| CollectorError::Tls(format!("parse rsa: {e}")));
    }
    Err(CollectorError::Tls("no private key found in file".into()))
}

/// Shared pinned-cert fingerprint set. Updated by enrollment handler.
#[derive(Clone, Default)]
pub struct PinnedCerts {
    inner: Arc<RwLock<HashSet<[u8; 32]>>>,
}

impl PinnedCerts {
    pub fn new() -> Self { Self::default() }

    pub fn add(&self, cert_der: &[u8]) {
        let mut h = Sha256::new();
        h.update(cert_der);
        let fp: [u8; 32] = h.finalize().into();
        self.inner.write().unwrap().insert(fp);
    }

    pub fn remove(&self, cert_der: &[u8]) {
        let mut h = Sha256::new();
        h.update(cert_der);
        let fp: [u8; 32] = h.finalize().into();
        self.inner.write().unwrap().remove(&fp);
    }

    pub fn contains(&self, cert_der: &[u8]) -> bool {
        let mut h = Sha256::new();
        h.update(cert_der);
        let fp: [u8; 32] = h.finalize().into();
        self.inner.read().unwrap().contains(&fp)
    }
}

#[derive(Debug)]
pub struct PinnedClientVerifier {
    pinned: PinnedCerts,
}

impl PinnedClientVerifier {
    pub fn new(pinned: PinnedCerts) -> Self { Self { pinned } }
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] { &[] }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        if self.pinned.contains(end_entity.as_ref()) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(RustlsError::General("client cert not in pinned set".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }

    fn offer_client_auth(&self) -> bool { true }
    fn client_auth_mandatory(&self) -> bool { false }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_contains_after_add() {
        let p = PinnedCerts::new();
        let der = b"not-real-der-but-hash-still-deterministic";
        assert!(!p.contains(der));
        p.add(der);
        assert!(p.contains(der));
        p.remove(der);
        assert!(!p.contains(der));
    }
}
```

Note: the rustls 0.23 API for `ClientCertVerifier` — double-check `WebPkiClientVerifier` vs custom. If the trait shape has drifted, adapt the signatures but keep the semantic (check DER against pinned set).

- [ ] **Step 2: Wire + build + commit**

```bash
# add pub mod tls; to lib.rs
cargo build -p epitropos-collector 2>&1 | tail -10
cargo test -p epitropos-collector tls 2>&1 | tail -5
git add collector/src/tls.rs collector/src/lib.rs
git -c commit.gpgsign=false commit -m "collector: rustls setup with pinned client-cert verifier"
```

## Task 13: `server.rs` — axum router with health, enroll, push handlers

**Files:**
- Create: `collector/src/server.rs`

- [ ] **Step 1: Write server.rs (skeleton + handlers)**

Full code for `server.rs` is long (~400 lines). Key shape:

```rust
use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use crate::chain::{ChainLock, SenderChain, GENESIS_PREV, append_log, strict_advance, read_head};
use crate::config::Config;
use crate::enroll::{
    burn, load_secret, validate_token, write_pending, EnrollmentDir, ValidateResult,
};
use crate::storage::{put_atomic, recording_paths, SenderDirs};
use crate::tls::PinnedCerts;
use crate::verify::{parse_manifest, Manifest};

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub pinned: PinnedCerts,
    pub enroll_secret: Arc<Vec<u8>>,
    pub collector_cert_pem: Arc<Vec<u8>>,
    pub collector_fingerprint_hex: Arc<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/enroll", post(enroll_handler))
        .route("/v1/sessions/:session_id/parts/:part", post(push_handler))
        .with_state(state)
}

async fn health() -> &'static str { "ok" }

#[derive(Deserialize)]
struct EnrollBody {
    sender_name: String,
    token: String,
    tls_cert_pem: String,
    signing_pub_hex: String,
}

#[derive(Serialize)]
struct EnrollResponse {
    collector_tls_cert_pem: String,
    collector_fingerprint_sha256: String,
}

async fn enroll_handler(
    State(state): State<AppState>,
    Json(body): Json<EnrollBody>,
) -> Result<Json<EnrollResponse>, (StatusCode, String)> {
    // Validate token, check pending, burn, pin cert, write sender state.
    // Uses blocking fs via spawn_blocking.
    let state2 = state.clone();
    let body2 = body;
    tokio::task::spawn_blocking(move || enroll_blocking(state2, body2))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;
    Ok(Json(EnrollResponse {
        collector_tls_cert_pem: String::from_utf8(state.collector_cert_pem.to_vec())
            .unwrap_or_default(),
        collector_fingerprint_sha256: state.collector_fingerprint_hex.to_string(),
    }))
}

fn enroll_blocking(state: AppState, body: EnrollBody) -> Result<(), (StatusCode, String)> {
    let edir = EnrollmentDir::under(&state.cfg.storage.dir);
    match validate_token(&state.enroll_secret, &edir, &body.token)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        ValidateResult::Ok { sender_name } => {
            if sender_name != body.sender_name {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "token does not belong to this sender_name".into(),
                ));
            }
        }
        ValidateResult::Expired => {
            return Err((StatusCode::UNAUTHORIZED, "token expired".into()))
        }
        ValidateResult::AlreadyBurned => {
            return Err((StatusCode::UNAUTHORIZED, "token already used".into()))
        }
        ValidateResult::NotPending => {
            return Err((StatusCode::UNAUTHORIZED, "unknown token".into()))
        }
        ValidateResult::BadMac | ValidateResult::Malformed => {
            return Err((StatusCode::UNAUTHORIZED, "invalid token".into()))
        }
    }

    // Parse the sender's TLS cert.
    let tls_cert_ders = rustls_pemfile::certs(&mut body.tls_cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cert pem: {e}")))?;
    if tls_cert_ders.len() != 1 {
        return Err((StatusCode::BAD_REQUEST, "expected exactly one cert".into()));
    }
    let cert_der = tls_cert_ders.into_iter().next().unwrap();

    // Parse signing pubkey.
    let signing_pub = hex::decode(&body.signing_pub_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("signing pub hex: {e}")))?;
    if signing_pub.len() != 32 {
        return Err((StatusCode::BAD_REQUEST, "signing pub must be 32 bytes".into()));
    }

    // Create sender dir.
    let sender = SenderDirs::under(&state.cfg.storage.dir, &body.sender_name)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if sender.root.exists() {
        return Err((StatusCode::CONFLICT, "sender already enrolled".into()));
    }
    sender
        .ensure_created()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    put_atomic(&sender.cert_pem, body.tls_cert_pem.as_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut h = Sha256::new();
    h.update(cert_der.as_ref());
    let fp_hex = hex::encode(h.finalize());
    put_atomic(&sender.cert_fingerprint, fp_hex.as_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    put_atomic(&sender.signing_pub, &signing_pub)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Burn the token.
    let mut h2 = Sha256::new();
    h2.update(body.token.as_bytes());
    burn(&edir, &hex::encode(h2.finalize()))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Add to in-memory pinned set.
    state.pinned.add(cert_der.as_ref());
    Ok(())
}

async fn push_handler(
    State(state): State<AppState>,
    AxumPath((session_id, part)): AxumPath<(String, u32)>,
    body: Body,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // NOTE: identifying the authenticated sender from the mTLS
    // handshake requires threading peer cert info through the tower
    // layer. In v1, the sender name is inferred by finding which
    // sender dir's cert.fingerprint matches the peer cert. This is
    // set up in Task 14 (TLS acceptor).
    let bytes = axum::body::to_bytes(body, state.cfg.storage.max_upload_bytes as usize)
        .await
        .map_err(|e| (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()))?;
    if bytes.len() < 4 {
        return Err((StatusCode::BAD_REQUEST, "body too short".into()));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&bytes[..4]);
    let manifest_len = u32::from_be_bytes(len_bytes) as usize;
    if manifest_len > 65536 || 4 + manifest_len > bytes.len() {
        return Err((StatusCode::BAD_REQUEST, "invalid manifest length".into()));
    }
    let manifest_bytes = &bytes[4..4 + manifest_len];
    let recording_bytes = &bytes[4 + manifest_len..];

    let manifest =
        parse_manifest(manifest_bytes).map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;

    if manifest.session_id != session_id || manifest.part != part {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "session/part mismatch with URL".into(),
        ));
    }

    // Determine sender name from the pinned sender state.
    // Without client-cert identification (see note above), fall back
    // to manifest.user — THIS IS A TEMPORARY GAP until Task 14 wires
    // peer cert info in. Track C does not accept this gap in the
    // final product; see §13 risks.
    //
    // For now, look up the sender whose signing.pub verifies the
    // manifest. This is slower than peer-cert lookup but works for
    // the integration tests until Task 14 lands.
    let sender_name = find_sender_for_manifest(&state.cfg.storage.dir, &manifest)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    let sender = SenderDirs::under(&state.cfg.storage.dir, &sender_name)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let signing_pub_bytes = std::fs::read(&sender.signing_pub)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("read signing.pub: {e}")))?;
    if signing_pub_bytes.len() != 32 {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "bad signing.pub on disk".into()));
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&signing_pub_bytes);
    manifest
        .verify(&pub_arr)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;

    // Hash the recording bytes.
    let mut h = Sha256::new();
    h.update(recording_bytes);
    let computed = hex::encode(h.finalize());
    if computed != manifest.recording_sha256 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "recording sha256 mismatch".into(),
        ));
    }

    // Per-sender chain.
    let chain = SenderChain::under(&sender.root);
    let _lock = ChainLock::acquire(&chain)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let current_head = read_head(&chain)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (rec_path, sidecar_path) = recording_paths(&sender, &manifest.user, &manifest.session_id, manifest.part)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Idempotency: if the recording already exists with the same hash, 409 success.
    if rec_path.exists() {
        let existing_hash = sha256_file_hex(&rec_path)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if existing_hash == manifest.recording_sha256 {
            return Ok(Json(serde_json::json!({
                "stored": true,
                "head_hash": current_head,
                "idempotent": true
            })));
        }
        return Err((StatusCode::CONFLICT, "different recording already stored".into()));
    }

    if manifest.prev_manifest_hash != current_head {
        return Err((
            StatusCode::PRECONDITION_FAILED,
            format!(
                "chain gap: collector head {} != manifest prev {}",
                current_head, manifest.prev_manifest_hash
            ),
        ));
    }

    put_atomic(&rec_path, recording_bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    put_atomic(&sidecar_path, manifest_bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    strict_advance(&chain, &current_head, &manifest.this_manifest_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let iso_now = iso_now();
    append_log(&chain, &iso_now, &manifest.user, &manifest.session_id, manifest.part, &manifest.this_manifest_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "stored": true,
        "head_hash": manifest.this_manifest_hash,
    })))
}

fn find_sender_for_manifest(
    storage_dir: &std::path::Path,
    manifest: &Manifest,
) -> Result<String, String> {
    // Walk `senders/*/signing.pub`; the sender whose pubkey verifies
    // the manifest is the match. This is O(senders) per push, which
    // is acceptable for small fleets. Track D can replace it with
    // peer-cert identification once the TLS acceptor threading lands.
    let senders_dir = storage_dir.join("senders");
    let read = std::fs::read_dir(&senders_dir).map_err(|e| format!("read senders: {e}"))?;
    for entry in read {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        let name = entry
            .file_name()
            .to_string_lossy()
            .into_owned();
        let pub_path = entry.path().join("signing.pub");
        let bytes = match std::fs::read(&pub_path) {
            Ok(b) if b.len() == 32 => b,
            _ => continue,
        };
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        if manifest.verify(&arr).is_ok() {
            return Ok(name);
        }
    }
    Err("no enrolled sender verifies this manifest".into())
}

fn sha256_file_hex(path: &std::path::Path) -> Result<String, crate::error::CollectorError> {
    let mut f = std::fs::File::open(path)
        .map_err(|e| crate::error::CollectorError::Storage(format!("open: {e}")))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    use std::io::Read;
    loop {
        let n = f.read(&mut buf).map_err(|e| crate::error::CollectorError::Storage(format!("read: {e}")))?;
        if n == 0 { break; }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn iso_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{}", secs) // ISO formatting happens in the sender side; collector uses unix seconds as the ts field
}
```

This task is large. The executor should expect to iterate on compile errors. Key items:

- axum 0.8 extractor order: state first, then path, then body
- `Json<serde_json::Value>` return type needs `IntoResponse`
- Error tuple `(StatusCode, String)` implements `IntoResponse` in axum 0.8

- [ ] **Step 2: Wire + build**

```bash
# add pub mod server; to lib.rs
cargo build -p epitropos-collector 2>&1 | tail -20
```

Expected: builds. Fix compile errors iteratively.

- [ ] **Step 3: Unit test helpers (no server boot)**

Add a small test module at the bottom of `server.rs` that exercises only the pure helpers (`iso_now`, `find_sender_for_manifest` with a known tempdir). Full integration test is in Task 15.

- [ ] **Step 4: Commit**

```bash
git add collector/src/server.rs collector/src/lib.rs
git -c commit.gpgsign=false commit -m "collector: axum router with health + enroll + push handlers"
```

## Task 14: TLS acceptor that feeds axum and exposes peer cert to handlers

**Files:**
- Modify: `collector/src/server.rs`
- Modify: `collector/src/tls.rs`

Hand-wire a `tokio::net::TcpListener` + `tokio_rustls::TlsAcceptor` loop that accepts connections, performs the TLS handshake, extracts the peer's leaf cert DER from the rustls `ServerConnection`, and injects it as a request extension so the `push_handler` can identify the authenticated sender without the slow `find_sender_for_manifest` walk.

This task is architecturally identical to the hyper-rustls "server with client cert" example. The executor should copy that pattern, replacing the fallback lookup in `push_handler` with a direct read from the request's `Extensions`.

- [ ] **Step 1: Add `serve()` function that runs the accept loop**
- [ ] **Step 2: Replace `find_sender_for_manifest` fallback with extension lookup**
- [ ] **Step 3: Build, commit**

---

# Phase 5 — Collector CLI

## Task 15: `cli.rs` + dispatch in main.rs

Subcommands: `serve`, `enroll`, `revoke`, `list`, `rotate-cert`, `verify`, `--version`.

`serve` calls `server::serve(cfg)`. `enroll <name>` uses `enroll::generate_token` + `write_pending`. `revoke <name>` moves the sender dir to `senders-revoked/<name>.<ts>/`. `list` walks `senders/` and prints a table. `rotate-cert` generates a new TLS cert via `rcgen`, saves the old one. `verify <path>` loads the manifest, finds the sender, verifies.

Full implementation is mechanical once the modules above exist. Commit as one task.

## Task 16: `epitropos-collector-keygen` first-boot helper (inlined in `cli.rs` as a subcommand)

Add a `keygen` subcommand that:
1. Checks if `tls/cert.pem` exists; exits 0 if so (idempotent for systemd oneshot).
2. Generates an ed25519 keypair via `rcgen`, 10-year validity.
3. Writes `tls/cert.pem` and `tls/key.pem` with mode 0400 owned by the current user.
4. Generates `tls/enroll.secret` via `enroll::generate_secret`.

---

# Phase 6 — NixOS collector module

## Task 17: `nixos-module-collector.nix`

Boilerplate module per spec §9.3. Generates config via `pkgs.formats.toml`, creates user, systemd units, tmpfiles, optional firewall rule.

## Task 18: Flake export `nixosModules.collector`

---

# Phase 7 — `epitropos-forward` rewrite

## Task 19: Add `ureq` + `rcgen` deps to proxy/Cargo.toml

## Task 20: `proxy/src/forward_config.rs` — TOML config for the forward side

## Task 21: Replace `proxy/src/forward.rs` stub with CLI dispatcher

Subcommands: `enroll`, `push`, `status`, `--version`.

## Task 22: `enroll` subcommand

1. Load or generate sender cert via `rcgen`.
2. Open TLS to collector, capture server cert.
3. Verify fingerprint matches `--expect-fingerprint`.
4. POST `/v1/enroll` with JSON body.
5. On 200, write `collector.pem` to state dir.

## Task 23: `push` subcommand

1. Load config + state (`last_shipped.hash`).
2. Read katagrapho's `head.hash.log`, find tail after `last_shipped.hash`.
3. For each pending line, open mTLS connection, frame + stream manifest + recording, handle 200/409/412/422.
4. Update `last_shipped.hash` atomically on success.

## Task 24: `status` subcommand

---

# Phase 8 — Forward NixOS submodule

## Task 25: Extend `nixos-module.nix` with `services.epitropos.forward.*`

---

# Phase 9 — Integration tests + VM test + acceptance

## Task 26: `collector/tests/e2e.rs` — in-process axum + hyper client

Boot a test collector on 127.0.0.1:0 with a tempdir as storage, generate an enrollment token, enroll, push a synthesized manifest + recording, assert 200 and filesystem state.

## Task 27: `tests/vm-collector.nix` — two-node VM test

Per spec §12.4.

## Task 28: Acceptance walkthrough — run every criterion from spec §14

## Task 29: `cargo clippy --all-targets --workspace -- -D warnings` clean

## Task 30: Push both track-c branches, merge to main

---

# Self-Review Notes

**Spec coverage:**
- §2 workspace restructure → Tasks 1–4
- §3 protocol → Tasks 13 (server routes), 14 (TLS peer cert threading), 22 (sender side)
- §4 enrollment tokens → Task 11
- §5 collector storage → Task 10
- §6 sender forward → Tasks 19–24
- §7 configs → Tasks 7 (collector), 20 (forward)
- §8 privilege separation (two keys + katagrapho-readers) → Task 5 (group), Task 22 (forward reads signing.pub)
- §9 NixOS modules → Tasks 17, 18, 25
- §10 collector CLI → Tasks 15, 16
- §11 deps → Tasks 6, 19
- §12 testing → Tasks 6–16 unit tests inline + Task 26 e2e + Task 27 VM
- §13 risks — mitigations are implicit in tasks
- §14 acceptance — Task 28

**Acknowledged gap:** Task 13 initially implements push-sender-identification by walking `senders/*/signing.pub` (O(senders) per request). Task 14 replaces it with peer-cert-identification via TLS extensions. The gap exists only between those two commits and is covered by a comment in the code. Mark this in the PR description.

**Known complexity hotspots:**
- Task 13 (server handlers) — ~400 lines, iterate on compile errors
- Task 14 (TLS peer cert threading) — depends on rustls + axum extractor plumbing; copy from the hyper-rustls example
- Task 23 (push subcommand) — streaming framed body over ureq; ureq's reader API needs the manifest written to an intermediate buffer before the recording bytes
