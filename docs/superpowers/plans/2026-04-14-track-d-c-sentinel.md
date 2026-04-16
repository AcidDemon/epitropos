# Track D(c) — epitropos-sentinel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** `epitropos/docs/superpowers/specs/2026-04-14-track-d-c-sentinel.md`

**Goal:** Add a new `sentinel/` workspace member that post-hoc analyzes decrypted session recordings against regex rules, emits structured events to journald, and writes signed events sidecars next to each recording.

**Architecture:** Third workspace member alongside `proxy/` and `collector/`. inotify-driven daemon on the collector host, streaming age decryption with its own key, Rust `regex` crate (RE2-style, no ReDoS), ed25519-signed events sidecar per session, per-host chain via `prev_events_hash`. Proxy and collector crates remain untouched.

**Tech Stack:** Rust edition 2024, tokio, age 0.11, regex 1, ed25519-dalek 2, sha2, inotify, serde/toml. Only the new sentinel crate adds these; proxy and collector trees are unchanged.

**Repo:** `/home/acid/Workspace/repos/epitropos/` — new `sentinel/` member.

**Phase order:**
1. Phase 1 — Workspace scaffolding + error + config
2. Phase 2 — Rules engine (compile + match + cooldown)
3. Phase 3 — Decryption + kgv1 parsing
4. Phase 4 — Signing + events sidecar
5. Phase 5 — Chain (per-host head pointer)
6. Phase 6 — journald emission
7. Phase 7 — Engine orchestration (scan → decrypt → match → emit)
8. Phase 8 — Inotify watcher + daemon
9. Phase 9 — CLI subcommands (keygen / list-rules / analyze / verify / serve)
10. Phase 10 — NixOS module
11. Phase 11 — VM test + acceptance

**Commit hygiene:** `git -c commit.gpgsign=false commit`, no Co-Authored-By, one task = one commit, `--jobs 1` for cargo commands to limit system load.

---

## File structure (new in this track)

```
epitropos/
├── Cargo.toml                            # MODIFY: members += "sentinel"
├── sentinel/
│   ├── Cargo.toml                        # CREATE
│   ├── build.rs                          # CREATE
│   └── src/
│       ├── main.rs                       # CLI dispatch
│       ├── lib.rs                        # module exports
│       ├── error.rs                      # SentinelError + sysexits
│       ├── config.rs                     # TOML config
│       ├── rules.rs                      # compile + match + cooldown
│       ├── decrypt.rs                    # age streaming decrypt
│       ├── signing.rs                    # ed25519 load/generate/sign/verify
│       ├── events.rs                     # events sidecar build + sign + write
│       ├── chain.rs                      # per-host head pointer
│       ├── journal.rs                    # structured journald emission
│       ├── engine.rs                     # orchestration per session
│       └── watcher.rs                    # inotify loop
├── nixos-module-sentinel.nix             # CREATE
└── tests/
    └── vm-sentinel.nix                   # CREATE (two-node VM test)
```

---

# Phase 1 — Scaffolding

## Task 1: Create worktree

- [ ] **Step 1**

```bash
cd /home/acid/Workspace/repos/epitropos
git worktree add .worktrees/track-d-c -b track-d-c main
cd .worktrees/track-d-c
cargo test --workspace --jobs 1 2>&1 | tail -5
```

Expected: proxy + collector baselines pass.

## Task 2: Add sentinel to workspace

**Files:**
- Modify: `Cargo.toml`
- Create: `sentinel/Cargo.toml`
- Create: `sentinel/src/main.rs`
- Create: `sentinel/build.rs`

- [ ] **Step 1: Workspace root**

Modify `Cargo.toml`:

```toml
[workspace]
members = ["proxy", "collector", "sentinel"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"
```

- [ ] **Step 2: Sentinel Cargo.toml**

Create `sentinel/Cargo.toml`:

```toml
[package]
name = "epitropos-sentinel"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "Post-hoc security event detector for epitropos session recordings"

[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "net", "io-util", "fs", "macros", "signal"] }
age = { version = "0.11", default-features = false }
regex = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
thiserror = "1"
ed25519-dalek = { version = "2", default-features = false, features = ["std"] }
sha2 = "0.10"
hex = "0.4"
inotify = "0.11"
libc = "0.2"
rand = "0.8"

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 3: build.rs**

Create `sentinel/build.rs`:

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
    println!("cargo:rustc-env=EPITROPOS_SENTINEL_GIT_COMMIT={commit}");
}
```

- [ ] **Step 4: Placeholder main.rs**

Create `sentinel/src/main.rs`:

```rust
fn main() {
    eprintln!("epitropos-sentinel: not yet implemented");
    std::process::exit(69);
}
```

- [ ] **Step 5: Build + commit**

```bash
cargo build --workspace --jobs 1 2>&1 | tail -5
git add Cargo.toml sentinel/
git -c commit.gpgsign=false commit -m "workspace: add sentinel member skeleton"
```

## Task 3: error.rs

**Files:**
- Create: `sentinel/src/lib.rs`
- Create: `sentinel/src/error.rs`

- [ ] **Step 1: lib.rs**

```rust
pub mod error;
```

- [ ] **Step 2: error.rs**

```rust
use std::io;

pub const EX_USAGE: i32 = 64;
pub const EX_DATAERR: i32 = 65;
pub const EX_NOINPUT: i32 = 66;
pub const EX_SOFTWARE: i32 = 70;
pub const EX_IOERR: i32 = 74;
pub const EX_CONFIG: i32 = 78;

#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("usage: {0}")]
    Usage(String),

    #[error("config: {0}")]
    Config(String),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("rules: {0}")]
    Rules(String),

    #[error("decrypt: {0}")]
    Decrypt(String),

    #[error("signing: {0}")]
    Signing(String),

    #[error("verify: {0}")]
    Verify(String),

    #[error("chain: {0}")]
    Chain(String),

    #[error("events: {0}")]
    Events(String),

    #[error("internal: {0}")]
    #[allow(dead_code)]
    Internal(String),
}

impl SentinelError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => EX_USAGE,
            Self::Config(_) => EX_CONFIG,
            Self::Io(_) => EX_IOERR,
            Self::Rules(_) => EX_CONFIG,
            Self::Decrypt(_) => EX_DATAERR,
            Self::Signing(_) => EX_SOFTWARE,
            Self::Verify(_) => EX_DATAERR,
            Self::Chain(_) => EX_IOERR,
            Self::Events(_) => EX_IOERR,
            Self::Internal(_) => EX_SOFTWARE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_distinct() {
        assert_eq!(SentinelError::Usage("x".into()).exit_code(), EX_USAGE);
        assert_eq!(SentinelError::Config("x".into()).exit_code(), EX_CONFIG);
        assert_eq!(SentinelError::Rules("x".into()).exit_code(), EX_CONFIG);
        assert_eq!(SentinelError::Verify("x".into()).exit_code(), EX_DATAERR);
        assert_eq!(SentinelError::Chain("x".into()).exit_code(), EX_IOERR);
    }
}
```

- [ ] **Step 3: Update main.rs**

```rust
use epitropos_sentinel::error::SentinelError;

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("epitropos-sentinel: {e}");
            std::process::exit(e.exit_code());
        }
    }
}

fn run() -> Result<(), SentinelError> {
    Err(SentinelError::Usage(
        "CLI dispatcher not yet wired (Track D(c) Phase 9)".into(),
    ))
}
```

- [ ] **Step 4: Test + commit**

```bash
cargo test -p epitropos-sentinel --jobs 1 error:: 2>&1 | tail -5
git add sentinel/
git -c commit.gpgsign=false commit -m "error: SentinelError + sysexits"
```

## Task 4: config.rs

**Files:**
- Create: `sentinel/src/config.rs`

- [ ] **Step 1: Write config.rs**

```rust
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::SentinelError;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub storage: Storage,
    #[serde(default)]
    pub keys: Keys,
    #[serde(default)]
    pub rules: RulesCfg,
    #[serde(default)]
    pub cooldown: Cooldown,
    #[serde(default)]
    pub context: Context,
    #[serde(default)]
    pub journal: Journal,
    #[serde(default)]
    pub events_sidecar: EventsSidecar,
    #[serde(default)]
    pub chain: ChainCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    #[serde(default = "Storage::default_dir")]
    pub dir: PathBuf,
}
impl Storage {
    fn default_dir() -> PathBuf { PathBuf::from("/var/lib/epitropos-collector") }
}
impl Default for Storage { fn default() -> Self { Self { dir: Self::default_dir() } } }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keys {
    #[serde(default = "Keys::default_age")]
    pub age_identity: PathBuf,
    #[serde(default = "Keys::default_sign_key")]
    pub signing_key: PathBuf,
    #[serde(default = "Keys::default_sign_pub")]
    pub signing_pub: PathBuf,
}
impl Keys {
    fn default_age() -> PathBuf { PathBuf::from("/var/lib/epitropos-sentinel/sentinel.key") }
    fn default_sign_key() -> PathBuf { PathBuf::from("/var/lib/epitropos-sentinel/signing.key") }
    fn default_sign_pub() -> PathBuf { PathBuf::from("/var/lib/epitropos-sentinel/signing.pub") }
}
impl Default for Keys {
    fn default() -> Self {
        Self { age_identity: Self::default_age(), signing_key: Self::default_sign_key(), signing_pub: Self::default_sign_pub() }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesCfg {
    #[serde(default = "RulesCfg::default_path")]
    pub path: PathBuf,
    #[serde(default = "RulesCfg::default_reload")]
    pub reload_on_change: bool,
}
impl RulesCfg {
    fn default_path() -> PathBuf { PathBuf::from("/etc/epitropos-sentinel/rules.toml") }
    fn default_reload() -> bool { true }
}
impl Default for RulesCfg {
    fn default() -> Self { Self { path: Self::default_path(), reload_on_change: Self::default_reload() } }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cooldown {
    #[serde(default = "Cooldown::default_secs")]
    pub per_rule_per_session_seconds: u64,
}
impl Cooldown { fn default_secs() -> u64 { 30 } }
impl Default for Cooldown { fn default() -> Self { Self { per_rule_per_session_seconds: Self::default_secs() } } }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    #[serde(default = "Context::default_before")]
    pub before_chars: usize,
    #[serde(default = "Context::default_after")]
    pub after_chars: usize,
}
impl Context {
    fn default_before() -> usize { 200 }
    fn default_after() -> usize { 200 }
}
impl Default for Context {
    fn default() -> Self { Self { before_chars: Self::default_before(), after_chars: Self::default_after() } }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    #[serde(default = "Journal::default_on")]
    pub enabled: bool,
}
impl Journal { fn default_on() -> bool { true } }
impl Default for Journal { fn default() -> Self { Self { enabled: Self::default_on() } } }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSidecar {
    #[serde(default = "EventsSidecar::default_on")]
    pub enabled: bool,
}
impl EventsSidecar { fn default_on() -> bool { true } }
impl Default for EventsSidecar { fn default() -> Self { Self { enabled: Self::default_on() } } }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainCfg {
    #[serde(default = "ChainCfg::default_head")]
    pub head_path: PathBuf,
}
impl ChainCfg { fn default_head() -> PathBuf { PathBuf::from("/var/lib/epitropos-sentinel/head.hash") } }
impl Default for ChainCfg { fn default() -> Self { Self { head_path: Self::default_head() } } }

impl Default for Config {
    fn default() -> Self {
        Self {
            storage: Storage::default(),
            keys: Keys::default(),
            rules: RulesCfg::default(),
            cooldown: Cooldown::default(),
            context: Context::default(),
            journal: Journal::default(),
            events_sidecar: EventsSidecar::default(),
            chain: ChainCfg::default(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, SentinelError> {
        let s = fs::read_to_string(path)
            .map_err(|e| SentinelError::Config(format!("read {}: {e}", path.display())))?;
        toml::from_str(&s).map_err(|e| SentinelError::Config(format!("parse: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_when_empty() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.cooldown.per_rule_per_session_seconds, 30);
        assert_eq!(cfg.context.before_chars, 200);
        assert!(cfg.journal.enabled);
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
    fn overrides_apply() {
        let toml_str = r#"
[cooldown]
per_rule_per_session_seconds = 5
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.cooldown.per_rule_per_session_seconds, 5);
    }
}
```

- [ ] **Step 2: Wire + test + commit**

```rust
// Add to sentinel/src/lib.rs
pub mod config;
```

```bash
cargo test -p epitropos-sentinel --jobs 1 config:: 2>&1 | tail -10
git add sentinel/
git -c commit.gpgsign=false commit -m "config: TOML with deny_unknown_fields"
```

---

# Phase 2 — Rules Engine

## Task 5: rules.rs — compile + match + cooldown

**Files:**
- Create: `sentinel/src/rules.rs`

- [ ] **Step 1: Write rules.rs**

```rust
//! Rule compilation + streaming matcher + per-(rule, session) cooldown.

use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::error::SentinelError;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    rules: Vec<RuleDef>,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub def: RuleDef,
    pub regexes: Vec<Regex>,
}

#[derive(Debug)]
pub struct RuleSet {
    pub rules: Vec<CompiledRule>,
    pub source_sha256: String,
}

impl RuleSet {
    pub fn load(path: &Path) -> Result<Self, SentinelError> {
        let bytes = fs::read(path)
            .map_err(|e| SentinelError::Rules(format!("read {}: {e}", path.display())))?;
        let mut h = Sha256::new();
        h.update(&bytes);
        let source_sha256 = hex::encode(h.finalize());

        let parsed: RulesFile = toml::from_slice(&bytes)
            .map_err(|e| SentinelError::Rules(format!("parse: {e}")))?;

        let mut compiled = Vec::with_capacity(parsed.rules.len());
        for def in parsed.rules {
            let mut regexes = Vec::with_capacity(def.patterns.len());
            for pat in &def.patterns {
                let rx = Regex::new(pat).map_err(|e| {
                    SentinelError::Rules(format!("rule {}: pattern {:?}: {e}", def.id, pat))
                })?;
                regexes.push(rx);
            }
            compiled.push(CompiledRule { def, regexes });
        }
        Ok(RuleSet { rules: compiled, source_sha256 })
    }
}

#[derive(Debug, Clone)]
pub struct Match {
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub matched_text: String,
    pub context: String,
    pub session_time: f64,
}

/// Per-session matcher with cooldown. One instance per session.
pub struct SessionMatcher<'a> {
    rules: &'a RuleSet,
    cooldown: Duration,
    last_fired: HashMap<String, Instant>,
    before_chars: usize,
    after_chars: usize,
    rolling_buffer: String,  // last ~before_chars bytes of output for context
    max_buffer_bytes: usize,
}

impl<'a> SessionMatcher<'a> {
    pub fn new(
        rules: &'a RuleSet,
        cooldown_secs: u64,
        before_chars: usize,
        after_chars: usize,
    ) -> Self {
        Self {
            rules,
            cooldown: Duration::from_secs(cooldown_secs),
            last_fired: HashMap::new(),
            before_chars,
            after_chars,
            rolling_buffer: String::new(),
            max_buffer_bytes: before_chars.max(4096),
        }
    }

    /// Feed one decoded `out` record's text. Returns matches that fired.
    pub fn feed(&mut self, t: f64, text: &str) -> Vec<Match> {
        let mut out = Vec::new();
        let now = Instant::now();

        // Context: check rolling buffer + new text for each rule.
        let combined = {
            let mut c = String::with_capacity(self.rolling_buffer.len() + text.len());
            c.push_str(&self.rolling_buffer);
            c.push_str(text);
            c
        };

        for rule in &self.rules.rules {
            // Cooldown check
            if let Some(last) = self.last_fired.get(&rule.def.id) {
                if now.duration_since(*last) < self.cooldown {
                    continue;
                }
            }

            for rx in &rule.regexes {
                if let Some(m) = rx.find(&combined) {
                    let match_start = m.start();
                    let match_end = m.end();
                    let context_start = match_start.saturating_sub(self.before_chars);
                    let context_end = (match_end + self.after_chars).min(combined.len());
                    // Clamp to char boundaries.
                    let context_start = find_char_boundary(&combined, context_start);
                    let context_end = find_char_boundary(&combined, context_end);
                    let matched_text = combined[match_start..match_end].to_string();
                    let context = combined[context_start..context_end].to_string();

                    out.push(Match {
                        rule_id: rule.def.id.clone(),
                        severity: rule.def.severity.clone(),
                        category: rule.def.category.clone(),
                        description: rule.def.description.clone(),
                        matched_text,
                        context,
                        session_time: t,
                    });
                    self.last_fired.insert(rule.def.id.clone(), now);
                    break; // one pattern match per rule is enough
                }
            }
        }

        // Update rolling buffer
        self.rolling_buffer.push_str(text);
        if self.rolling_buffer.len() > self.max_buffer_bytes {
            let drop_to = self.rolling_buffer.len() - self.max_buffer_bytes;
            let boundary = find_char_boundary(&self.rolling_buffer, drop_to);
            self.rolling_buffer.drain(..boundary);
        }

        out
    }
}

fn find_char_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    fn write_rules(contents: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "{}", contents).unwrap();
        f
    }

    #[test]
    fn compiles_valid_rules() {
        let f = write_rules(r#"
[[rules]]
id = "test"
severity = "high"
category = "test"
description = "Test"
patterns = ["\\bsudo\\s+"]
"#);
        let rs = RuleSet::load(f.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        assert_eq!(rs.rules[0].def.id, "test");
        assert_eq!(rs.source_sha256.len(), 64);
    }

    #[test]
    fn rejects_invalid_regex() {
        let f = write_rules(r#"
[[rules]]
id = "bad"
severity = "low"
category = "test"
description = "Bad"
patterns = ["(unclosed"]
"#);
        let err = RuleSet::load(f.path()).unwrap_err();
        match err {
            SentinelError::Rules(msg) => {
                assert!(msg.contains("bad"));
            }
            _ => panic!("wrong error variant"),
        }
    }

    #[test]
    fn matcher_fires_on_pattern() {
        let f = write_rules(r#"
[[rules]]
id = "sudo"
severity = "high"
category = "priv"
description = "sudo"
patterns = ["\\bsudo\\s+"]
"#);
        let rs = RuleSet::load(f.path()).unwrap();
        let mut m = SessionMatcher::new(&rs, 30, 100, 100);
        let hits = m.feed(1.0, "alice@host:~$ sudo ls\n");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "sudo");
        assert!(hits[0].matched_text.contains("sudo"));
    }

    #[test]
    fn matcher_cooldown_suppresses_duplicates() {
        let f = write_rules(r#"
[[rules]]
id = "sudo"
severity = "high"
category = "priv"
description = "sudo"
patterns = ["\\bsudo\\s+"]
"#);
        let rs = RuleSet::load(f.path()).unwrap();
        let mut m = SessionMatcher::new(&rs, 3600, 100, 100); // huge cooldown
        let hit1 = m.feed(1.0, "sudo ls\n");
        let hit2 = m.feed(2.0, "sudo ls\n");
        assert_eq!(hit1.len(), 1);
        assert_eq!(hit2.len(), 0);
    }

    #[test]
    fn near_miss_does_not_fire() {
        let f = write_rules(r#"
[[rules]]
id = "sudo"
severity = "high"
category = "priv"
description = "sudo"
patterns = ["\\bsudo\\s+"]
"#);
        let rs = RuleSet::load(f.path()).unwrap();
        let mut m = SessionMatcher::new(&rs, 30, 100, 100);
        let hits = m.feed(1.0, "sudoku puzzle\n");
        assert_eq!(hits.len(), 0);
    }

    #[test]
    fn context_includes_surrounding_text() {
        let f = write_rules(r#"
[[rules]]
id = "sudo"
severity = "high"
category = "priv"
description = "sudo"
patterns = ["\\bsudo\\s+"]
"#);
        let rs = RuleSet::load(f.path()).unwrap();
        let mut m = SessionMatcher::new(&rs, 30, 50, 50);
        let hits = m.feed(1.0, "prompt:~$ sudo -u root whoami\nroot\n");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].context.contains("sudo"));
        assert!(hits[0].context.contains("whoami") || hits[0].context.contains("root"));
    }
}
```

Note: toml 0.8 removed `from_slice`; replace with `from_str(std::str::from_utf8(&bytes)?)`.

- [ ] **Step 2: Fix toml parse**

In the `load` function, replace:

```rust
let parsed: RulesFile = toml::from_slice(&bytes)
    .map_err(|e| SentinelError::Rules(format!("parse: {e}")))?;
```

with:

```rust
let s = std::str::from_utf8(&bytes)
    .map_err(|e| SentinelError::Rules(format!("utf8: {e}")))?;
let parsed: RulesFile = toml::from_str(s)
    .map_err(|e| SentinelError::Rules(format!("parse: {e}")))?;
```

- [ ] **Step 3: Wire + test + commit**

```rust
// lib.rs
pub mod rules;
```

```bash
cargo test -p epitropos-sentinel --jobs 1 rules:: 2>&1 | tail -15
git add sentinel/
git -c commit.gpgsign=false commit -m "rules: compile + streaming match + cooldown"
```

---

# Phase 3 — Decryption

## Task 6: decrypt.rs — streaming age + kgv1 parsing

**Files:**
- Create: `sentinel/src/decrypt.rs`

- [ ] **Step 1: Write decrypt.rs**

```rust
//! Streaming age decryption + kgv1 line extraction.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::error::SentinelError;

pub struct KgvRecord {
    pub kind: String,
    pub t: f64,
    pub data: Option<String>,  // base64-decoded bytes, UTF-8-lossy, for `out`/`in`
    pub cols: Option<u16>,
    pub rows: Option<u16>,
    pub raw: serde_json::Value,
}

pub fn iterate_records<F>(
    path: &Path,
    identity_str: &str,
    mut f: F,
) -> Result<(), SentinelError>
where
    F: FnMut(&KgvRecord) -> Result<(), SentinelError>,
{
    let identity: age::x25519::Identity = identity_str
        .trim()
        .parse()
        .map_err(|e| SentinelError::Decrypt(format!("parse identity: {e}")))?;

    let file = File::open(path)
        .map_err(|e| SentinelError::Decrypt(format!("open {}: {e}", path.display())))?;

    let decryptor = age::Decryptor::new(file)
        .map_err(|e| SentinelError::Decrypt(format!("age header: {e}")))?;

    let reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| SentinelError::Decrypt(format!("decrypt: {e}")))?;

    let buf = BufReader::new(reader);
    for line in buf.lines() {
        let line = line.map_err(|e| SentinelError::Decrypt(format!("read: {e}")))?;
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let kind = v["kind"].as_str().unwrap_or("").to_string();
        let t = v["t"].as_f64().unwrap_or(0.0);
        let data = match kind.as_str() {
            "out" | "in" => v["b"].as_str().and_then(|b64| decode_base64(b64).ok())
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
            _ => None,
        };
        let cols = v["cols"].as_u64().map(|x| x as u16);
        let rows = v["rows"].as_u64().map(|x| x as u16);

        let rec = KgvRecord { kind, t, data, cols, rows, raw: v };
        f(&rec)?;
    }
    Ok(())
}

fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
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
        return Err("base64 len not multiple of 4".into());
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
    use std::io::Write;
    use tempfile::tempdir;

    fn age_encrypt(plaintext: &[u8], recipient: &age::x25519::Recipient) -> Vec<u8> {
        let encryptor = age::Encryptor::with_recipients(
            std::iter::once(recipient as &dyn age::Recipient),
        ).unwrap();
        let mut out = Vec::new();
        let mut writer = encryptor.wrap_output(&mut out).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();
        out
    }

    #[test]
    fn iterate_records_yields_kinds() {
        use age::secrecy::ExposeSecret;
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let kgv = concat!(
            "{\"kind\":\"header\",\"v\":\"katagrapho-v1\",\"session_id\":\"t\",\"user\":\"a\",",
            "\"host\":\"h\",\"boot_id\":\"b\",\"part\":0,\"started\":1.0,\"cols\":80,\"rows\":24,",
            "\"shell\":\"/bin/sh\",\"epitropos_version\":\"0\",\"epitropos_commit\":\"0\",",
            "\"katagrapho_version\":\"0\",\"katagrapho_commit\":\"0\",\"audit_session_id\":null,",
            "\"ppid\":1,\"ssh_client\":null,\"ssh_connection\":null,\"ssh_original_command\":null,",
            "\"parent_comm\":null,\"parent_cmdline\":null,\"pam_rhost\":null,\"pam_service\":null,",
            "\"prev_manifest_hash_link\":null}\n",
            "{\"kind\":\"out\",\"t\":0.5,\"b\":\"aGVsbG8=\"}\n",
            "{\"kind\":\"end\",\"t\":1.0,\"reason\":\"eof\",\"exit_code\":0}\n",
        );
        let encrypted = age_encrypt(kgv.as_bytes(), &recipient);
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.kgv1.age");
        std::fs::write(&path, encrypted).unwrap();

        let identity_str = format!("{}", identity.to_string().expose_secret());
        let mut kinds = Vec::new();
        iterate_records(&path, &identity_str, |rec| {
            kinds.push(rec.kind.clone());
            Ok(())
        }).unwrap();
        assert_eq!(kinds, vec!["header", "out", "end"]);
    }

    #[test]
    fn out_record_decodes_base64() {
        use age::secrecy::ExposeSecret;
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let kgv = "{\"kind\":\"out\",\"t\":0.5,\"b\":\"aGVsbG8=\"}\n";
        let encrypted = age_encrypt(kgv.as_bytes(), &recipient);
        let dir = tempdir().unwrap();
        let path = dir.path().join("t.age");
        std::fs::write(&path, encrypted).unwrap();
        let identity_str = format!("{}", identity.to_string().expose_secret());

        let mut got = None;
        iterate_records(&path, &identity_str, |rec| {
            if rec.kind == "out" {
                got = rec.data.clone();
            }
            Ok(())
        }).unwrap();
        assert_eq!(got.as_deref(), Some("hello"));
    }

    #[test]
    fn wrong_identity_returns_error() {
        use age::secrecy::ExposeSecret;
        let identity = age::x25519::Identity::generate();
        let other = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let kgv = "{\"kind\":\"out\",\"t\":0.5,\"b\":\"aGVsbG8=\"}\n";
        let encrypted = age_encrypt(kgv.as_bytes(), &recipient);
        let dir = tempdir().unwrap();
        let path = dir.path().join("t.age");
        std::fs::write(&path, encrypted).unwrap();
        let wrong = format!("{}", other.to_string().expose_secret());
        let res = iterate_records(&path, &wrong, |_| Ok(()));
        assert!(res.is_err());
    }
}
```

- [ ] **Step 2: Wire + test + commit**

```rust
// lib.rs
pub mod decrypt;
```

```bash
cargo test -p epitropos-sentinel --jobs 1 decrypt:: 2>&1 | tail -10
git add sentinel/
git -c commit.gpgsign=false commit -m "decrypt: streaming age + kgv1 record iterator"
```

---

# Phase 4 — Signing + Events Sidecar

## Task 7: signing.rs

**Files:**
- Create: `sentinel/src/signing.rs`

- [ ] **Step 1: Copy pattern from katagrapho signing.rs**

Copy the full contents of `/home/acid/Workspace/repos/katagrapho/src/signing.rs` into `sentinel/src/signing.rs`. Replace every `KatagraphoError` with `SentinelError`:

```rust
//! Ed25519 key loading and signing for sentinel events sidecars.
//! Mirrors katagrapho's signing.rs.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::error::SentinelError;

pub struct KeyPair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl KeyPair {
    pub fn load(key_path: &Path, pub_path: &Path) -> Result<Self, SentinelError> {
        let key_bytes = fs::read(key_path)
            .map_err(|e| SentinelError::Signing(format!("read {}: {e}", key_path.display())))?;
        if key_bytes.len() != 32 {
            return Err(SentinelError::Signing(format!(
                "{} must be exactly 32 bytes, got {}",
                key_path.display(), key_bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key_bytes);
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();

        if pub_path.exists() {
            let on_disk = fs::read(pub_path).map_err(|e| {
                SentinelError::Signing(format!("read {}: {e}", pub_path.display()))
            })?;
            if on_disk.len() != 32 || on_disk != verifying.as_bytes() {
                return Err(SentinelError::Signing(
                    "signing.pub does not match signing.key".into(),
                ));
            }
        }

        Ok(Self { signing, verifying })
    }

    pub fn generate_to(key_path: &Path, pub_path: &Path) -> Result<Self, SentinelError> {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();

        let key_tmp = key_path.with_extension("tmp");
        let mut f = fs::OpenOptions::new()
            .create(true).write(true).truncate(true).mode(0o400)
            .open(&key_tmp)
            .map_err(|e| SentinelError::Signing(format!("open key tmp: {e}")))?;
        f.write_all(signing.as_bytes())
            .map_err(|e| SentinelError::Signing(format!("write key: {e}")))?;
        f.sync_all().map_err(|e| SentinelError::Signing(format!("fsync: {e}")))?;
        drop(f);
        fs::rename(&key_tmp, key_path)
            .map_err(|e| SentinelError::Signing(format!("rename key: {e}")))?;

        let pub_tmp = pub_path.with_extension("tmp");
        let mut f = fs::OpenOptions::new()
            .create(true).write(true).truncate(true).mode(0o444)
            .open(&pub_tmp)
            .map_err(|e| SentinelError::Signing(format!("open pub tmp: {e}")))?;
        f.write_all(verifying.as_bytes())
            .map_err(|e| SentinelError::Signing(format!("write pub: {e}")))?;
        f.sync_all().map_err(|e| SentinelError::Signing(format!("fsync: {e}")))?;
        drop(f);
        fs::rename(&pub_tmp, pub_path)
            .map_err(|e| SentinelError::Signing(format!("rename pub: {e}")))?;

        Ok(Self { signing, verifying })
    }

    pub fn sign(&self, digest: &[u8; 32]) -> [u8; 64] {
        self.signing.sign(digest).to_bytes()
    }

    pub fn key_id_hex(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.verifying.as_bytes());
        hex::encode(h.finalize())
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }
}

pub fn verify_with_pub(
    pub_bytes: &[u8; 32],
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), SentinelError> {
    let vk = VerifyingKey::from_bytes(pub_bytes)
        .map_err(|e| SentinelError::Verify(format!("invalid pubkey: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    vk.verify(digest, &sig)
        .map_err(|e| SentinelError::Verify(format!("signature: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_load_round_trip() {
        let dir = tempdir().unwrap();
        let k = dir.path().join("k");
        let p = dir.path().join("p");
        let kp = KeyPair::generate_to(&k, &p).unwrap();
        let kp2 = KeyPair::load(&k, &p).unwrap();
        assert_eq!(kp.public_bytes(), kp2.public_bytes());
    }

    #[test]
    fn sign_verify_round_trip() {
        let dir = tempdir().unwrap();
        let kp = KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let d = [7u8; 32];
        let s = kp.sign(&d);
        verify_with_pub(&kp.public_bytes(), &d, &s).unwrap();
    }

    #[test]
    fn verify_rejects_tampered() {
        let dir = tempdir().unwrap();
        let kp = KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let d = [7u8; 32];
        let mut s = kp.sign(&d);
        s[0] ^= 0xFF;
        assert!(verify_with_pub(&kp.public_bytes(), &d, &s).is_err());
    }
}
```

- [ ] **Step 2: Wire + test + commit**

```bash
# lib.rs: pub mod signing;
cargo test -p epitropos-sentinel --jobs 1 signing:: 2>&1 | tail -10
git add sentinel/
git -c commit.gpgsign=false commit -m "signing: ed25519 keypair (mirrors katagrapho)"
```

## Task 8: events.rs — sidecar build + sign + write + verify

**Files:**
- Create: `sentinel/src/events.rs`

- [ ] **Step 1: Write events.rs**

```rust
//! Events sidecar: build + sign + atomic write + verify.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::error::SentinelError;
use crate::signing::{KeyPair, verify_with_pub};

pub const EVENTS_VERSION: &str = "epitropos-sentinel-events-v1";
pub const GENESIS_PREV: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub t: f64,
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub matched_text: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsSidecar {
    pub v: String,
    pub session_id: String,
    pub part: u32,
    pub sentinel_version: String,
    pub sentinel_commit: String,
    pub rules_file_sha256: String,
    pub analyzed_at: f64,
    pub events: Vec<EventRecord>,
    pub prev_events_hash: String,
    #[serde(default)]
    pub this_events_hash: String,
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub signature: String,
}

impl EventsSidecar {
    fn canonical_bytes(&self) -> Result<Vec<u8>, SentinelError> {
        let json = serde_json::to_string(&serde_json::json!({
            "v": self.v,
            "session_id": self.session_id,
            "part": self.part,
            "sentinel_version": self.sentinel_version,
            "sentinel_commit": self.sentinel_commit,
            "rules_file_sha256": self.rules_file_sha256,
            "analyzed_at": self.analyzed_at,
            "events": self.events,
            "prev_events_hash": self.prev_events_hash,
        }))
        .map_err(|e| SentinelError::Events(format!("canonical: {e}")))?;
        Ok(json.into_bytes())
    }

    pub fn compute_hash(&self) -> Result<[u8; 32], SentinelError> {
        let bytes = self.canonical_bytes()?;
        let mut h = Sha256::new();
        h.update(&bytes);
        Ok(h.finalize().into())
    }

    pub fn sign(&mut self, key: &KeyPair) -> Result<(), SentinelError> {
        let digest = self.compute_hash()?;
        let sig = key.sign(&digest);
        self.this_events_hash = hex::encode(digest);
        self.key_id = key.key_id_hex();
        self.signature = base64_encode(&sig);
        Ok(())
    }

    pub fn verify(&self, pub_bytes: &[u8; 32]) -> Result<(), SentinelError> {
        let recomputed = self.compute_hash()?;
        let stored = hex::decode(&self.this_events_hash)
            .map_err(|e| SentinelError::Verify(format!("hex: {e}")))?;
        if stored.len() != 32 || recomputed[..] != stored[..] {
            return Err(SentinelError::Verify("content != this_events_hash".into()));
        }
        let sig_bytes = base64_decode(&self.signature)
            .map_err(|e| SentinelError::Verify(format!("sig base64: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(SentinelError::Verify("sig wrong length".into()));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        verify_with_pub(pub_bytes, &recomputed, &sig)
    }

    pub fn write_to(&self, path: &Path) -> Result<(), SentinelError> {
        let tmp = path.with_extension("tmp");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| SentinelError::Events(format!("serialize: {e}")))?;
        let mut f = fs::OpenOptions::new()
            .create(true).write(true).truncate(true).mode(0o640)
            .open(&tmp)
            .map_err(|e| SentinelError::Events(format!("open tmp: {e}")))?;
        f.write_all(json.as_bytes())
            .map_err(|e| SentinelError::Events(format!("write: {e}")))?;
        f.sync_all().map_err(|e| SentinelError::Events(format!("fsync: {e}")))?;
        drop(f);
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o640))
            .map_err(|e| SentinelError::Events(format!("chmod: {e}")))?;
        fs::rename(&tmp, path)
            .map_err(|e| SentinelError::Events(format!("rename: {e}")))?;
        Ok(())
    }

    pub fn load_from(path: &Path) -> Result<Self, SentinelError> {
        let bytes = fs::read(path)
            .map_err(|e| SentinelError::Events(format!("read {}: {e}", path.display())))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| SentinelError::Events(format!("parse {}: {e}", path.display())))
    }
}

fn base64_encode(input: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(ALPH[(b0 >> 2) as usize] as char);
        out.push(ALPH[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPH[((b1 & 0x0F) << 2 | b2 >> 6) as usize] as char);
        } else { out.push('='); }
        if chunk.len() > 2 {
            out.push(ALPH[(b2 & 0x3F) as usize] as char);
        } else { out.push('='); }
    }
    out
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
        return Err("base64 len not multiple of 4".into());
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
    use tempfile::tempdir;

    fn sample() -> EventsSidecar {
        EventsSidecar {
            v: EVENTS_VERSION.into(),
            session_id: "s1".into(),
            part: 0,
            sentinel_version: "0.1.0".into(),
            sentinel_commit: "abc".into(),
            rules_file_sha256: "00".repeat(32),
            analyzed_at: 1.0,
            events: vec![EventRecord {
                t: 1.23,
                rule_id: "test".into(),
                severity: "high".into(),
                category: "test".into(),
                description: "test".into(),
                matched_text: "sudo".into(),
                context: "prompt$ sudo".into(),
            }],
            prev_events_hash: GENESIS_PREV.into(),
            this_events_hash: String::new(),
            key_id: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let dir = tempdir().unwrap();
        let kp = KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let mut s = sample();
        s.sign(&kp).unwrap();
        s.verify(&kp.public_bytes()).unwrap();
    }

    #[test]
    fn verify_rejects_tampered() {
        let dir = tempdir().unwrap();
        let kp = KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let mut s = sample();
        s.sign(&kp).unwrap();
        s.events[0].matched_text = "tampered".into();
        assert!(s.verify(&kp.public_bytes()).is_err());
    }

    #[test]
    fn write_load_round_trip() {
        let dir = tempdir().unwrap();
        let kp = KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let mut s = sample();
        s.sign(&kp).unwrap();
        let path = dir.path().join("events.json");
        s.write_to(&path).unwrap();
        let loaded = EventsSidecar::load_from(&path).unwrap();
        loaded.verify(&kp.public_bytes()).unwrap();
    }
}
```

- [ ] **Step 2: Wire + test + commit**

```bash
# lib.rs: pub mod events;
cargo test -p epitropos-sentinel --jobs 1 events:: 2>&1 | tail -10
git add sentinel/
git -c commit.gpgsign=false commit -m "events: sidecar build/sign/verify with canonical JSON"
```

---

# Phase 5 — Chain

## Task 9: chain.rs — per-host head pointer

**Files:**
- Create: `sentinel/src/chain.rs`

- [ ] **Step 1: Write chain.rs**

```rust
//! Per-host head pointer for events sidecars. Mirrors katagrapho's
//! chain.rs but single-head (not per-sender).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::error::SentinelError;
use crate::events::GENESIS_PREV;

pub struct ChainPaths {
    pub head: PathBuf,
    pub lock: PathBuf,
}

impl ChainPaths {
    pub fn new(head: PathBuf) -> Self {
        let lock = head.with_extension("lock");
        Self { head, lock }
    }
}

pub struct ChainLock { file: fs::File }

impl ChainLock {
    pub fn acquire(paths: &ChainPaths) -> Result<Self, SentinelError> {
        if let Some(parent) = paths.lock.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| SentinelError::Chain(format!("mkdir {}: {e}", parent.display())))?;
        }
        let file = OpenOptions::new()
            .create(true).read(true).write(true).truncate(false).mode(0o600)
            .open(&paths.lock)
            .map_err(|e| SentinelError::Chain(format!("open lock: {e}")))?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(SentinelError::Chain(format!(
                "flock: {}", std::io::Error::last_os_error()
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

pub fn read_head(paths: &ChainPaths) -> Result<String, SentinelError> {
    if !paths.head.exists() {
        return Ok(GENESIS_PREV.to_string());
    }
    let s = fs::read_to_string(&paths.head)
        .map_err(|e| SentinelError::Chain(format!("read head: {e}")))?;
    let t = s.trim();
    if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SentinelError::Chain(format!("head not 64 hex: {t:?}")));
    }
    Ok(t.to_string())
}

pub fn write_head(paths: &ChainPaths, hex: &str) -> Result<(), SentinelError> {
    if hex.len() != 64 {
        return Err(SentinelError::Chain("hash not 64 hex".into()));
    }
    let tmp = paths.head.with_extension("tmp");
    let mut f = OpenOptions::new()
        .create(true).write(true).truncate(true).mode(0o600)
        .open(&tmp)
        .map_err(|e| SentinelError::Chain(format!("open tmp: {e}")))?;
    f.write_all(hex.as_bytes())
        .map_err(|e| SentinelError::Chain(format!("write: {e}")))?;
    f.sync_all().map_err(|e| SentinelError::Chain(format!("fsync: {e}")))?;
    drop(f);
    fs::rename(&tmp, &paths.head)
        .map_err(|e| SentinelError::Chain(format!("rename: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn genesis_when_missing() {
        let dir = tempdir().unwrap();
        let c = ChainPaths::new(dir.path().join("head.hash"));
        assert_eq!(read_head(&c).unwrap(), GENESIS_PREV);
    }

    #[test]
    fn write_read_round_trip() {
        let dir = tempdir().unwrap();
        let c = ChainPaths::new(dir.path().join("head.hash"));
        let h = "a".repeat(64);
        write_head(&c, &h).unwrap();
        assert_eq!(read_head(&c).unwrap(), h);
    }

    #[test]
    fn reject_bad_length() {
        let dir = tempdir().unwrap();
        let c = ChainPaths::new(dir.path().join("head.hash"));
        assert!(write_head(&c, "deadbeef").is_err());
    }

    #[test]
    fn lock_round_trip() {
        let dir = tempdir().unwrap();
        let c = ChainPaths::new(dir.path().join("head.hash"));
        { let _g = ChainLock::acquire(&c).unwrap(); }
        let _g2 = ChainLock::acquire(&c).unwrap();
    }
}
```

- [ ] **Step 2: Wire + test + commit**

```bash
# lib.rs: pub mod chain;
cargo test -p epitropos-sentinel --jobs 1 chain:: 2>&1 | tail -10
git add sentinel/
git -c commit.gpgsign=false commit -m "chain: per-host head pointer with flock"
```

---

# Phase 6 — Journal emission

## Task 10: journal.rs

**Files:**
- Create: `sentinel/src/journal.rs`

- [ ] **Step 1: Write journal.rs**

```rust
//! Structured journald emission for sentinel matches.

use std::os::unix::net::UnixDatagram;

const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

pub struct MatchEvent<'a> {
    pub rule_id: &'a str,
    pub severity: &'a str,
    pub category: &'a str,
    pub session_id: &'a str,
    pub part: u32,
    pub user: &'a str,
    pub host: &'a str,
    pub t: f64,
    pub matched_text: &'a str,
}

pub fn emit_match(ev: &MatchEvent) {
    let priority = match ev.severity {
        "critical" => "2",
        "high" => "4",
        _ => "5",
    };
    let msg = format!(
        "sentinel: {} matched in session {} at t={:.3}",
        ev.rule_id, ev.session_id, ev.t
    );
    let part_s = ev.part.to_string();
    let t_s = format!("{:.3}", ev.t);

    let fields: &[(&str, &str)] = &[
        ("MESSAGE", &msg),
        ("PRIORITY", priority),
        ("SYSLOG_IDENTIFIER", "epitropos-sentinel"),
        ("EPITROPOS_SENTINEL_EVENT", "match"),
        ("EPITROPOS_SENTINEL_RULE", ev.rule_id),
        ("EPITROPOS_SENTINEL_SEVERITY", ev.severity),
        ("EPITROPOS_SENTINEL_CATEGORY", ev.category),
        ("EPITROPOS_SENTINEL_SESSION", ev.session_id),
        ("EPITROPOS_SENTINEL_PART", &part_s),
        ("EPITROPOS_SENTINEL_USER", ev.user),
        ("EPITROPOS_SENTINEL_HOST", ev.host),
        ("EPITROPOS_SENTINEL_T", &t_s),
        ("EPITROPOS_SENTINEL_MATCH", ev.matched_text),
    ];

    let mut payload = String::new();
    for (k, v) in fields {
        payload.push_str(k);
        payload.push('=');
        payload.push_str(v);
        payload.push('\n');
    }

    let Ok(sock) = UnixDatagram::unbound() else { return };
    let _ = sock.send_to(payload.as_bytes(), JOURNAL_SOCKET);
}
```

- [ ] **Step 2: Commit**

```bash
# lib.rs: pub mod journal;
cargo check -p epitropos-sentinel --jobs 1 2>&1 | tail -3
git add sentinel/
git -c commit.gpgsign=false commit -m "journal: structured journald emission for matches"
```

---

# Phase 7 — Engine orchestration

## Task 11: engine.rs — scan → decrypt → match → emit

**Files:**
- Create: `sentinel/src/engine.rs`

- [ ] **Step 1: Write engine.rs**

```rust
//! Per-session orchestration: decrypt recording, run rules, emit
//! journald + build + sign + write events sidecar, advance chain.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::chain::{self, ChainLock, ChainPaths};
use crate::config::Config;
use crate::decrypt::iterate_records;
use crate::error::SentinelError;
use crate::events::{EventRecord, EventsSidecar, EVENTS_VERSION};
use crate::journal::{self, MatchEvent};
use crate::rules::{RuleSet, SessionMatcher};
use crate::signing::KeyPair;

pub struct AnalysisContext<'a> {
    pub cfg: &'a Config,
    pub rules: &'a RuleSet,
    pub age_identity: &'a str,
    pub signing: &'a KeyPair,
    pub emit_journal: bool,
}

/// Minimal manifest fields needed by the engine.
pub struct ManifestHeader {
    pub session_id: String,
    pub user: String,
    pub host: String,
    pub part: u32,
}

pub fn analyze_recording(
    ctx: &AnalysisContext,
    recording_path: &Path,
    manifest: &ManifestHeader,
    force: bool,
) -> Result<PathBuf, SentinelError> {
    let sidecar_path = sidecar_path_for(recording_path);
    if sidecar_path.exists() && !force {
        return Err(SentinelError::Events(format!(
            "events sidecar already exists at {} (use --force to overwrite)",
            sidecar_path.display()
        )));
    }

    let mut matcher = SessionMatcher::new(
        ctx.rules,
        ctx.cfg.cooldown.per_rule_per_session_seconds,
        ctx.cfg.context.before_chars,
        ctx.cfg.context.after_chars,
    );

    let mut events: Vec<EventRecord> = Vec::new();

    iterate_records(recording_path, ctx.age_identity, |rec| {
        if rec.kind == "out" || rec.kind == "in" {
            if let Some(ref text) = rec.data {
                let hits = matcher.feed(rec.t, text);
                for h in hits {
                    if ctx.emit_journal {
                        journal::emit_match(&MatchEvent {
                            rule_id: &h.rule_id,
                            severity: &h.severity,
                            category: &h.category,
                            session_id: &manifest.session_id,
                            part: manifest.part,
                            user: &manifest.user,
                            host: &manifest.host,
                            t: h.session_time,
                            matched_text: &h.matched_text,
                        });
                    }
                    events.push(EventRecord {
                        t: h.session_time,
                        rule_id: h.rule_id,
                        severity: h.severity,
                        category: h.category,
                        description: h.description,
                        matched_text: h.matched_text,
                        context: h.context,
                    });
                }
            }
        }
        Ok(())
    })?;

    // Build + sign + write sidecar under chain lock.
    let chain_paths = ChainPaths::new(ctx.cfg.chain.head_path.clone());
    let _lock = ChainLock::acquire(&chain_paths)?;
    let prev = chain::read_head(&chain_paths)?;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let mut sidecar = EventsSidecar {
        v: EVENTS_VERSION.into(),
        session_id: manifest.session_id.clone(),
        part: manifest.part,
        sentinel_version: env!("CARGO_PKG_VERSION").into(),
        sentinel_commit: env!("EPITROPOS_SENTINEL_GIT_COMMIT").into(),
        rules_file_sha256: ctx.rules.source_sha256.clone(),
        analyzed_at: now_unix,
        events,
        prev_events_hash: prev,
        this_events_hash: String::new(),
        key_id: String::new(),
        signature: String::new(),
    };
    sidecar.sign(ctx.signing)?;
    sidecar.write_to(&sidecar_path)?;

    chain::write_head(&chain_paths, &sidecar.this_events_hash)?;

    Ok(sidecar_path)
}

pub fn sidecar_path_for(recording: &Path) -> PathBuf {
    let mut s = recording.as_os_str().to_os_string();
    s.push(".events.json");
    PathBuf::from(s)
}
```

- [ ] **Step 2: Wire + check + commit**

```bash
# lib.rs: pub mod engine;
cargo check -p epitropos-sentinel --jobs 1 2>&1 | tail -5
git add sentinel/
git -c commit.gpgsign=false commit -m "engine: per-session analysis orchestration"
```

---

# Phase 8 — Inotify watcher

## Task 12: watcher.rs — discover manifests + trigger engine

**Files:**
- Create: `sentinel/src/watcher.rs`

- [ ] **Step 1: Write watcher.rs**

```rust
//! Inotify-driven discovery of new .manifest.json files. For each
//! finalized manifest, load its minimal header fields, locate the
//! matching .kgv1.age file, and invoke the engine.

use inotify::{Inotify, WatchMask};
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::engine::{self, AnalysisContext, ManifestHeader};
use crate::error::SentinelError;
use crate::rules::RuleSet;
use crate::signing::KeyPair;

pub fn watch_and_analyze(
    cfg: &Config,
    rules: &RuleSet,
    age_identity: &str,
    signing: &KeyPair,
) -> Result<(), SentinelError> {
    let inotify = Inotify::init().map_err(|e| SentinelError::Io(e))?;

    let watched = discover_dirs(&cfg.storage.dir)?;
    for dir in &watched {
        let _ = inotify
            .watches()
            .add(dir, WatchMask::CLOSE_WRITE | WatchMask::CREATE);
    }

    // Run an initial pass over existing manifests that don't yet have
    // sidecars (so sessions finalized before sentinel started aren't
    // skipped during normal operation).
    initial_pass(cfg, rules, age_identity, signing, &watched);

    let mut buffer = [0; 4096];
    let mut inotify = inotify;
    loop {
        let events = inotify
            .read_events_blocking(&mut buffer)
            .map_err(|e| SentinelError::Io(e))?;

        for ev in events {
            if let Some(name) = ev.name {
                let name_s = name.to_string_lossy();
                if !name_s.ends_with(".manifest.json") {
                    continue;
                }
                for dir in &watched {
                    let candidate = dir.join(name_s.as_ref());
                    if candidate.exists() {
                        handle_manifest(cfg, rules, age_identity, signing, &candidate);
                    }
                }
            }
        }
    }
}

fn initial_pass(
    cfg: &Config,
    rules: &RuleSet,
    identity: &str,
    signing: &KeyPair,
    watched: &[PathBuf],
) {
    for dir in watched {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json")
                    && path.file_name().map(|n| n.to_string_lossy().ends_with(".manifest.json")).unwrap_or(false)
                {
                    let sidecar = engine::sidecar_path_for(&strip_manifest_suffix(&path));
                    if !sidecar.exists() {
                        handle_manifest(cfg, rules, identity, signing, &path);
                    }
                }
            }
        }
    }
}

fn strip_manifest_suffix(manifest_path: &Path) -> PathBuf {
    // <name>.kgv1.age.manifest.json → <name>.kgv1.age
    let s = manifest_path.as_os_str().to_string_lossy().to_string();
    if let Some(stripped) = s.strip_suffix(".manifest.json") {
        return PathBuf::from(stripped);
    }
    manifest_path.to_path_buf()
}

fn discover_dirs(storage_dir: &Path) -> Result<Vec<PathBuf>, SentinelError> {
    // Collector layout: storage_dir/senders/<sender>/recordings/<user>/
    let mut dirs = Vec::new();
    let senders = storage_dir.join("senders");
    if !senders.exists() {
        return Ok(dirs);
    }
    if let Ok(entries) = std::fs::read_dir(&senders) {
        for entry in entries.flatten() {
            let recs = entry.path().join("recordings");
            if recs.exists()
                && let Ok(user_dirs) = std::fs::read_dir(&recs) {
                for user_entry in user_dirs.flatten() {
                    if user_entry.path().is_dir() {
                        dirs.push(user_entry.path());
                    }
                }
            }
        }
    }
    Ok(dirs)
}

fn handle_manifest(
    cfg: &Config,
    rules: &RuleSet,
    identity: &str,
    signing: &KeyPair,
    manifest_path: &Path,
) {
    let recording = strip_manifest_suffix(manifest_path);
    if !recording.exists() {
        eprintln!(
            "epitropos-sentinel: recording missing for {}",
            manifest_path.display()
        );
        return;
    }

    let header = match read_manifest_header(manifest_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("epitropos-sentinel: skip {}: {e}", manifest_path.display());
            return;
        }
    };

    let ctx = AnalysisContext {
        cfg,
        rules,
        age_identity: identity,
        signing,
        emit_journal: cfg.journal.enabled,
    };

    match engine::analyze_recording(&ctx, &recording, &header, false) {
        Ok(p) => eprintln!("epitropos-sentinel: analyzed {} -> {}", recording.display(), p.display()),
        Err(SentinelError::Events(msg)) if msg.contains("already exists") => {
            // Expected for sessions already analyzed.
        }
        Err(e) => eprintln!("epitropos-sentinel: analyze {} failed: {e}", recording.display()),
    }
}

fn read_manifest_header(path: &Path) -> Result<ManifestHeader, SentinelError> {
    let bytes = std::fs::read(path)
        .map_err(|e| SentinelError::Events(format!("read {}: {e}", path.display())))?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| SentinelError::Events(format!("parse: {e}")))?;
    Ok(ManifestHeader {
        session_id: v["session_id"].as_str().unwrap_or("").to_string(),
        user: v["user"].as_str().unwrap_or("").to_string(),
        host: v["host"].as_str().unwrap_or("").to_string(),
        part: v["part"].as_u64().unwrap_or(0) as u32,
    })
}
```

- [ ] **Step 2: Wire + check + commit**

```bash
# lib.rs: pub mod watcher;
cargo check -p epitropos-sentinel --jobs 1 2>&1 | tail -3
git add sentinel/
git -c commit.gpgsign=false commit -m "watcher: inotify-driven discovery + initial pass"
```

---

# Phase 9 — CLI

## Task 13: Rewire main.rs with full CLI

**Files:**
- Modify: `sentinel/src/main.rs`

- [ ] **Step 1: Write main.rs**

```rust
use epitropos_sentinel::chain::{self, ChainPaths};
use epitropos_sentinel::config::Config;
use epitropos_sentinel::engine::{self, AnalysisContext, ManifestHeader};
use epitropos_sentinel::error::SentinelError;
use epitropos_sentinel::events::EventsSidecar;
use epitropos_sentinel::rules::RuleSet;
use epitropos_sentinel::signing::KeyPair;
use epitropos_sentinel::watcher;
use std::path::{Path, PathBuf};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    for arg in args.iter().skip(1) {
        if arg == "--version" || arg == "-V" {
            println!(
                "epitropos-sentinel {} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("EPITROPOS_SENTINEL_GIT_COMMIT")
            );
            std::process::exit(0);
        }
    }

    if args.len() < 2 {
        print_usage();
        std::process::exit(64);
    }

    let result = match args[1].as_str() {
        "serve" => cmd_serve(&args[2..]),
        "keygen" => cmd_keygen(&args[2..]),
        "analyze" => cmd_analyze(&args[2..]),
        "list-rules" => cmd_list_rules(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "--help" | "-h" | "help" => { print_usage(); Ok(()) }
        other => Err(SentinelError::Usage(format!("unknown subcommand: {other}"))),
    };

    if let Err(e) = result {
        eprintln!("epitropos-sentinel: {e}");
        std::process::exit(e.exit_code());
    }
}

fn print_usage() {
    eprintln!(
        "Usage: epitropos-sentinel <command>\n\
         \n\
         Commands:\n\
           serve [--config PATH]\n\
           keygen\n\
           analyze <manifest-path> [--force]\n\
           list-rules [--config PATH]\n\
           verify <events-sidecar-path>\n\
           --version"
    );
}

fn config_path(args: &[String]) -> PathBuf {
    args.iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/epitropos-sentinel/sentinel.toml"))
}

fn load_config(args: &[String]) -> Result<Config, SentinelError> {
    let p = config_path(args);
    if p.exists() { Config::load(&p) } else { Ok(Config::default()) }
}

fn load_age_identity(path: &Path) -> Result<String, SentinelError> {
    let bytes = std::fs::read(path)
        .map_err(|e| SentinelError::Decrypt(format!("read {}: {e}", path.display())))?;
    let s = String::from_utf8(bytes)
        .map_err(|e| SentinelError::Decrypt(format!("utf8: {e}")))?;
    // Accept either a raw AGE-SECRET-KEY line or a multi-line identity
    // file with leading comments.
    for line in s.lines() {
        let t = line.trim();
        if t.starts_with("AGE-SECRET-KEY-") {
            return Ok(t.to_string());
        }
    }
    Err(SentinelError::Decrypt(
        "no AGE-SECRET-KEY line found in identity file".into(),
    ))
}

// --- keygen ---

fn cmd_keygen(args: &[String]) -> Result<(), SentinelError> {
    let cfg = load_config(args)?;
    if cfg.keys.age_identity.exists() && !args.iter().any(|a| a == "--force") {
        return Err(SentinelError::Usage(format!(
            "age identity already at {}; pass --force to regenerate",
            cfg.keys.age_identity.display()
        )));
    }

    // Age identity
    let identity = age::x25519::Identity::generate();
    use age::secrecy::ExposeSecret;
    let identity_str = identity.to_string().expose_secret().to_string();
    let recipient = identity.to_public();

    if let Some(parent) = cfg.keys.age_identity.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| SentinelError::Signing(format!("mkdir: {e}")))?;
    }
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true).write(true).truncate(true).mode(0o400)
        .open(&cfg.keys.age_identity)
        .map_err(|e| SentinelError::Signing(format!("open age key: {e}")))?;
    use std::io::Write;
    writeln!(f, "# created: sentinel keygen")
        .map_err(|e| SentinelError::Signing(format!("write: {e}")))?;
    writeln!(f, "# public key: {}", recipient)
        .map_err(|e| SentinelError::Signing(format!("write: {e}")))?;
    writeln!(f, "{}", identity_str)
        .map_err(|e| SentinelError::Signing(format!("write: {e}")))?;
    drop(f);

    // Ed25519 signing keypair
    let kp = KeyPair::generate_to(&cfg.keys.signing_key, &cfg.keys.signing_pub)?;

    eprintln!("Generated sentinel age identity: {}", cfg.keys.age_identity.display());
    eprintln!("Generated sentinel signing keypair: {}", cfg.keys.signing_key.display());
    eprintln!();
    eprintln!("Age public key (add to katagrapho recipient file):");
    eprintln!("  {}", recipient);
    eprintln!();
    eprintln!("Signing key_id: {}", kp.key_id_hex());
    Ok(())
}

// --- list-rules ---

fn cmd_list_rules(args: &[String]) -> Result<(), SentinelError> {
    let cfg = load_config(args)?;
    let rs = RuleSet::load(&cfg.rules.path)?;
    println!("Loaded {} rules from {} (sha256={})",
        rs.rules.len(), cfg.rules.path.display(), rs.source_sha256);
    for r in &rs.rules {
        println!("  [{}] {} ({}) — {} pattern(s)",
            r.def.severity, r.def.id, r.def.category, r.def.regexes().len());
    }
    Ok(())
}

// --- analyze ---

fn cmd_analyze(args: &[String]) -> Result<(), SentinelError> {
    let manifest_path = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or_else(|| SentinelError::Usage("analyze requires <manifest-path>".into()))?;
    let manifest_path = PathBuf::from(manifest_path);
    let force = args.iter().any(|a| a == "--force");

    // Find config among remaining args.
    let cfg = load_config(args)?;
    let rules = RuleSet::load(&cfg.rules.path)?;
    let identity = load_age_identity(&cfg.keys.age_identity)?;
    let signing = KeyPair::load(&cfg.keys.signing_key, &cfg.keys.signing_pub)?;

    let header = read_manifest_header(&manifest_path)?;
    let recording = strip_manifest_suffix(&manifest_path);
    if !recording.exists() {
        return Err(SentinelError::Events(format!(
            "recording not found at {}", recording.display()
        )));
    }

    let ctx = AnalysisContext {
        cfg: &cfg,
        rules: &rules,
        age_identity: &identity,
        signing: &signing,
        emit_journal: false,  // one-shot: don't spam journal
    };
    let out = engine::analyze_recording(&ctx, &recording, &header, force)?;
    println!("analyzed -> {}", out.display());
    Ok(())
}

fn strip_manifest_suffix(p: &Path) -> PathBuf {
    let s = p.as_os_str().to_string_lossy().to_string();
    if let Some(t) = s.strip_suffix(".manifest.json") {
        PathBuf::from(t)
    } else {
        p.to_path_buf()
    }
}

fn read_manifest_header(path: &Path) -> Result<ManifestHeader, SentinelError> {
    let bytes = std::fs::read(path)
        .map_err(|e| SentinelError::Events(format!("read {}: {e}", path.display())))?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| SentinelError::Events(format!("parse: {e}")))?;
    Ok(ManifestHeader {
        session_id: v["session_id"].as_str().unwrap_or("").to_string(),
        user: v["user"].as_str().unwrap_or("").to_string(),
        host: v["host"].as_str().unwrap_or("").to_string(),
        part: v["part"].as_u64().unwrap_or(0) as u32,
    })
}

// --- verify ---

fn cmd_verify(args: &[String]) -> Result<(), SentinelError> {
    let path = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or_else(|| SentinelError::Usage("verify requires <sidecar-path>".into()))?;
    let cfg = load_config(args)?;
    let pub_bytes = std::fs::read(&cfg.keys.signing_pub)
        .map_err(|e| SentinelError::Verify(format!("read pub: {e}")))?;
    if pub_bytes.len() != 32 {
        return Err(SentinelError::Verify("pub key wrong length".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pub_bytes);

    let sc = EventsSidecar::load_from(Path::new(path))?;
    sc.verify(&arr)?;
    println!("ok: {}", path);
    Ok(())
}

// --- serve ---

fn cmd_serve(args: &[String]) -> Result<(), SentinelError> {
    let cfg = load_config(args)?;
    let rules = RuleSet::load(&cfg.rules.path)?;
    let identity = load_age_identity(&cfg.keys.age_identity)?;
    let signing = KeyPair::load(&cfg.keys.signing_key, &cfg.keys.signing_pub)?;

    // Ensure head.hash parent exists.
    let chain_paths = ChainPaths::new(cfg.chain.head_path.clone());
    if let Some(parent) = chain_paths.head.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| SentinelError::Chain(format!("mkdir: {e}")))?;
    }
    let _ = chain::read_head(&chain_paths)?;  // validate format

    eprintln!("epitropos-sentinel: watching {}", cfg.storage.dir.display());
    watcher::watch_and_analyze(&cfg, &rules, &identity, &signing)?;
    Ok(())
}
```

- [ ] **Step 2: Add `regexes` accessor**

`rules.rs` currently exposes `regexes: Vec<Regex>` as public; the `list-rules` command uses `r.def.regexes().len()` which doesn't exist. Fix by using the existing field directly:

In `cmd_list_rules`, replace:

```rust
r.def.regexes().len()
```

with:

```rust
r.regexes.len()
```

- [ ] **Step 3: Build**

```bash
cargo build -p epitropos-sentinel --jobs 1 2>&1 | tail -10
```

- [ ] **Step 4: Smoke test — keygen + list-rules + verify**

```bash
# keygen into a temp config
mkdir -p /tmp/sentinel-test/etc /tmp/sentinel-test/var
cat > /tmp/sentinel-test/etc/sentinel.toml <<EOF
[storage]
dir = "/tmp/sentinel-test/collector"

[keys]
age_identity = "/tmp/sentinel-test/var/sentinel.key"
signing_key = "/tmp/sentinel-test/var/signing.key"
signing_pub = "/tmp/sentinel-test/var/signing.pub"

[rules]
path = "/tmp/sentinel-test/etc/rules.toml"

[chain]
head_path = "/tmp/sentinel-test/var/head.hash"
EOF

cat > /tmp/sentinel-test/etc/rules.toml <<EOF
[[rules]]
id = "sudo"
severity = "high"
category = "priv"
description = "sudo"
patterns = ["\\\\bsudo\\\\s+"]
EOF

./target/debug/epitropos-sentinel --version
./target/debug/epitropos-sentinel keygen --config /tmp/sentinel-test/etc/sentinel.toml 2>&1
./target/debug/epitropos-sentinel list-rules --config /tmp/sentinel-test/etc/sentinel.toml
```

Expected: version prints, keygen generates three files, list-rules shows 1 rule.

- [ ] **Step 5: Commit**

```bash
git add sentinel/
git -c commit.gpgsign=false commit -m "main: CLI dispatcher with serve/keygen/analyze/list-rules/verify"
```

---

# Phase 10 — NixOS module

## Task 14: nixos-module-sentinel.nix

**Files:**
- Create: `nixos-module-sentinel.nix`

- [ ] **Step 1: Write module**

```nix
flakeSelf:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.epitropos-sentinel;
  inherit (lib) mkEnableOption mkOption mkIf types literalExpression;

  tomlFormat = pkgs.formats.toml { };

  configFile = tomlFormat.generate "sentinel.toml" {
    storage.dir = cfg.storageDir;
    keys = {
      age_identity = "${cfg.stateDir}/sentinel.key";
      signing_key = "${cfg.stateDir}/signing.key";
      signing_pub = "${cfg.stateDir}/signing.pub";
    };
    rules.path = toString cfg.rulesFile;
    cooldown.per_rule_per_session_seconds = cfg.cooldownSeconds;
    chain.head_path = "${cfg.stateDir}/head.hash";
  };
in
{
  options.services.epitropos-sentinel = {
    enable = mkEnableOption "epitropos security event sentinel";

    package = mkOption {
      type = types.package;
      default = flakeSelf.packages.${pkgs.stdenv.hostPlatform.system}.epitropos-sentinel;
      defaultText = literalExpression "inputs.epitropos.packages.\${system}.epitropos-sentinel";
    };

    storageDir = mkOption {
      type = types.path;
      default = "/var/lib/epitropos-collector";
      description = "Root directory of the collector's recordings.";
    };

    stateDir = mkOption {
      type = types.path;
      default = "/var/lib/epitropos-sentinel";
      readOnly = true;
    };

    rulesFile = mkOption {
      type = types.path;
      description = "Path to rules.toml file.";
    };

    cooldownSeconds = mkOption {
      type = types.int;
      default = 30;
    };
  };

  config = mkIf cfg.enable {
    users.users.epitropos-sentinel = {
      isSystemUser = true;
      group = "epitropos-sentinel";
      description = "Epitropos sentinel (post-hoc detector)";
      home = "/var/empty";
      shell = "/run/current-system/sw/bin/nologin";
      extraGroups = [ "epitropos-collector" ];
    };
    users.groups.epitropos-sentinel = { };

    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 0750 epitropos-sentinel epitropos-sentinel -"
    ];

    systemd.services.epitropos-sentinel-keygen = {
      description = "Generate sentinel age + signing keypairs (first boot)";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      unitConfig = {
        ConditionPathExists = "!${cfg.stateDir}/sentinel.key";
      };
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${cfg.package}/bin/epitropos-sentinel keygen --config ${configFile}";
        User = "epitropos-sentinel";
        Group = "epitropos-sentinel";
        RemainAfterExit = true;
      };
    };

    systemd.services.epitropos-sentinel = {
      description = "Epitropos security event sentinel";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" "epitropos-sentinel-keygen.service" ];
      requires = [ "epitropos-sentinel-keygen.service" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/epitropos-sentinel serve --config ${configFile}";
        User = "epitropos-sentinel";
        Group = "epitropos-sentinel";
        Restart = "on-failure";
        RestartSec = 5;

        ProtectSystem = "strict";
        ReadOnlyPaths = [ cfg.storageDir cfg.rulesFile ];
        ReadWritePaths = [ cfg.stateDir ];
        PrivateTmp = true;
        NoNewPrivileges = true;
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        PrivateDevices = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
      };
    };
  };
}
```

- [ ] **Step 2: Add to flake.nix**

Modify the flake's `nixosModules` block to include:

```nix
sentinel = import ./nixos-module-sentinel.nix self;
```

And the `packages` block to include the sentinel output (copy the pattern from `mkEpitroposCollector`):

```nix
epitropos-sentinel = mkEpitroposSentinel (pkgsFor system);
```

Define `mkEpitroposSentinel` as a copy of `mkEpitroposCollector` with `cargoExtraArgs = "-p epitropos-sentinel"` and `mainProgram = "epitropos-sentinel"`.

- [ ] **Step 3: Commit**

```bash
git add nixos-module-sentinel.nix flake.nix
git -c commit.gpgsign=false commit -m "nixos: sentinel module + flake package output"
```

---

# Phase 11 — Acceptance + VM test

## Task 15: Clippy + fmt clean

- [ ] **Step 1**

```bash
cargo clippy --workspace --jobs 1 -- -D warnings 2>&1 | tail -10
cargo fmt
git diff --cached --quiet || (git add -u && git -c commit.gpgsign=false commit -m "style: clippy + fmt")
```

## Task 16: Acceptance walk-through

Walk every item in spec §13. Most are covered by unit tests already. For the ones that aren't (journald entry shape, end-to-end with a real recording), capture evidence:

```bash
# Use the demo session we created for theatron testing (/tmp/theatron-test/alice/demo-live.part0.kgv1.age)
# plus the existing age identity (/tmp/theatron-test-key.txt).

# (a) list-rules on the sample rules file
./target/debug/epitropos-sentinel list-rules --config /tmp/sentinel-test/etc/sentinel.toml

# (b) analyze the demo recording
cp /tmp/theatron-test/alice/demo-live.part0.kgv1.age.manifest.json /tmp/sentinel-test/
cp /tmp/theatron-test/alice/demo-live.part0.kgv1.age /tmp/sentinel-test/
# BUT: the demo was encrypted to a DIFFERENT key. For a clean test,
# re-encrypt the demo kgv1 plaintext to the sentinel's age public key.
SENTINEL_PUB=$(grep "^# public key" /tmp/sentinel-test/var/sentinel.key | awk '{print $NF}')
age -r "$SENTINEL_PUB" -o /tmp/sentinel-test/demo.kgv1.age /tmp/theatron-test-recording.kgv1
# Craft a matching manifest (reuse the existing one with adjusted filename)
# ... then:
./target/debug/epitropos-sentinel analyze /tmp/sentinel-test/demo.kgv1.age.manifest.json --config /tmp/sentinel-test/etc/sentinel.toml

# (c) verify the sidecar
./target/debug/epitropos-sentinel verify /tmp/sentinel-test/demo.kgv1.age.events.json --config /tmp/sentinel-test/etc/sentinel.toml
```

- [ ] Confirm `list-rules` reports the expected rule count
- [ ] Confirm `analyze` produces `events.json` with one or more matches
- [ ] Confirm `verify` exits 0
- [ ] Tamper one byte in the events.json → `verify` exits 1

## Task 17: VM test (deferred follow-up)

- [ ] Document as follow-up. Two-node VM test is scoped in spec §11 but requires the existing collector VM test as a prerequisite; skip for this track if not already wired.

## Task 18: Merge + push

- [ ] Commit final checkpoint, push, fast-forward main.

```bash
cd /home/acid/Workspace/repos/epitropos/.worktrees/track-d-c
git push -u origin track-d-c 2>&1 | tail -3
cd /home/acid/Workspace/repos/epitropos
git merge --ff-only track-d-c 2>&1 | tail -3
git push origin main 2>&1 | tail -3
git branch -d track-d-c
git push origin --delete track-d-c
git worktree remove .worktrees/track-d-c
```

---

# Self-Review Notes

**Spec coverage:**
- §2 architecture → Tasks 6 (decrypt), 11 (engine), 12 (watcher)
- §3 rules → Task 5 (rules.rs)
- §4 events sidecar → Task 8
- §5 journald → Task 10
- §6 config → Task 4
- §7 file layout → all tasks
- §8 subcommands → Task 13
- §9 deps → Task 2
- §10 NixOS → Task 14
- §11 testing → Task 15 (clippy) + Task 16 (acceptance walk)
- §12 risks — mitigations are implicit in tests (cooldown test, tamper test, wrong-identity test)
- §13 acceptance — Task 16

**Known shortcuts:**
- VM test is documented but deferred (Task 17). The spec's §11 two-node test depends on the collector VM test plumbing from Track C VM test; the executor can wire it as a follow-up once the unit/integration tests for sentinel are green.
- `rules.rs` TOML parsing uses `toml::from_str(std::str::from_utf8(&bytes)?)` after the spec's `from_slice` pattern was removed in toml 0.8.

**Type consistency check:**
- `RuleSet` / `CompiledRule` / `SessionMatcher` / `Match` used consistently in rules.rs and engine.rs
- `EventsSidecar` / `EventRecord` used consistently in events.rs and engine.rs
- `ChainPaths` API (`new`, `read_head`, `write_head`, `ChainLock::acquire`) consistent in chain.rs and engine.rs and main.rs
- `AnalysisContext` / `ManifestHeader` used consistently in engine.rs, watcher.rs, main.rs
