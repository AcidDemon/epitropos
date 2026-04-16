# Track D(c) — epitropos-sentinel: Security Event Detector

**Status:** Design approved 2026-04-14
**Predecessors:** Tracks A + B + C + D(a) + D(b) merged to main
**Scope:** New workspace member `sentinel/` alongside existing `proxy/` and `collector/`

The sentinel is a post-hoc security event detector. It runs on the
collector host, decrypts session recordings with its own age
identity, runs regex-based pattern rules from a TOML config, and
emits detected events to journald and to a signed events sidecar
next to each recording.

## 1. Goals

1. **Detect security-relevant patterns in session content** that OS-
   level tools (auditd, sudo JSON, pam_exec) can't see: shell
   redirections, pasted payloads, output-based patterns, multi-step
   reconnaissance.
2. **Zero impact on the setuid recording pipeline.** Detection runs
   on the collector, not the recording host. The proxy stays narrow.
3. **Narrow decryption key scope.** Sentinel has its own age key
   added as a recipient at recording time; operator's master key
   remains separate. Compromise of the sentinel host leaks session
   content but nothing else.
4. **Tamper-evident events.** Each events sidecar is signed by the
   sentinel's own ed25519 key, following the same canonicalization
   pattern as katagrapho manifests (Track B).
5. **Operator-editable rules** via a TOML file; hot-reloadable.

**Non-goals:**
- Real-time detection in the proxy
- AI/ML classification (Track E)
- Rule scripting languages (regex only in v1)
- External notification channels beyond journald (no webhooks)
- Retroactive analysis of pre-sentinel recordings (future `backfill`
  subcommand)

## 2. Architecture

```
┌────────────────────────────────────────────────────────┐
│                  collector host                         │
│                                                         │
│  /var/lib/epitropos-collector/senders/*/recordings/    │
│      ├── session.part0.kgv1.age                 ◄──┐   │
│      ├── session.part0.kgv1.age.manifest.json   ◄─┼──┐│
│      └── session.part0.kgv1.age.events.json     ──┘  ││
│                                                        ││
│  ┌─────────────────────────────────────────────┐      ││
│  │           epitropos-sentinel                 │──────┘│
│  │                                              │       │
│  │  inotify → new .manifest.json                │       │
│  │    ↓                                         │       │
│  │  decrypt .kgv1.age with sentinel.key ────────┼───────┘
│  │    ↓                                         │
│  │  stream kgv1 NDJSON → rule engine            │
│  │    ↓                                         │
│  │  matches → emit events:                      │
│  │    ├── journald (EPITROPOS_SENTINEL_*)       │
│  │    └── sign + write events.json sidecar      │
│  └─────────────────────────────────────────────┘
└────────────────────────────────────────────────────────┘
```

### Key flow — recording time

Operator configures katagrapho's recipient file with **both** keys:

```
age1operator00...   # operator's master key for playback
age1sentinel00...   # sentinel's key for analysis
```

Every recorded session is encrypted to both recipients. Each
recipient adds ~200 bytes of header overhead (age native multi-
recipient support).

### Key flow — analysis time

1. Sentinel starts as a systemd service. Inotify-watches the
   collector's `senders/*/recordings/` tree.
2. When a `.manifest.json` appears (finalize already happened; the
   recording is committed), sentinel:
   - Opens the corresponding `.kgv1.age` file
   - Decrypts streaming with its own age identity
   - Streams kgv1 JSON lines through the rule engine
   - For each `out` record, base64-decodes bytes, UTF-8-lossy to
     string, matches against compiled regexes
   - On match, subject to cooldown, emits an event
3. When EOF on the stream: signs the events list with the sentinel's
   ed25519 signing key and writes it atomically to
   `<recording>.events.json`.

### Trust model

- **Sentinel age identity:** decrypts session recordings. Not used
  for anything else. Generated on the sentinel host; its public key
  is copied into katagrapho's recipient files by the operator.
- **Sentinel ed25519 signing key:** signs events sidecars. Mirrors
  katagrapho's signing key but scoped to this host's sentinel.
- **Host compromise:** attacker reads session content (via the age
  key) and can forge events sidecars (via the signing key). Mitigation:
  `prev_events_hash` chain across events sidecars on this host
  provides a deletion-detection mechanism parallel to the manifest
  chain.

## 3. Rule format

`/etc/epitropos-sentinel/rules.toml`:

```toml
[[rules]]
id = "priv_esc_sudo_su"
severity = "high"
category = "privilege_escalation"
description = "User invoked sudo, su, or doas"
patterns = [
  "\\bsudo\\s+",
  "\\bsu\\s+-",
  "\\bdoas\\s+",
]

[[rules]]
id = "sensitive_file_read"
severity = "high"
category = "data_access"
description = "Read of known-sensitive file"
patterns = [
  "cat\\s+/etc/shadow",
  "cat\\s+/etc/sudoers",
  "cat\\s+[^\\s]*\\.ssh/id_(rsa|ed25519|ecdsa)",
  "less\\s+/etc/shadow",
]

[[rules]]
id = "reverse_shell_nc"
severity = "critical"
category = "c2"
description = "Netcat reverse shell pattern"
patterns = [
  "nc\\s+-e\\s+",
  "ncat\\s+-e\\s+",
  "bash\\s+-i\\s+>&\\s+/dev/tcp/",
]

[[rules]]
id = "curl_to_shell"
severity = "critical"
category = "malware_download"
description = "Download-and-execute pattern"
patterns = [
  "curl\\s+[^\\|]*\\|\\s*(bash|sh|zsh|python)",
  "wget\\s+[^\\|]*\\|\\s*(bash|sh|zsh|python)",
]

[[rules]]
id = "base64_decode_to_shell"
severity = "high"
category = "obfuscation"
description = "Base64-decoded command execution"
patterns = [
  "echo\\s+[A-Za-z0-9+/=]{20,}\\s+\\|\\s+base64\\s+-d\\s+\\|\\s+(bash|sh)",
  "base64\\s+-d\\s+<<<",
]

[[rules]]
id = "permission_weakening"
severity = "medium"
category = "defense_evasion"
description = "World-writable chmod or critical-dir ownership change"
patterns = [
  "chmod\\s+777",
  "chmod\\s+\\+x\\s+/tmp/",
  "chown\\s+\\S+\\s+/etc/",
]

[[rules]]
id = "crypto_mining_indicators"
severity = "high"
category = "malware"
description = "Cryptominer process names and config paths"
patterns = [
  "xmrig",
  "minerd",
  "\\.conf.*pool\\.(minexmr|supportxmr|nanopool)",
]

[[rules]]
id = "persistence_cron"
severity = "high"
category = "persistence"
description = "Cron-based persistence attempt"
patterns = [
  "crontab\\s+-e",
  "echo\\s+.*>>\\s+/etc/cron",
  "/etc/cron\\.(daily|hourly|weekly)/",
]
```

### Rule semantics

- Each `patterns` entry compiles to a Rust `regex` crate pattern at
  startup. The `regex` crate is RE2-style (no backtracking), so
  ReDoS is structurally prevented regardless of rule content.
- Matching runs against the UTF-8-lossy decoded bytes of each `out`
  record (base64-decoded first).
- Cooldown: one event per `(rule_id, session_id)` per cooldown window
  (default 30 seconds). Prevents flood when the same command
  scrolls through screen output.
- Context: matched event includes `before_chars` chars before the
  match (default 200) and `after_chars` after (default 200),
  extracted from the rolling window of recent output.
- `severity` is free-form string with operator convention:
  `info`, `low`, `medium`, `high`, `critical`. Only `high` and
  `critical` trigger journald PRIORITY lifts.

## 4. Events sidecar

Path: `<recording>.kgv1.age.events.json`, mode 0640 owned by the
sentinel user, group `epitropos-collector`.

```json
{
  "v": "epitropos-sentinel-events-v1",
  "session_id": "abc-123",
  "part": 0,
  "sentinel_version": "0.1.0",
  "sentinel_commit": "abc1234",
  "rules_file_sha256": "<hex>",
  "analyzed_at": 1712540000.5,
  "events": [
    {
      "t": 12.345,
      "rule_id": "priv_esc_sudo_su",
      "severity": "high",
      "category": "privilege_escalation",
      "description": "User invoked sudo, su, or doas",
      "matched_text": "sudo su -",
      "context": "alice@host:~$ sudo su -\nPassword: "
    }
  ],
  "prev_events_hash": "<hex of previous events sidecar's this_events_hash on this host>",
  "this_events_hash": "<hex SHA-256 over canonicalized fields excluding signature>",
  "key_id": "<hex SHA-256 of sentinel signing pubkey>",
  "signature": "<base64 ed25519>"
}
```

Canonicalization mirrors katagrapho's manifest (Track B):
- Fixed field order exactly as shown above.
- `this_events_hash` and `signature` excluded from the hash input.
- Hash = SHA-256 of the canonical serialization.
- Signature = ed25519 over the hash.

Chain: `prev_events_hash` points at the previous events sidecar
written on this host, forming a per-host chain parallel to
katagrapho's manifest chain. Head pointer lives at
`/var/lib/epitropos-sentinel/head.hash`.

## 5. journald format

Each match (subject to cooldown) emits:

```
MESSAGE=sentinel: <rule_id> matched in session <session_id> at t=<time>
PRIORITY=4 (default) / 2 (severity=critical)
SYSLOG_IDENTIFIER=epitropos-sentinel
EPITROPOS_SENTINEL_EVENT=match
EPITROPOS_SENTINEL_RULE=<rule_id>
EPITROPOS_SENTINEL_SEVERITY=<severity>
EPITROPOS_SENTINEL_CATEGORY=<category>
EPITROPOS_SENTINEL_SESSION=<session_id>
EPITROPOS_SENTINEL_PART=<part>
EPITROPOS_SENTINEL_USER=<user>
EPITROPOS_SENTINEL_HOST=<host>
EPITROPOS_SENTINEL_T=<time_in_session>
EPITROPOS_SENTINEL_MATCH=<matched_text>
```

Operator queries:

```bash
journalctl EPITROPOS_SENTINEL_SEVERITY=critical --since "24 hours ago"
journalctl EPITROPOS_SENTINEL_CATEGORY=privilege_escalation
journalctl EPITROPOS_SENTINEL_USER=root EPITROPOS_SENTINEL_EVENT=match
```

## 6. Config

`/etc/epitropos-sentinel/sentinel.toml`:

```toml
[storage]
dir = "/var/lib/epitropos-collector"

[keys]
age_identity = "/var/lib/epitropos-sentinel/sentinel.key"
signing_key  = "/var/lib/epitropos-sentinel/signing.key"
signing_pub  = "/var/lib/epitropos-sentinel/signing.pub"

[rules]
path = "/etc/epitropos-sentinel/rules.toml"
reload_on_change = true

[cooldown]
per_rule_per_session_seconds = 30

[context]
before_chars = 200
after_chars  = 200

[journal]
enabled = true

[events_sidecar]
enabled = true

[chain]
head_path = "/var/lib/epitropos-sentinel/head.hash"
```

All structs have `#[serde(deny_unknown_fields)]`.

## 7. Binary layout

`epitropos-sentinel` is a new workspace member under `epitropos/`:

```
epitropos/
├── Cargo.toml                  # [workspace] members += "sentinel"
├── proxy/                      # unchanged (setuid recording proxy)
├── collector/                  # unchanged (HTTP push receiver)
├── sentinel/                   # NEW
│   ├── Cargo.toml
│   ├── build.rs
│   └── src/
│       ├── main.rs             # CLI dispatch
│       ├── lib.rs
│       ├── error.rs            # SentinelError + sysexits
│       ├── config.rs           # TOML config parser
│       ├── rules.rs            # rule compilation + streaming matcher
│       ├── decrypt.rs          # age streaming decryption
│       ├── engine.rs           # orchestration: scan → decrypt → match → emit
│       ├── events.rs           # events sidecar: build, sign, write
│       ├── chain.rs            # per-host head pointer for events
│       ├── journal.rs          # journald emission
│       ├── signing.rs          # ed25519 (copy of katagrapho/src/signing.rs)
│       └── watcher.rs          # inotify loop
└── nixos-module-sentinel.nix   # NEW
```

## 8. Subcommands

```
epitropos-sentinel serve [--config PATH]
  Daemon: watch + analyze new recordings as they finalize.

epitropos-sentinel keygen
  First-boot: generate sentinel age identity + ed25519 signing keypair.
  Prints the age public key for inclusion in katagrapho recipient files.

epitropos-sentinel analyze <manifest-path> [--force]
  One-shot: analyze the single session identified by the given
  manifest. Writes events sidecar (refuses if exists, unless --force).
  Journald entries are NOT emitted in one-shot mode (avoid alert spam
  on rule development).

epitropos-sentinel list-rules [--config PATH]
  Parse the rules file, compile all regexes, print summary
  (id, severity, category, pattern count). Exits non-zero on compile
  error. Use this as a pre-deploy lint.

epitropos-sentinel verify <events-sidecar-path>
  Verify the signature on an events sidecar using the local sentinel.pub.

epitropos-sentinel --version
```

## 9. Dependencies (sentinel only)

```toml
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
```

Proxy and collector crates unchanged. No new deps cross the setuid
boundary or the HTTP intake path.

## 10. NixOS module

`nixos-module-sentinel.nix` exposes:

```nix
services.epitropos-sentinel = {
  enable = mkEnableOption "epitropos security event sentinel";
  package = mkOption { type = types.package; };
  storageDir = mkOption { type = types.path; default = "/var/lib/epitropos-collector"; };
  rulesFile = mkOption { type = types.path; };
  cooldownSeconds = mkOption { type = types.int; default = 30; };
};
```

When enabled:
- Creates `epitropos-sentinel` system user in `epitropos-collector`
  group (read access to collector storage)
- `systemd.tmpfiles` for `/var/lib/epitropos-sentinel` (0750)
- `systemd.services.epitropos-sentinel-keygen`: one-shot on first
  boot, `ConditionPathExists=!.../sentinel.key`, generates age and
  signing keys, prints the age pubkey to stderr/journal for operator
  copy-paste into katagrapho recipient files
- `systemd.services.epitropos-sentinel`: `Type=simple`,
  `ProtectSystem=strict`, `ReadOnlyPaths=[ storageDir rulesFile ]`,
  `ReadWritePaths=[ /var/lib/epitropos-sentinel ]`, `PrivateTmp`,
  `NoNewPrivileges`, `RestrictAddressFamilies=AF_UNIX`
  (journald only, no network), seccomp filter permitting only
  `read`, `write`, `openat`, `inotify_*`, `sendmsg`, etc.

## 11. Testing

### Unit tests (in sentinel/src)

- `rules::compile` on valid rule set → Ok
- `rules::compile` on rule with broken regex → Err with clear message
- `rules::Engine::match_line` fires on known-positive inputs for each
  starter rule
- `rules::Engine::match_line` does NOT fire on near-miss inputs
  ("sudoku" shouldn't trigger sudo rule)
- `rules::Engine` cooldown: feed same match twice within cooldown
  window → one event; feed again after cooldown → second event
- `events::sign` + `events::verify` round-trip
- `events::verify` rejects tampered events field
- `decrypt::stream` decrypts a known-input .kgv1.age with known
  identity and yields expected lines
- `chain::read_head` / `chain::write_head` round-trip

### Integration

- `analyze` subcommand on a crafted kgv1.age file produces an events
  sidecar with expected matches, valid signature, expected context
- `analyze --force` overwrites an existing sidecar
- `analyze` without `--force` on an existing sidecar → clear error
- Wrong age identity in config → daemon logs and skips (one log line
  per session), doesn't crash
- Bad regex in rules.toml → daemon exits at startup with clear error
- `list-rules` on the sample rules file reports 8 rules compiled

### NixOS VM test

Two-node test (`tests/vm-sentinel.nix`):
- Node A: katagrapho + epitropos proxy + forward, sentinel pubkey
  added to recipient file
- Node B: collector + sentinel enabled

Script:
1. Wait for services on both nodes
2. On B: run `epitropos-sentinel keygen`, capture age pubkey
3. On A: update recipient file with the sentinel's pubkey
4. On A: SSH in as a test user, run `sudo whoami` and exit
5. Wait for recording to ship to the collector
6. On B: assert events sidecar exists for that session
7. On B: assert events sidecar contains at least one event with
   `rule_id == "priv_esc_sudo_su"`
8. On B: assert `journalctl EPITROPOS_SENTINEL_RULE=priv_esc_sudo_su`
   returns a matching entry
9. On B: run `epitropos-sentinel verify` on the sidecar → exit 0
10. On B: corrupt one byte in the sidecar → `verify` → exit 1

## 12. Risks and mitigations

1. **False positives in rules.** Starter rules are conservative;
   operator tunes over time. Context field preserved in events
   so operator can triage quickly.
2. **False negatives via obfuscation** (quoting, encoding, piping
   through `xxd`). Acknowledged limitation. Track E's AI analysis
   layer covers what regex can't.
3. **Regex catastrophic backtracking.** Rust `regex` crate uses RE2-
   style NFA without backtracking — structurally prevents ReDoS.
4. **Sentinel key compromise.** Attacker reads session content flowing
   into this collector. Narrower than operator key. Rotation:
   `epitropos-sentinel keygen --force` generates new keys; operator
   updates katagrapho recipient files; future recordings encrypted to
   the new key. Old recordings remain accessible only via the old
   key (retained in backup if needed).
5. **Signing key compromise.** Attacker can forge events sidecars.
   Chain via `prev_events_hash` detects deletion/insertion of
   sessions' events. Operator should replicate `/var/lib/epitropos-
   sentinel/head.hash` off-host (out of scope for v1).
6. **Missing backfill.** Sessions that existed before sentinel
   started are not analyzed. Documented; add `backfill` subcommand
   in a follow-up if needed.
7. **Event volume on busy hosts.** Cooldown caps events per rule per
   session. A session with 100 sudo invocations produces ~3 events
   (at 30s cooldown) not 100.
8. **Rules drift.** Events sidecars record `rules_file_sha256`; if
   rules change, old sidecars reflect old rules. `analyze --force`
   re-runs with current rules.

## 13. Acceptance criteria

1. `cargo build --release -p epitropos-sentinel` succeeds
2. `cargo clippy --workspace --all-targets -- -D warnings` clean
3. `epitropos-sentinel keygen` generates both keys (0400 perms) and
   prints the age pubkey
4. `epitropos-sentinel list-rules` on the sample rules file reports
   the expected rule count and exits 0
5. `epitropos-sentinel list-rules` on a file with a broken regex
   exits non-zero with the rule ID and regex error in the message
6. `epitropos-sentinel analyze <path>` on a crafted recording
   produces a signed events sidecar with expected matches
7. `epitropos-sentinel verify <sidecar>` returns 0 on valid sidecar,
   non-zero on tampered sidecar
8. journald entries emitted on match with all expected
   `EPITROPOS_SENTINEL_*` fields
9. Cooldown observed: repeated match within cooldown = 1 event;
   after cooldown = 2 events
10. NixOS VM test passes (two-node: recorder + collector+sentinel)
11. Proxy and collector crates' test suites unchanged and passing
    (no regression from the workspace addition)
