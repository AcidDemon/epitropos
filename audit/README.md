# epitropos-audit

Authoritative privilege-event feed. Correlates Linux **kernel audit** records
(sudo / su / doas) to session recordings and emits a **signed, hash-chained**
`<recording>.privileges.json` sidecar — the tamper-evident, kernel-sourced
counterpart to the sentinel's advisory content-scan markers.

## Why it exists

The sentinel detects sudo/su by **regex over decrypted terminal output** — it can
miss aliased/obfuscated invocations and false-positive on the string "sudo". This
feed reads the **kernel audit trail**, so its markers are authoritative and
cannot be forged from inside the session.

## The join

A recording's random `session_id` is invisible to the kernel. The authoritative
join is the tuple **`(host, boot_id, audit_session_id)`** — auditd's `ses=` field
*is* the kernel `audit_session_id`, which the recording's signed **manifest**
already carries. The manifest is the bridge table; nested su/sudo share one
`audit_session_id` and map to the outer recording.

## What's built (this crate)

- `signing.rs` / `chain.rs` — ed25519 keypair + per-host hash-chain, copied from
  the sentinel (own key + own head file; the collector already isolates per host).
- `events.rs` — `PrivilegeEventsSidecar` (`epitropos-audit-events-v1`) carrying the
  `(boot_id, audit_session_id)` provenance; same canonical-bytes + sign + verify
  contract as the manifest/sentinel sidecars.
- `parse.rs` — audit-log parser: `SYSCALL`+`EXECVE` execs of sudo/su/doas (with
  the command) and `USER_AUTH`/`USER_ACCT` PAM records (captures **denied**
  attempts). Handles `k=v`, `k="v"`, nested `msg='…'`.
- `correlate.rs` — join by `ses` within the recording window; resolve uids →
  names; reject unjoinable recordings (`audit_session_id` null or `boot_id`
  `"unknown"`).
- `main.rs` — `keygen` / `analyze <manifest> <audit-slice>` / `verify`.

    epitropos-audit keygen
    epitropos-audit analyze <recording>.kgv1.age.manifest.json /var/log/audit/audit.log
    epitropos-audit verify  <recording>.kgv1.age.privileges.json

theatron reads the sidecar and shows these as `✓ authoritative` timeline markers,
distinct from the sentinel's `◆ advisory` ones.

## Deploy (topology: recording-host producer + ship)

The plumbing is wired (compiles + Nix evaluates), but is **not** live-verified —
it needs a real audited host + collector. What's built:

- **Daemon** — `epitropos-audit serve` (`watch.rs`), an inotify watcher over the
  recordings tree that runs `analyze` when a manifest lands. Mirrors
  `sentinel/watcher.rs`.
- **Event source + service** — `nixos-module-audit.nix` (`nixosModules.audit`):
  enables `security.auditd` + execute-watch rules for `/run/wrappers/bin/{sudo,su,doas}`,
  **asserts `pam_loginuid`** on sshd (else `audit_session_id` is null and the join
  breaks), and runs the daemon as a hardened service.
- **Shipping** — backward-compatible: `epitropos-forward` best-effort POSTs the
  sidecar to a new collector endpoint `POST /v1/sessions/{id}/parts/{part}/privileges`,
  which stores it beside the recording (bound to the authenticated mTLS sender).

Two host-specific permission details to tune on first deploy (flagged in the
module): reading `/var/log/audit/audit.log` (root:root 0600) and writing the
sidecar into katagrapho's recording dirs — the module uses `CAP_DAC_*` shortcuts;
the clean fix is a shared group + group-writable recording dirs, and audit-netlink
(`CAP_AUDIT_READ`) for tamper-resistant real-time capture.

Still deferred: collector-side signature re-verification (needs a 2nd pinned
pubkey at enrollment) and a robust re-ship/backfill if the sidecar lands after
forward has advanced past its recording.
