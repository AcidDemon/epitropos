# Recording-Path Fail-Closed Blockers (Phase 1 remediation)

**Status:** Design approved 2026-07-12
**Scope:** `/home/acid/Workspace/repos/epitropos/` — `proxy/` crate + `tests/`
**Out of scope:** collector TLS/enrollment (deferred, separate effort), live-mirror
encryption (Phase 2), sentinel watcher, docs rewrite (Phase 2).

Remediation of the four recording-path **blockers** surfaced by the 2026-07-12
go-live audit, plus the test gap that let them ship and one test-reliability
fix. These bugs are all in the proxy's failure-handling paths. The proxy's
security architecture (privilege drop, seccomp, fd isolation, env sanitization,
PIE/RELRO, fail-policy) was audited and verified sound — this phase closes the
*failure* paths only.

The unifying invariant this phase restores:

> **If recording cannot continue, the session must not continue.**
> No path may leave an interactive shell running while its I/O goes unrecorded,
> and the recorded user must not be able to disable recording without ending
> their own session.

## 1. Goals

1. Restore the flagship invariant: any recording failure (writer death, pipe
   failure, backpressure exhaustion) terminates the session — actively kills
   the shell, does not merely stop the loop.
2. Never leave the final integrity record unsealed.
3. Make startup fail-closed **deterministic** when katagrapho is missing/broken.
4. Never let a stalled-but-alive katagrapho freeze the recorded session.
5. Make PID-namespace isolation **mandatory (fail-closed)** so the recorded user
   cannot see or signal the recorder — and if the user does induce a failure,
   it becomes a self-terminating session (goal 1), not an escape.
6. Preserve partial evidence: on every teardown, flush everything the sink can
   still accept, and document the unavoidable loss window.
7. Backfill the negative-path tests that prove (1)/(5) and would have caught them.
8. Make `cargo test` deterministic (fix the shared-global flaky test).

Non-goals: collector, live mirror, sentinel, README/docs, PAM (all other phases).

## 2. Fix list (dependency order)

### F0 — Failing negative-path VM test (write first, TDD anchor)

`tests/vm-proxy.nix` currently drives only the happy path. Add a test case (or a
sibling test) that:

1. Starts a recorded session (as the existing test does).
2. From outside the session, **kills the katagrapho child mid-session** (e.g.
   `pkill -TERM katagrapho`, or send it a fatal signal by pid).
3. Asserts the session is **terminated** shortly after: the recorded user's
   shell/PTY is gone (no lingering shell process for that session), and
   the proxy has exited.
4. Asserts the recording is **closed with a failure marker** — the interrupted
   recording is preserved with its termination marker (per the existing
   "partial evidence preserved" property) and `EPITROPOS_END_REASON=recording_failed`
   appears in the journal.
5. Asserts **partial evidence on disk**: the output produced *before* the kill
   is present in the persisted (decrypted) recording — i.e. everything the sink
   durably received is preserved, not discarded on teardown. (This guards the
   data-preservation property; see §3.)

**Must fail against current `main`** (today the shell survives and the session
continues unrecorded). Passes once F1 lands. This is the acceptance test for F1.

### F1 — Recording failure kills the session

**File:** `proxy/src/event_loop.rs` (`run`), interacting with `proxy/src/main.rs`
teardown (`waitpid` on `shell_pid`).

**Root cause (two parts):**
- The kata-death branch (`event_loop.rs:~208`) and the periodic-flush-failure
  branch (`event_loop.rs:~325`) set `recording_failed = true` but do **not**
  break; the `break 'event_loop` paths at `:193/:275/:319` are all inside
  `if !recording_failed { … }`, so once the flag is set they are unreachable.
  I/O keeps bridging (`write_all_fd(user_stdout, …)` at `:262`,
  `write_all_fd(pty_master, …)` at `:309`) until the shell exits on its own.
- Even the paths that *do* break do not kill the shell: after `break`, the
  blocking `waitpid(shell_pid, …, 0)` in `main.rs` (~`:336`) waits for a shell
  that nothing has killed, so teardown hangs / the shell lingers, and the
  failure hook + journal fire only after the user eventually exits.

**Fix:** centralize fail-closed teardown so *every* `recording_failed` transition
routes through it:
1. Add a single check evaluated once per loop iteration (after the poll handling
   block): `if recording_failed { break 'event_loop; }`. This covers the two
   currently-break-less branches without hunting every setter.
2. On recording-failure teardown, **SIGKILL the shell's process group**
   (`kill(-shell_pid, SIGKILL)`) before the blocking `waitpid`, so the wait
   returns promptly and no unrecorded shell survives. (SIGTERM-then-SIGKILL is
   acceptable, but SIGKILL is the safe default for a security teardown — the
   shell does not get to trap it.)
3. Ensure `main.rs` teardown, on `recording_failed`, still: writes the
   interrupted-recording termination marker, runs the `onRecordingFailure` hook,
   and emits the `recording_failed` journal end reason. (Preserve existing
   behavior; only the ordering/kill changes.)

**Note:** `kill(2)` is currently absent from the seccomp allowlist
(`proxy/src/seccomp.rs`) — audit Medium finding. Since F1's teardown calls
`kill(-pid, SIGKILL)` from the proxy under seccomp, **add `kill` (x86_64 `62`,
aarch64 `129`) to `allowed_syscalls()`** as part of F1, otherwise the teardown
itself is killed by the seccomp default action. Fold this in here.

**Acceptance:** F0 passes. A unit test at the event-loop level (if feasible with
a fake writer) asserting that a write/flush error leads to a teardown decision.

### F2 — Flush the trailing integrity chunk

**File:** `proxy/src/main.rs` (~`:409`).

`force_flush_chunk(&mut write_buf)` appends the final `chunk` record (carrying
the streaming SHA-256 seal) into the `FlushBuffer`, but the buffer is only
flushed at capacity; the next statement closes `pipe_write` (~`:413`), discarding
it. `FlushBuffer` has no flush-on-drop.

**Fix:** `let _ = write_buf.flush();` immediately after the `force_flush_chunk`
call and before `close(pipe_write)`.

**Acceptance:** a test asserting that after a clean session the sink received the
final `chunk` record (the recording's tail is sealed). Can piggyback on the VM
test's manifest/recording assertions, or a focused unit test on the
recorder/FlushBuffer finalize path.

### F3 — Deterministic startup fail-closed on missing/broken katagrapho

**File:** `proxy/src/process.rs` (`spawn_katagrapho`), `proxy/src/main.rs`
(startup ordering / `handle_startup_failure`).

`spawn_katagrapho` returns `Ok((pid, pipe_write))` after a successful `fork()`
even when the child's `execv` fails (child does `execv(...); _exit(1)` — the
parent never learns). The early child-death SIGCHLD is lost because the signal
handler is installed after the fork.

**Fix:** exec-sync pipe. Create an extra pipe with the write end `O_CLOEXEC`;
the child inherits it and it closes automatically on a successful `execv`
(parent's read returns EOF = success). On `execv` failure the child writes one
error byte to it before `_exit`. The parent, after fork, reads the sync pipe:
- EOF → katagrapho exec'd → proceed.
- byte read (or a specific errno payload) → exec failed → return `Err` →
  `handle_startup_failure` applies the fail policy (Closed denies the session).

This removes reliance on catching the early SIGCHLD and makes "closed" deny
deterministically.

**Acceptance:** a test (unit or VM) that points the proxy at a non-existent
katagrapho path with `failPolicy=closed` and asserts the session is denied
(no shell spawned), deterministically.

### F4 — Non-blocking katagrapho pipe (backpressure → fail, not freeze)

**Files:** `proxy/src/process.rs` (~`:230`, `pipe2`), `proxy/src/buffer.rs`
(`FlushBuffer::flush` / `write`).

The pipe to katagrapho is blocking (`O_CLOEXEC` only). A slow-but-alive
katagrapho fills the 64 KiB kernel pipe; the next `flush()` blocks the
single-threaded event loop, freezing the recorded session. The intended 4 MiB
`max_size` backpressure valve (mark `broken` → `recording_failed`) is
unreachable because the 64 KiB capacity flush blocks first.

**Fix:**
1. Open `pipe_write` with `O_NONBLOCK` (add to the `pipe2` flags).
2. In `FlushBuffer::flush`, on `EAGAIN`/`EWOULDBLOCK`: do **not** block — leave
   the unwritten bytes buffered and return `Ok` (partial-write aware). This lets
   the buffer grow toward `max_size`.
3. When the buffer reaches `max_size` and still cannot drain, mark `broken` and
   surface the error so the caller sets `recording_failed` → F1 teardown.
4. **Startup header writes** (before the shell exists) must remain reliable:
   there is no session to freeze pre-shell, so those writes should block/retry
   until complete (e.g. a bounded retry/poll on `EAGAIN`), or be done before the
   pipe is switched to non-blocking. Do not let a pre-shell `EAGAIN` silently
   drop the header.
5. The `max_size` ceiling is the **maximum in-flight data-loss window** if the
   sink dies while stalled (see §3). Make it an explicit calibration knob
   (config, default the current 4 MiB) rather than a bare constant, and keep the
   normal flush cadence tight so the common-case window stays small. The ceiling
   only fills during an active stall, when katagrapho isn't draining anyway.

**Acceptance:** a unit test on `FlushBuffer` with a non-blocking pipe whose reader
never drains: assert `write`/`flush` do not block, the buffer grows to
`max_size`, and then `broken`/error is signaled (feeding `recording_failed`)
rather than hanging.

### F5 — Deterministic signal tests (test-reliability)

**File:** `proxy/src/signals.rs` (`#[cfg(test)] mod tests`).

The two `drain_*` tests mutate process-global `static AtomicBool` flags
(`SIGWINCH_RECEIVED` etc.) and race under Rust's default parallel test runner,
so `cargo test` is nondeterministically red.

**Fix:** serialize the shared-global tests — a module-local `static TEST_LOCK:
Mutex<()>` acquired at the top of each affected test (no new deps), or equivalent.
Do not change production `drain()`; it is correct.

**Acceptance:** `cargo test --workspace` (default parallel) is green repeatably.

### F6 — PID-namespace isolation is mandatory (fail-closed)

**Files:** `proxy/src/main.rs` (`~:347–355`), `proxy/src/process.rs`
(`spawn_shell`, `~:355–375`), `proxy/src/config.rs` (new knob), possibly
`nixos-module.nix`.

Two fail-open holes let the recorded user run outside PID isolation — the
property that hides the recorder's pids so the user cannot see or signal it:
- `main.rs:347–355`: a missing `ns_exec` binary prints a warning and passes
  `None`, spawning the shell unisolated.
- `spawn_shell:355–366`: when `ns_exec` is requested but its `execv` fails, the
  child **falls through to the direct (unisolated) exec** at `:368–375`.

**Fix:**
1. Add config `requirePidIsolation: bool` (default **true**). When the `ns_exec`
   binary is missing/unusable and this is true → route through
   `handle_startup_failure` (fail policy applies; Closed denies the session).
   `false` is an explicit operator opt-out for constrained hosts (warn +
   proceed, current behavior).
2. `spawn_shell`: when `ns_exec_path` is `Some` and its `execv` fails, **do not
   fall through** — report failure via the F3 exec-sync pipe and `_exit`, so the
   parent fails closed. The direct exec is reached only when `ns_exec_path` is
   `None` (isolation explicitly not required).
3. Reuse the **single exec-sync-pipe helper** from F3 to detect ns_exec/unshare
   failure in the shell child (parent EOF = shell exec'd isolated; byte = failed
   → deny per fail policy).

Combined with F1, this closes the "user can kill the recorder" concern: the user
can no longer see the pids to signal them, and inducing a failure self-terminates
their session rather than yielding an unrecorded shell.

**Acceptance:** with `ns_exec_path` pointing at a nonexistent binary and
`requirePidIsolation=true` (default), the session is denied (no shell); with
`false`, it proceeds with a warning.

## 3. Data preservation & durability boundary

The chain is: proxy buffers → flushes to katagrapho over the pipe → katagrapho
fsyncs to disk. "On disk" means katagrapho fsync'd it. What survives each abrupt
event:

| Event | Preserved | Lost |
|---|---|---|
| Shell exits / killed (graceful) | everything — teardown does `force_flush_chunk` + flush (F2), katagrapho drains the pipe to EOF, finalizes, fsyncs, and the proxy `waitpid`s it | nothing |
| Recording failure (user kills katagrapho / disk full) | everything katagrapho already fsync'd | the proxy's in-flight buffer — the sink is gone, nowhere to write it |
| User SIGKILLs the proxy | kernel pipe buffer (katagrapho drains it on EOF) + all prior fsync'd data | the proxy's userspace buffer not yet written to the pipe |

- F2 makes "everything so far is written" true on the graceful path.
- The unavoidable loss window equals the proxy's in-flight `FlushBuffer` —
  normally tiny (flushed every `latency` s / 64 KiB), bounded by F4's `max_size`
  knob only during an active stall (when katagrapho isn't draining anyway).
- The durability backstop is **katagrapho's fsync cadence** (its own repo) — a
  cross-boundary dependency, not fixed in this phase.

## 4. Testing strategy

- **TDD order:** F0 (failing VM test) → F1 → confirm F0 green. Then F2, F3, F4,
  F6 each with a focused test written first. F5 alongside.
- **Baseline:** release build + clippy stay clean; the full workspace suite
  (currently 96 unit tests) plus the new tests pass under default `cargo test`.
- **Negative-path is the point:** every fix ships with a test that exercises the
  *failure*, not just the happy path — that is the class of gap this phase exists
  to close.

## 5. Risk / ordering notes

- F1 is the highest-value, highest-care change: SIGKILL of a process group in a
  seccomp-confined setuid process. The seccomp `kill` allowance (folded into F1)
  is a prerequisite for F1 to work at all — verify together.
- F3 and F6 share the exec-sync-pipe helper; build it once in F3 and reuse it in
  F6. F3, F4, and F6 all touch `process.rs` spawn/pipe paths — sequence
  F3 → F4 → F6 to avoid churn on the same lines.
- F4's non-blocking switch must not regress the pre-shell header write (see
  F4.4) — this is the one place a naive change could *introduce* a silent
  unrecorded-header bug.
- F6 `requirePidIsolation=true` default may block deployment on hosts without
  PID-namespace capability; that is intended fail-closed, with the knob as the
  documented escape hatch.
