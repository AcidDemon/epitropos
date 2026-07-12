# epitropos

PTY-proxy for tamper-proof session recording. Installed as the recorded user's login shell, it interposes between the user and their real shell so that recording **cannot be bypassed, killed, or interfered with** from within the session.

Named after the Greek *epitropos* (guardian/overseer) — the process that watches over every recorded session.

## How it works

When a recorded user logs in (SSH, console, `su`, etc.), their login shell **is** `epitropos` — installed setuid to a dedicated, unprivileged `session-proxy` user. It allocates a new PTY, spawns the user's real shell on the slave side, and bridges all I/O while generating an [asciicinema v2](https://docs.asciinema.org/manual/asciicast/v2/) stream. This stream is piped to [katagrapho](https://github.com/AcidDemon/katagrapho) for age encryption and tamper-proof storage.

```
login ─► epitropos (setuid session-proxy, never root)
           │
           ├─ allocates PTY
           ├─ spawns katagrapho (stdin pipe)
           ├─ forks the real shell, dropping it to the invoking user on the PTY slave
           ├─ isolates the recorder in a PID namespace (via epitropos-ns-exec)
           │
           └─ event loop:
                user terminal ◄──► PTY master ──► asciicinema ──► katagrapho
```

`epitropos` runs as the dedicated `session-proxy` user throughout — it is **never root**. Because it runs under a different UID than the recorded shell, and PID-namespace isolation hides its pids, the user **cannot signal, ptrace, or kill it**.

## Security properties

- **Unkillable proxy** — runs as `session-proxy` UID, not the user's UID
- **No ptrace** — `PR_SET_DUMPABLE(0)` and `PR_SET_PTRACER(none)`
- **Fd isolation** — shell only has fds 0/1/2 (PTY slave), no access to pipe or PTY master
- **Login-shell enforcement** — the proxy *is* the user's login shell; no shell without recording
- **Environment sanitized** — `LD_PRELOAD`, `LD_LIBRARY_PATH`, etc. stripped
- **Recording failure kills session** — no unrecorded activity allowed
- **Partial evidence preserved** — interrupted recordings kept with termination marker
- **Full RELRO, PIE, overflow checks**

## Installation (NixOS)

Requires both `epitropos` and `katagrapho` flakes:

```nix
# flake.nix
{
  inputs = {
    katagrapho.url = "github:AcidDemon/katagrapho";
    epitropos.url = "github:AcidDemon/epitropos";
  };

  outputs = { self, nixpkgs, katagrapho, epitropos, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        katagrapho.nixosModules.default
        epitropos.nixosModules.default
        {
          services.katagrapho = {
            enable = true;
            encryption.recipientFile = "/etc/age/session-recording.pub";
          };

          services.epitropos = {
            enable = true;
            recordUsers = [ "alice" "bob" ];  # users whose login shell becomes the recorder
            encryption = {
              enable = true;
              recipientFile = "/etc/age/session-recording.pub";
            };
            failPolicy.default = "closed";
            failPolicy.closedForGroups = [ "wheel" ];
          };
        }
      ];
    };
  };
}
```

## Configuration

### Recorded users

Recording is enabled per-user by replacing the user's login shell with the proxy:

```nix
services.epitropos.recordUsers = [ "alice" "bob" ];    # these users' login shells become the recorder
```

### Fail policy

Controls what happens when recording cannot start (missing katagrapho, disk full, etc.):

```nix
services.epitropos.failPolicy = {
  default = "closed";              # deny session if recording fails
  openForGroups = [ "users" ];     # allow these groups through unrecorded
  closedForGroups = [ "wheel" ];   # never allow these groups unrecorded
};
```

### Other options

```nix
services.epitropos.recordInput = false;           # record keyboard input (asciicinema "i" events)
services.epitropos.onRecordingFailure = null;     # optional hook script on failure
services.epitropos.requirePidIsolation = true;    # deny the session if PID-namespace isolation is unavailable
```

## Architecture

`epitropos` is one half of a two-component system:

| Component | Role |
|---|---|
| **epitropos** | PTY proxy — the recorded user's login shell, owns the terminal, generates asciicinema v2 |
| **katagrapho** | Storage writer — encrypts with age, writes tamper-proof files |

IPC is a stdin pipe. `epitropos` spawns `katagrapho` as a child process. If `katagrapho` dies, the pipe breaks, and `epitropos` kills the session.

### Nesting detection

Sessions nested inside an already-recorded session (e.g. `su`/`sudo` into another recorded user) are detected by the **kernel audit session id** (`/proc/self/sessionid`) plus an advisory `flock` on `/run/epitropos/session.<audit-session-id>.lock`. A nested session finds the lock already held and is skipped — the outer session already captures everything. The audit session id is assigned by the kernel and cannot be forged from within the session, so nesting detection cannot be bypassed by manipulating the environment. (`EPITROPOS_SESSION_ID` is exported into the shell for journald correlation only; it is never read to make recording decisions.)

## Building from source

```sh
# With Nix
nix build

# With Cargo
cargo build --release
```

Requires Rust >= 1.85 (edition 2024).

## Dependencies

- `libc` — POSIX syscalls (PTY, fork, signals, terminal control)
- `serde` + `toml` — config file parsing
- `serde_json` — asciicinema v2 event formatting

## License

MIT
