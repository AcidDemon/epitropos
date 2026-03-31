# epitropos

PTY-proxy for tamper-proof session recording. Triggered via PAM, it interposes between the user and their shell so that recording **cannot be bypassed, killed, or interfered with** from within the session.

Named after the Greek *epitropos* (guardian/overseer) — the process that watches over every recorded session.

## How it works

When a user logs in (SSH, console, `su`, etc.), PAM launches `epitropos` as a session wrapper. It allocates a new PTY, spawns the user's shell on the slave side, and bridges all I/O while generating an [asciicinema v2](https://docs.asciinema.org/manual/asciicast/v2/) stream. This stream is piped to [katagrapho](https://github.com/AcidDemon/katagrapho) for age encryption and tamper-proof storage.

```
PAM ─► epitropos (setuid root)
         │
         ├─ allocates PTY
         ├─ spawns katagrapho (stdin pipe)
         ├─ forks shell as user on PTY slave
         ├─ drops to session-proxy UID
         │
         └─ event loop:
              user terminal ◄──► PTY master ──► asciicinema ──► katagrapho
```

After setup, `epitropos` drops from root to a dedicated `session-proxy` user. Since it runs under a different UID than the recorded user, the user **cannot signal, ptrace, or kill it**.

## Security properties

- **Unkillable proxy** — runs as `session-proxy` UID, not the user's UID
- **No ptrace** — `PR_SET_DUMPABLE(0)` and `PR_SET_PTRACER(none)`
- **Fd isolation** — shell only has fds 0/1/2 (PTY slave), no access to pipe or PTY master
- **PAM enforcement** — the proxy *is* the session; no shell without recording
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
            services = [ "sshd" "login" ];  # PAM services to record
            recipientFile = "/etc/age/session-recording.pub";
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

### PAM services

```nix
services.epitropos.services = [ "sshd" "login" ];      # recorded by default
services.epitropos.alwaysRecord = [ "sshd" ];           # ignore nesting for these
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
services.epitropos.recordInput = false;          # record keyboard input (asciicinema "i" events)
services.epitropos.onRecordingFailure = null;    # optional hook script on failure
```

## Architecture

`epitropos` is one half of a two-component system:

| Component | Role |
|---|---|
| **epitropos** | PTY proxy — PAM-triggered, owns the terminal, generates asciicinema v2 |
| **katagrapho** | Storage writer — encrypts with age, writes tamper-proof files |

IPC is a stdin pipe. `epitropos` spawns `katagrapho` as a child process. If `katagrapho` dies, the pipe breaks, and `epitropos` kills the session.

### Nesting detection

When `su`/`sudo` is configured for recording, sessions inside already-recorded sessions are detected via the `EPITROPOS_SESSION_ID` environment variable. Nested recordings are skipped (the outer session already captures everything) unless the service is in `alwaysRecord`.

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
