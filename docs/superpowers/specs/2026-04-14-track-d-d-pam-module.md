# Track D(d) — PAM Module for Session Metadata

**Status:** Design approved 2026-04-14
**Predecessors:** Tracks A–D(c) merged to main
**Scope:** New C PAM module + epitropos proxy changes + NixOS module update

A tiny C PAM module (`pam_epitropos.so`, ~40 lines) that stashes
`PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY`, `PAM_USER` to a per-session
file during `pam_sm_open_session`. Epitropos reads the file at
startup to populate the kgv1 header with real PAM fields. The
login-shell approach is unchanged.

## 1. Goals

1. Close the audit gap: kgv1 headers get real `PAM_RHOST` and
   `PAM_SERVICE` instead of `null`.
2. Zero disruption to the existing login-shell + setuid architecture.
3. Graceful degradation: if the PAM module is absent, recording
   works as before (fields stay null).

**Non-goals:**
- Replacing the login-shell trick with PAM-based session wrapping
- Recording non-SSH sessions (console, serial) — PAM module is
  deployed only in `/etc/pam.d/sshd`

## 2. Flow

```
sshd authenticates user
    ↓
PAM stack runs pam_sm_open_session
    ↓
pam_epitropos.so writes /var/run/epitropos/pam.<sshd_pid>.env:
    PAM_RHOST=203.0.113.5
    PAM_SERVICE=sshd
    PAM_TTY=/dev/pts/3
    PAM_USER=alice
    ↓
sshd forks, drops to user, execs epitropos (the login shell)
    ↓
epitropos reads /var/run/epitropos/pam.<ppid>.env
    → populates auth_meta.pam_rhost, auth_meta.pam_service
    → these flow into the kgv1 header
    ↓
pam_sm_close_session unlinks the file
```

## 3. Stash file format

Path: `/var/run/epitropos/pam.<pid>.env`

```
PAM_RHOST=203.0.113.5
PAM_SERVICE=sshd
PAM_TTY=/dev/pts/3
PAM_USER=alice
```

Plain `KEY=VALUE\n` lines. Mode 0640, owned `root:session-proxy`.
Directory `/var/run/epitropos` is owned `root:session-proxy` mode
0750 (changed from the current `session-proxy:session-proxy` 0700
to allow root writes from the PAM stack).

## 4. C source

`epitropos/pam/pam_epitropos.c`:

```c
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#define ENV_DIR "/var/run/epitropos"

static void get_path(char *buf, size_t len) {
    snprintf(buf, len, "%s/pam.%d.env", ENV_DIR, (int)getpid());
}

PAM_EXTERN int pam_sm_open_session(
    pam_handle_t *pamh, int flags, int argc, const char **argv
) {
    (void)flags; (void)argc; (void)argv;
    const char *rhost = NULL, *service = NULL, *tty = NULL, *user = NULL;
    pam_get_item(pamh, PAM_RHOST,   (const void **)&rhost);
    pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    pam_get_item(pamh, PAM_TTY,     (const void **)&tty);
    pam_get_item(pamh, PAM_USER,    (const void **)&user);

    char path[256];
    get_path(path, sizeof(path));

    FILE *f = fopen(path, "w");
    if (!f) return PAM_SUCCESS;
    fchmod(fileno(f), 0640);
    if (rhost)   fprintf(f, "PAM_RHOST=%s\\n", rhost);
    if (service) fprintf(f, "PAM_SERVICE=%s\\n", service);
    if (tty)     fprintf(f, "PAM_TTY=%s\\n", tty);
    if (user)    fprintf(f, "PAM_USER=%s\\n", user);
    fclose(f);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(
    pam_handle_t *pamh, int flags, int argc, const char **argv
) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    char path[256];
    get_path(path, sizeof(path));
    unlink(path);
    return PAM_SUCCESS;
}
```

Returns `PAM_SUCCESS` unconditionally — best-effort. If the file
write fails, the session proceeds without PAM fields (same as
today).

## 5. Epitropos proxy changes

In `proxy/src/auth_meta.rs`, add to `AuthMeta::capture()`:

```rust
fn read_pam_stash() -> (Option<String>, Option<String>) {
    let ppid = unsafe { libc::getppid() };
    let path = format!("/var/run/epitropos/pam.{ppid}.env");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return (None, None);
    };
    let mut rhost = None;
    let mut service = None;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("PAM_RHOST=") {
            rhost = Some(v.to_string());
        }
        if let Some(v) = line.strip_prefix("PAM_SERVICE=") {
            service = Some(v.to_string());
        }
    }
    (rhost, service)
}
```

`AuthMeta::capture()` calls `read_pam_stash()` and fills
`pam_rhost` and `pam_service` (currently always `None`). Called
before `env::sanitize()` but the stash file is independent of the
environment.

## 6. Build

```
epitropos/
├── pam/
│   ├── pam_epitropos.c     # CREATE
│   └── Makefile             # CREATE
```

Makefile:

```makefile
CC ?= gcc
CFLAGS = -Wall -Wextra -Werror -fPIC -O2
LDFLAGS = -shared -lpam

pam_epitropos.so: pam_epitropos.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f pam_epitropos.so

.PHONY: clean
```

Nix derivation in the flake or in the NixOS module:

```nix
pam_epitropos = pkgs.stdenv.mkDerivation {
  pname = "pam-epitropos";
  version = "0.1.0";
  src = ./pam;
  buildInputs = [ pkgs.pam ];
  buildPhase = "make";
  installPhase = ''
    mkdir -p $out/lib/security
    cp pam_epitropos.so $out/lib/security/
  '';
};
```

## 7. NixOS module changes

In `nixos-module.nix`:

Add the PAM module to sshd's session stack:

```nix
security.pam.services.sshd.rules.session.epitropos = {
  order = 10000;  # after standard modules
  control = "optional";
  modulePath = "${pam_epitropos}/lib/security/pam_epitropos.so";
};
```

`control = "optional"` means if pam_epitropos fails (returns
anything other than PAM_SUCCESS), sshd continues without error.
This gives graceful degradation.

Change the tmpfiles rule for `/var/run/epitropos`:

```nix
"d /var/run/epitropos 0750 root ${cfg.proxyGroup} -"
```

(Changed from `${cfg.proxyUser}` owner to `root` owner so the PAM
module, running as root inside sshd, can write files. The group
stays `session-proxy` so epitropos can read.)

## 8. Testing

- Compile test: `make` produces `pam_epitropos.so` with no warnings
- Symbol test: `nm pam_epitropos.so | grep pam_sm` shows both
  `pam_sm_open_session` and `pam_sm_close_session`
- NixOS VM test: SSH into the test user, check the kgv1 recording
  header's `pam_rhost` is non-null and matches the SSH client IP.
  Check `pam_service` is `"sshd"`.
- Regression: remove the PAM module from the stack, SSH in, confirm
  recording still works (fields are null).

## 9. Acceptance criteria

1. `pam_epitropos.so` compiles from C source with `-Wall -Wextra
   -Werror` and no warnings
2. After SSH login, `/var/run/epitropos/pam.<pid>.env` exists with
   `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY`, `PAM_USER` fields
3. After session ends, the stash file is cleaned up by
   `pam_sm_close_session`
4. kgv1 recording header contains non-null `pam_rhost` and
   `pam_service` for SSH sessions
5. Recording still works if the PAM module is not installed (fields
   stay `None`, no errors)
6. NixOS module deploys the PAM module into the sshd PAM stack
   with `control = "optional"`
7. tmpfiles rule creates `/var/run/epitropos` as `root:session-proxy`
   mode 0750
