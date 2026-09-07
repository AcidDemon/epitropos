# NixOS VM test for epitropos + katagrapho integration.
# Run with: nix build .#checks.x86_64-linux.vm-test
{ pkgs, katagraphoFlake, epitroposFlake }:
let
  ssh = "ssh -i /tmp/test-key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null testuser@localhost";
  # Fixed throwaway keypair, generated for this test only. The public half is
  # baked into the store so the test covers the module's store-path
  # recipientFile plumbing (install to /etc/epitropos); a runtime-generated
  # key could only ever exercise the /etc passthrough case.
  testPubKey = "age17gnsphc43g7eehckaxq6ecqkamaqd7prxddxfzul3950wqgakd9qu7zldg";
  testSecretKey = "AGE-SECRET-KEY-1R59K78Z3TUK27KF3K90WXYKZCJC7UCUAYQC32SFGUXY4HGAGMQ4SAGUG2R";
in
pkgs.testers.nixosTest {
  name = "epitropos-session-recording";

  nodes.server = { config, pkgs, ... }: {
    imports = [
      katagraphoFlake.nixosModules.default
      epitroposFlake.nixosModules.default
    ];

    services.katagrapho = {
      enable = true;
      encryption = {
        required = true;
        recipientFile = "/etc/age/recipients.txt";
      };
    };

    services.epitropos = {
      enable = true;
      encryption = {
        enable = true;
        # Store path on purpose: the module must relocate it to
        # /etc/epitropos/recording-recipients or katagrapho rejects it.
        recipientFile = pkgs.writeText "test-recipients" testPubKey;
      };
      recordUsers = [ "testuser" ];
      shell.default = "/run/current-system/sw/bin/bash";
      failPolicy.default = "closed";
    };

    # Materialize /etc as symlinks into the store (not the newer overlay of
    # real files) so the recipient file at /etc/epitropos/recording-recipients
    # is a store symlink, exactly as on a deployed host. This is what a naive
    # canonicalize-then-allowlist check in katagrapho gets wrong.
    system.etc.overlay.enable = false;

    services.openssh = {
      enable = true;
      settings.PasswordAuthentication = false;
    };

    users.users.testuser = {
      isNormalUser = true;
    };


    # katagrapho-verify lives in the katagrapho package; services.katagrapho
    # does not put it on PATH, so the test has to install it explicitly.
    environment.systemPackages = [
      pkgs.age
      katagraphoFlake.packages.${pkgs.stdenv.hostPlatform.system}.default
    ];
  };

  testScript = ''
    # kgv1 base64-encodes every out/in payload in "b" (kgv1.rs:63-65), so the
    # session text never appears literally in a decrypted cast. Decode each
    # chunk and return the concatenation. Chunks are padded individually, hence
    # the loop rather than one base64 -d over the whole stream.
    def decoded(path):
        return server.succeed(
            f"grep -o '\"b\":\"[^\"]*\"' {path} | cut -d'\"' -f4 "
            "| while read -r b; do printf '%s' \"$b\" | base64 -d; done"
        )

    server.wait_for_unit("sshd.service")
    server.wait_for_unit("multi-user.target")

    # Install the fixed test keypair. The private half decrypts recordings;
    # recipients.txt serves the katagrapho-module path that still reads /etc/age.
    server.succeed("mkdir -p /etc/age")
    server.succeed("echo '${testSecretKey}' > /etc/age/key.txt && chmod 600 /etc/age/key.txt")
    server.succeed("echo '${testPubKey}' > /etc/age/recipients.txt")
    # The store-path recipientFile must be installed under /etc/epitropos as a
    # REAL file, not a symlink into the store: katagrapho canonicalizes the
    # recipient path against its /etc allowlist, so a store symlink resolves out
    # and is rejected (this is what locked the host out). A real file's
    # canonical path stays in /etc/epitropos.
    server.succeed("grep -q '${testPubKey}' /etc/epitropos/recording-recipients")
    server.succeed("test ! -L /etc/epitropos/recording-recipients")
    server.succeed("[ \"$(readlink -f /etc/epitropos/recording-recipients)\" = /etc/epitropos/recording-recipients ]")

    # Set up SSH key auth
    server.succeed("ssh-keygen -t ed25519 -f /tmp/test-key -N \"\"")
    server.succeed("mkdir -p /home/testuser/.ssh && chmod 700 /home/testuser/.ssh")
    server.succeed("cp /tmp/test-key.pub /home/testuser/.ssh/authorized_keys")
    server.succeed("chown -R testuser:users /home/testuser/.ssh")

    # Track B: verify signing key was generated at boot
    server.succeed("test -f /var/lib/katagrapho/signing.key")
    server.succeed("test -f /var/lib/katagrapho/signing.pub")
    server.succeed("[ $(stat -c '%a' /var/lib/katagrapho/signing.key) = '400' ]")
    server.succeed("[ $(stat -c '%a' /var/lib/katagrapho/signing.pub) = '444' ]")

    # Run a recorded session
    server.succeed("${ssh} 'echo encrypted-test-data'")

    # Verify encrypted recording exists
    server.succeed("ls /var/log/ssh-sessions/testuser/*.cast.age")

    # Track B: verify signed manifest sidecar was written
    server.succeed("ls /var/log/ssh-sessions/testuser/*.cast.age.manifest.json")

    # Track B: head.hash was advanced and log has a line
    server.succeed("test -s /var/lib/katagrapho/head.hash")
    server.succeed("grep -q testuser /var/lib/katagrapho/head.hash.log")

    # Verify we can decrypt the recording
    server.succeed("age -d -i /etc/age/key.txt /var/log/ssh-sessions/testuser/*.cast.age > /tmp/decrypted.cast")

    # The recording must actually contain what the session printed. Everything
    # else here checks structure -- file exists, header parses, signature and
    # chain verify -- all of which pass on a recording with the wrong payload.
    assert "encrypted-test-data" in decoded("/tmp/decrypted.cast"), \
        "recording does not contain the session output"

    # Verify decrypted content is kgv1 format
    server.succeed("head -1 /tmp/decrypted.cast | grep -q '\"kind\":\"header\"'")
    server.succeed("head -1 /tmp/decrypted.cast | grep -q '\"v\":\"katagrapho-v1\"'")

    # Verify katagrapho-verify validates the sidecar signature
    server.succeed("katagrapho-verify /var/log/ssh-sessions/testuser/*.manifest.json")

    # ------------------------------------------------------------------
    # Everything below records further sessions, so it must come after the
    # single-recording assertions above -- those glob *.cast.age and age(1)
    # takes exactly one input file.
    # ------------------------------------------------------------------

    # A recorded session must not damage the host. ns_exec unshares a mount
    # namespace and mounts /proc; without MS_REC|MS_PRIVATE that mount
    # propagates back into the host namespace, shadows the real procfs, breaks
    # unix_chkpwd and denies every later login on the machine -- including for
    # accounts that are not recorded at all.
    server.succeed("test -e /proc/self/mountinfo")
    server.succeed("timeout 30 ${ssh} 'echo post-recording-login-ok'")

    # The proxy wrapper is setgid ssh-sessions so it can exec the katagrapho
    # wrapper (0550 session-writer:ssh-sessions). drop_to_real_user does not
    # call setgroups -- it cannot, without CAP_SETGID -- so assert the
    # privileged group does not survive into the recorded shell, and that the
    # user's real groups are still intact. One session, three ids.
    ids = server.succeed("timeout 30 ${ssh} 'id -un; id -gn; id -Gn'").splitlines()
    assert ids[0].strip() == "testuser", f"wrong uid in recorded shell: {ids}"
    assert ids[1].strip() == "users", f"wrong gid in recorded shell: {ids}"
    shell_groups = ids[2].split()
    assert "ssh-sessions" not in shell_groups, \
        f"recorded shell leaked the wrapper setgid group: {shell_groups}"
    assert "session-proxy" in shell_groups, \
        f"recorded shell lost its real supplementary groups: {shell_groups}"

    # id -G cannot observe the SAVED gid: a regression from setresgid to
    # setegid-only would leave saved-gid=ssh-sessions (silently restorable
    # via setegid) and still pass the checks above. /proc/self/status shows
    # real/effective/saved/fs — all four must be the user's real gid.
    users_gid = server.succeed("getent group users").split(":")[2].strip()
    gid_line = server.succeed(
        "timeout 30 ${ssh} 'grep ^Gid: /proc/self/status'"
    ).split()
    assert gid_line[1:5] == [users_gid] * 4, \
        f"recorded shell kept a privileged gid (real/eff/saved/fs): {gid_line}"

    # PID isolation: the recorded shell runs as PID 1 in its own PID namespace,
    # so the recorder's pids are not addressable from inside the session. This
    # is what makes the proxy unkillable -- both it and the recorded shell run
    # with the same real uid, so kill(2) would otherwise be permitted.
    hidden = server.succeed(
        "timeout 30 ${ssh} '"
        "pgrep -x epitropos >/dev/null || echo PROXY-HIDDEN; "
        "pgrep -x katagrapho >/dev/null || echo WRITER-HIDDEN'"
    )
    assert "PROXY-HIDDEN" in hidden, "recorded shell can see the proxy pid"
    assert "WRITER-HIDDEN" in hidden, "recorded shell can see the katagrapho pid"

    # ------------------------------------------------------------------
    # F1: recording failure kills the session (fail-closed), partial
    # evidence preserved. This is the negative-path acceptance test whose
    # absence let the fail-open bug ship. Requires /dev/kvm to run.
    # ------------------------------------------------------------------
    with subtest("recording failure tears down the session (F1)"):
        # Background a recorded session: emit a marker, push >64 KiB so the
        # marker is flushed to katagrapho/disk, then idle on `sleep`.
        server.succeed(
            "nohup ${ssh} 'echo MARKER-BEFORE-KILL; yes x | head -n 40000; "
            "exec sleep 600' >/tmp/f1-sess.log 2>&1 &"
        )

        # In-progress recording exists and the recorded shell (now `sleep`) runs.
        server.wait_until_succeeds("ls /var/log/ssh-sessions/testuser/*.cast.age", timeout=60)
        server.wait_until_succeeds("pgrep -u testuser -x sleep", timeout=30)

        # Kill katagrapho mid-session. SIGTERM lets it finalize partial evidence;
        # the proxy sees the writer die and must fail closed.
        server.succeed("kill -TERM $(pgrep -n -x katagrapho)")

        # F1 core invariant: the recorded shell is killed (not left unrecorded)...
        server.wait_until_fails("pgrep -u testuser -x sleep", timeout=30)
        # ...and the proxy exits rather than bridging an unrecorded session.
        server.wait_until_fails("pgrep -x epitropos", timeout=30)

        # Operator-visible: the failure reason is journalled.
        server.wait_until_succeeds(
            "journalctl -b | grep -q 'reason=recording_failed'", timeout=30
        )

        # Partial evidence preserved: the newest recording decrypts and contains
        # the pre-kill output. (Depends on katagrapho finalizing on SIGTERM.)
        newest = server.succeed(
            "ls -t /var/log/ssh-sessions/testuser/*.cast.age | head -n1"
        ).strip()
        server.succeed(f"age -d -i /etc/age/key.txt {newest} > /tmp/f1-partial.cast")
        assert "MARKER-BEFORE-KILL" in decoded("/tmp/f1-partial.cast"), \
            "partial recording lost the output written before the kill"
  '';
}
