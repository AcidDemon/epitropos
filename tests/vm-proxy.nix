# NixOS VM test for epitropos + katagrapho integration.
# Run with: nix build .#checks.x86_64-linux.vm-test
{ pkgs, katagraphoFlake, epitroposFlake }:
let
  ssh = "ssh -i /tmp/test-key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null testuser@localhost";
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
        recipientFile = "/etc/age/recipients.txt";
      };
      recordUsers = [ "testuser" ];
      shell.default = "/run/current-system/sw/bin/bash";
      failPolicy.default = "closed";
    };

    services.openssh = {
      enable = true;
      settings.PasswordAuthentication = false;
    };

    users.users.testuser = {
      isNormalUser = true;
    };

    environment.systemPackages = [ pkgs.age ];
  };

  testScript = ''
    server.wait_for_unit("sshd.service")
    server.wait_for_unit("multi-user.target")

    # Generate age keypair
    server.succeed("mkdir -p /etc/age")
    server.succeed("age-keygen -o /etc/age/key.txt 2>&1 | grep '^Public key:' | awk '{print $NF}' > /etc/age/recipients.txt")
    print(server.succeed("cat /etc/age/recipients.txt"))

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

    # Verify decrypted content is kgv1 format
    server.succeed("grep -q 'encrypted-test-data' /tmp/decrypted.cast")
    server.succeed("head -1 /tmp/decrypted.cast | grep -q '\"kind\":\"header\"'")
    server.succeed("head -1 /tmp/decrypted.cast | grep -q '\"v\":\"katagrapho-v1\"'")

    # Verify katagrapho-verify validates the sidecar signature
    server.succeed("katagrapho-verify /var/log/ssh-sessions/testuser/*.manifest.json")

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
        server.succeed("grep -q MARKER-BEFORE-KILL /tmp/f1-partial.cast")
  '';
}
