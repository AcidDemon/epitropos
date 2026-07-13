# NixOS VM test for the epitropos-audit authoritative privilege-event feed.
# Run: nix build .#checks.x86_64-linux.vm-audit-test
#
# Validates the feed end-to-end on a REAL audited host with REAL kernel audit
# records: enable auditd + the execute-watch rules, run a real login session
# (pam_loginuid → real audit_session_id) that executes sudo, then correlate the
# kernel audit trail to a recording manifest and assert a signed, verifiable
# <recording>.privileges.json capturing the escalation.
#
# NOTE ON THE MANIFEST: the feed consumes katagrapho's signed manifest purely as
# a bridge table (it carries the (host, boot_id, audit_session_id) join tuple).
# We hand-author that manifest here instead of driving epitropos's recorder,
# because the recorder's shell exec is currently broken in this tree — an
# unrelated upstream bug (a minimal epitropos+katagrapho config reproduces
# "epitropos: shell failed to start: child process failed to exec", with no
# audit feed involved). Standing in for the manifest keeps this test faithful to
# what the feed actually reads while decoupling it from that bug.
{ pkgs, katagraphoFlake, epitroposFlake }:
let
  system = pkgs.stdenv.hostPlatform.system;
  auditPkg = epitroposFlake.packages.${system}.epitropos-audit;
  ssh = "ssh -i /tmp/test-key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null auditor@localhost";
in
pkgs.testers.nixosTest {
  name = "epitropos-audit-feed";

  nodes.host = { config, pkgs, ... }: {
    imports = [
      katagraphoFlake.nixosModules.default
      epitroposFlake.nixosModules.default
      epitroposFlake.nixosModules.audit
    ];

    # katagrapho + epitropos are enabled so the feed deploys in its real context
    # (recording dirs, ssh-sessions group). Their recorder is not exercised here.
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

    services.epitropos-audit.enable = true;

    services.openssh = {
      enable = true;
      settings.PasswordAuthentication = false;
    };

    # The join key (audit_session_id) requires pam_loginuid at login.
    security.pam.services.sshd.setLoginUid = true;

    # auditor is a normal (non-recorded) user with passwordless sudo, so its
    # login shell is a plain bash and it can run sudo through /run/wrappers/bin.
    security.sudo.extraRules = [{
      users = [ "auditor" ];
      commands = [{ command = "ALL"; options = [ "NOPASSWD" ]; }];
    }];

    users.users.testuser = { isNormalUser = true; };
    users.users.auditor = { isNormalUser = true; };

    environment.systemPackages = [ pkgs.age auditPkg ];
    virtualisation.memorySize = 2048;
  };

  testScript = ''
    host.wait_for_unit("multi-user.target")
    host.wait_for_unit("sshd.service")
    host.wait_for_unit("auditd.service")
    host.wait_for_unit("epitropos-audit-rules.service")
    host.wait_for_unit("epitropos-audit.service")

    # ssh key for the auditor login.
    host.succeed("ssh-keygen -t ed25519 -f /tmp/test-key -N \"\"")
    host.succeed("mkdir -p /home/auditor/.ssh && chmod 700 /home/auditor/.ssh")
    host.succeed("cp /tmp/test-key.pub /home/auditor/.ssh/authorized_keys")
    host.succeed("chown -R auditor:users /home/auditor/.ssh")

    # The execute-watch rules loaded and the feed's signing key was generated.
    host.wait_until_succeeds("auditctl -l | grep -q epitropos_privesc", timeout=30)
    host.succeed("test -f /var/lib/epitropos-audit/signing.key")

    # A real login session (pam_loginuid assigns a kernel audit_session_id) that
    # escalates via sudo. /proc/self/sessionid == auditd's ses= == the manifest's
    # audit_session_id — the authoritative join key.
    # (/proc/self/sessionid has no trailing newline — separate it from sudo output)
    out = host.succeed("${ssh} 'cat /proc/self/sessionid; echo; sudo -n id'")
    ses = out.splitlines()[0].strip()
    print(f"=== auditor session ses={ses} ===\n{out}")
    assert ses.isdigit() and ses != "4294967295", f"no audit_session_id (pam_loginuid?): {ses!r}"

    # The kernel captured the sudo execution under our rule key, tagged with ses.
    host.wait_until_succeeds(f"grep -a 'ses={ses}' /var/log/audit/audit.log | grep -q epitropos_privesc", timeout=30)

    # Hand-authored katagrapho manifest carrying the join tuple (see header note).
    boot = host.succeed("cat /proc/sys/kernel/random/boot_id").strip()
    now = int(host.succeed("date +%s").strip())
    sid = "diagsession0000"
    recdir = "/var/log/ssh-sessions/testuser"
    rec = f"{recdir}/{sid}.part0.kgv1.age"
    host.succeed(f"install -d -o session-writer -g ssh-sessions -m 2750 {recdir}")
    host.succeed(f": > {rec}")
    manifest = ('{"session_id":"%s","part":0,"host":"host","boot_id":"%s",'
                '"audit_session_id":%s,"started":%d,"ended":%d}'
                % (sid, boot, ses, now - 120, now + 120))
    host.succeed(f"printf '%s' '{manifest}' > {rec}.manifest.json")

    # Part A — the daemon correlates the manifest against the local audit trail
    # and writes a signed sidecar. Restart forces a deterministic scan_tree pickup.
    with subtest("daemon produces a signed sidecar from real audit data"):
        host.succeed("systemctl restart epitropos-audit.service")
        host.wait_until_succeeds(f"test -f {rec}.privileges.json", timeout=60)
        print("=== daemon sidecar ===\n" + host.succeed(f"cat {rec}.privileges.json"))
        host.succeed(f"epitropos-audit verify {rec}.privileges.json --pub /var/lib/epitropos-audit/signing.pub")
        host.succeed(f"grep -q '\"kind\": \"sudo\"' {rec}.privileges.json")
        host.succeed(f"grep -q '\"target_user\": \"root\"' {rec}.privileges.json")
        host.succeed(f"grep -q '\"actor_user\": \"auditor\"' {rec}.privileges.json")
        # decoded argv from the EXECVE record, not raw SYSCALL pointer args
        host.succeed(f"grep -q '\"command\": \"sudo -n id\"' {rec}.privileges.json")

    # Part B — deterministic cross-check with a fresh key + explicit analyze.
    with subtest("explicit analyze reproduces the capture and verifies"):
        host.succeed("epitropos-audit keygen --key /tmp/k --pub /tmp/p")
        host.succeed(f"epitropos-audit analyze {rec}.manifest.json /var/log/audit/audit.log "
                     "--key /tmp/k --pub /tmp/p --chain-head /tmp/h --out /tmp/priv.json")
        host.succeed("epitropos-audit verify /tmp/priv.json --pub /tmp/p")
        host.succeed("grep -q '\"kind\": \"sudo\"' /tmp/priv.json")
        host.succeed("grep -q '\"target_user\": \"root\"' /tmp/priv.json")
  '';
}
