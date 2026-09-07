# NixOS VM test: recording encrypted to an age PLUGIN recipient (age-plugin-yubikey).
#
# This reproduces the "darcy" deployment, whose recipient is a YubiKey plugin
# recipient (age1yubikey1…), not a native X25519 key. katagrapho must load the
# plugin recipient and encrypt to it. Encryption to such a recipient needs the
# age-plugin-yubikey binary but NOT the physical key (only decryption does), so
# this asserts an encrypted recording is produced with a piv-p256 stanza rather
# than decrypting it.
{ pkgs, katagraphoFlake, epitroposFlake }:
let
  ssh = "ssh -i /tmp/test-key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null testuser@localhost";
  # A real age-plugin-yubikey recipient (the deployed darcy recipient). Its
  # private half lives on a YubiKey and is never needed to encrypt.
  ykRecipient = "age1yubikey1qtkly5zgk75f7fnwkvru2pcaxps2s6z9pxj4r2lygsr3cnm0wfazzr3rvvu";
in
pkgs.testers.nixosTest {
  name = "epitropos-yubikey-recipient";

  nodes.server = { config, pkgs, ... }: {
    imports = [
      katagraphoFlake.nixosModules.default
      epitroposFlake.nixosModules.default
    ];

    # Mirror a real host: /etc as store symlinks, not the overlay of real files.
    system.etc.overlay.enable = false;

    services.katagrapho = {
      enable = true;
      encryption = {
        required = true;
        recipientFile = pkgs.writeText "yk-recipients" ykRecipient;
        # The binary katagrapho re-adds to PATH to reach the plugin recipient.
        plugins = [ pkgs.age-plugin-yubikey ];
      };
    };

    services.epitropos = {
      enable = true;
      encryption = {
        enable = true;
        recipientFile = pkgs.writeText "yk-recipients" ykRecipient;
      };
      recordUsers = [ "testuser" ];
      shell.default = "/run/current-system/sw/bin/bash";
      failPolicy.default = "closed";
    };

    services.openssh = {
      enable = true;
      settings.PasswordAuthentication = false;
    };

    users.users.testuser.isNormalUser = true;
  };

  testScript = ''
    server.wait_for_unit("sshd.service")
    server.wait_for_unit("multi-user.target")
    server.succeed("test -f /var/lib/katagrapho/signing.key")

    # katagrapho's config must carry the plugin bin dir.
    server.succeed("grep -q plugin_path /etc/katagrapho/config.toml")

    server.succeed('ssh-keygen -t ed25519 -f /tmp/test-key -N ""')
    server.succeed("mkdir -p /home/testuser/.ssh && chmod 700 /home/testuser/.ssh")
    server.succeed("cp /tmp/test-key.pub /home/testuser/.ssh/authorized_keys")
    server.succeed("chown -R testuser:users /home/testuser/.ssh")

    # A recorded session must SUCCEED (fail policy is closed): if katagrapho
    # could not encrypt to the yubikey recipient it would exit and this login
    # would be killed, exactly as it was on the host.
    got = server.succeed("timeout 30 ${ssh} 'echo recorded-ok'")
    assert "recorded-ok" in got, f"recorded session did not run: {got!r}"

    # An encrypted recording exists and is a real age file wrapped to the
    # yubikey recipient (piv-p256 stanza). We cannot decrypt without hardware.
    rec = server.succeed(
        "ls -t /var/log/ssh-sessions/testuser/*.cast.age | head -n1"
    ).strip()
    server.succeed(f"head -c 64 {rec} | grep -q 'age-encryption.org'")
    server.succeed(f"head -c 200 {rec} | grep -q 'piv-p256'")
  '';
}
