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
      encryption.required = false;
    };

    services.epitropos = {
      enable = true;
      encryption.enable = false;
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
  };

  testScript = ''
    server.wait_for_unit("sshd.service")
    server.wait_for_unit("multi-user.target")

    # Set up ephemeral SSH key auth
    server.succeed("ssh-keygen -t ed25519 -f /tmp/test-key -N \"\"")
    server.succeed("mkdir -p /home/testuser/.ssh && chmod 700 /home/testuser/.ssh")
    server.succeed("cp /tmp/test-key.pub /home/testuser/.ssh/authorized_keys")
    server.succeed("chown -R testuser:users /home/testuser/.ssh")

    print(server.succeed("getent passwd testuser"))

    server.succeed("${ssh} 'echo hello-from-test'")

    server.succeed("ls /var/log/ssh-sessions/testuser/*.cast")
    server.succeed("grep -q 'hello-from-test' /var/log/ssh-sessions/testuser/*.cast")
    server.succeed("head -1 /var/log/ssh-sessions/testuser/*.cast | grep -q '\"version\":2'")
  '';
}
