# NixOS VM test for epitropos + katagrapho integration.
# Run with: nix build .#checks.x86_64-linux.vm-test
{ pkgs, katagraphoFlake, epitroposFlake }:
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
      services = [ "sshd" ];
      encryption.enable = false;
      failPolicy.default = "closed";
    };

    services.openssh = {
      enable = true;
      settings.PasswordAuthentication = true;
    };

    users.users.testuser = {
      isNormalUser = true;
      password = "testpass";
    };

    environment.systemPackages = [ pkgs.sshpass ];
  };

  testScript = ''
    server.wait_for_unit("sshd.service")
    server.wait_for_unit("multi-user.target")

    # Verify config and binaries are in place
    print(server.succeed("cat /etc/epitropos/config.toml"))
    server.succeed("test -u /run/wrappers/bin/epitropos")
    server.succeed("test -u /run/wrappers/bin/katagrapho")

    # Verify sshd has ForceCommand configured
    print(server.succeed("grep -i forcecommand /etc/ssh/sshd_config || true"))

    # Test 1: SSH session creates a recording
    server.succeed(
      "sshpass -p testpass ssh -o StrictHostKeyChecking=no testuser@localhost 'echo hello-from-test'"
    )

    # Verify a recording file exists
    server.succeed("ls /var/log/ssh-sessions/testuser/*.cast")

    # Verify the recording contains our test output
    server.succeed("grep -q 'hello-from-test' /var/log/ssh-sessions/testuser/*.cast")
  '';
}
