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

    # Test 1: SSH command creates a recording and exits cleanly
    server.succeed(
      "sshpass -p testpass ssh -o StrictHostKeyChecking=no testuser@localhost 'echo hello-from-test'"
    )

    # Verify recording file exists with correct ownership
    server.succeed("ls /var/log/ssh-sessions/testuser/*.cast")

    # Verify recording contains session output
    server.succeed("grep -q 'hello-from-test' /var/log/ssh-sessions/testuser/*.cast")

    # Verify recording is valid asciicinema v2 (has version header)
    server.succeed("head -1 /var/log/ssh-sessions/testuser/*.cast | grep -q '\"version\":2'")
  '';
}
