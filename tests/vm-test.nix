# NixOS VM test for epitropos + katagrapho integration.
# Run with: nix build .#checks.x86_64-linux.vm-test
{ pkgs, katagraphoFlake, epitroposFlake }:
pkgs.nixosTest {
  name = "epitropos-session-recording";

  nodes.server = { config, pkgs, ... }: {
    imports = [
      katagraphoFlake.nixosModules.default
      epitroposFlake.nixosModules.default
    ];

    services.katagrapho = {
      enable = true;
      encryption = {
        required = false;
      };
    };

    services.epitropos = {
      enable = true;
      services = [ "sshd" ];
      recipientFile = "/dev/null";
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
  };

  testScript = ''
    server.wait_for_unit("sshd.service")
    server.wait_for_unit("multi-user.target")

    # Test 1: SSH session creates a recording
    server.succeed(
      "sshpass -p testpass ssh -o StrictHostKeyChecking=no testuser@localhost 'echo hello-from-test; exit'"
    )

    # Verify a recording file exists
    server.succeed("ls /var/log/ssh-sessions/testuser/*.cast")

    # Verify the recording contains our test output
    server.succeed("grep -q 'hello-from-test' /var/log/ssh-sessions/testuser/*.cast")

    # Test 2: Verify fd isolation — shell should only have fds 0, 1, 2
    server.succeed(
      "sshpass -p testpass ssh -o StrictHostKeyChecking=no testuser@localhost 'ls -la /proc/self/fd | wc -l' | grep -q '^4$'"
    )
  '';
}
