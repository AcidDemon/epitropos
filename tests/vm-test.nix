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

    # Verify setup
    server.succeed("test -u /run/wrappers/bin/epitropos")
    server.succeed("test -u /run/wrappers/bin/katagrapho")

    # Run SSH command and capture all output
    exit_code, output = server.execute(
      "sshpass -p testpass ssh -o StrictHostKeyChecking=no testuser@localhost 'echo hello-from-test' 2>&1"
    )
    print(f"SSH exit code: {exit_code}")
    print(f"SSH output: {output}")

    # Check recording files regardless of exit code
    print(server.succeed("ls -la /var/log/ssh-sessions/ 2>&1 || true"))
    print(server.succeed("ls -la /var/log/ssh-sessions/testuser/ 2>&1 || true"))
    print(server.succeed("cat /var/log/ssh-sessions/testuser/*.cast 2>&1 || echo 'no .cast files'"))

    # Verify output was captured
    assert "hello-from-test" in output, f"Expected 'hello-from-test' in output but got: {output}"

    # Verify recording exists and contains our output
    server.succeed("ls /var/log/ssh-sessions/testuser/*.cast")
    server.succeed("grep -q 'hello-from-test' /var/log/ssh-sessions/testuser/*.cast")
  '';
}
