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

    # Run a recorded session
    server.succeed("${ssh} 'echo encrypted-test-data'")

    # Verify encrypted recording exists (.cast.age)
    server.succeed("ls /var/log/ssh-sessions/testuser/*.cast.age")

    # Verify we can decrypt it
    server.succeed("age -d -i /etc/age/key.txt /var/log/ssh-sessions/testuser/*.cast.age > /tmp/decrypted.cast")

    # Verify decrypted content
    server.succeed("grep -q 'encrypted-test-data' /tmp/decrypted.cast")
    server.succeed("head -1 /tmp/decrypted.cast | grep -q '\"version\":2'")
  '';
}
