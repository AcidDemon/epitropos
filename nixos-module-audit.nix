# NixOS module for epitropos-audit — the authoritative privilege-event feed.
# Runs on RECORDING hosts (where sudo/su happen), alongside the katagrapho
# recorder + epitropos-forward. Enables the kernel audit source, then runs a
# daemon that writes a signed `<recording>.privileges.json` sidecar as each
# recording finalizes; epitropos-forward ships it to the collector.
#
# Consumed as: imports = [ inputs.epitropos.nixosModules.audit ];
#
# NOT deployment-verified in this groundwork. Two host-specific details to tune,
# flagged inline below: (1) the audit-log read permission, (2) write access to
# katagrapho's recording directories.
flakeSelf:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.epitropos-audit;
  inherit (lib) mkEnableOption mkOption mkIf types literalExpression;
in
{
  options.services.epitropos-audit = {
    enable = mkEnableOption "epitropos authoritative privilege-event feed";

    package = mkOption {
      type = types.package;
      default = flakeSelf.packages.${pkgs.stdenv.hostPlatform.system}.epitropos-audit;
      defaultText = literalExpression "inputs.epitropos.packages.\${system}.epitropos-audit";
      description = "The epitropos-audit package to use.";
    };

    recordingsDir = mkOption {
      type = types.path;
      default = "/var/log/ssh-sessions";
      description = "katagrapho recording root to watch for finalized manifests.";
    };

    auditLog = mkOption {
      type = types.path;
      default = "/var/log/audit/audit.log";
      description = "Linux audit log the feed reads privilege events from.";
    };

    stateDir = mkOption {
      type = types.path;
      default = "/var/lib/epitropos-audit";
      readOnly = true;
      description = "Signing key + hash-chain head for the audit feed.";
    };

    manageAuditRules = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Enable Linux auditd and install execute-watch rules for sudo/su/doas.
        Set false if you manage the audit subsystem elsewhere.
      '';
    };
  };

  config = mkIf cfg.enable {

    # (1) THE EVENT SOURCE — none exists in epitropos otherwise. Watch execution
    # of the privilege tools; each fires SYSCALL(+EXECVE) records carrying ses=
    # (== the recording's audit_session_id). NixOS wraps setuid binaries under
    # /run/wrappers/bin. Enable the auditd daemon (writes audit.log) + the
    # kernel audit=1 baseline; the watches themselves are loaded LATE (below).
    security.auditd.enable = mkIf cfg.manageAuditRules true;
    security.audit.enable = mkIf cfg.manageAuditRules true;

    # NixOS's audit-rules-nixos.service runs Before=sysinit.target — far too
    # early for a `-w /run/wrappers/bin/sudo` watch, since the setuid wrappers
    # are not created until suid-sgid-wrappers.service later in boot. auditctl
    # silently fails to attach a watch on a path that doesn't exist yet, so the
    # rules would never appear. Load them once the wrappers exist instead.
    systemd.services.epitropos-audit-rules = mkIf cfg.manageAuditRules {
      description = "Load epitropos privilege-escalation audit watches";
      wantedBy = [ "multi-user.target" ];
      after = [ "suid-sgid-wrappers.service" "audit-rules-nixos.service" ];
      wants = [ "suid-sgid-wrappers.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeShellScript "epitropos-audit-rules" ''
          for tool in sudo su doas; do
            p="/run/wrappers/bin/$tool"
            [ -e "$p" ] && ${lib.getExe' pkgs.audit "auditctl"} -w "$p" -p x -k epitropos_privesc || true
          done
        '';
      };
    };

    # The join key (audit_session_id) only exists if pam_loginuid ran at login.
    # systemd-logind + the sshd PAM stack set it on NixOS; assert it isn't
    # disabled so the feed does not silently produce unjoinable (null-ses)
    # recordings.
    assertions = [
      {
        assertion = !(config.security.pam.services ? sshd)
          || config.security.pam.services.sshd.setLoginUid or true;
        message = "epitropos-audit: sshd PAM must set loginuid (pam_loginuid) or audit_session_id is null and events cannot be joined to recordings.";
      }
    ];

    users.users.epitropos-audit = {
      isSystemUser = true;
      group = "epitropos-audit";
      description = "Epitropos authoritative privilege-event feed";
      home = "/var/empty";
      shell = "/run/current-system/sw/bin/nologin";
      # (2) WRITE the sidecar next to the recording: the feed must write into
      # katagrapho's per-user recording dirs. The clean way is a shared group —
      # add this user to `ssh-sessions` and make katagrapho's per-user dirs
      # group-writable (2770). Until katagrapho does that, CAP_DAC_OVERRIDE below
      # is the groundwork shortcut.
      extraGroups = [ "ssh-sessions" ];
    };
    users.groups.epitropos-audit = { };

    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 0750 epitropos-audit epitropos-audit -"
    ];

    systemd.services.epitropos-audit-keygen = {
      description = "Generate epitropos-audit ed25519 signing key (first boot)";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      unitConfig.ConditionPathExists = "!${cfg.stateDir}/signing.key";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${lib.getExe cfg.package} keygen --key ${cfg.stateDir}/signing.key --pub ${cfg.stateDir}/signing.pub";
        User = "epitropos-audit";
        Group = "epitropos-audit";
        RemainAfterExit = true;
      };
    };

    systemd.services.epitropos-audit = {
      description = "Epitropos authoritative privilege-event feed";
      wantedBy = [ "multi-user.target" ];
      after = [ "auditd.service" "epitropos-audit-keygen.service" ];
      requires = [ "epitropos-audit-keygen.service" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = lib.escapeShellArgs [
          (lib.getExe cfg.package)
          "serve"
          "--recordings" (toString cfg.recordingsDir)
          "--audit-log" (toString cfg.auditLog)
          "--key" "${cfg.stateDir}/signing.key"
          "--pub" "${cfg.stateDir}/signing.pub"
          "--chain-head" "${cfg.stateDir}/head.hash"
        ];
        User = "epitropos-audit";
        Group = "epitropos-audit";
        Restart = "on-failure";
        RestartSec = 5;

        # Read the audit log (root:root 0600) + write sidecars into katagrapho's
        # dirs. CAP_DAC_READ_SEARCH reads any file; CAP_DAC_OVERRIDE writes past
        # DAC — both are groundwork shortcuts. Tighten to a shared group +
        # audit-netlink (CAP_AUDIT_READ) once the perms above are arranged.
        AmbientCapabilities = [ "CAP_DAC_READ_SEARCH" "CAP_DAC_OVERRIDE" ];
        CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH" "CAP_DAC_OVERRIDE" ];

        # Hardening (mirrors the collector module).
        ProtectSystem = "strict";
        ReadOnlyPaths = [ (toString cfg.auditLog) ];
        ReadWritePaths = [ (toString cfg.stateDir) (toString cfg.recordingsDir) ];
        PrivateTmp = true;
        NoNewPrivileges = true;
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        RestrictRealtime = true;
      };
    };
  };
}
