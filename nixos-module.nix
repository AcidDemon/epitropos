# NixOS module for epitropos.
# Consumed as: imports = [ inputs.epitropos.nixosModules.default ];
flakeSelf:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.epitropos;
  inherit (lib)
    mkEnableOption
    mkOption
    mkIf
    types
    literalExpression
    ;

  tomlFormat = pkgs.formats.toml { };

  configFile = tomlFormat.generate "epitropos-config.toml" {
    general = {
      katagrapho_path = "/run/wrappers/bin/katagrapho";
      record_input = cfg.recordInput;
      ns_exec_path = "/run/wrappers/bin/epitropos-ns-exec";
    };
    shell = {
      default = cfg.shell.default;
      users = cfg.shell.users;
    };
    encryption = {
      enabled = cfg.encryption.enable;
      recipient_file = if cfg.encryption.recipientFile != null then cfg.encryption.recipientFile else "";
    };
    fail_policy = {
      default = cfg.failPolicy.default;
      open_for_groups = cfg.failPolicy.openForGroups;
      closed_for_groups = cfg.failPolicy.closedForGroups;
    };
    notice = {
      text = cfg.noticeText;
    };
    hooks = {
      on_recording_failure = if cfg.onRecordingFailure != null then cfg.onRecordingFailure else "";
    };
    chunk = {
      max_bytes = cfg.chunk.maxBytes;
      max_messages = cfg.chunk.maxMessages;
      max_seconds = cfg.chunk.maxSeconds;
    };
  };
in
{
  options.services.epitropos = {
    enable = mkEnableOption "epitropos session recording proxy";

    package = mkOption {
      type = types.package;
      default = flakeSelf.packages.${pkgs.stdenv.hostPlatform.system}.epitropos;
      defaultText = literalExpression "inputs.epitropos.packages.\${system}.epitropos";
      description = "The epitropos package to use.";
    };

    proxyUser = mkOption {
      type = types.str;
      default = "session-proxy";
      description = "System user for the privilege drop target.";
    };

    proxyGroup = mkOption {
      type = types.str;
      default = "session-proxy";
      description = "System group for the privilege drop target.";
    };

    # Users whose shell should be replaced with epitropos.
    recordUsers = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        List of usernames whose login shell will be replaced with epitropos.
        Their real shell is preserved in the epitropos config and spawned
        inside the recording PTY proxy.
      '';
    };

    shell = {
      default = mkOption {
        type = types.str;
        default = "/run/current-system/sw/bin/bash";
        description = "Default real shell for recorded users.";
      };

      users = mkOption {
        type = types.attrsOf types.str;
        default = { };
        description = ''
          Per-user real shell overrides. Automatically populated from
          users' configured shells when recordUsers is set, but can be
          extended manually.
        '';
      };
    };

    failPolicy = {
      default = mkOption {
        type = types.enum [
          "closed"
          "open"
        ];
        default = "closed";
        description = ''
          Default fail policy when epitropos cannot record a session.
          "closed" denies the session; "open" allows it through unrecorded.
        '';
      };

      openForGroups = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Groups for which the fail policy is overridden to open.";
      };

      closedForGroups = mkOption {
        type = types.listOf types.str;
        default = [ "wheel" ];
        description = "Groups for which the fail policy is overridden to closed.";
      };
    };

    encryption = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Whether to encrypt recordings with age.";
      };

      recipientFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to file containing the age public key(s) used to encrypt recordings.";
      };
    };

    recordInput = mkOption {
      type = types.bool;
      default = false;
      description = "Whether to record terminal input in addition to output.";
    };

    noticeText = mkOption {
      type = types.str;
      default = "\\nATTENTION! Your session is being recorded!\\n\\n";
      description = "Banner shown before recording starts. Empty string to disable.";
    };

    onRecordingFailure = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Optional path to a script/binary invoked when a recording fails.";
    };

    chunk = {
      maxBytes = mkOption {
        type = types.int;
        default = 65536;
        description = "Max bytes per chunk before forcing a boundary.";
      };
      maxMessages = mkOption {
        type = types.int;
        default = 256;
        description = "Max messages per chunk before forcing a boundary.";
      };
      maxSeconds = mkOption {
        type = types.float;
        default = 10.0;
        description = "Max elapsed seconds per chunk before forcing a boundary.";
      };
    };

    forward = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable automatic shipping of recordings to a collector.";
      };

      collector = mkOption {
        type = types.str;
        default = "";
        example = "nyx.tailnet:8443";
        description = "Collector address and port.";
      };

      pushIntervalSeconds = mkOption {
        type = types.int;
        default = 300;
        description = "How often the push timer fires (seconds).";
      };
    };
  };

  config = mkIf cfg.enable {

    assertions = [
      {
        assertion = config.services.katagrapho.enable or false;
        message = "epitropos requires services.katagrapho.enable = true for session recording storage.";
      }
    ];

    users.groups.${cfg.proxyGroup}.members = cfg.recordUsers;

    users.users = {
      ${cfg.proxyUser} = {
        isSystemUser = true;
        group = cfg.proxyGroup;
        description = "Epitropos session proxy (privilege drop target)";
        home = "/var/empty";
        shell = "/run/current-system/sw/bin/nologin";
      };
    } // lib.genAttrs cfg.recordUsers (_username: {
      shell = lib.mkForce "/run/wrappers/bin/epitropos";
    });

    security.wrappers.epitropos = {
      source = lib.getExe cfg.package;
      owner = cfg.proxyUser;
      group = cfg.proxyGroup;
      setuid = true;
      permissions = "u+rx,g+rx,o-rwx";
    };

    security.wrappers.epitropos-ns-exec = {
      source = "${cfg.package}/bin/epitropos-ns-exec";
      owner = "root";
      group = cfg.proxyGroup;
      # +ep required: unshare(2) needs CAP_SYS_ADMIN in effective set.
      # Binary drops all caps immediately after unshare+fork.
      capabilities = "cap_sys_admin+ep";
      setuid = false;
      permissions = "u+rx,g+rx,o-rwx";
    };

    environment.etc."epitropos/config.toml" = {
      source = configFile;
      mode = "0440";
      user = cfg.proxyUser;
      group = cfg.proxyGroup;
    };

    systemd.tmpfiles.rules = [
      "d /var/run/epitropos 0700 ${cfg.proxyUser} ${cfg.proxyGroup} -"
    ] ++ lib.optionals cfg.forward.enable [
      "d /var/lib/epitropos-forward 0750 epitropos-forward epitropos-forward -"
    ];

    # Forward submodule: timer-driven push to the collector.
    users.users.epitropos-forward = lib.mkIf cfg.forward.enable {
      isSystemUser = true;
      group = "epitropos-forward";
      description = "Epitropos recording shipper";
      home = "/var/empty";
      shell = "/run/current-system/sw/bin/nologin";
      extraGroups = [ "katagrapho-readers" ];
    };

    users.groups.epitropos-forward = lib.mkIf cfg.forward.enable { };

    systemd.services.epitropos-forward-push = lib.mkIf cfg.forward.enable {
      description = "Ship session recordings to collector";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${cfg.package}/bin/epitropos-forward push --once";
        User = "epitropos-forward";
        Group = "epitropos-forward";
        ProtectSystem = "strict";
        ReadWritePaths = [ "/var/lib/epitropos-forward" ];
        ReadOnlyPaths = [
          "/var/lib/katagrapho"
          "/var/log/ssh-sessions"
        ];
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
        PrivateDevices = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
      };
    };

    systemd.timers.epitropos-forward-push = lib.mkIf cfg.forward.enable {
      description = "Timer for recording shipment";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnUnitActiveSec = "${toString cfg.forward.pushIntervalSeconds}s";
        OnBootSec = "60s";
        Persistent = true;
      };
    };

  };
}
