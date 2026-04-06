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
      mode = "0444";
    };

    systemd.tmpfiles.rules = [
      "d /var/run/epitropos 0700 ${cfg.proxyUser} ${cfg.proxyGroup} -"
    ];

  };
}
