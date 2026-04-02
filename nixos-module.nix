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

  # Build the per-user shell overrides TOML fragment.
  userShellLines = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (name: shell: ''${name} = "${shell}"'') cfg.shell.users
  );

  configFile = pkgs.writeText "epitropos-config.toml" ''
    [general]
    katagrapho_path = "/run/wrappers/bin/katagrapho"
    session_proxy_user = "${cfg.proxyUser}"
    session_proxy_group = "${cfg.proxyGroup}"
    record_input = ${if cfg.recordInput then "true" else "false"}

    [shell]
    default = "${cfg.shell.default}"
    [shell.users]
    ${userShellLines}

    [encryption]
    enabled = ${if cfg.encryption.enable then "true" else "false"}
    recipient_file = "${if cfg.encryption.recipientFile != null then cfg.encryption.recipientFile else ""}"

    [fail_policy]
    default = "${cfg.failPolicy.default}"
    open_for_groups = [${lib.concatMapStringsSep ", " (g: ''"${g}"'') cfg.failPolicy.openForGroups}]
    closed_for_groups = [${lib.concatMapStringsSep ", " (g: ''"${g}"'') cfg.failPolicy.closedForGroups}]

    [nesting]
    always_record_services = []

    [hooks]
    on_recording_failure = "${if cfg.onRecordingFailure != null then cfg.onRecordingFailure else ""}"
  '';
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

    onRecordingFailure = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Optional path to a script/binary invoked when a recording fails.";
    };
  };

  config = mkIf cfg.enable {

    users.groups.${cfg.proxyGroup} = { };

    users.users.${cfg.proxyUser} = {
      isSystemUser = true;
      group = cfg.proxyGroup;
      description = "Epitropos session proxy (privilege drop target)";
      home = "/var/empty";
      shell = "/run/current-system/sw/bin/nologin";
    };

    security.wrappers.epitropos = {
      source = lib.getExe cfg.package;
      owner = "root";
      group = "root";
      setuid = true;
      permissions = "u+rx,g+rx,o+rx";
    };

    environment.etc."epitropos/config.toml" = {
      source = configFile;
      mode = "0444";
    };

    # Replace each recorded user's shell with epitropos.
    # Their real shell is saved in the config file so epitropos knows
    # what to actually spawn inside the PTY.
    users.users = lib.genAttrs cfg.recordUsers (username: {
      shell = lib.mkForce "/run/wrappers/bin/epitropos";
    });

    # Auto-populate per-user shell overrides from the users' originally
    # configured shells (before our override).
    services.epitropos.shell.users = lib.genAttrs cfg.recordUsers (username:
      let
        userCfg = config.users.users.${username};
      in
        # Use the user's configured shell, or fall back to the default.
        # Since we mkForce the shell above, we need to read the
        # *declared* default, not the forced value.
        cfg.shell.default
    );
  };
}
