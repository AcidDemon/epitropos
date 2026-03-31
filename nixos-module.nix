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

  configFile = pkgs.writeText "epitropos-config.toml" ''
    [general]
    katagrapho_path = "/run/wrappers/bin/katagrapho"
    session_proxy_uid = ${toString config.users.users.${cfg.proxyUser}.uid}
    session_proxy_gid = ${toString config.users.groups.${cfg.proxyGroup}.gid}
    record_input = ${if cfg.recordInput then "true" else "false"}

    [encryption]
    recipient_file = "${cfg.recipientFile}"

    [fail_policy]
    default = "${cfg.failPolicy.default}"
    open_for_groups = [${lib.concatMapStringsSep ", " (g: ''"${g}"'') cfg.failPolicy.openForGroups}]
    closed_for_groups = [${lib.concatMapStringsSep ", " (g: ''"${g}"'') cfg.failPolicy.closedForGroups}]

    [nesting]
    always_record_services = [${lib.concatMapStringsSep ", " (s: ''"${s}"'') cfg.alwaysRecord}]

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

    services = mkOption {
      type = types.listOf types.str;
      default = [
        "sshd"
        "login"
      ];
      description = "PAM services to attach epitropos to.";
    };

    alwaysRecord = mkOption {
      type = types.listOf types.str;
      default = [ "sshd" ];
      description = "PAM services for which session nesting is ignored and recording always happens.";
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

    recipientFile = mkOption {
      type = types.path;
      description = "Path to file containing the age public key(s) used to encrypt recordings.";
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

    security.pam.services = lib.genAttrs cfg.services (_svc: {
      rules.session.epitropos = {
        order = 10000;
        control = "required";
        modulePath = "pam_exec.so";
        args = [ "/run/wrappers/bin/epitropos" ];
      };
    });
  };
}
