# NixOS module for epitropos-collector.
# Consumed as: imports = [ inputs.epitropos.nixosModules.collector ];
flakeSelf:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.epitropos-collector;
  inherit (lib)
    mkEnableOption
    mkOption
    mkIf
    types
    literalExpression
    ;

  tomlFormat = pkgs.formats.toml { };

  configFile = tomlFormat.generate "collector.toml" {
    listen = {
      address = cfg.listenAddress;
      port = cfg.listenPort;
    };
    storage = {
      dir = cfg.storageDir;
      max_upload_bytes = cfg.maxUploadBytes;
    };
    enrollment = {
      token_ttl_seconds = cfg.tokenTtlSeconds;
    };
  };
in
{
  options.services.epitropos-collector = {
    enable = mkEnableOption "epitropos collector service";

    package = mkOption {
      type = types.package;
      default = flakeSelf.packages.${pkgs.stdenv.hostPlatform.system}.epitropos-collector;
      defaultText = literalExpression "inputs.epitropos.packages.\${system}.epitropos-collector";
      description = "The epitropos-collector package to use.";
    };

    listenAddress = mkOption {
      type = types.str;
      default = "0.0.0.0";
      description = "Address the collector binds to.";
    };

    listenPort = mkOption {
      type = types.port;
      default = 8443;
      description = "Port the collector listens on.";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Open the listen port in the firewall.";
    };

    storageDir = mkOption {
      type = types.path;
      default = "/var/lib/epitropos-collector";
      readOnly = true;
      description = "Root directory for collector state and recordings.";
    };

    maxUploadBytes = mkOption {
      type = types.int;
      default = 1073741824;
      description = "Maximum upload size per push request (bytes).";
    };

    tokenTtlSeconds = mkOption {
      type = types.int;
      default = 900;
      description = "Enrollment token validity period (seconds).";
    };
  };

  config = mkIf cfg.enable {

    users.users.epitropos-collector = {
      isSystemUser = true;
      group = "epitropos-collector";
      description = "Epitropos collector daemon";
      home = "/var/empty";
      shell = "/run/current-system/sw/bin/nologin";
    };

    users.groups.epitropos-collector = { };

    systemd.tmpfiles.rules = [
      "d ${cfg.storageDir}              0750 epitropos-collector epitropos-collector -"
      "d ${cfg.storageDir}/tls          0750 epitropos-collector epitropos-collector -"
      "d ${cfg.storageDir}/senders      0750 epitropos-collector epitropos-collector -"
      "d ${cfg.storageDir}/enrollments  0750 epitropos-collector epitropos-collector -"
    ];

    systemd.services.epitropos-collector-keygen = {
      description = "Generate epitropos-collector TLS cert + enrollment secret (first boot)";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      unitConfig = {
        ConditionPathExists = "!${cfg.storageDir}/tls/cert.pem";
      };
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${lib.getExe cfg.package} keygen";
        User = "epitropos-collector";
        Group = "epitropos-collector";
        RemainAfterExit = true;
      };
    };

    systemd.services.epitropos-collector = {
      description = "Epitropos session recording collector";
      wantedBy = [ "multi-user.target" ];
      after = [
        "network.target"
        "epitropos-collector-keygen.service"
      ];
      requires = [ "epitropos-collector-keygen.service" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${lib.getExe cfg.package} serve --config ${configFile}";
        User = "epitropos-collector";
        Group = "epitropos-collector";
        Restart = "on-failure";
        RestartSec = 5;

        # Hardening
        ProtectSystem = "strict";
        ReadWritePaths = [ cfg.storageDir ];
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

    networking.firewall.allowedTCPPorts = lib.optional cfg.openFirewall cfg.listenPort;
  };
}
