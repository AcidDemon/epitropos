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

  # katagrapho only accepts recipient files under /etc/katagrapho, /etc/age,
  # or /etc/epitropos. A path-literal recipientFile is copied into the nix
  # store, which katagrapho rejects at session start — and with the default
  # closed fail policy that denies every recorded login. Install store paths
  # into /etc/epitropos and point the config there; non-store paths (already
  # under /etc, or provisioned at runtime) pass through unchanged.
  recipientInStore =
    cfg.encryption.recipientFile != null
    && lib.hasPrefix "${builtins.storeDir}/" (toString cfg.encryption.recipientFile);
  recipientPath =
    if cfg.encryption.recipientFile == null then
      ""
    else if recipientInStore then
      "/etc/epitropos/recording-recipients"
    else
      toString cfg.encryption.recipientFile;

  configFile = tomlFormat.generate "epitropos-config.toml" {
    general = {
      katagrapho_path = "/run/wrappers/bin/katagrapho";
      record_input = cfg.recordInput;
      ns_exec_path = "/run/wrappers/bin/epitropos-ns-exec";
      require_pid_isolation = cfg.requirePidIsolation;
    };
    shell = {
      default = cfg.shell.default;
      users = cfg.shell.users;
    };
    encryption = {
      enabled = cfg.encryption.enable;
      recipient_file = recipientPath;
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
    live = {
      enabled = cfg.live.enable;
      directory = "/run/epitropos/live";
      recipient_file = if cfg.live.recipientFile != null then cfg.live.recipientFile else "";
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

    requirePidIsolation = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Require PID-namespace isolation of the recorded shell. When true
        (the default) and the epitropos-ns-exec helper is unavailable, a
        session is denied rather than started unisolated — an unisolated
        session lets the recorded user see and signal (kill) the recorder.
        Set to false only on hosts that cannot provide PID namespaces,
        accepting that the recorder becomes visible and killable from within
        the session.
      '';
    };

    noticeText = mkOption {
      type = types.str;
      default = "\nATTENTION! Your session is being recorded!\n\n";
      description = ''
        Banner printed once before the shell starts. Written verbatim, so
        include real newlines (as here) for spacing around the prompt; the
        proxy does not interpret C-style escapes. Set to "" to disable the
        banner entirely.
      '';
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

    live = {
      enable = mkEnableOption ''
        live session viewing. The live mirror is encrypted per-record to the
        operator recipient in live.recipientFile; only a viewer holding the
        matching age identity can read it, so possessing the identity — not a
        Unix group — is the access control. Requires live.recipientFile
      '';

      package = mkOption {
        type = types.package;
        default = flakeSelf.packages.${pkgs.stdenv.hostPlatform.system}.epitropos-live;
        defaultText = literalExpression "inputs.epitropos.packages.\${system}.epitropos-live";
        description = "The epitropos-live package to use.";
      };

      recipientFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = ''
          Path to the dedicated live-viewer age PUBLIC recipient (age1...).
          Distinct from encryption.recipientFile so that "watch live sessions"
          is a separate capability from "decrypt the archive". Required when
          live.enable is true. The matching secret identity is provisioned to
          operators out of band (agenix/sops, never in the Nix store) and passed
          to epitropos-live via --identity or EPITROPOS_LIVE_IDENTITY.
        '';
      };
    };
  };

  config = mkIf cfg.enable {

    assertions = [
      {
        assertion = config.services.katagrapho.enable or false;
        message = "epitropos requires services.katagrapho.enable = true for session recording storage.";
      }
      {
        assertion = !cfg.live.enable || cfg.live.recipientFile != null;
        message = "services.epitropos.live.enable requires services.epitropos.live.recipientFile (the operator's age public recipient).";
      }
      {
        # internal-sftp runs inside sshd and never execs the user's login
        # shell, so sftp/scp sessions would bypass recording entirely.
        # The default external sftp-server goes through the shell wrapper.
        assertion = config.services.openssh.sftpServerExecutable or "" != "internal-sftp";
        message = "epitropos: services.openssh.sftpServerExecutable = \"internal-sftp\" bypasses session recording (sftp never execs the login shell); use the default external sftp-server.";
      }
    ];

    users.groups = {
      ${cfg.proxyGroup}.members = cfg.recordUsers;
    } // lib.optionalAttrs cfg.forward.enable {
      epitropos-forward = { };
    };

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
    }) // lib.optionalAttrs cfg.forward.enable {
      epitropos-forward = {
        isSystemUser = true;
        group = "epitropos-forward";
        description = "Epitropos recording shipper";
        home = "/var/empty";
        shell = "/run/current-system/sw/bin/nologin";
        extraGroups = [ "katagrapho-readers" ];
      };
    };

    security.wrappers = {
      epitropos = {
        source = lib.getExe cfg.package;
        owner = cfg.proxyUser;
        # setgid ssh-sessions so the proxy can exec the katagrapho wrapper,
        # which is 0550 session-writer:ssh-sessions. setuid moves euid only —
        # the process keeps the recorded user's supplementary groups — so a
        # group on the session-proxy account would never reach spawn_katagrapho.
        # This grants no read on the corpus: that is katagrapho-readers.
        group = "ssh-sessions";
        setuid = true;
        setgid = true;
        # o+x replaces the proxyGroup gate the group field used to provide.
        # The recorded users are still in proxyGroup, which is what gates
        # epitropos-ns-exec below.
        permissions = "u+rx,g+rx,o+x";
      };
      epitropos-ns-exec = {
        source = "${cfg.package}/bin/epitropos-ns-exec";
        owner = "root";
        group = cfg.proxyGroup;
        # +ep required: unshare(2) needs CAP_SYS_ADMIN in effective set.
        # Binary drops all caps immediately after unshare+fork.
        capabilities = "cap_sys_admin+ep";
        setuid = false;
        permissions = "u+rx,g+rx,o-rwx";
      };
    } // lib.optionalAttrs cfg.live.enable {
      # Not setuid and no longer group-gated: the mirror is encrypted, so
      # running the viewer without the operator age identity yields nothing.
      # Access control is the identity, not who may execute this launcher.
      epitropos-live = {
        source = "${cfg.live.package}/bin/epitropos-live";
        owner = "root";
        group = cfg.proxyGroup;
        setuid = false;
        permissions = "u+rx,g+rx,o+rx";
      };
    };

    environment.etc."epitropos/config.toml" = {
      source = configFile;
      mode = "0440";
      user = cfg.proxyUser;
      group = cfg.proxyGroup;
    };

    # Materialize the recipient as a REAL file, not an environment.etc symlink.
    # katagrapho only accepts recipient paths under /etc/katagrapho, /etc/age,
    # or /etc/epitropos, and it canonicalizes before checking: an /etc symlink
    # into the nix store resolves back out of the allowlist and is rejected,
    # which under a closed fail policy denies every recorded login. A copied
    # file has no symlink to follow, so its canonical path stays in
    # /etc/epitropos. Age recipients are public keys, so 0444 is fine, and
    # katagrapho reads it as session-writer (not the proxy group).
    # Runs after the `etc` activation so /etc/epitropos exists.
    system.activationScripts.epitroposRecipient = mkIf recipientInStore {
      deps = [ "etc" ];
      text = ''
        install -Dm0444 ${lib.escapeShellArg (toString cfg.encryption.recipientFile)} \
          /etc/epitropos/recording-recipients
      '';
    };

    systemd.tmpfiles.rules = [
      # setgid (2xxx) so root-written PAM stash files inherit proxyGroup and the
      # proxy can group-read the handoff; owner-only (x700) so recorded users
      # (all in proxyGroup) cannot traverse the dir to read another session's
      # stash. The proxy accesses as owner (proxyUser), so no group-traverse is
      # needed. Symlink-race writes are prevented by O_NOFOLLOW|O_EXCL in
      # pam_epitropos.c, independent of this ownership.
      "d /var/run/epitropos 2700 ${cfg.proxyUser} ${cfg.proxyGroup} -"
    ] ++ lib.optionals cfg.forward.enable [
      "d /var/lib/epitropos-forward 0750 epitropos-forward epitropos-forward -"
    ] ++ lib.optionals cfg.live.enable [
      # World-traversable so any operator holding the age identity can read the
      # encrypted mirror; the ciphertext (0644) is the only thing on disk, so
      # the ACL is not the confidentiality boundary. Local users can see session
      # ids (filenames) + sizes/mtimes but not content.
      "d /run/epitropos/live 0755 ${cfg.proxyUser} ${cfg.proxyGroup} -"
    ];

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
