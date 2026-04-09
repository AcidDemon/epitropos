{
  description = "epitropos: PTY-proxy for tamper-proof session recording via PAM";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    katagrapho = {
      url = "github:AcidDemon/katagrapho";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      rust-overlay,
      katagrapho,
      ...
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

      rustToolchainFor = pkgs: pkgs.rust-bin.stable.latest.minimal;

      mkCraneLib =
        pkgs:
        let
          rustToolchain = rustToolchainFor pkgs;
        in
        (crane.mkLib pkgs).overrideToolchain rustToolchain;

      workspaceCommonArgs = pkgs: {
        src = (mkCraneLib pkgs).cleanCargoSource ./.;
        strictDeps = true;
        RUSTFLAGS = builtins.concatStringsSep " " [
          "-C link-arg=-Wl,-z,relro,-z,now"
          "-C link-arg=-pie"
          "-C panic=abort"
        ];
      };

      mkEpitropos =
        pkgs:
        let
          craneLib = mkCraneLib pkgs;
          common = workspaceCommonArgs pkgs // {
            pname = "epitropos";
            version = "0.1.0";
          };
          cargoArtifacts = craneLib.buildDepsOnly (
            common // { doCheck = false; }
          );
        in
        craneLib.buildPackage (
          common
          // {
            inherit cargoArtifacts;
            doCheck = false;
            cargoExtraArgs = "-p epitropos";
            meta = {
              description = "PTY-proxy for tamper-proof session recording via PAM";
              license = pkgs.lib.licenses.mit;
              platforms = pkgs.lib.platforms.linux;
              mainProgram = "epitropos";
            };
          }
        );

      mkEpitroposCollector =
        pkgs:
        let
          craneLib = mkCraneLib pkgs;
          common = workspaceCommonArgs pkgs // {
            pname = "epitropos-collector";
            version = "0.1.0";
          };
          cargoArtifacts = craneLib.buildDepsOnly (
            common // { doCheck = false; }
          );
        in
        craneLib.buildPackage (
          common
          // {
            inherit cargoArtifacts;
            doCheck = false;
            cargoExtraArgs = "-p epitropos-collector";
            meta = {
              description = "Off-host collector for epitropos session recordings";
              license = pkgs.lib.licenses.mit;
              platforms = pkgs.lib.platforms.linux;
              mainProgram = "epitropos-collector";
            };
          }
        );
    in
    {
      packages = forAllSystems (system: rec {
        epitropos = mkEpitropos (pkgsFor system);
        epitropos-collector = mkEpitroposCollector (pkgsFor system);
        default = epitropos;
      });

      nixosModules = {
        default = self.nixosModules.epitropos;
        epitropos = import ./nixos-module.nix self;
      };

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rustToolchain = rustToolchainFor pkgs;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          src = craneLib.cleanCargoSource ./.;
        in
        {
          package = self.packages.${system}.default;

          clippy = craneLib.cargoClippy {
            inherit src;
            pname = "epitropos";
            version = "0.1.0";
            strictDeps = true;
            cargoClippyExtraArgs = "-- --deny warnings";
          };

          fmt = craneLib.cargoFmt {
            inherit src;
            pname = "epitropos";
            version = "0.1.0";
          };

          tests = craneLib.cargoTest {
            inherit src;
            pname = "epitropos";
            version = "0.1.0";
            strictDeps = true;
          };

          vm-test = import ./tests/vm-proxy.nix {
            inherit pkgs;
            katagraphoFlake = katagrapho;
            epitroposFlake = self;
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rustToolchain = (pkgs.rust-bin.stable.latest.default).override {
            extensions = [
              "rust-src"
              "rust-analyzer"
              "clippy"
            ];
          };
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = [ rustToolchain ];
          };
        }
      );
    };
}
