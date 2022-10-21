{
  description = "kup";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-22.05";
    flake-utils.url = "github:numtide/flake-utils";
    rv-utils.url = "github:runtimeverification/rv-nix-tools";
    # needed by nix/flake-compat-k-unwrapped.nix
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
    poetry2nix.url = "github:nix-community/poetry2nix";
  };

  outputs = { self, nixpkgs, flake-utils, rv-utils, flake-compat, poetry2nix }:
    let
      allOverlays = [
        poetry2nix.overlay
        (final: prev:
          let
            k-version =
              prev.lib.removeSuffix "\n" (builtins.readFile ./package/version);
            src = prev.stdenv.mkDerivation {
              name = "k-${k-version}-${self.rev or "dirty"}-src";
              src = prev.lib.cleanSource
                (prev.nix-gitignore.gitignoreSourcePure [
                  ./.gitignore
                  ".github/"
                  "result*"
                  "nix/"
                  "*.nix"
                ] ./.);
              dontBuild = true;
              installPhase = ''
                mkdir $out
                cp -rv $src/* $out
                chmod -R u+w $out
              '';
            };
          in {
            kup = prev.poetry2nix.mkPoetryApplication {
              python = prev.python39;
              # projectDir = ./kup;
              overrides = prev.poetry2nix.overrides.withDefaults (
                final: prev: {
                  mypy = prev.mypy.overridePythonAttrs (_old: {
                    MYPY_USE_MYPYC = false;
                  });
                }
          );
            };
          })
      ];
    in flake-utils.lib.eachSystem [
      "x86_64-linux"
      "x86_64-darwin"
      "aarch64-linux"
      "aarch64-darwin"
    ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;

          # Temporarily required until a bug on pyOpenSSL is resolved for aarch64-darwin
          # https://github.com/NixOS/nixpkgs/pull/172397
          config.allowBroken = system == "aarch64-darwin";
          overlays = allOverlays;
        };
      in rec {

        packages = rec {
          inherit (pkgs) kup;
        };
        defaultPackage = packages.kup;
      }) // {
        overlay = nixpkgs.lib.composeManyExtensions allOverlays;
      };
}
