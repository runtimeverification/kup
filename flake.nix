{
  description = "kup";
  inputs = {
    rv-nix-tools.url = "github:runtimeverification/rv-nix-tools/854d4f05ea78547d46e807b414faad64cea10ae4";
    nixpkgs.follows = "rv-nix-tools/nixpkgs";
  
    flake-utils.url = "github:numtide/flake-utils";
    poetry2nix.url = "github:nix-community/poetry2nix";
    poetry2nix.inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs = { self, nixpkgs, rv-nix-tools, flake-utils, poetry2nix }:
    let
      allOverlays = [
        poetry2nix.overlays.default
        (final: prev:
        let
          p2n = poetry2nix.lib.mkPoetry2Nix { pkgs = final; };
        in {
          kup = p2n.mkPoetryApplication {
            python = prev.python311;
            projectDir = ./.;
            # We remove `"dev"` from `checkGroups`, so that poetry2nix does not try to resolve dev dependencies.
            checkGroups = [];
            overrides = p2n.defaultPoetryOverrides.extend
              (self: super: {
                tinynetrc = super.tinynetrc.overridePythonAttrs (
                  old: {
                    buildInputs = (old.buildInputs or [ ]) ++ [ super.setuptools ];
                  }
                );
                git-url-parse = super.git-url-parse.overridePythonAttrs (
                  old: {
                    buildInputs = (old.buildInputs or [ ]) ++ [ super.setuptools ];
                  }
                );
              });
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
          overlays = allOverlays;
        };
      in rec {
        packages = {
          inherit (pkgs) kup;
        };
        defaultPackage = packages.kup;
      }) // {
        overlay = nixpkgs.lib.composeManyExtensions allOverlays;
      };
}
