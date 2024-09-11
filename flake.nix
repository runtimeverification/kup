{
  description = "kup";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    poetry2nix.url = "github:nix-community/poetry2nix/2024.9.538703";
  };
  outputs = { self, nixpkgs, flake-utils, ... }@inputs:
    let
      overlay = (final: prev:
        let poetry2nix = inputs.poetry2nix.lib.mkPoetry2Nix { pkgs = prev; };
        in {
          kup = poetry2nix.mkPoetryApplication {
            python = prev.python39;
            projectDir = ./.;
            groups = [ ];
            # We remove `"dev"` from `checkGroups`, so that poetry2nix does not try to resolve dev dependencies.
            checkGroups = [ ];
            overrides = poetry2nix.overrides.withDefaults
              (finalPython: prevPython: {
                git-url-parse = prevPython.git-url-parse.overridePythonAttrs
                  (old: {
                    propagatedBuildInputs = (old.propagatedBuildInputs or [ ])
                      ++ [ finalPython.setuptools ];
                  });
                tinynetrc = prevPython.tinynetrc.overridePythonAttrs (old: {
                  propagatedBuildInputs = (old.propagatedBuildInputs or [ ])
                    ++ [ finalPython.setuptools ];
                });
              });

            nativeBuildInputs = [ prev.makeWrapper ];
            postInstall = ''
              wrapProgram "$out/bin/kup" \
                --set PINNED_NIX "${prev.nixVersions.nix_2_23}/bin/nix"
            '';
          };
        });
    in flake-utils.lib.eachSystem [
      "x86_64-linux"
      "x86_64-darwin"
      "aarch64-linux"
      "aarch64-darwin"
    ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ overlay ];
        };
      in {
        packages = {
          inherit (pkgs) kup;
          default = pkgs.kup;
        };
      }) // {
        inherit overlay;
      };
}
