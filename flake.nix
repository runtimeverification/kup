{
  description = "kup";
  inputs = {
    rv-nix-tools.url = "github:runtimeverification/rv-nix-tools/854d4f05ea78547d46e807b414faad64cea10ae4";
    nixpkgs.follows = "rv-nix-tools/nixpkgs";
  
    flake-utils.url = "github:numtide/flake-utils";

    uv2nix.url = "github:pyproject-nix/uv2nix/c8cf711802cb00b2e05d5c54d3486fce7bfc8f7c";
    # stale nixpkgs is missing the alias `lib.match` -> `builtins.match`
    # therefore point uv2nix to a patched nixpkgs, which introduces this alias
    # this is a temporary solution until nixpkgs us up-to-date again
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
    uv2nix.inputs.nixpkgs.url = "github:runtimeverification/nixpkgs/libmatch";
    # inputs.nixpkgs.follows = "nixpkgs";
    pyproject-build-systems.url = "github:pyproject-nix/build-system-pkgs/795a980d25301e5133eca37adae37283ec3c8e66";
    pyproject-build-systems = {
      inputs.nixpkgs.follows = "uv2nix/nixpkgs";
      inputs.uv2nix.follows = "uv2nix";
      inputs.pyproject-nix.follows = "uv2nix/pyproject-nix";
    };
    pyproject-nix.follows = "uv2nix/pyproject-nix";
  };
  outputs = {
      self,
      rv-nix-tools,
      nixpkgs,
      flake-utils,
      pyproject-nix,
      pyproject-build-systems,
      uv2nix,
      nixpkgs-unstable,
    }:
  let
    pythonVer = "310";
  in flake-utils.lib.eachSystem [
    "x86_64-linux"
    "x86_64-darwin"
    "aarch64-linux"
    "aarch64-darwin"
  ] (system:
    let
      # for uv2nix, remove both `pkgs-unstable` and `staleNixpkgsOverlay` once we updated to a newer version of nixpkgs
      pkgs-unstable = import nixpkgs-unstable {
        inherit system;
      };
      staleNixpkgsOverlay = final: prev: {
        inherit (pkgs-unstable) replaceVars;
      };
      uvOverlay = final: prev: {
        uv = uv2nix.packages.${final.system}.uv-bin;
      };
      kupOverlay = final: prev: {
        kup = final.callPackage ./nix/kup {
          inherit pyproject-nix pyproject-build-systems uv2nix;
          python = final."python${pythonVer}";
        };
      };
      pkgs = import nixpkgs {
        inherit system;
        overlays = [
          staleNixpkgsOverlay
          uvOverlay
          kupOverlay
        ];
      };
      python = pkgs."python${pythonVer}";
    in rec {
      devShells.default = pkgs.mkShell {
        name = "uv develop shell";
        buildInputs = [
          python
          pkgs.uv
        ];
        env = {
          # prevent uv from managing Python downloads and force use of specific 
          UV_PYTHON_DOWNLOADS = "never";
          UV_PYTHON = python.interpreter;
        };
        shellHook = ''
          unset PYTHONPATH
        '';
      };
      packages = rec {
        inherit (pkgs) kup;
        default = kup;
      };
    }) // {
      overlays.default = final: prev: {
        inherit (self.packages.${final.system}) kup;
      };
    };
}
