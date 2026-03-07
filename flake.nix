{
  description = "ACME client for DNS-01 challenge issuance without broad DNS API credentials";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "acme-dns-client";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          meta = with pkgs.lib; {
            description = "ACME client for DNS-01 challenge issuance without broad DNS API credentials";
            homepage = "https://github.com/tcurdt/acme-dns-client";
            license = licenses.asl20;
            maintainers = [ ];
          };
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/acme-dns-client";
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            rust-analyzer
            clippy
            rustfmt
          ];
        };
      }
    );
}
