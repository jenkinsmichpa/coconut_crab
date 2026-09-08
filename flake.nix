{
  description = "coconut_crab";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "aarch64-linux" "x86_64-linux" ];
      mkDevShell = pkgs: system: pkgs.mkShell {
        packages = with pkgs; [ zig llvmPackages.libclang ];
        env = {
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        } // pkgs.lib.optionalAttrs (system == "aarch64-darwin") {
          BINDGEN_EXTRA_CLANG_ARGS_aarch64_apple_darwin = "--target=aarch64-apple-darwin";
        };
      };
    in
    {
      devShells = nixpkgs.lib.genAttrs systems (system: {
        default = mkDevShell nixpkgs.legacyPackages.${system} system;
      });
    };
}
