inputs: { config, lib, pkgs, ... }: let
  inherit (pkgs.stdenv.hostPlatform) system;
in {
  options.programs.v8p = {
    enable = lib.mkEnableOption "v8p";
  };

  config = lib.mkIf config.programs.v8p {
    home.packages = [ inputs.self.packages.${system}.default ];
  };
}
