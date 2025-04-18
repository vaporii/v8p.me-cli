inputs: { config, lib, pkgs, ... }: let
  inherit (pkgs.stdenv.hostPlatform) system;
  package = inputs.self.packages.${system}.default;
in {
  options.programs.v8p = {
    enable = lib.mkEnableOption "v8p";
  };

  config = lib.mkIf config.programs.v8p.enable {
    home.packages = [ package ];
    home.shellAliases.v8p = "${package}/bin/v8p.me-cli";
  };
}
