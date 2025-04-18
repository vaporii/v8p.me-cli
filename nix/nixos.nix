{ config, lib, pkgs, ... }@inputs: let
  
in {
  options.v8p = {
    enable = lib.mkEnableOption "v8p";
  };

  config = lib.mkIf config.v8p.enable {
    environment.systemPackages = [
      (import ./. { inherit pkgs; })
    ];
  };
}
