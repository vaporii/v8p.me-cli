inputs: { config, lib, pkgs, ... }: let
  inherit (pkgs.stdenv.hostPlatform) system;
  package = inputs.self.packages.${system}.default;

  clipTool = if config.programs.v8p.usingWayland then pkgs.wl-clipboard else pkgs.xclip;
  
  wrappedPkg = pkgs.symlinkJoin {
    name = "v8p-wrapped";
    paths = [ package ];
    buildInputs = [ pkgs.makeWrapper ];
    postBuild = ''
      wrapProgram $out/bin/v8p.me-cli \
        --prefix PATH : ${lib.makeBinPath [ clipTool ]}
    '';
  };
in {
  options.programs.v8p = {
    enable = lib.mkEnableOption "v8p";
    usingWayland = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "use wl-clipboard package instead of xclip";
    };
  };

  config = lib.mkIf config.programs.v8p.enable {
    home.packages = [ wrappedPkg ];
    home.shellAliases.v8p = "${wrappedPkg}/bin/v8p.me-cli";
  };
}
