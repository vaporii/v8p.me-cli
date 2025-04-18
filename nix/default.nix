{ pkgs ? (import <nixpkgs> {}), ... }:

pkgs.buildGoModule {
  pname = "v8p.me-cli";
  version = "0.1.0";

  nativeBuildInputs = [ pkgs.makeWrapper ];

  src = ../.;

  vendorHash = "sha256-un4+9Pozo8ArUP6m0BIoeidpDrksxte0WZrfDJH9Mwo=";

  postFixup = ''
    wrapProgram $out/bin/v8p.me-cli \
      --set PATH ${pkgs.lib.makeBinPath (with pkgs; [
        xclip
        wl-clipboard
    ])}
  '';

  # installPhase = ''
  #   mkdir -p $out/bin
  #   cp $src/result/bin/v8p.me-cli $out/bin/v8p
  # '';
}
