{ pkgs ? (import <nixpkgs> {}), ... }:

pkgs.buildGoModule {
  pname = "v8p";
  version = "0.1.0";

  src = ../.;

  vendorHash = pkgs.lib.fakeHash;

  # installPhase = ''
  #   mkdir -p $out/bin
  #   cp result/
  # ''
}
