{ channel ? "nightly", profile ? "default", pkgs ? import <nixpkgs> }:
let
  pkgs' = pkgs.extend (import (builtins.fetchTarball {
    url =
      "https://github.com/oxalica/rust-overlay/archive/848db855cb9e88785996e961951659570fc58814.tar.gz";
    sha256 = "0w6msdr39vx13smkn1az5x9b5i75m1mzpxh8fxxccpkj9si6p0mz";
  }));
in pkgs'.mkShell {
  nativeBuildInputs = with pkgs'; [
    nixfmt-classic
    # Rust
    ((if channel == "nightly" then
      rust-bin.selectLatestNightlyWith (toolchain: toolchain.${profile})
    else
      rust-bin.${channel}.latest.${profile}).override {
        extensions = [ "rust-src" ];
        targets = [
          # Linux (x86)
          "x86_64-unknown-linux-musl"
          "x86_64-unknown-linux-gnu"
          # Linux (ARM)
          "aarch64-unknown-linux-musl"
          "aarch64-unknown-linux-gnu"
          # Windows (x86)
          "x86_64-pc-windows-gnu"
          "x86_64-pc-windows-msvc"
          # Windows (ARM)
          "aarch64-pc-windows-msvc"
          "aarch64-pc-windows-gnullvm"
          # macOS (x86)
          "x86_64-apple-darwin"
          # macOS (ARM)
          "aarch64-apple-darwin"
        ];
      })
    # Easy cross-compilation to Windows
    cargo-xwin
  ];
}
