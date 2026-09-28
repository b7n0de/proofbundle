#!/bin/sh
# Build pb_verify_rs for the browser page: the unchanged sources in ../pb_verify_rs, compiled for
# wasm32-wasip1 with the toolchain that ../pb_verify_rs/rust-toolchain.toml pins, from Cargo.lock.
# Needs: rustup target add wasm32-wasip1 --toolchain <that toolchain>
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/../pb_verify_rs"
cargo build --release --locked --target wasm32-wasip1 --target-dir "$here/target"
cp "$here/target/wasm32-wasip1/release/pb_verify_rs.wasm" "$here/site/pb_verify_rs.wasm"
wc -c "$here/site/pb_verify_rs.wasm"
sha256sum "$here/site/pb_verify_rs.wasm"
