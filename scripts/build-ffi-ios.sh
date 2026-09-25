#!/usr/bin/env bash
# Build vault-ffi for iOS and stage the static libs where the linker looks.
#
# One .a per platform in its own directory, picked by the SDK-conditional
# LIBRARY_SEARCH_PATHS in apps/ios/project.yml. Two are needed because device
# and simulator are different *platforms*, not two architectures of one.
#
# NOT an xcframework, though docs/IOS.md originally asked for one and the first
# cut of this script built one. Xcode resolves a framework dependency when it
# sets the target up — before any pre-build script runs — so an xcframework this
# project builds itself can never exist in time:
#
#   error: There is no XCFramework found at '.../libs/VaultFFI.xcframework'
#   note: Run script build phase 'Build vault-ffi (Rust xcframework)' will be run
#         during every build
#
# Library search paths are resolved at LINK time, after this script has run,
# which is also exactly how apps/macos links the same library. An xcframework is
# the right packaging for a binary shipped to someone else; for a library built
# from source in the same repo it only breaks a clean checkout.
#
# Run from anywhere; the Xcode pre-build phase in apps/ios/project.yml calls it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_OUTPUT="$(python3 "$ROOT/scripts/cargo-target-dir.py")"
OUT="$ROOT/apps/ios/libs"

# Devices are all arm64, so the device slice needs one architecture.
#
# The SIMULATOR needs two. `ARCHS_STANDARD` for iphonesimulator is
# `arm64 x86_64`, and a generic simulator destination has no concrete device to
# narrow that to, so Xcode links both — an arm64-only lib fails with
# "ignoring file ... found architecture 'arm64', required architecture 'x86_64'"
# followed by every vault_ffi_* symbol undefined. lipo puts both in one archive.
# (x86_64-apple-ios IS the Intel simulator target; there is no -sim variant.)
DEVICE_TARGET="aarch64-apple-ios"
SIM_ARM_TARGET="aarch64-apple-ios-sim"
SIM_X86_TARGET="x86_64-apple-ios"

echo "==> Rust targets"
rustup target add "$DEVICE_TARGET" "$SIM_ARM_TARGET" "$SIM_X86_TARGET"

echo "==> cargo build"
cd "$ROOT"
for target in "$DEVICE_TARGET" "$SIM_ARM_TARGET" "$SIM_X86_TARGET"; do
    cargo build -p vault-ffi --release --target "$target"
done

# Separate directories, not separate filenames: the linker gets one search path
# per SDK and asks for -lvault_ffi in both.
echo "==> staging into $OUT"
mkdir -p "$OUT/device" "$OUT/simulator"
cp -f "$CARGO_OUTPUT/$DEVICE_TARGET/release/libvault_ffi.a" "$OUT/device/libvault_ffi.a"
lipo -create \
    "$CARGO_OUTPUT/$SIM_ARM_TARGET/release/libvault_ffi.a" \
    "$CARGO_OUTPUT/$SIM_X86_TARGET/release/libvault_ffi.a" \
    -output "$OUT/simulator/libvault_ffi.a"

echo "==> device:    $(lipo -archs "$OUT/device/libvault_ffi.a")"
echo "==> simulator: $(lipo -archs "$OUT/simulator/libvault_ffi.a")"
