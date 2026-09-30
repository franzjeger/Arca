#!/usr/bin/env bash
#
# Put the AutoFill extension inside a built Arca.app and sign all of it: the
# browser host (already inside, beside the app's executable), the extension,
# then the app.
#
#   scripts/assemble-app-macos.sh APP PLAN WORK
#
#   APP   the Arca.app `tauri build` made, copied outside Documents
#   PLAN  a signing plan from prepare-autofill-signing.py
#   WORK  a scratch folder for entitlements and the build log
#
# A development plan signs for this Mac (scripts/install-app-macos.sh). A
# --distribution plan signs with Developer ID, the hardened runtime and a
# secure timestamp, for every Mac (scripts/release-macos.sh). One script for
# both, so the app the owner runs every day is the app that ships.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP="$1"
PLAN="$2"
WORK="$3"
CARGO_OUTPUT="$(python3 "$REPO/scripts/cargo-target-dir.py")"
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

HOST="$APP/Contents/MacOS/vault-native-host"
[ -f "$HOST" ] || die "no browser host at $HOST"
IDENTITY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["identity"])' "$PLAN")"
DISTRIBUTION="$(python3 -c 'import json,sys; print("yes" if json.load(open(sys.argv[1])).get("distribution") else "")' "$PLAN")"

# Isolate the FFI cache and compile outside Xcode's build environment first.
# Reusing desktop proc-macro artifacts under Xcode caused E0463 on this Mac.
echo "==> Building the AutoFill extension"
APPLE_BUILD="${ARCA_APPLE_BUILD_ROOT:-$CARGO_OUTPUT/apple}/ArcaHost"
( export CARGO_TARGET_DIR="$CARGO_OUTPUT/apple-ffi"
  cd "$REPO" || exit
  cargo build -p vault-ffi --profile release-ffi --target aarch64-apple-darwin || exit
  cd apps/macos || exit
  xcodegen generate >/dev/null || exit
  xcodebuild -project Arca.xcodeproj -scheme ArcaHost -configuration Release \
    -derivedDataPath "$APPLE_BUILD" ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
    CODE_SIGNING_ALLOWED=NO build >"$WORK/autofill-build.log" 2>&1 ) \
  || { cat "$WORK/autofill-build.log" >&2 2>/dev/null || true; die "AutoFill build failed"; }
BUILT="$APPLE_BUILD/Build/Products/Release/ArcaHost.app/Contents/PlugIns/ArcaAutoFill.appex"
[ -d "$BUILT" ] || die "no ArcaAutoFill.appex at $BUILT"
APPEX="$APP/Contents/PlugIns/ArcaAutoFill.appex"
mkdir -p "$APP/Contents/PlugIns"
ditto --norsrc "$BUILT" "$APPEX"

python3 "$REPO/scripts/prepare-autofill-signing.py" --prepare \
  "$APPEX" "$REPO/apps/macos/ArcaAutoFill/ArcaAutoFill.entitlements" "$WORK/autofill.entitlements" "$PLAN"
python3 "$REPO/scripts/prepare-autofill-signing.py" --prepare \
  "$APP" "$REPO/apps/desktop/src-tauri/Entitlements.plist" "$WORK/desktop.entitlements" "$PLAN"
xattr -cr "$APP"

sign() {
  if [ -n "$DISTRIBUTION" ]; then
    # Notarization requires both: the hardened runtime on every executable,
    # and a timestamp from Apple rather than this Mac's clock.
    codesign --force --options runtime --timestamp -s "$IDENTITY" "$@"
  else
    codesign --force -s "$IDENTITY" "$@"
  fi
}
echo "==> Signing the browser host and the extension, then the app"
sign -i no.sybr.vault.native-host "$HOST"
sign --entitlements "$WORK/autofill.entitlements" "$APPEX"
sign --entitlements "$WORK/desktop.entitlements" "$APP"
for bundle in "$APPEX" "$APP"; do
  if [ -n "$DISTRIBUTION" ]; then
    python3 "$REPO/scripts/prepare-autofill-signing.py" --verify "$bundle" --distribution
  else
    python3 "$REPO/scripts/prepare-autofill-signing.py" --verify "$bundle"
  fi
done
codesign --verify --deep --strict "$APP"
