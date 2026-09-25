#!/usr/bin/env bash
#
# Build the release app and (re)install it into /Applications.
#
# Produces a development-signed Arca.app with native AutoFill.
# ARCA_ADHOC=1 explicitly builds without shared capabilities or AutoFill.
# Distribution to OTHER machines needs a Developer ID + notarization instead.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }
[ "$(uname)" = Darwin ] || die "This installer requires macOS."
for command in python3 cargo rustc node npm xcodebuild xcodegen codesign; do
  command -v "$command" >/dev/null || die "Missing required tool: $command"
done
node -e 'if (Number(process.versions.node.split(".")[0]) < 22) process.exit(1)' \
  || die "Node.js 22 or newer is required for the browser tests."
xcodebuild -checkFirstLaunchStatus >/dev/null || die "Complete Xcode setup with xcodebuild -runFirstLaunch first."
CARGO_OUTPUT="$(python3 "$REPO/scripts/cargo-target-dir.py")"
APP_BUILD="$CARGO_OUTPUT/release/bundle/macos/Arca.app"
APP_SRC="$APP_BUILD"
APP_DST="/Applications/Arca.app"
SIGNING_DIR=""
INSTALL_STAGE=""
ROLLBACK_APP=""
OLD_APP_MOVED=0
NEW_APP_INSTALLED=0
INSTALL_COMMITTED=0
WAS_RUNNING=0
SUPPORT_JOURNAL=""
HOST_BIN="$HOME/.local/lib/arca/vault-native-host"

cleanup() {
  status=$?
  trap - EXIT
  if [ "$INSTALL_COMMITTED" != 1 ] && [ -f "$SUPPORT_JOURNAL/files.json" ]; then
    if ! python3 "$REPO/scripts/install-macos-support.py" --rollback "$SUPPORT_JOURNAL"; then
      echo "Support-file rollback failed; recovery journal: $SUPPORT_JOURNAL" >&2
      SIGNING_DIR="" # Keep the recovery journal for a manual retry.
      status=1
    fi
  fi
  if [ "$INSTALL_COMMITTED" != 1 ] && { [ "$OLD_APP_MOVED" = 1 ] || [ "$NEW_APP_INSTALLED" = 1 ]; }; then
    echo "==> Install failed — rolling back Arca.app" >&2
    osascript -e 'quit app "Arca"' >/dev/null 2>&1 || true
    pkill -f "$APP_DST/Contents/MacOS/vault-desktop" 2>/dev/null || true
    if [ "$NEW_APP_INSTALLED" = 1 ]; then rm -rf "$APP_DST"; fi
    if [ "$OLD_APP_MOVED" = 1 ]; then
      if mv "$ROLLBACK_APP" "$APP_DST"; then
        if [ "$WAS_RUNNING" = 1 ]; then open -a "$APP_DST" >/dev/null 2>&1 || true; fi
      else
        echo "App rollback failed; previous app retained at $ROLLBACK_APP" >&2
        INSTALL_STAGE=""
        status=1
      fi
    fi
  fi
  [ -z "$SIGNING_DIR" ] || rm -rf "$SIGNING_DIR"
  [ -z "$INSTALL_STAGE" ] || rm -rf "$INSTALL_STAGE"
  exit "$status"
}
trap cleanup EXIT
# Entitlements (App Group + shared keychain group) so the vault + device key are
# shared with the AutoFill extension. The re-sign below MUST pass these or it
# strips what `tauri build` embedded.
ENTITLEMENTS="$REPO/apps/desktop/src-tauri/Entitlements.plist"
SIGNING_DIR="$(mktemp -d /tmp/arca-install.XXXXXX)"
SIGNING_PLAN="$SIGNING_DIR/signing.json"
if [ "${ARCA_ADHOC:-}" != "1" ]; then
  python3 "$REPO/scripts/prepare-autofill-signing.py" --plan "$SIGNING_PLAN" \
    || die "Local development signing is not ready. See apps/macos/README.md."
  IDENTITY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["identity"])' "$SIGNING_PLAN")"
fi

echo "==> Installing locked frontend dependencies…"
(cd "$REPO/apps/desktop" && npm ci)
if [ "${SKIP_SMOKE:-}" != "1" ]; then
  echo "==> Preparing Chromium for desktop and extension tests…"
  (cd "$REPO/apps/desktop" && npx --no-install playwright install chromium)
  CHROME_BIN="$(cd "$REPO/apps/desktop" && node --input-type=module -e 'import { chromium } from "playwright"; console.log(chromium.executablePath())')"
  export CHROME_BIN
  export ARCA_REQUIRE_BROWSER_E2E=1
fi

# Gate every install on the smoke test (Rust tests + frontend build + on macOS
# the keychain quick-unlock drift regression). Skip only with SKIP_SMOKE=1 and a
# reason you can defend.
if [ "${SKIP_SMOKE:-}" != "1" ]; then
  echo "==> Smoke test (set SKIP_SMOKE=1 to bypass)…"
  bash "$REPO/scripts/smoke-test.sh" --full
fi

# The Google OAuth client secret lives outside the repository (it is public);
# crates/vault-sync's build script picks it up from here. Say so out loud rather
# than installing an app whose Settings pane refuses to connect for no visible
# reason.
if [ -z "${ARCA_GOOGLE_CLIENT_SECRET:-}" ] && [ ! -s "$HOME/.arca/google-client-secret" ]; then
  echo "==> WARNING: no Google client secret at ~/.arca/google-client-secret."
  echo "    This build will run fine but Drive sync cannot connect. See docs/SYNC.md."
fi

echo "==> Building release bundle…"
(cd "$REPO/apps/desktop" && npm run tauri build -- --bundles app)

# Sign outside Documents: File Provider can continuously re-attach FinderInfo
# metadata to bundles there, while codesign correctly refuses such detritus.
APP_SRC="$SIGNING_DIR/Arca.app"
ditto --norsrc "$APP_BUILD" "$APP_SRC"

# EVERY binary that speaks the app's protocols is built HERE, with the app.
#
# They drifted once and it cost an afternoon: a new bridge message, both sides
# written and tested, and the browser answered "malformed message" because the
# installed native host was five days old and had never heard of it. Nothing was
# broken except that two halves of one product were built by two different
# commands and only one of them was ever run. A protocol means nothing if its
# ends can be a week apart.

# The `arca` command line, on PATH, so scripts and automation can create a login
# and use it without the secret passing through their own output.
echo "==> Building the arca command line…"
cargo build --release -p arca-cli --manifest-path "$REPO/Cargo.toml" \
  || die "the arca command line failed to build"

# The browser host is installed with the CLI after bundle verification.
# Registrations always point at ~/.local/lib/arca, never a Cargo build cache.
echo "==> Building the native messaging host (release)…"
cargo build --release -p vault-native-host --manifest-path "$REPO/Cargo.toml" \
  || die "the native messaging host failed to build"

# All profiles come from Xcode or the installed app and were matched to one
# usable certificate, this Mac, both bundle IDs and their capabilities above.
if [ "${ARCA_ADHOC:-}" != "1" ]; then
  echo "==> Building the AutoFill extension"
  APPLE_BUILD="${ARCA_APPLE_BUILD_ROOT:-$CARGO_OUTPUT/apple}/ArcaHost"
  # Isolate the FFI cache and compile outside Xcode's build environment first.
  # Reusing desktop proc-macro artifacts under Xcode caused E0463 on this Mac.
  ( export CARGO_TARGET_DIR="$CARGO_OUTPUT/apple-ffi"
    cd "$REPO" || exit
    cargo build -p vault-ffi --release --target aarch64-apple-darwin || exit
    cd apps/macos || exit
    xcodegen generate >/dev/null || exit
    xcodebuild -project Arca.xcodeproj -scheme ArcaHost -configuration Release \
      -derivedDataPath "$APPLE_BUILD" ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
      CODE_SIGNING_ALLOWED=NO build >"$SIGNING_DIR/autofill-build.log" 2>&1 ) \
    || { cat "$SIGNING_DIR/autofill-build.log" >&2 2>/dev/null || true; die "AutoFill build failed"; }
  APPEX="$APPLE_BUILD/Build/Products/Release/ArcaHost.app/Contents/PlugIns/ArcaAutoFill.appex"
  [ -d "$APPEX" ] || die "no ArcaAutoFill.appex at $APPEX"
  mkdir -p "$APP_SRC/Contents/PlugIns"
  ditto --norsrc "$APPEX" "$APP_SRC/Contents/PlugIns/ArcaAutoFill.appex"
  APPEX_ENT="$SIGNING_DIR/autofill.entitlements"
  APP_ENT="$SIGNING_DIR/desktop.entitlements"
  python3 "$REPO/scripts/prepare-autofill-signing.py" --prepare \
    "$APP_SRC/Contents/PlugIns/ArcaAutoFill.appex" \
    "$REPO/apps/macos/ArcaAutoFill/ArcaAutoFill.entitlements" "$APPEX_ENT" "$SIGNING_PLAN"
  python3 "$REPO/scripts/prepare-autofill-signing.py" --prepare \
    "$APP_SRC" "$ENTITLEMENTS" "$APP_ENT" "$SIGNING_PLAN"
  xattr -cr "$APP_SRC"
  echo "==> Signing the extension, then the app"
  codesign --force --entitlements "$APPEX_ENT" -s "$IDENTITY" "$APP_SRC/Contents/PlugIns/ArcaAutoFill.appex"
  codesign --force --entitlements "$APP_ENT" -s "$IDENTITY" "$APP_SRC"
  for bundle in "$APP_SRC/Contents/PlugIns/ArcaAutoFill.appex" "$APP_SRC"; do
    python3 "$REPO/scripts/prepare-autofill-signing.py" --verify "$bundle"
  done
else
  echo "==> Explicit ad hoc build: native AutoFill and shared entitlements are unavailable"
  codesign --force --deep -s - "$APP_SRC"
fi
codesign --verify --deep --strict "$APP_SRC"

echo "==> Installing to /Applications…"
# Copy and validate the candidate on the destination filesystem before moving
# the old app. The final two renames are same-volume operations, and the EXIT
# trap restores the previous bundle if anything after the first rename fails.
INSTALL_STAGE="$(mktemp -d /Applications/.arca-install.XXXXXX)"
INSTALL_CANDIDATE="$INSTALL_STAGE/Arca.app"
ROLLBACK_APP="$INSTALL_STAGE/Arca.previous.app"
ditto --norsrc "$APP_SRC" "$INSTALL_CANDIDATE"
codesign --verify --deep --strict "$INSTALL_CANDIDATE"
EXPECTED_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP_SRC/Contents/Info.plist")"
CANDIDATE_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$INSTALL_CANDIDATE/Contents/Info.plist")"
[ "$CANDIDATE_VERSION" = "$EXPECTED_VERSION" ] \
  || die "staged app version $CANDIDATE_VERSION does not match build $EXPECTED_VERSION"

# A running Arca keeps running the OLD binary: replacing the bundle on disk does
# not touch a process that already mapped it. That failure is silent and very
# convincing — the app is there, the version string in Settings is the new one
# because it reads the bundle, and yet a feature added in this build is missing.
# It cost an afternoon once, chasing a bridge command the running app had never
# heard of.
if pgrep -f "$APP_DST/Contents/MacOS/vault-desktop" >/dev/null 2>&1; then
  WAS_RUNNING=1
  echo "    Arca is running the previous build — quitting it (your vault locks)."
  osascript -e 'quit app "Arca"' >/dev/null 2>&1 || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pgrep -f "$APP_DST/Contents/MacOS/vault-desktop" >/dev/null 2>&1 || break
    sleep 1
  done
  # Only after asking nicely: a graceful quit lets it clear the clipboard and
  # release the bridge socket.
  pkill -f "$APP_DST/Contents/MacOS/vault-desktop" 2>/dev/null || true
  sleep 1
fi

if [ -d "$APP_DST" ]; then
  mv "$APP_DST" "$ROLLBACK_APP"
  OLD_APP_MOVED=1
fi
mv "$INSTALL_CANDIDATE" "$APP_DST"
NEW_APP_INSTALLED=1
codesign --verify --deep --strict "$APP_DST"
INSTALLED_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP_DST/Contents/Info.plist")"
[ "$INSTALLED_VERSION" = "$EXPECTED_VERSION" ] \
  || die "installed app version $INSTALLED_VERSION does not match build $EXPECTED_VERSION"
SUPPORT_JOURNAL="$SIGNING_DIR/support-rollback"
python3 "$REPO/scripts/install-macos-support.py" "$REPO" "$CARGO_OUTPUT" "$SUPPORT_JOURNAL"
echo "==> Launching and verifying the installed app…"
open -a "$APP_DST"
python3 "$REPO/scripts/verify-installed-bridge.py" \
  "$HOST_BIN" "$EXPECTED_VERSION" \
  || die "The installed app failed its live bridge check"
if [ "$WAS_RUNNING" != 1 ]; then
  osascript -e 'quit app "Arca"'
fi
INSTALL_COMMITTED=1

# Remove the just-built source bundle so Spotlight/Launch Services don't show a
# second "Arca" alongside the installed one, then refresh Launch Services.
rm -rf "$APP_BUILD"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
[ -x "$LSREGISTER" ] && "$LSREGISTER" -f "$APP_DST" 2>/dev/null || true

if [ "$WAS_RUNNING" = 1 ]; then
  echo "Done: $APP_DST — running the build you just made. Unlock it again."
else
  echo "Done: $APP_DST (launch it from Spotlight: 'Arca')"
fi
