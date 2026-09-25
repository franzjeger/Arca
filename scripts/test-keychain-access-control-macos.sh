#!/usr/bin/env bash
# Interactive signed test, isolated from real vault/keychain entries.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(uname)" = Darwin ] || { echo "Requires macOS" >&2; exit 1; }
TEST_DIR="$(mktemp -d /tmp/arca-keychain-check.XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT
TEST_APP="$TEST_DIR/Arca Keychain Check.app"
mkdir -p "$TEST_APP/Contents/MacOS"
cat > "$TEST_APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>no.sybr.vault</string>
<key>CFBundleName</key><string>Arca Keychain Check</string>
<key>CFBundleExecutable</key><string>keychain-check</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>NSFaceIDUsageDescription</key><string>Verify protection of a temporary test key.</string>
</dict></plist>
PLIST
xcrun clang -fobjc-arc -mmacosx-version-min=11.0 \
  -framework AppKit -framework LocalAuthentication -framework Security \
  "$REPO/scripts/tests/keychain-access-control.m" "$REPO/crates/vault-sharedkey/src/protected.m" -o "$TEST_APP/Contents/MacOS/keychain-check"
python3 "$REPO/scripts/prepare-autofill-signing.py" --plan "$TEST_DIR/signing.json" --desktop-only
IDENTITY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["identity"])' "$TEST_DIR/signing.json")"
python3 "$REPO/scripts/prepare-autofill-signing.py" --prepare "$TEST_APP" \
  "$REPO/apps/desktop/src-tauri/Entitlements.plist" "$TEST_DIR/entitlements.plist" "$TEST_DIR/signing.json"
codesign --force -s "$IDENTITY" --entitlements "$TEST_DIR/entitlements.plist" "$TEST_APP"
python3 "$REPO/scripts/prepare-autofill-signing.py" --verify "$TEST_APP"
codesign --verify --strict "$TEST_APP"
"$TEST_APP/Contents/MacOS/keychain-check"
