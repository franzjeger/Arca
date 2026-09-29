#!/usr/bin/env bash
#
# Connects the browser extension to Arca on macOS.
#
# The native messaging host ships inside Arca.app, and Arca registers it with
# every installed Chromium-family browser and Firefox each time it starts, so
# there is nothing to build or copy here: this starts Arca once and checks that
# the browsers now start its host. What is left is Chrome's "Load unpacked"
# (Google blocks programmatic unpacked installs), and because the extension's
# id is pinned by the public `key` in chromium/manifest.json, no id-copying or
# file-editing is needed.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP="/Applications/Arca.app"
HOST="$APP/Contents/MacOS/vault-native-host"

[ -d "$APP" ] || { echo "Install Arca in /Applications first (scripts/install-app-macos.sh)." >&2; exit 1; }
[ -x "$HOST" ] || { echo "This Arca predates the browser host inside the app. Update it (scripts/install-app-macos.sh)." >&2; exit 1; }
VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")"

echo "==> Starting Arca, which registers its browser host…"
open -g -a "$APP"
python3 "$REPO/scripts/verify-installed-bridge.py" --registrations "$HOST" "$VERSION"

cat <<DONE

Done. Last step (Chrome's one unavoidable click):
  1. chrome://extensions  ->  enable "Developer mode"
  2. "Load unpacked"  ->  select:  $REPO/extension/chromium
The pinned extension id matches the registration Arca wrote.
Then keep the desktop app open + unlocked and autofill will work.
DONE
