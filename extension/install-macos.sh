#!/usr/bin/env bash
#
# One-shot installer for the Arca native-messaging host (macOS).
#
# Builds the host binary and registers it for every installed Chromium-family
# browser, with the extension's PINNED id (derived from the public `key` in
# chromium/manifest.json). After running this, the only manual step left is
# Chrome's mandatory "Load unpacked" (Google blocks programmatic unpacked
# installs) — and because the id is pinned, no id-copying or file-editing is
# needed.
#
# Re-runnable and reversible: delete the written no.sybr.vault.json files to
# undo (see the paths it prints).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_OUTPUT="$(python3 "$REPO/scripts/cargo-target-dir.py")"
HOST_BIN="$CARGO_OUTPUT/release/vault-native-host"

echo "==> Building the native messaging host (release)…"
( cd "$REPO" && cargo build -p vault-native-host --release )
[ -x "$HOST_BIN" ] || { echo "host binary not found at $HOST_BIN" >&2; exit 1; }

# Share the desktop installer's stable host path and atomic registration logic.
JOURNAL_ROOT="$(mktemp -d /tmp/arca-host-install.XXXXXX)"
trap 'rm -rf "$JOURNAL_ROOT"' EXIT
python3 "$REPO/scripts/install-macos-support.py" --host-only \
  "$REPO" "$CARGO_OUTPUT" "$JOURNAL_ROOT/rollback"

cat <<DONE

Done. Last step (Chrome's one unavoidable click):
  1. chrome://extensions  ->  enable "Developer mode"
  2. "Load unpacked"  ->  select:  $REPO/extension/chromium
The pinned extension id matches the host registration above.
Then keep the desktop app open + unlocked and autofill will work.
DONE
