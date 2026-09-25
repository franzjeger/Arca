#!/usr/bin/env bash
# Install a tested desktop/native-host pair from a clean Git checkout.
# --restart permits closing a running Arca (save unfinished edits first).
# --rollback restores the previous installation, leaving vault data untouched.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
RESTART=()
ROLLBACK=0
for argument in "$@"; do
    case "$argument" in
        --restart) RESTART=(--restart) ;;
        --rollback) ROLLBACK=1 ;;
        *) echo "Usage: $0 [--restart] [--rollback]" >&2; exit 2 ;;
    esac
done
mkdir -p "$HOME/.local/lib/arca"
exec 9> "$HOME/.local/lib/arca/.update.lock"
flock -n 9 || { echo "Another Arca update is already running." >&2; exit 1; }
if [ "$ROLLBACK" -eq 1 ]; then
    python3 scripts/install-linux.py rollback "${RESTART[@]}"
    exit
fi
if [ -n "$(git status --porcelain)" ]; then
    echo "Commit the source changes before installing, so the installed build has an exact Git identity." >&2
    exit 1
fi
CARGO_OUTPUT="$(python3 "$REPO/scripts/cargo-target-dir.py")"
python3 scripts/check-versions.py
(cd apps/desktop && npm ci)
scripts/smoke-test.sh
mkdir -p "$REPO/target/install-staging"
STAGING="$(mktemp -d "$REPO/target/install-staging/update-XXXXXXXX")"
trap 'rm -rf -- "$STAGING"' EXIT
python3 scripts/install-linux.py prepare --snapshot "$STAGING/previous"
echo "==> Building the desktop app and native host from the same commit…"
(cd apps/desktop && npm run tauri build -- --no-bundle)
cargo build -p vault-native-host --release
if [ -n "$(git status --porcelain)" ]; then
    echo "Source changed during the build. Installation stopped." >&2
    exit 1
fi
install -m755 "$CARGO_OUTPUT/release/vault-desktop" "$STAGING/arca"
install -m755 "$CARGO_OUTPUT/release/vault-native-host" "$STAGING/vault-native-host"
python3 scripts/install-linux.py apply --snapshot "$STAGING/previous" \
    --app "$STAGING/arca" --host "$STAGING/vault-native-host" \
    "${RESTART[@]}"
update-desktop-database "${XDG_DATA_HOME:-$HOME/.local/share}/applications" 2>/dev/null || true
echo "Arca is installed, running, and verified against its Git commit."
