#!/usr/bin/env bash
#
# Pre-install smoke test — run BEFORE installing any build over the working app.
#
#   scripts/smoke-test.sh          # hermetic: Rust + frontend + extension tests
#   scripts/smoke-test.sh --full   # + OS-keychain regression tests (macOS desktop,
#                                  #   may touch the real keychain with test-only
#                                  #   service names) + live bridge round-trip if
#                                  #   the app is running
#
# Exists because we shipped builds that passed partial checks while the real
# user flow (quick unlock, autofill) was broken. Rule: no install without a
# green smoke run; never claim a flow works without exercising THAT flow.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
FULL="${1:-}"

step() { printf '\n==> %s\n' "$1"; }

step "Installers: Cargo output directory overrides"
python3 scripts/check-versions.py
python3 scripts/test-check-release.py
python3 scripts/test-cargo-target-dir.py
python3 scripts/test-installed-bridge.py
python3 scripts/test-autofill-signing.py
python3 scripts/test-install-macos-support.py
python3 scripts/test-apple-ci.py
if [ "$(uname)" = "Linux" ]; then
  step "Installer: transaction, build identity and rollback"
  python3 scripts/test-install-linux.py
fi

step "Rust: hermetic workspace tests"
cargo test --quiet --workspace --locked

step "Rust: desktop app compiles"
cargo build --quiet --locked -p vault-desktop

step "Frontend: typecheck + build"
(cd apps/desktop && npm run --silent build)

step "Frontend: component tests"
(cd apps/desktop && npm run --silent test)

step "Desktop: keyboard and dialog browser checks"
(cd apps/desktop && npm run --silent test:browser)

step "Browser extension tests"
for test_file in extension/test/*.test.mjs; do
  node "$test_file"
done

if [ "$FULL" = "--full" ]; then
  if [ "$(uname)" = "Darwin" ]; then
    step "Keychain regression tests (quick-unlock drift heal)"
    cargo test --quiet -p vault-store -- --ignored
  fi

  step "Live bridge round-trip (only if the app is running)"
  CARGO_OUTPUT="$(python3 "$REPO/scripts/cargo-target-dir.py")"
  NATIVE_HOST="$CARGO_OUTPUT/release/vault-native-host"
  case "$(uname)" in
    Darwin) BRIDGE="$HOME/Library/Application Support/no.sybr.vault/native-bridge.json" ;;
    Linux) BRIDGE="${XDG_DATA_HOME:-$HOME/.local/share}/no.sybr.vault/native-bridge.json" ;;
    *) BRIDGE="" ;;
  esac
  if [ -f "$BRIDGE" ] && [ -x "$NATIVE_HOST" ]; then
    python3 - "$NATIVE_HOST" <<'PY'
import json, struct, subprocess, sys
msg = json.dumps({"type": "hello", "version": "smoke", "protocol": 1}).encode()
p = subprocess.run([sys.argv[1]],
                   input=struct.pack("<I", len(msg)) + msg,
                   capture_output=True, timeout=10, check=True)
out = p.stdout
if len(out) < 4:
    sys.exit("native host gave no response")
n = struct.unpack("<I", out[:4])[0]
resp = json.loads(out[4:4 + n])
if resp.get("app_connected") is not True:
    sys.exit("native host cannot authenticate the running desktop app")
print(f"   native host {resp.get('version')} connected to desktop {resp.get('app_version')}")
PY
  else
    echo "   (skipped: app not running or native host not built)"
  fi
fi

printf '\nSMOKE OK\n'
