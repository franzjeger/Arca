#!/usr/bin/env bash
# Install the desktop and native host together so their versions stay matched.
# The host is registered from ~/.local/lib/arca, independent of Cargo's cache.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
exec "$REPO/scripts/install-linux.sh" "$@"
