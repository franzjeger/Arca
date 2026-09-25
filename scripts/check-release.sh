#!/usr/bin/env bash
# Run before signing/publishing coordinated desktop and Apple releases.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
python3 scripts/check-versions.py
python3 scripts/check-release.py
