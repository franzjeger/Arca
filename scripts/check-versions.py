#!/usr/bin/env python3
"""Fail CI when application packages accidentally advertise different releases."""
import json
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parent.parent
workspace = (root / "Cargo.toml").read_text()
expected = re.search(r'(?m)^version = "([^"]+)"', workspace)[1]
versions = {}
for name in ("apps/desktop/package.json", "apps/desktop/package-lock.json",
             "apps/desktop/src-tauri/tauri.conf.json", "extension/chromium/manifest.json", "extension/chromium/manifest.firefox.json"):
    data = json.loads((root / name).read_text())
    versions[name] = data["version"]
    if "packages" in data:
        versions[name + " (root package)"] = data["packages"][""]["version"]
for name in ("apps/ios/project.yml", "apps/macos/project.yml"):
    versions[name] = re.search(r'MARKETING_VERSION: "([^"]+)"', (root / name).read_text())[1]
errors = [f"{name}: {version} (expected {expected})" for name, version in versions.items() if version != expected]
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"All application packages: {expected}")
