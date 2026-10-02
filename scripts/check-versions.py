#!/usr/bin/env python3
"""Fail CI when application packages accidentally advertise different releases,
or the app and its AutoFill extension ask for different macOS versions."""
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
# The app declares the macOS its AutoFill extension needs. Below that the
# extension does not load, and the interface, built with Tailwind 4, needs
# WebKit from macOS 13.3 on: a lower declaration lets the app open broken
# where macOS would otherwise say plainly that it cannot run.
app_macos = json.loads((root / "apps/desktop/src-tauri/tauri.conf.json").read_text())["bundle"].get(
    "macOS", {}).get("minimumSystemVersion")
autofill_macos = re.search(r'deploymentTarget:\s*\n\s*macOS: "([^"]+)"',
                           (root / "apps/macos/project.yml").read_text())[1]
if app_macos != autofill_macos:
    errors.append(f"apps/desktop/src-tauri/tauri.conf.json bundle.macOS.minimumSystemVersion: "
                  f"{app_macos} (the AutoFill extension needs macOS {autofill_macos})")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"All application packages: {expected}; macOS {app_macos} or later")
