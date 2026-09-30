#!/usr/bin/env python3
"""Regression: installers must use the configured Cargo cache, not repo/target."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parent.parent
helper = repo / "scripts/cargo-target-dir.py"
with tempfile.TemporaryDirectory(prefix="arca-cargo-path-") as directory:
    target = Path(directory) / "output with spaces"
    env = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    resolved = subprocess.check_output(["python3", str(helper)], env=env, text=True).strip()
    assert Path(resolved) == target
    assert not target.exists(), "Resolving output should not build anything"
for name in ("scripts/install-linux.sh",
             "scripts/install-app-macos.sh", "scripts/release-macos.sh", "scripts/build-ffi-ios.sh",
             "scripts/smoke-test.sh"):
    source = (repo / name).read_text()
    assert "cargo-target-dir.py" in source, name
    assert "$REPO/target/release" not in source, name
# The macOS extension setup builds nothing: the host comes inside the app.
macos_extension = (repo / "extension/install-macos.sh").read_text()
assert "cargo" not in macos_extension, "extension/install-macos.sh"
assert "Contents/MacOS/vault-native-host" in macos_extension, "extension/install-macos.sh"
assert 'exec "$REPO/scripts/install-linux.sh" "$@"' in (repo / "extension/install-linux.sh").read_text()
config = json.loads((repo / "apps/desktop/src-tauri/tauri.conf.json").read_text())
for package in ("deb", "rpm"):
    assert config["bundle"]["linux"][package]["files"]["/usr/bin/vault-native-host"] == "../../../target/linux-packaging/vault-native-host"
print("Cargo output override and installer/packaging paths verified.")
