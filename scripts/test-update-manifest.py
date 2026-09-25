#!/usr/bin/env python3
"""Regression: one release must not delete another platform's update entry.

`latest.json` is the file every installed copy polls. Each release script used
to write the whole thing, so publishing macOS replaced `linux-*` with
`darwin-*` and every Linux install silently stopped seeing updates — and the
other way round. The merge is the fix, and these are the properties it has to
keep.
"""
import json
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parent.parent
helper = repo / "scripts/update-manifest.py"


def merge(manifest, version, url, signature, *platforms):
    sig = manifest.parent / "sig"
    sig.write_text(signature)
    args = ["python3", str(helper), "--manifest", str(manifest), "--version", version,
            "--url", url, "--signature-file", str(sig)]
    for platform in platforms:
        args += ["--platform", platform]
    subprocess.run(args, check=True, capture_output=True, text=True)
    return json.loads(manifest.read_text())


with tempfile.TemporaryDirectory(prefix="arca-manifest-") as directory:
    manifest = Path(directory) / "latest.json"

    # macOS releases first, naming both Apple architectures.
    result = merge(manifest, "0.6.2", "https://x/Arca.app.tar.gz", "mac-sig",
                   "darwin-aarch64", "darwin-x86_64")
    assert set(result["platforms"]) == {"darwin-aarch64", "darwin-x86_64"}, result

    # Linux follows for the SAME version: the whole point — darwin survives.
    result = merge(manifest, "0.6.2", "https://x/Arca.AppImage", "linux-sig", "linux-x86_64")
    assert set(result["platforms"]) == {"darwin-aarch64", "darwin-x86_64", "linux-x86_64"}, result
    assert result["platforms"]["darwin-aarch64"]["signature"] == "mac-sig"
    assert result["platforms"]["linux-x86_64"]["url"] == "https://x/Arca.AppImage"
    assert result["version"] == "0.6.2"

    # A new version drops the old entries instead of mixing them: their URLs
    # point at the previous release's files, which no longer match the version
    # the manifest claims.
    result = merge(manifest, "0.7.0", "https://y/Arca.AppImage", "linux-sig", "linux-x86_64")
    assert set(result["platforms"]) == {"linux-x86_64"}, result
    assert result["version"] == "0.7.0"

    # An empty signature means the build was never signed. Publishing that
    # manifest would offer an update every client then refuses, so it fails.
    sig = manifest.parent / "sig"
    sig.write_text("")
    unsigned = subprocess.run(
        ["python3", str(helper), "--manifest", str(manifest), "--version", "0.7.0",
         "--url", "https://y/x", "--signature-file", str(sig), "--platform", "linux-x86_64"],
        capture_output=True, text=True)
    assert unsigned.returncode != 0, "an unsigned artifact must not reach the manifest"

# Both release scripts must go through the merge rather than writing the file.
for name in ("scripts/release-macos.sh", "scripts/release-linux.sh"):
    source = (repo / name).read_text()
    assert "update-manifest.py" in source, name

# The Linux release has to build the AppImage: it is the only Linux artifact
# tauri-plugin-updater can install. A .deb/.rpm-only release cannot self-update.
linux = (repo / "scripts/release-linux.sh").read_text()
assert "appimage" in linux, "the Linux release must produce an AppImage"

print("Update manifest merge, version reset and signing guard verified.")
