#!/usr/bin/env python3
"""Regression: one release must not delete another platform's update entry.

`latest.json` is the file every installed copy polls. Each release script used
to write the whole thing, so publishing macOS replaced `linux-*` with
`darwin-*` and every Linux install silently stopped seeing updates — and the
other way round. The merge is the fix, and these are the properties it has to
keep.
"""
import base64
import json
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parent.parent
helper = repo / "scripts/update-manifest.py"
conf = json.loads((repo / "apps/desktop/src-tauri/tauri.conf.json").read_text())
public_key = base64.b64decode(conf["plugins"]["updater"]["pubkey"]).decode().splitlines()[1]
TRUSTED_KEY_ID = base64.b64decode(public_key)[2:10]


def signature(version, tag, key_id=TRUSTED_KEY_ID):
    """Shaped like what `tauri signer sign` writes. The key id and the version
    are what the merge checks; the updater itself checks the cryptography."""
    signed = base64.b64encode(b"ED" + key_id + tag.encode().ljust(64, b"\0")).decode()
    text = ("untrusted comment: signature from tauri secret key\n"
            f"{signed}\n"
            f"trusted comment: timestamp:1\tfile:Arca.app.tar.gz\tversion:{version}\n"
            f"{base64.b64encode(bytes(64)).decode()}\n")
    return base64.b64encode(text.encode()).decode()


def run(manifest, version, url, signature, *platforms):
    sig = manifest.parent / "sig"
    sig.write_text(signature)
    args = ["python3", str(helper), "--manifest", str(manifest), "--version", version,
            "--url", url, "--signature-file", str(sig)]
    for platform in platforms:
        args += ["--platform", platform]
    return subprocess.run(args, capture_output=True, text=True)


def merge(manifest, version, url, signature, *platforms):
    run(manifest, version, url, signature, *platforms).check_returncode()
    return json.loads(manifest.read_text())


with tempfile.TemporaryDirectory(prefix="arca-manifest-") as directory:
    manifest = Path(directory) / "latest.json"

    # macOS releases first, naming both Apple architectures.
    mac = signature("0.6.2", "mac")
    result = merge(manifest, "0.6.2", "https://x/Arca.app.tar.gz", mac,
                   "darwin-aarch64", "darwin-x86_64")
    assert set(result["platforms"]) == {"darwin-aarch64", "darwin-x86_64"}, result

    # Linux follows for the SAME version: the whole point — darwin survives.
    result = merge(manifest, "0.6.2", "https://x/Arca.AppImage", signature("0.6.2", "linux"),
                   "linux-x86_64")
    assert set(result["platforms"]) == {"darwin-aarch64", "darwin-x86_64", "linux-x86_64"}, result
    assert result["platforms"]["darwin-aarch64"]["signature"] == mac
    assert result["platforms"]["linux-x86_64"]["url"] == "https://x/Arca.AppImage"
    assert result["version"] == "0.6.2"

    # A new version drops the old entries instead of mixing them: their URLs
    # point at the previous release's files, which no longer match the version
    # the manifest claims.
    result = merge(manifest, "0.7.0", "https://y/Arca.AppImage", signature("0.7.0", "linux"),
                   "linux-x86_64")
    assert set(result["platforms"]) == {"linux-x86_64"}, result
    assert result["version"] == "0.7.0"

    # Each of these would offer an update every client then refuses, so none
    # reaches the manifest: no signature at all, one that is not a signature,
    # one by a key the installed copies do not trust, and one for another
    # version.
    before = manifest.read_text()
    for refused, why in [
        ("", "an unsigned artifact"),
        ("mac-sig", "a string that is not a signature"),
        (signature("0.7.0", "linux", key_id=bytes(8)), "a signature by another key"),
        (signature("0.6.2", "linux"), "a signature for another version"),
    ]:
        result = run(manifest, "0.7.0", "https://y/x", refused, "linux-x86_64")
        assert result.returncode != 0, f"{why} must not reach the manifest"
        assert manifest.read_text() == before, f"{why} changed the manifest"

# Both release scripts must go through the merge rather than writing the file.
for name in ("scripts/release-macos.sh", "scripts/release-linux.sh"):
    source = (repo / name).read_text()
    assert "update-manifest.py" in source, name

# The Linux release has to build the AppImage: it is the only Linux artifact
# tauri-plugin-updater can install. A .deb/.rpm-only release cannot self-update.
linux = (repo / "scripts/release-linux.sh").read_text()
assert "appimage" in linux, "the Linux release must produce an AppImage"

print("Update manifest merge, version reset and signing guard verified.")
