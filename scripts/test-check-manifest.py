#!/usr/bin/env python3
"""Regression: a release is published only with a manifest that matches it.

`latest.json` is now put together on two machines, the Mac and the Linux
release workflow, and the half that arrives second merges into the first. Each
property below is a way that file could go out describing something other than
the release it sits on, and every installed copy would act on it.
"""
import json
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parent.parent
helper = repo / "scripts/check-manifest.py"
conf = json.loads((repo / "apps/desktop/src-tauri/tauri.conf.json").read_text())
REPO_URL = conf["plugins"]["updater"]["endpoints"][0].partition("/releases/")[0]

VERSION = "9.9.9"
MAC = "Arca_9.9.9_aarch64.app.tar.gz"
LINUX = "Arca_9.9.9_amd64.AppImage"


def url(name, version=VERSION, repo_url=REPO_URL):
    return f"{repo_url}/releases/download/v{version}/{name}"


def manifest(**platforms):
    return {"version": VERSION, "platforms": platforms}


def entry(name, signature):
    return {"url": url(name), "signature": signature}


def run(directory, data, assets, sigs, *extra):
    path = Path(directory)
    (path / "latest.json").write_text(json.dumps(data))
    (path / "assets.txt").write_text("\n".join(assets) + "\n")
    sig_dir = path / "sigs"
    sig_dir.mkdir(exist_ok=True)
    for old in sig_dir.iterdir():
        old.unlink()
    for name, text in sigs.items():
        (sig_dir / name).write_text(text + "\n")
    return subprocess.run(
        ["python3", str(helper), "--manifest", str(path / "latest.json"), "--version", VERSION,
         "--assets", str(path / "assets.txt"), "--sig-dir", str(sig_dir), *extra],
        capture_output=True, text=True,
    )


ALL_ASSETS = [MAC, f"{MAC}.sig", "Arca_9.9.9_aarch64.dmg", LINUX, f"{LINUX}.sig",
              "Arca_9.9.9_amd64.deb", "Arca-9.9.9-1.x86_64.rpm", "latest.json"]
ALL_SIGS = {f"{MAC}.sig": "mac-signature", f"{LINUX}.sig": "linux-signature"}
BOTH = manifest(**{"darwin-aarch64": entry(MAC, "mac-signature"),
                   "linux-x86_64": entry(LINUX, "linux-signature")})
EXPECT_BOTH = ("--expect", "darwin-aarch64", "--expect", "linux-x86_64")


def fails(result, needle):
    assert result.returncode != 0, f"accepted, expected to fail on {needle!r}: {result.stdout}"
    assert needle in result.stderr, f"failed for another reason than {needle!r}: {result.stderr}"


with tempfile.TemporaryDirectory(prefix="arca-check-manifest-") as d:
    # A release carrying both platforms, each file and signature attached.
    result = run(d, BOTH, ALL_ASSETS, ALL_SIGS, *EXPECT_BOTH)
    assert result.returncode == 0, result.stderr
    assert "darwin-aarch64, linux-x86_64" in result.stdout, result.stdout

    # The manifest of another version, as an old latest.json left on a draft.
    stale = dict(BOTH, version="9.9.8")
    fails(run(d, stale, ALL_ASSETS, ALL_SIGS), "is for 9.9.8, not 9.9.9")

    # The Linux merge dropped the Mac entry: every installed Mac would stop
    # seeing updates, and nothing else would say so.
    linux_only = manifest(**{"linux-x86_64": entry(LINUX, "linux-signature")})
    fails(run(d, linux_only, ALL_ASSETS, ALL_SIGS, *EXPECT_BOTH),
          "expected darwin-aarch64, linux-x86_64")

    # An entry pointing at the previous release's file.
    old_file = manifest(**{"linux-x86_64": {"url": url(LINUX, version="9.9.8"),
                                            "signature": "linux-signature"}})
    fails(run(d, old_file, ALL_ASSETS, ALL_SIGS), "not a file on v9.9.9")

    # An entry pointing at another repository.
    elsewhere = manifest(**{"linux-x86_64": {
        "url": url(LINUX, repo_url="https://github.com/someone/else"),
        "signature": "linux-signature"}})
    fails(run(d, elsewhere, ALL_ASSETS, ALL_SIGS), "not a file on v9.9.9")

    # A name that is not a single file on the release.
    nested = manifest(**{"linux-x86_64": entry(f"../v9.9.8/{LINUX}", "linux-signature")})
    fails(run(d, nested, ALL_ASSETS, ALL_SIGS), "not a file on v9.9.9")

    # The manifest names a file that was never attached.
    missing = [name for name in ALL_ASSETS if name != LINUX]
    fails(run(d, BOTH, missing, ALL_SIGS), f"{LINUX} is not attached")

    # The file is there but its signature is not.
    unsigned = [name for name in ALL_ASSETS if name != f"{LINUX}.sig"]
    fails(run(d, BOTH, unsigned, ALL_SIGS), f"{LINUX}.sig is not attached")

    # The manifest carries a signature other than the one beside the file, as
    # after a rebuild that re-uploaded the AppImage but not the manifest.
    resigned = dict(ALL_SIGS, **{f"{LINUX}.sig": "a-later-signature"})
    fails(run(d, BOTH, ALL_ASSETS, resigned), "carries a signature other than")

    # The Linux workflow has only its own .sig on disk; it verifies its own
    # entry and asks only that the Mac entry is still there.
    linux_sig = {f"{LINUX}.sig": "linux-signature"}
    result = run(d, BOTH, ALL_ASSETS, linux_sig, "--verify", "linux-x86_64", *EXPECT_BOTH)
    assert result.returncode == 0, result.stderr
    fails(run(d, BOTH, ALL_ASSETS, linux_sig), "to compare the signature with")

    # Not a manifest at all.
    fails(run(d, ["not", "a", "manifest"], ALL_ASSETS, ALL_SIGS), "cannot check")

print("check-manifest: ok")
