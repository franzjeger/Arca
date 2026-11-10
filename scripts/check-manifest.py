#!/usr/bin/env python3
"""Check that an updater manifest (`latest.json`) describes its own release.

The manifest is not signed, and every installed copy acts on it the moment it
is public. It is assembled on two machines — the Mac adds `darwin-aarch64`, the
Linux release workflow adds `linux-x86_64` — so before anyone can see it, this
checks, platform by platform, that:

- it is the manifest for this version;
- each entry downloads a file attached to this version's release, in the
  repository the app's own updater endpoint names;
- that file's detached `.sig` is attached as well, and is exactly the
  signature the entry carries.

`update-manifest.py` already refuses a signature by an untrusted key or for
another version while it merges; this is the check of the finished file
against what is actually on the release.

Usage:
  check-manifest.py --manifest latest.json --version 0.8.6 \\
      --assets assets.txt --sig-dir DIR [--expect P ...] [--verify P ...]

  --assets   a file listing the release's asset names, one per line
  --sig-dir  a folder holding the `.sig` files the manifest refers to
  --expect   the manifest must carry exactly these platforms
  --verify   check only these platforms' files and signatures (default: all)
"""

import argparse
import json
from pathlib import Path
import sys

TAURI_CONF = Path(__file__).resolve().parent.parent / "apps/desktop/src-tauri/tauri.conf.json"


def release_prefix(version):
    """Where a version's files download from, derived from the endpoint the
    installed copies poll rather than written out a second time."""
    endpoint = json.loads(TAURI_CONF.read_text())["plugins"]["updater"]["endpoints"][0]
    repo, separator, _ = endpoint.partition("/releases/")
    if not separator:
        raise ValueError(f"the updater endpoint {endpoint} is not a GitHub release")
    return f"{repo}/releases/download/v{version}/"


def check(manifest, version, assets, sig_dir, expect=None, verify=None):
    """What is wrong with `manifest`, as sentences; empty when it is sound."""
    if manifest.get("version") != version:
        return [f"latest.json is for {manifest.get('version')}, not {version}"]
    platforms = manifest.get("platforms") or {}
    if not platforms:
        return ["latest.json names no platforms"]

    problems = []
    if expect is not None and set(expect) != set(platforms):
        problems.append(
            f"latest.json carries {', '.join(sorted(platforms))}; "
            f"expected {', '.join(sorted(expect))}"
        )
    prefix = release_prefix(version)
    for platform in verify or sorted(platforms):
        entry = platforms.get(platform)
        if entry is None:
            problems.append(f"{platform}: not in latest.json")
            continue
        url = entry.get("url", "")
        name = url[len(prefix):] if url.startswith(prefix) else ""
        if not name or "/" in name:
            problems.append(f"{platform}: downloads {url or 'nothing'}, not a file on v{version}")
            continue
        if name not in assets:
            problems.append(f"{platform}: {name} is not attached to the release")
        if f"{name}.sig" not in assets:
            problems.append(f"{platform}: {name}.sig is not attached to the release")
        sig = sig_dir / f"{name}.sig"
        if not sig.is_file():
            problems.append(f"{platform}: no {sig} to compare the signature with")
        elif entry.get("signature") != sig.read_text(encoding="utf-8").strip():
            problems.append(f"{platform}: carries a signature other than {name}.sig")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--sig-dir", required=True, type=Path)
    parser.add_argument("--expect", action="append")
    parser.add_argument("--verify", action="append")
    args = parser.parse_args(argv)

    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        assets = {
            line.strip()
            for line in args.assets.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        problems = check(manifest, args.version, assets, args.sig_dir, args.expect, args.verify)
    except (OSError, ValueError, AttributeError) as error:
        problems = [f"cannot check {args.manifest}: {error}"]
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if problems:
        return 1
    print("   latest.json:", ", ".join(sorted(manifest["platforms"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
