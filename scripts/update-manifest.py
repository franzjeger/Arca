#!/usr/bin/env python3
"""Merge one platform's entry into the updater manifest (`latest.json`).

Every release script calls this instead of writing the manifest itself. The
macOS script used to emit the whole file, which meant the manifest only ever
described the platform that happened to build last: a Linux release published
after a macOS one replaced `darwin-*` with `linux-*`, and every installed Mac
stopped seeing updates. Merging is the whole point of this file existing.

A manifest describes ONE version. The `url` in each entry names a file on that
version's release, so entries from different versions cannot coexist — a mixed
manifest hands half the users a download that does not belong to the version it
claims. When the version changes, the old platforms are therefore dropped
rather than merged, and the script says so.

Usage:
  update-manifest.py --manifest PATH --version 0.6.2 --signature-file F \\
                     --url URL --platform linux-x86_64 [--platform ...]
"""

import argparse
import base64
import datetime
import json
import os
from pathlib import Path
import sys

TAURI_CONF = Path(__file__).resolve().parent.parent / "apps/desktop/src-tauri/tauri.conf.json"


def check_signature(signature, version):
    """What `tauri signer sign` wrote: by the key installed copies trust, and
    for this version. Get either wrong and every client refuses the update,
    which nobody notices until somebody wonders why they never get one. The
    updater itself checks the cryptography."""
    try:
        lines = base64.b64decode(signature, validate=True).decode().splitlines()
        key_id = base64.b64decode(lines[1])[2:10]
        trusted = lines[2].removeprefix("trusted comment: ")
    except (ValueError, IndexError) as error:
        raise ValueError(f"not a minisign signature ({error})") from error
    pubkey = json.loads(TAURI_CONF.read_text())["plugins"]["updater"]["pubkey"]
    trusted_key = base64.b64decode(base64.b64decode(pubkey).decode().splitlines()[1])[2:10]
    if key_id != trusted_key:
        raise ValueError("signed with a key installed copies do not trust")
    fields = dict(field.split(":", 1) for field in trusted.split("\t") if ":" in field)
    if fields.get("version") != version:
        raise ValueError(f"signed for version {fields.get('version')}, not {version}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--url", required=True)
    p.add_argument("--signature-file", required=True)
    # Several keys may share one artifact where that is genuinely true, as both
    # Apple architectures would with a universal bundle.
    p.add_argument("--platform", action="append", required=True, dest="platforms")
    p.add_argument("--notes", default="See the release notes on GitHub.")
    args = p.parse_args()

    with open(args.signature_file, encoding="utf-8") as f:
        signature = f.read().strip()
    if not signature:
        print(f"ERROR: {args.signature_file} is empty; the build was not signed.", file=sys.stderr)
        return 1
    try:
        check_signature(signature, args.version)
    except ValueError as error:
        print(f"ERROR: {args.signature_file}: {error}.", file=sys.stderr)
        return 1

    manifest = {}
    if os.path.exists(args.manifest):
        with open(args.manifest, encoding="utf-8") as f:
            try:
                manifest = json.load(f)
            except json.JSONDecodeError:
                # Not a manifest we can reason about. Replacing it is safe:
                # the entries we cannot read are ones no client could use.
                print(f"   note: {args.manifest} was unreadable and is being rewritten")
                manifest = {}

    platforms = manifest.get("platforms", {})
    previous = manifest.get("version")
    if previous and previous != args.version:
        print(
            f"   note: manifest was for {previous}, now {args.version} — "
            f"dropping {', '.join(sorted(platforms)) or 'nothing'}, "
            "those files belong to the old release"
        )
        platforms = {}

    for key in args.platforms:
        platforms[key] = {"signature": signature, "url": args.url}

    manifest.update(
        {
            "version": args.version,
            "pub_date": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "notes": args.notes,
            "platforms": platforms,
        }
    )

    with open(args.manifest, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    print(f"   {args.manifest} (v{args.version}): {', '.join(sorted(platforms))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
