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
import datetime
import json
import os
import sys


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--url", required=True)
    p.add_argument("--signature-file", required=True)
    # Several keys share one artifact where that is genuinely true — both Apple
    # architectures run the same universal bundle.
    p.add_argument("--platform", action="append", required=True, dest="platforms")
    p.add_argument("--notes", default="See the release notes on GitHub.")
    args = p.parse_args()

    with open(args.signature_file, encoding="utf-8") as f:
        signature = f.read().strip()
    if not signature:
        print(f"ERROR: {args.signature_file} is empty; the build was not signed.", file=sys.stderr)
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
