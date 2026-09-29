#!/usr/bin/env python3
"""Verify a locked or unlocked desktop through the authenticated native host.

With --registrations, also that every installed browser starts that host,
which the app registers when it starts (apps/desktop/src-tauri/src/browser_host.rs).
"""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

# CHROMIUM_BROWSERS in browser_host.rs, and Firefox.
BROWSERS = ("Google/Chrome", "BraveSoftware/Brave-Browser", "Microsoft Edge", "Chromium", "Mozilla")


def check(host, version):
    message = json.dumps({"type": "hello", "version": "install-check", "protocol": 1}).encode()
    result = subprocess.run([host], input=struct.pack("<I", len(message)) + message,
                            capture_output=True, timeout=3, check=True)
    if len(result.stdout) < 4:
        raise ValueError("Native host gave no response")
    length = struct.unpack("<I", result.stdout[:4])[0]
    response = json.loads(result.stdout[4:4 + length])
    if response.get("app_connected") is not True:
        raise ValueError("Native host cannot authenticate the installed desktop")
    if response.get("version") != version or response.get("app_version") != version:
        raise ValueError("Desktop or native host version does not match the installed bundle")


def check_registrations(home, host):
    """Every installed browser's registration names `host`."""
    support = Path(home) / "Library/Application Support"
    for browser in BROWSERS:
        if not (support / browser).is_dir():
            continue
        registration = support / browser / "NativeMessagingHosts/no.sybr.vault.json"
        try:
            path = json.loads(registration.read_text()).get("path")
        except (OSError, ValueError, AttributeError):
            path = None
        if path != host:
            raise ValueError(f"{browser} does not start {host}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registrations", action="store_true",
                        help="also check that the browsers start this host")
    parser.add_argument("host")
    parser.add_argument("version")
    args = parser.parse_args()
    deadline = time.monotonic() + 30
    while True:
        try:
            check(args.host, args.version)
            if args.registrations:
                check_registrations(Path.home(), args.host)
            print(f"Verified: native host and running desktop are both {args.version}")
            return
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            if time.monotonic() >= deadline:
                sys.exit(f"Installed app verification failed: {error}")
            time.sleep(1)


if __name__ == "__main__":
    main()
