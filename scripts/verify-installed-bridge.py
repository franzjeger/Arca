#!/usr/bin/env python3
"""Verify a locked or unlocked desktop through the authenticated native host."""
import json
import struct
import subprocess
import sys
import time


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


def main():
    host, version = sys.argv[1:]
    deadline = time.monotonic() + 30
    while True:
        try:
            check(host, version)
            print(f"Verified: native host and running desktop are both {version}")
            return
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            if time.monotonic() >= deadline:
                sys.exit(f"Installed app verification failed: {error}")
            time.sleep(1)


if __name__ == "__main__":
    main()
