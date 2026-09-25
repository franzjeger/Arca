#!/usr/bin/env python3
"""Reject disconnected, stale and malformed native-host replies."""
import importlib.util
from pathlib import Path
import json
import struct
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bridge", Path(__file__).with_name("verify-installed-bridge.py"))
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class VerificationTests(unittest.TestCase):
    def reply(self, response):
        payload = json.dumps(response).encode()
        return subprocess.CompletedProcess([], 0, struct.pack("<I", len(payload)) + payload)

    def test_current_connected_pair(self):
        with patch.object(bridge.subprocess, "run", return_value=self.reply(
                {"app_connected": True, "version": "0.5.0", "app_version": "0.5.0"})):
            bridge.check("host", "0.5.0")

    def test_reject_stale_or_disconnected_pair(self):
        for response in [
            {"app_connected": False, "version": "0.5.0", "app_version": "0.5.0"},
            {"app_connected": True, "version": "0.4.0", "app_version": "0.5.0"},
            {"app_connected": True, "version": "0.5.0", "app_version": "0.4.0"},
        ]:
            with self.subTest(response=response), patch.object(bridge.subprocess, "run", return_value=self.reply(response)):
                with self.assertRaises(ValueError):
                    bridge.check("host", "0.5.0")

    def test_empty_response(self):
        with patch.object(bridge.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"")):
            with self.assertRaises(ValueError):
                bridge.check("host", "0.5.0")


if __name__ == "__main__":
    unittest.main()
