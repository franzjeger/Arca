#!/usr/bin/env python3
"""Reject disconnected, stale and malformed native-host replies, and browsers that start another host."""
import importlib.util
from pathlib import Path
import json
import shutil
import struct
import subprocess
import tempfile
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


class RegistrationTests(unittest.TestCase):
    HOST = "/Applications/Arca.app/Contents/MacOS/vault-native-host"

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="arca-registrations-test-")
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.support = self.home / "Library/Application Support"

    def register(self, browser, contents):
        path = self.support / browser / "NativeMessagingHosts/no.sybr.vault.json"
        path.parent.mkdir(parents=True)
        path.write_text(contents)

    def test_every_installed_browser_starts_the_host(self):
        self.register("Google/Chrome", json.dumps({"path": self.HOST}))
        self.register("Mozilla", json.dumps({"path": self.HOST}))
        (self.support / "Unrelated").mkdir()
        bridge.check_registrations(self.home, self.HOST)

    def test_a_browser_without_the_host_fails(self):
        for contents in [json.dumps({"path": "/Users/someone/.local/lib/arca/vault-native-host"}),
                         "not json", "[]"]:
            with self.subTest(contents=contents):
                registration = self.support / "Chromium"
                if registration.exists():
                    shutil.rmtree(registration)
                self.register("Chromium", contents)
                with self.assertRaises(ValueError):
                    bridge.check_registrations(self.home, self.HOST)

    def test_an_installed_browser_never_registered_fails(self):
        (self.support / "Microsoft Edge").mkdir(parents=True)
        with self.assertRaises(ValueError):
            bridge.check_registrations(self.home, self.HOST)

    def test_no_browsers_is_nothing_to_check(self):
        bridge.check_registrations(self.home, self.HOST)


if __name__ == "__main__":
    unittest.main()
