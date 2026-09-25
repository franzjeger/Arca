#!/usr/bin/env python3
"""Exercise stable browser registrations and rollback without touching the OS."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('support', Path(__file__).with_name('install-macos-support.py'))
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
REPO = Path(__file__).resolve().parent.parent


@unittest.skipUnless(os.name == 'posix', 'macOS support-file permissions require POSIX')
class SupportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='arca-support-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home with spaces'
        self.output = self.root / 'cargo cache'
        (self.output / 'release').mkdir(parents=True)
        (self.output / 'release/vault-native-host').write_bytes(b'new host')
        (self.output / 'release/arca').write_bytes(b'new cli')
        self.chrome = self.home / 'Library/Application Support/Google/Chrome'
        self.chrome.mkdir(parents=True)
        self.firefox = self.home / 'Library/Application Support/Mozilla'
        self.firefox.mkdir(parents=True)
        self.host = self.home / '.local/lib/arca/vault-native-host'
        self.cli = self.home / '.local/bin/arca'
        self.manifest = self.chrome / 'NativeMessagingHosts/no.sybr.vault.json'
        self.journal = self.root / 'rollback'

    def payloads(self, host_only=False):
        return support.payloads(REPO, self.output, self.home, host_only)

    def seed(self):
        support.atomic_write(self.host, b'old host', 0o750)
        support.atomic_write(self.cli, b'old cli', 0o700)
        support.atomic_write(self.manifest, b'{"path":"/old/build/cache/host"}', 0o640)

    def test_install_moves_registrations_to_persistent_host(self):
        self.seed()
        support.install(self.payloads(), self.journal)
        self.assertEqual(self.host.read_bytes(), b'new host')
        self.assertEqual(self.cli.read_bytes(), b'new cli')
        self.assertEqual(self.host.stat().st_mode & 0o777, 0o755)
        chromium = json.loads(self.manifest.read_text())
        self.assertEqual(chromium['path'], str(self.host))
        # The extension's published, pinned ID (independent of this helper's derivation).
        self.assertEqual(chromium['allowed_origins'], ['chrome-extension://joeolbejbmnhmgajgmidpnpnjahdiobc/'])
        firefox = json.loads((self.firefox / 'NativeMessagingHosts/no.sybr.vault.json').read_text())
        self.assertEqual(firefox['path'], str(self.host))
        self.assertIn('allowed_extensions', firefox)
        self.assertFalse((self.home / 'Library/Application Support/Microsoft Edge').exists())

    def test_later_app_failure_restores_binaries_permissions_and_manifests(self):
        self.seed()
        support.install(self.payloads(), self.journal)
        support.rollback(self.journal)
        self.assertEqual(self.host.read_bytes(), b'old host')
        self.assertEqual(self.cli.read_bytes(), b'old cli')
        self.assertEqual(self.host.stat().st_mode & 0o777, 0o750)
        self.assertEqual(self.manifest.stat().st_mode & 0o777, 0o640)
        self.assertEqual(json.loads(self.manifest.read_text())['path'], '/old/build/cache/host')
        self.assertFalse((self.firefox / 'NativeMessagingHosts/no.sybr.vault.json').exists())
        support.rollback(self.journal)  # The shell trap may retry a helper rollback.

    def test_partial_install_failure_rolls_back(self):
        self.seed()
        real_write = support.atomic_write
        failed = False

        def write(path, data, mode):
            nonlocal failed
            if path == self.cli and not failed:
                failed = True
                raise OSError('simulated full disk')
            real_write(path, data, mode)

        with patch.object(support, 'atomic_write', side_effect=write):
            with self.assertRaises(OSError):
                support.install(self.payloads(), self.journal)
        self.assertEqual(self.host.read_bytes(), b'old host')
        self.assertEqual(self.cli.read_bytes(), b'old cli')

    def test_host_only_does_not_replace_cli_and_restores_symlink(self):
        self.seed()
        self.host.unlink()
        original = self.root / 'previous-host'
        original.write_bytes(b'previous executable')
        self.host.symlink_to(original)
        support.install(self.payloads(host_only=True), self.journal)
        self.assertFalse(self.host.is_symlink())
        self.assertEqual(original.read_bytes(), b'previous executable')
        self.assertEqual(self.cli.read_bytes(), b'old cli')
        support.rollback(self.journal)
        self.assertTrue(self.host.is_symlink())

    def test_bad_extension_key_leaves_installed_files_untouched(self):
        self.seed()
        repo = self.root / 'invalid repo'
        manifest = repo / 'extension/chromium/manifest.json'
        manifest.parent.mkdir(parents=True)
        manifest.write_text('{"key":"not-base64!"}')
        with self.assertRaises(ValueError):
            support.payloads(repo, self.output, self.home)
        self.assertEqual(self.host.read_bytes(), b'old host')


if __name__ == '__main__':
    unittest.main()
