#!/usr/bin/env python3
"""Exercise the command-line install, the old host's retirement and rollback without touching the OS."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('support', Path(__file__).with_name('install-macos-support.py'))
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)

OLD_REGISTRATION = b'{"path":"/Users/someone/.local/lib/arca/vault-native-host"}'
APP_REGISTRATION = b'{"path":"/Applications/Arca.app/Contents/MacOS/vault-native-host"}'


@unittest.skipUnless(os.name == 'posix', 'macOS support-file permissions require POSIX')
class SupportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='arca-support-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home with spaces'
        self.output = self.root / 'cargo cache'
        (self.output / 'release').mkdir(parents=True)
        (self.output / 'release/arca').write_bytes(b'new cli')
        self.support = self.home / 'Library/Application Support'
        self.chrome = self.support / 'Google/Chrome/NativeMessagingHosts/no.sybr.vault.json'
        self.firefox = self.support / 'Mozilla/NativeMessagingHosts/no.sybr.vault.json'
        (self.support / 'Google/Chrome').mkdir(parents=True)
        (self.support / 'Mozilla').mkdir(parents=True)
        self.old_host = self.home / '.local/lib/arca/vault-native-host'
        self.cli = self.home / '.local/bin/arca'
        self.journal = self.root / 'rollback'

    def payloads(self):
        return support.payloads(self.output, self.home)

    def seed(self):
        support.atomic_write(self.old_host, b'old host', 0o750)
        support.atomic_write(self.cli, b'old cli', 0o700)
        support.atomic_write(self.chrome, OLD_REGISTRATION, 0o640)

    def app_registers(self):
        """What the new Arca does when it starts."""
        support.atomic_write(self.chrome, APP_REGISTRATION, 0o600)
        support.atomic_write(self.firefox, APP_REGISTRATION, 0o600)

    def test_install_writes_the_cli_and_retires_the_old_host(self):
        self.seed()
        support.install(self.payloads(), self.journal)
        self.assertEqual(self.cli.read_bytes(), b'new cli')
        self.assertEqual(self.cli.stat().st_mode & 0o777, 0o755)
        self.assertFalse(self.old_host.exists())
        # Registrations are the app's to write.
        self.assertEqual(self.chrome.read_bytes(), OLD_REGISTRATION)
        self.assertFalse(self.firefox.exists())
        self.assertFalse((self.support / 'Microsoft Edge').exists())

    def test_a_failed_install_restores_the_cli_the_old_host_and_what_the_browsers_started(self):
        self.seed()
        support.install(self.payloads(), self.journal)
        self.app_registers()
        support.rollback(self.journal)
        self.assertEqual(self.cli.read_bytes(), b'old cli')
        self.assertEqual(self.old_host.read_bytes(), b'old host')
        self.assertEqual(self.old_host.stat().st_mode & 0o777, 0o750)
        self.assertEqual(self.chrome.read_bytes(), OLD_REGISTRATION)
        self.assertEqual(self.chrome.stat().st_mode & 0o777, 0o640)
        self.assertFalse(self.firefox.exists())
        self.assertFalse((self.support / 'Microsoft Edge').exists())
        support.rollback(self.journal)  # The shell trap may retry a helper rollback.

    def test_partial_install_failure_brings_the_old_host_back(self):
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
        self.assertEqual(self.old_host.read_bytes(), b'old host')
        self.assertEqual(self.cli.read_bytes(), b'old cli')

    def test_a_symlinked_old_host_comes_back_as_a_symlink(self):
        self.seed()
        self.old_host.unlink()
        original = self.root / 'previous-host'
        original.write_bytes(b'previous executable')
        self.old_host.symlink_to(original)
        support.install(self.payloads(), self.journal)
        self.assertFalse(self.old_host.is_symlink())
        self.assertEqual(original.read_bytes(), b'previous executable')
        support.rollback(self.journal)
        self.assertTrue(self.old_host.is_symlink())

    def test_a_first_install_has_nothing_to_retire(self):
        support.install(self.payloads(), self.journal)
        self.assertEqual(self.cli.read_bytes(), b'new cli')
        support.rollback(self.journal)
        self.assertFalse(self.cli.exists())
        self.assertFalse(self.old_host.exists())
        self.assertFalse(self.chrome.exists())


if __name__ == '__main__':
    unittest.main()
