#!/usr/bin/env python3
"""Exercise installation, validation and rollback using isolated fake files."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("installer", Path(__file__).with_name("install-linux.py"))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="arca-install-test-")
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        home = root / 'home with spaces'
        self.paths = installer.Locations(home, home / 'data', home / 'config')
        (self.paths.config / 'chromium').mkdir(parents=True)
        self.paths.lib.mkdir(parents=True)
        self.paths.app.write_bytes(b'old desktop')
        self.paths.host.write_bytes(b'old native host')
        self.paths.vault.parent.mkdir(parents=True)
        self.paths.vault.write_bytes(b'current encrypted vault')
        self.snapshot = installer.capture(self.paths, root / 'snapshot')
        self.app = root / 'candidate-app'; self.app.write_bytes(b'new desktop')
        self.host = root / 'candidate-host'; self.host.write_bytes(b'new host')
        self.info = {"version": "0.6.0", "build": "a" * 12, "commit": "a" * 40}
        self.process = Mock(pid=123)
        self.response = {"version": "0.6.0", "app_version": "0.6.0", "app_commit": "a" * 40}

    def mocks(self):
        return patch.multiple(installer,
            build_info=Mock(return_value=self.info),
            stop_installed=Mock(return_value=True),
            launch=Mock(return_value=self.process),
            verify_running=Mock(return_value=self.response),
            installed_processes=Mock(return_value=[123]))

    def install(self):
        with self.mocks(), patch.object(installer.subprocess, 'check_output', return_value='a' * 40), \
             patch.object(installer.subprocess, 'run', return_value=Mock(returncode=0)):
            return installer.apply(self.paths, self.snapshot, self.app, self.host, True)

    def test_install_records_verified_build_and_stable_native_host(self):
        result = self.install()
        self.assertEqual(result['commit'], 'a' * 40)
        self.assertEqual(result['sha256'], installer.sha(self.app))
        self.assertTrue(result['singleInstanceVerified'])
        manifest_path, _ = self.paths.browser_manifests()[0]
        native = json.loads(manifest_path.read_text())
        self.assertEqual(native['path'], str(self.paths.host))
        self.assertEqual(len(native['allowed_origins'][0].split('//')[1].rstrip('/')), 32)
        self.assertEqual(self.paths.host.read_bytes(), b'new host')
        self.assertEqual(self.paths.vault.read_bytes(), b'current encrypted vault')
        previous = Path(result['previousInstall'])
        self.assertEqual((previous / 'vault-before-update.vault').stat().st_mode & 0o777, 0o600)

    def test_startup_failure_restores_every_installation_file(self):
        with self.mocks(), patch.object(installer.subprocess, 'check_output', return_value='a' * 40), \
             patch.object(installer, 'verify_running', side_effect=RuntimeError('startup failed')):
            with self.assertRaisesRegex(RuntimeError, 'startup failed'):
                installer.apply(self.paths, self.snapshot, self.app, self.host, True)
        self.assertEqual(self.paths.app.read_bytes(), b'old desktop')
        self.assertEqual(self.paths.host.read_bytes(), b'old native host')
        self.assertFalse(self.paths.manifest.exists())
        self.assertFalse(self.paths.launcher.exists())
        self.assertEqual(self.paths.vault.read_bytes(), b'current encrypted vault')

    def test_mismatched_artifacts_refuse_before_closing_the_app(self):
        with patch.object(installer, 'build_info', side_effect=[self.info, {**self.info, 'commit': 'b' * 40}]), \
             patch.object(installer, 'stop_installed') as stop:
            with self.assertRaisesRegex(RuntimeError, 'different source'):
                installer.apply(self.paths, self.snapshot, self.app, self.host)
            stop.assert_not_called()
        self.assertEqual(self.paths.app.read_bytes(), b'old desktop')

    def test_write_failure_rolls_back_a_partially_written_installation(self):
        write = installer.atomic_write
        failed = False
        def fail_once(path, data, mode=0o600):
            nonlocal failed
            if path == self.paths.host and not failed:
                failed = True
                raise OSError('simulated write failure')
            return write(path, data, mode)
        with patch.object(installer, 'atomic_write', side_effect=fail_once):
            with self.assertRaisesRegex(OSError, 'simulated write failure'):
                self.install()
        self.assertEqual(self.paths.app.read_bytes(), b'old desktop')
        self.assertEqual(self.paths.host.read_bytes(), b'old native host')
        self.assertFalse(self.paths.pending.exists())

    def test_interrupted_update_can_recover_without_a_new_install_manifest(self):
        previous = self.paths.lib / 'previous' / 'interrupted'
        previous.parent.mkdir()
        installer.shutil.copytree(self.snapshot, previous)
        installer.write_json(self.paths.pending, {'previousInstall': str(previous)})
        self.paths.app.write_bytes(b'partially installed app')
        with patch.object(installer, 'stop_installed', return_value=False):
            installer.rollback(self.paths)
        self.assertEqual(self.paths.app.read_bytes(), b'old desktop')
        self.assertEqual(self.paths.host.read_bytes(), b'old native host')
        self.assertFalse(self.paths.pending.exists())

    def test_concurrent_install_change_is_not_overwritten(self):
        self.paths.app.write_bytes(b'another update')
        with self.mocks(), patch.object(installer.subprocess, 'check_output', return_value='a' * 40):
            with self.assertRaisesRegex(RuntimeError, 'changed during the build'):
                installer.apply(self.paths, self.snapshot, self.app, self.host)
        self.assertEqual(self.paths.app.read_bytes(), b'another update')

    def test_rollback_preserves_vault_edits_made_after_installation(self):
        self.install()
        self.paths.vault.write_bytes(b'new user data')
        with patch.object(installer, 'stop_installed', return_value=False):
            installer.rollback(self.paths)
        self.assertEqual(self.paths.app.read_bytes(), b'old desktop')
        self.assertEqual(self.paths.host.read_bytes(), b'old native host')
        self.assertEqual(self.paths.vault.read_bytes(), b'new user data')

    def test_damaged_rollback_is_rejected_before_replacing_files(self):
        (self.snapshot / '0').write_bytes(b'corrupt backup')
        self.paths.app.write_bytes(b'currently working app')
        with self.assertRaisesRegex(RuntimeError, 'checksum'):
            installer.restore_files(self.paths, self.snapshot)
        self.assertEqual(self.paths.app.read_bytes(), b'currently working app')

    def test_legacy_cache_host_is_preserved_before_a_new_build(self):
        self.paths.host.unlink()
        cache = Path(self.directory.name) / 'cargo-cache-host'
        cache.write_bytes(b'old cached host')
        path, _ = self.paths.browser_manifests()[0]
        installer.write_json(path, {'path': str(cache), 'name': installer.HOST_NAME})
        snapshot = installer.capture(self.paths, Path(self.directory.name) / 'legacy-snapshot')
        cache.write_bytes(b'new build overwrites cache')
        installer.restore_files(self.paths, snapshot)
        self.assertEqual(self.paths.host.read_bytes(), b'old cached host')
        self.assertEqual(json.loads(path.read_text())['path'], str(self.paths.host))

    def test_a_handshake_from_the_previous_process_cannot_pass_verification(self):
        response = {**self.response, 'app_connected': True, 'app_pid': 122}
        process = Mock(pid=123); process.poll.return_value = None
        with patch.object(installer, 'native_hello', return_value=response), \
             patch.object(installer.time, 'monotonic', side_effect=[0, 1, 31]), patch.object(installer.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'Could not verify'):
                installer.verify_running(self.paths, process, self.info)


if __name__ == '__main__':
    unittest.main()
