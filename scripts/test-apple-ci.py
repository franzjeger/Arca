#!/usr/bin/env python3
"""The Apple CI gate must reject a successful build that ran no Swift tests."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parent.parent


@unittest.skipUnless(os.name == 'posix', 'Apple build driver requires a POSIX shell')
class AppleGateTests(unittest.TestCase):
    def run_gate(self, summary, code=0):
        with tempfile.TemporaryDirectory(prefix='arca-apple-gate-') as directory:
            root = Path(directory)
            (root / 'xcodegen').write_text('#!/bin/sh\nexit 0\n')
            (root / 'xcodebuild').write_text(
                '#!/bin/sh\ncase " $* " in *" test "*) printf "%s\\n" "$TEST_SUMMARY";; esac\nexit "$TEST_BUILD_STATUS"\n')
            for name in ('xcodegen', 'xcodebuild'):
                (root / name).chmod(0o755)
            env = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                   'RUNNER_TEMP': str(root), 'ARCA_APPLE_BUILD_ROOT': str(root / 'build'),
                   'TEST_SUMMARY': summary, 'TEST_BUILD_STATUS': str(code)}
            return subprocess.run(['bash', str(REPO / 'scripts/build-apple-ci.sh')],
                                  env=env, text=True, capture_output=True)

    def test_nonzero_test_summary_passes(self):
        result = self.run_gate('Executed 13 tests, with 0 failures')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_zero_or_absent_test_summary_fails(self):
        for summary in ('Executed 0 tests, with 0 failures', ''):
            with self.subTest(summary=summary):
                result = self.run_gate(summary)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('NO TEST SUMMARY', result.stdout)

    def test_build_failure_is_not_hidden_by_test_summary(self):
        result = self.run_gate('Executed 13 tests, with 0 failures', 65)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
