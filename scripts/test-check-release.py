#!/usr/bin/env python3
"""Release evidence must not accept skipped jobs, stale commits or partial CI."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("check-release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseChecks(unittest.TestCase):
    def test_accepts_completed_run_for_exact_commit(self):
        self.assertEqual(release.release_run([
            {"headSha": "current", "status": "completed", "conclusion": "success", "databaseId": 42}
        ], "current"), 42)

    def test_rejects_absent_stale_pending_or_failed_runs(self):
        good = {"headSha": "current", "status": "completed", "conclusion": "success", "databaseId": 42}
        for runs in [[], [{**good, "headSha": "old"}], [{**good, "status": "in_progress"}],
                     [{**good, "conclusion": "failure"}], [{**good, "conclusion": "cancelled"}]]:
            with self.subTest(runs=runs), self.assertRaises(ValueError):
                release.release_run(runs, "current")

    def test_accepts_full_release_evidence(self):
        release.validate_jobs([{"name": name, "conclusion": "success"} for name in release.REQUIRED_JOBS])

    def test_every_required_job_must_run_and_pass(self):
        jobs = [{"name": name, "conclusion": "success"} for name in release.REQUIRED_JOBS]
        for index, job in enumerate(jobs):
            for state in ("skipped", "cancelled", "failure", None):
                with self.subTest(job=job["name"], state=state), self.assertRaises(ValueError):
                    release.validate_jobs(jobs[:index] + [{**job, "conclusion": state}] + jobs[index + 1:])
            with self.subTest(missing=job["name"]), self.assertRaises(ValueError):
                release.validate_jobs(jobs[:index] + jobs[index + 1:])

    def test_job_names_are_exact_not_substrings(self):
        with self.assertRaises(ValueError):
            release.validate_jobs([{"name": "fake " + name, "conclusion": "success"}
                                   for name in release.REQUIRED_JOBS])


if __name__ == "__main__":
    unittest.main()
