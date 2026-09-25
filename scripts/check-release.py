#!/usr/bin/env python3
"""Require full CI evidence for the exact committed release candidate."""
import json
from pathlib import Path
import subprocess
import sys

REQUIRED_JOBS = (
    "build & test (ubuntu-latest)",
    "build & test (macos-latest)",
    "build & test (windows-latest)",
    "linux .deb/.rpm ship the native host",
    "linux real-clipboard & keychain smoke",
    "dependency audit",
)


def release_run(runs, commit):
    if not runs:
        raise ValueError("Run CI with workflow_dispatch for this commit before release.")
    run = runs[0]
    if run.get("headSha") != commit:
        raise ValueError("CI evidence belongs to a different commit.")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ValueError("The latest full CI run for this commit must finish successfully.")
    return run["databaseId"]


def validate_jobs(jobs):
    for name in REQUIRED_JOBS:
        matches = [job for job in jobs if job.get("name") == name]
        if len(matches) != 1 or matches[0].get("conclusion") != "success":
            raise ValueError(f"Missing successful release verification: {name}")


def main():
    root = Path(__file__).resolve().parent.parent

    def output(*args):
        return subprocess.check_output(args, cwd=root, text=True).strip()

    if output("git", "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("Release requires a clean committed checkout.")
    commit = output("git", "rev-parse", "HEAD")
    # Push CI deliberately skips packaging and OS smoke tests. A release must
    # use a manual full run; success with skipped jobs is insufficient evidence.
    runs = json.loads(output(
        "gh", "run", "list", "--workflow", "ci.yml", "--commit", commit,
        "--event", "workflow_dispatch", "--limit", "1",
        "--json", "databaseId,status,conclusion,headSha",
    ))
    run_id = release_run(runs, commit)
    validate_jobs(json.loads(output("gh", "run", "view", str(run_id), "--json", "jobs"))["jobs"])
    print(f"Coordinated release checks passed for {commit} (CI run {run_id}).")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Release blocked: {error}", file=sys.stderr)
        sys.exit(1)
