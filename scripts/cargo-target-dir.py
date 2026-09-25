#!/usr/bin/env python3
"""Resolve Cargo's actual output directory, including user config/env overrides."""
import json
from pathlib import Path
import subprocess

repo = Path(__file__).resolve().parent.parent
metadata = subprocess.check_output(
    ["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=repo, text=True
)
print(json.loads(metadata)["target_directory"])
