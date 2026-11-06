#!/usr/bin/env python3
"""Scan history and a private, non-ignored source snapshot; never build caches or .env files."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--gitleaks", default="gitleaks")
args = parser.parse_args()
root = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
scanner = shutil.which(args.gitleaks)
if not scanner:
    raise SystemExit("Install pinned gitleaks v8.30.1 first.")
# --redact prevents credential values from appearing in logs; no raw report is published.
subprocess.run([scanner, "git", "--redact", "--no-banner", "--log-opts=--all", "."], cwd=root, check=True)
with tempfile.TemporaryDirectory(prefix="scamguard-secret-scan-") as directory:
    destination = Path(directory)
    paths = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root).split(b"\0")
    for raw in paths:
        if not raw:
            continue
        relative = Path(raw.decode())
        source = root / relative
        if not source.resolve().is_relative_to(root):
            raise SystemExit("Refusing an out-of-repository symlink during source scanning.")
        if source.is_file():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    subprocess.run([scanner, "dir", "--redact", "--no-banner", str(destination)], cwd=root, check=True)
