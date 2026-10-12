#!/usr/bin/env python3
"""Require the backend a release's backend.json names to report that release's version and public service key."""
import json, pathlib, subprocess, sys

config, tag = sys.argv[1:]
backend = json.loads(pathlib.Path(config).read_text())
expected = {"version": tag.removeprefix("v"), "membership": backend["membershipKey"]}
# Retries cover a service that is still starting after its restart.
health = subprocess.run(["curl", "-fsS", "--max-time", "10", "--retry", "6", "--retry-all-errors", "--retry-delay", "5",
                         backend["relay"] + "/health"], capture_output=True, text=True)
if health.returncode:
    sys.exit(f"backend health check failed: {health.stderr.strip()}")
reported = json.loads(health.stdout)
if {key: reported.get(key) for key in expected} != expected:
    sys.exit(f"backend reports {health.stdout.strip()}, expected {json.dumps(expected)}")
print(json.dumps({**expected, "relay": backend["relay"]}))
