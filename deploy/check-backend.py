#!/usr/bin/env python3
"""Require the backend a release's backend.json names to report that release's version and public service key, and to publish the directory it names."""
import json, pathlib, subprocess, sys

config, tag = sys.argv[1:]
backend = json.loads(pathlib.Path(config).read_text())
domain, directory = backend["domain"], backend["directory"]
expected = {"version": tag.removeprefix("v"), "membership": directory["key"]}


def fetch(path):
    # Retries cover a service that is still starting after its restart.
    result = subprocess.run(["curl", "-fsS", "--max-time", "10", "--retry", "6", "--retry-all-errors", "--retry-delay", "5",
                             f"https://{domain}{path}"], capture_output=True, text=True)
    if result.returncode:
        sys.exit(f"backend check of {path} failed: {result.stderr.strip()}")
    return result.stdout


reported = json.loads(fetch("/health"))
if {key: reported.get(key) for key in expected} != expected:
    sys.exit(f"backend reports {json.dumps(reported)}, expected {json.dumps(expected)}")
if json.loads(fetch("/.well-known/letmeknow.json")) != directory:
    sys.exit(f"{domain} publishes another directory than {config} names")
print(json.dumps({**expected, "domain": domain}))
