#!/usr/bin/env python3
import datetime, hashlib, json, pathlib, subprocess, sys

binary, config, tag, run, sha = sys.argv[1:]
binary = pathlib.Path(binary).resolve()
backend = json.loads(pathlib.Path(config).read_text())
result = subprocess.run([
    str(binary), "check-service", "--membership", f"{backend['membershipKey']}@{backend['relay']}",
    "--expect-version", tag[1:], "--expect-run", run, "--expect-sha", sha,
], capture_output=True, text=True, timeout=35)
if result.returncode:
    sys.exit(result.stderr.strip() or "pinned backend check failed")
expected = {"ok": True, "version": tag[1:], "run": run, "sha": sha}
if json.loads(result.stdout) != expected:
    sys.exit("unexpected pinned backend check result")
with binary.open("rb") as file:
    digest = hashlib.file_digest(file, "sha256").hexdigest()
print(json.dumps({**expected, "backend": backend, "checker_sha256": digest,
                  "checked_at": datetime.datetime.now(datetime.UTC).isoformat()}))
