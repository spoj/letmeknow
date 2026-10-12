#!/usr/bin/env python3
"""Verify the reviewed release before publication follow-up or either deployment."""
import json, re, subprocess, sys

repo, run, tag, sha = sys.argv[1:]
if not (re.fullmatch(r"[\w.-]+/[\w.-]+", repo) and re.fullmatch(r"[1-9][0-9]*", run)
        and re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag)
        and re.fullmatch(r"[0-9a-f]{40}", sha)):
    sys.exit("expected repository, numeric run, vX.Y.Z tag and full commit SHA")


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", f"repos/{repo}/{path}"], text=True))


workflow = api("actions/workflows/release.yml")
selected = api(f"actions/runs/{run}")
if not (workflow["path"] == selected["path"] == ".github/workflows/release.yml"
        and selected["workflow_id"] == workflow["id"]
        and selected["repository"]["full_name"] == selected["head_repository"]["full_name"] == repo
        and selected["status"] == "completed" and selected["conclusion"] == "success"
        and selected["event"] == "push" and selected["head_branch"] == tag and selected["head_sha"] == sha):
    sys.exit("run is not the completed, published release for the reviewed repository/tag/commit")
reference = api(f"git/ref/tags/{tag}")["object"]
if reference["type"] == "tag":
    reference = api(f"git/tags/{reference['sha']}")["object"]
if reference["type"] != "commit" or reference["sha"] != sha:
    sys.exit("release tag no longer names the reviewed commit")
print(json.dumps({"repository": repo, "workflow": workflow["path"], "workflow_id": workflow["id"],
                  "tag": tag, "sha": sha, "run": int(run)}))
