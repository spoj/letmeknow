#!/usr/bin/env python3
"""Exercise both deployment gates with fake gh/ssh/scp; never connect to a host."""
import copy, io, json, os, pathlib, re, subprocess, sys, tarfile, tempfile, textwrap

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPO, TAG, SHA = "spoj/letmeknow", "v0.16.0", "a" * 40
RUN = {"name": "release", "path": ".github/workflows/release.yml", "workflow_id": 17,
       "repository": {"full_name": REPO}, "head_repository": {"full_name": REPO},
       "status": "completed", "conclusion": "success", "event": "push", "head_branch": TAG, "head_sha": SHA}
MOCK = r'''
import json, os, pathlib, shutil, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ["MOCK_LOG"], "a") as f:
    f.write(json.dumps([name, *sys.argv[1:]]) + "\n")
if name == "gh":
    if sys.argv[1] == "api":
        print(json.dumps(json.loads(os.environ["MOCK_METADATA"])[sys.argv[2]]))
    else:
        assert sys.argv[1:3] == ["run", "download"]
        assert sys.argv[sys.argv.index("--repo") + 1] == "spoj/letmeknow"
        artifact = sys.argv[sys.argv.index("--name") + 1]
        dest = pathlib.Path(sys.argv[sys.argv.index("--dir") + 1])
        dest.mkdir(parents=True, exist_ok=True)
        if artifact == "frontend":
            shutil.copy(os.environ["MOCK_FRONTEND"], dest / "frontend.tar.gz")
        else:
            assert artifact == "archive-x86_64-unknown-linux-musl"
            shutil.copy(os.environ["MOCK_ARCHIVE"], dest / "letmeknow-v0.16.0-x86_64-unknown-linux-musl.tar.gz")
elif name == "ssh" and "systemctl is-active" in sys.argv[-1]:
    prelude = 'systemctl() { [ "$MOCK_LITESTREAM" = "$1" ]; }; id() { return 0; }; test() { return 0; }; '
    sys.exit(subprocess.run(["sh", "-c", prelude + sys.argv[-1]]).returncode)
elif name == "scp" and sys.argv[-1].endswith("letmeknow.service"):
    assert "--web" not in pathlib.Path(sys.argv[-2]).read_text()
    assert "--domain relay.example.com" in pathlib.Path(sys.argv[-2]).read_text()
'''

pages = (ROOT / ".github/workflows/pages.yml").read_text()
script = textwrap.dedent(re.search(r"        run: \|\n((?:          .*\n)+)", pages)[1])
assert "release-run.py" in script
with tempfile.TemporaryDirectory(prefix="lmk-deploy-test-") as directory:
    tmp = pathlib.Path(directory)
    for name in ["gh", "ssh", "scp"]:
        path = tmp / name
        path.write_text(f"#!{sys.executable}\n" + MOCK)
        path.chmod(0o755)
    archive, frontend = tmp / "release.tar.gz", tmp / "frontend.tar.gz"
    for path, files in [(archive, [("release/letmeknow", b"not executable in this test"),
                                   ("release/letmeknow.service", (ROOT / "deploy/letmeknow.service").read_bytes())]),
                        (frontend, [("index.html", b"selected artifact")])]:
        with tarfile.open(path, "w:gz") as tar:
            for name, data in files:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    cases = [
        ("failed publication", {"conclusion": "failure"}, SHA, "disabled", False),
        ("incomplete publication", {"status": "in_progress"}, SHA, "disabled", False),
        ("copied workflow named release", {"workflow_id": 18, "path": ".github/workflows/copy.yml"}, SHA, "disabled", False),
        ("renamed canonical display label", {"name": "publish binaries"}, SHA, "disabled", True),
        ("wrong event", {"event": "workflow_dispatch"}, SHA, "disabled", False),
        ("wrong tag", {"head_branch": "v0.15.1"}, SHA, "disabled", False),
        ("wrong SHA", {"head_sha": "c" * 40}, SHA, "disabled", False),
        ("wrong repository", {"repository": {"full_name": "elsewhere/letmeknow"}}, SHA, "disabled", False),
        ("fork source", {"head_repository": {"full_name": "elsewhere/letmeknow"}}, SHA, "disabled", False),
        ("moved tag", {}, "d" * 40, "disabled", False),
        ("active replication", {}, SHA, "is-active", True),
        ("enabled replication", {}, SHA, "is-enabled", True),
        ("reviewed release", {}, SHA, "disabled", True),
    ]
    for index, (name, changes, tag_sha, litestream, accepted) in enumerate(cases):
        selected = {**copy.deepcopy(RUN), **changes}
        metadata = {
            f"repos/{REPO}/actions/workflows/release.yml": {"id": 17, "path": ".github/workflows/release.yml"},
            f"repos/{REPO}/actions/runs/123": selected,
            f"repos/{REPO}/git/ref/tags/{TAG}": {"object": {"type": "tag", "sha": "b" * 40}},
            f"repos/{REPO}/git/tags/{'b' * 40}": {"object": {"type": "commit", "sha": tag_sha}},
        }
        for mode in ["backend", "pages"]:
            work = tmp / f"{index}-{mode}"
            work.mkdir()
            (work / "deploy").symlink_to(ROOT / "deploy", target_is_directory=True)
            log = work / "calls.jsonl"
            log.write_text("")
            env = {**os.environ, "PATH": str(tmp) + os.pathsep + os.environ["PATH"],
                   "MOCK_LOG": str(log), "MOCK_ARCHIVE": str(archive), "MOCK_FRONTEND": str(frontend),
                   "MOCK_METADATA": json.dumps(metadata), "MOCK_LITESTREAM": litestream,
                   "GITHUB_REPOSITORY": REPO, "RELEASE_RUN": "123", "RELEASE_TAG": TAG, "RELEASE_SHA": SHA,
                   "GITHUB_STEP_SUMMARY": str(work / "summary.md")}
            command = (["sh", str(ROOT / "deploy/deploy.sh"), "mock-host", "relay.example.com", REPO, "123", TAG, SHA]
                       if mode == "backend" else ["bash", "-eu", "-c", script])
            result = subprocess.run(command, cwd=work, env=env, capture_output=True, text=True, timeout=10)
            ok = accepted and (mode == "pages" or litestream == "disabled")
            assert (result.returncode == 0) == ok, (name, mode, result.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            downloads = [call for call in calls if call[:3] == ["gh", "run", "download"]]
            uploads = [call for call in calls if call[0] == "scp"]
            assert len(downloads) == int(accepted), calls
            assert len(uploads) == (2 if ok and mode == "backend" else 0), calls
            if ok:
                assert SHA in result.stdout and TAG in result.stdout and '"workflow_id": 17' in result.stdout
                if mode == "backend":
                    assert uploads[0][-1] == "mock-host:/usr/local/bin/letmeknow.new"
                    assert uploads[1][-1] == "mock-host:/etc/systemd/system/letmeknow.service"
                else:
                    assert (work / "site/index.html").read_bytes() == b"selected artifact"
                    assert '"workflow_id": 17' in (work / "summary.md").read_text()
            print(f"ok - {mode}: {name}, deployment={ok}")
