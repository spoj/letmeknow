#!/usr/bin/env python3
"""Execute rollout shells with structured gh metadata and a backend /health double."""
import copy, io, json, os, pathlib, re, subprocess, sys, tarfile, tempfile, textwrap

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERSION = re.search(r'^version = "(.+)"', (ROOT / "Cargo.toml").read_text(), re.M).group(1)
REPO, TAG, SHA = "spoj/letmeknow", f"v{VERSION}", "a" * 40
BACKEND = {"domain": "relay.example.com", "directory": {"key": "11" * 32, "addrs": ["relay.example.com:7843"],
                                                     "relay": "https://relay.example.com", "relays": ["https://relay.example.com"]}}
RUN = {"name": "release", "path": ".github/workflows/release.yml", "workflow_id": 17,
       "repository": {"full_name": REPO}, "head_repository": {"full_name": REPO},
       "status": "completed", "conclusion": "success", "event": "push", "head_branch": TAG, "head_sha": SHA}
MOCK = r'''
import json, os, pathlib, shutil, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ["MOCK_LOG"], "a") as f:
    f.write(json.dumps([name, *sys.argv[1:]]) + "\n")
if name == "git":
    assert sys.argv[1:] == ["rev-parse", "HEAD"]
    print("a" * 40)
elif name == "gh":
    if sys.argv[1] == "api":
        print(json.dumps(json.loads(os.environ["MOCK_METADATA"])[sys.argv[2]]))
    else:
        assert sys.argv[1:3] == ["run", "download"]
        assert sys.argv[sys.argv.index("--repo") + 1] == "spoj/letmeknow"
        assert sys.argv[3] == "123"
        artifact = sys.argv[sys.argv.index("--name") + 1]
        dest = pathlib.Path(sys.argv[sys.argv.index("--dir") + 1])
        dest.mkdir(parents=True, exist_ok=True)
        if artifact == "frontend":
            shutil.copy(os.environ["MOCK_FRONTEND"], dest / "frontend.tar.gz")
        else:
            assert artifact == "archive-x86_64-unknown-linux-musl"
            shutil.copy(os.environ["MOCK_ARCHIVE"], dest / f"letmeknow-{os.environ['RELEASE_TAG']}-x86_64-unknown-linux-musl.tar.gz")
elif name == "ssh" and "systemctl is-active" in sys.argv[-1]:
    prelude = 'systemctl() { [ "$MOCK_LITESTREAM" = "$1" ]; }; id() { return 0; }; test() { return 0; }; '
    sys.exit(subprocess.run(["sh", "-c", prelude + sys.argv[-1]]).returncode)
elif name == "scp" and sys.argv[-1].endswith("letmeknow.service"):
    assert "--web" not in pathlib.Path(sys.argv[-2]).read_text()
    assert "--domain relay.example.com" in pathlib.Path(sys.argv[-2]).read_text()
elif name == "curl" and sys.argv[-1].endswith("/.well-known/letmeknow.json"):
    assert sys.argv[-1] == "https://relay.example.com/.well-known/letmeknow.json"
    print(os.environ["MOCK_DIRECTORY"])
elif name == "curl":
    assert sys.argv[-1] == "https://relay.example.com/health"
    if os.environ["MOCK_PROBE"] == "fail":
        sys.exit(22)
    version = "0.15.1" if os.environ["MOCK_PROBE"] == "stale" else os.environ["RELEASE_TAG"].removeprefix("v")
    print(json.dumps({"version": version, "membership": "11" * 32}))
'''

pages = (ROOT / ".github/workflows/pages.yml").read_text()
scripts = [textwrap.dedent(block) for block in re.findall(r"        run: \|\n((?:          .*\n)+)", pages)]
assert len(scripts) == 2
assert all("release-run.py" in script and "check-backend.py" in script for script in scripts)
verify, deploy = pages.split("  deploy:\n", 1)
assert "environment:" not in verify and "needs: verify" in deploy and "environment:" in deploy
assert "artifact-ids: ${{ needs.verify.outputs.config_artifact }}" in deploy
assert "config_artifact: ${{ steps.config.outputs.artifact-id }}" in verify
assert deploy.index("Recheck the backend") < deploy.index("actions/deploy-pages@")

with tempfile.TemporaryDirectory(prefix="lmk-deploy-test-") as directory:
    tmp = pathlib.Path(directory)
    executable = (f"#!{sys.executable}\n" + MOCK).encode()
    for name in ["gh", "ssh", "scp", "git", "curl"]:
        path = tmp / name
        path.write_bytes(executable)
        path.chmod(0o755)
    archive = tmp / "release.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, data in [("release/letmeknow", executable),
                           ("release/letmeknow.service", (ROOT / "deploy/letmeknow.service").read_bytes()),
                           ("release/backend.json", json.dumps(BACKEND).encode())]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if name.endswith("/letmeknow") else 0o644
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
        ("backend unreachable", {}, SHA, "disabled", True),
        ("backend runs another version", {}, SHA, "disabled", True),
        ("frontend backend mismatch", {}, SHA, "disabled", True),
        ("wrong installation domain", {}, SHA, "disabled", True),
    ]
    for index, (name, changes, tag_sha, litestream, accepted) in enumerate(cases):
        selected = {**copy.deepcopy(RUN), **changes}
        metadata = {
            f"repos/{REPO}/actions/workflows/release.yml": {"id": 17, "path": ".github/workflows/release.yml"},
            f"repos/{REPO}/actions/runs/123": selected,
            f"repos/{REPO}/git/ref/tags/{TAG}": {"object": {"type": "tag", "sha": "b" * 40}},
            f"repos/{REPO}/git/tags/{'b' * 40}": {"object": {"type": "commit", "sha": tag_sha}},
        }
        frontend = tmp / f"frontend-{index}.tar.gz"
        frontend_config = copy.deepcopy(BACKEND)
        if name == "frontend backend mismatch":
            frontend_config["directory"]["key"] = "22" * 32
        with tarfile.open(frontend, "w:gz") as tar:
            for file, data in [("index.html", b"selected artifact"), ("backend.json", json.dumps(frontend_config).encode())]:
                info = tarfile.TarInfo(file)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        for mode in ["backend", "pages-before", "pages-after"]:
            work = tmp / f"{index}-{mode}"
            work.mkdir()
            (work / "deploy").symlink_to(ROOT / "deploy", target_is_directory=True)
            # Simulate downloading the exact config artifact ID prepared before approval; do not reselect a release artifact.
            (work / "config").mkdir()
            (work / "config/backend.json").write_text(json.dumps(BACKEND))
            log = work / "calls.jsonl"
            log.write_text("")
            probe = {"backend unreachable": "fail", "backend runs another version": "stale"}.get(name, "ok")
            env = {**os.environ, "PATH": str(tmp) + os.pathsep + os.environ["PATH"],
                   "MOCK_LOG": str(log), "MOCK_ARCHIVE": str(archive), "MOCK_FRONTEND": str(frontend),
                   "MOCK_METADATA": json.dumps(metadata), "MOCK_LITESTREAM": litestream, "MOCK_PROBE": probe,
                   "MOCK_DIRECTORY": json.dumps(BACKEND["directory"]),
                   "GITHUB_REPOSITORY": REPO, "RELEASE_RUN": "123", "RELEASE_TAG": TAG, "RELEASE_SHA": SHA,
                   "GITHUB_STEP_SUMMARY": str(work / "summary.md")}
            domain = "wrong.example.com" if name == "wrong installation domain" else "relay.example.com"
            command = (["sh", str(ROOT / "deploy/deploy.sh"), "mock-host", domain, REPO, "123", TAG, SHA]
                       if mode == "backend" else ["bash", "-eu", "-c", scripts[mode == "pages-after"] + "\nprintf ready >pages-authorized\n"])
            result = subprocess.run(command, cwd=work, env=env, capture_output=True, text=True, timeout=10)
            preflight = accepted and (mode != "backend" or (litestream == "disabled" and name != "wrong installation domain"))
            preflight = preflight and (mode != "pages-before" or name != "frontend backend mismatch")
            ok = preflight and probe == "ok"
            assert (result.returncode == 0) == ok, (name, mode, result.stdout, result.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            downloads = [call for call in calls if call[:3] == ["gh", "run", "download"]]
            uploads = [call for call in calls if call[0] == "scp"]
            probes = [call for call in calls if call[0] == "curl"]
            assert len(downloads) == (0 if mode == "pages-after" else int(accepted) * (2 if mode == "pages-before" else 1)), calls
            assert len(uploads) == (2 if preflight and mode == "backend" else 0), calls
            assert len(probes) == (2 if ok else int(preflight)), calls
            if mode != "backend":
                assert (work / "pages-authorized").exists() == ok
            if ok:
                assert SHA in result.stdout and TAG in result.stdout and '"workflow_id": 17' in result.stdout
                evidence = json.loads(result.stdout.splitlines()[-1])
                assert evidence == {"version": VERSION, "membership": BACKEND["directory"]["key"], "domain": BACKEND["domain"]}
                if mode == "backend":
                    assert uploads[0][-1] == "mock-host:/usr/local/bin/letmeknow.new"
                    assert uploads[1][-1] == "mock-host:/etc/systemd/system/letmeknow.service"
                    assert calls.index(probes[0]) > max(i for i, call in enumerate(calls) if call[0] == "ssh")
                else:
                    assert '"membership"' in (work / "summary.md").read_text()
                    if mode == "pages-before":
                        assert (work / "site/index.html").read_bytes() == b"selected artifact"
            print(f"ok - {mode}: {name}, deployment={ok}")

# deploy/release.sh, from a clean main pushed to a bare origin: the commit carries the version and any pins, and the tag is pushed.
RELEASE_MOCK = r"""
import pathlib, sys
name = pathlib.Path(sys.argv[0]).name
if name == "gh" and sys.argv[1:3] == ["repo", "view"]:
    print("spoj/letmeknow")
elif name == "gh" and sys.argv[1:3] == ["run", "list"]:
    print(123)
elif name == "npm":
    print(sys.argv[2].rsplit("@", 1)[1])
"""
PIN_FILES = ["README.md", "SKILL.md", "web/src/index.html", "web/src/main.ts", "AGENTS.md"]


def git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def release(tmp, before, version, mock_dir):
    tmp = tmp / f"{before}-{version}"
    tmp.mkdir()
    origin, work = tmp / "origin.git", tmp / "work"
    git("init", "-q", "--bare", "-b", "main", str(origin), cwd=tmp)
    (work / "deploy").mkdir(parents=True)
    (work / "web/src").mkdir(parents=True)
    (work / "deploy/release.sh").write_bytes((ROOT / "deploy/release.sh").read_bytes())
    (work / "deploy/release-run.py").write_text("")
    (work / "Cargo.toml").write_text(f'[workspace.package]\nversion = "{before}"\n')
    for name in PIN_FILES:
        (work / name).write_text(f"@letmeknow/cli@{before.rsplit('.', 1)[0]}\n")
    git("init", "-q", "-b", "main", cwd=work)
    git("config", "user.name", "test", cwd=work)
    git("config", "user.email", "test@example.com", cwd=work)
    git("remote", "add", "origin", str(origin), cwd=work)
    git("add", "-A", cwd=work)
    git("commit", "-qm", "before", cwd=work)
    git("push", "-q", "origin", "main", cwd=work)
    notes = tmp / "notes.md"
    notes.write_text("notes\n")
    env = {**os.environ, "PATH": str(mock_dir) + os.pathsep + os.environ["PATH"]}
    result = subprocess.run(["sh", "deploy/release.sh", version, str(notes)], cwd=work, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, (version, result.stdout, result.stderr)
    minor = version.rsplit(".", 1)[0]
    patch = version.endswith(".0")
    pinned = minor if patch else before.rsplit(".", 1)[0]
    pins = {name: git("show", f"main:{name}", cwd=origin) for name in PIN_FILES}
    assert f'version = "{version}"' in git("show", "main:Cargo.toml", cwd=origin), version
    assert pins == {name: f"@letmeknow/cli@{pinned}\n" for name in PIN_FILES}, pins
    assert ("MINOR = \"" + minor + "\"" in result.stdout) == patch, result.stdout
    assert f"v{version}" in git("tag", cwd=origin).split(), version
    print(f"ok - release {version} from {before}: pins at {pinned}")


with tempfile.TemporaryDirectory(prefix="lmk-release-test-") as directory:
    tmp = pathlib.Path(directory)
    mock_dir = tmp / "bin"
    mock_dir.mkdir()
    for name in ["gh", "npm", "cargo", "sleep"]:
        path = mock_dir / name
        path.write_text(f"#!{sys.executable}\n" + RELEASE_MOCK)
        path.chmod(0o755)
    release(tmp, "0.16.1", "0.17.0", mock_dir)
    release(tmp, "0.16.1", "0.16.2", mock_dir)
    release(tmp, "0.17.0", "0.17.0", mock_dir)
