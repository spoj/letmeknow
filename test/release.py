#!/usr/bin/env python3
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GIT = shutil.which("git")
FILES = ["Cargo.toml", "Cargo.lock", "README.md", "SKILL.md", "AGENTS.md", "web/src/index.html",
         "deploy/release.sh", "deploy/release-run.py", "deploy/version-pins.py"]
MOCK = r'''
import json, os, pathlib, subprocess, sys, tomllib
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with open(os.environ["MOCK_LOG"], "a") as log:
    log.write(json.dumps([name, *args]) + "\n")
real_git = os.environ["REAL_GIT"]
if name == "git":
    if "push" in args:
        assert not any(arg.startswith("--force") or arg.startswith("+") for arg in args)
        sys.exit(1 if "-C" in args and os.environ.get("MOCK_PI_PUSH_FAIL") else 0)
    sys.exit(subprocess.run([real_git, *args]).returncode)
elif name == "cargo":
    assert args == ["update", "-w", "--offline"]
    version = tomllib.loads(pathlib.Path("Cargo.toml").read_text())["workspace"]["package"]["version"]
    pathlib.Path("Cargo.lock").write_text("fixture lock " + version + "\n")
elif name == "node":
    script, action, version, expected_head = args
    assert pathlib.Path(script).name == "pin.mjs"
    repo = pathlib.Path(script).parent.parent
    if os.environ.get("MOCK_PREFLIGHT_FAIL"):
        sys.exit(1)
    assert subprocess.check_output([real_git, "-C", str(repo), "branch", "--show-current"], text=True).strip() == "main"
    assert not subprocess.check_output([real_git, "-C", str(repo), "status", "--porcelain"], text=True)
    assert subprocess.check_output([real_git, "-C", str(repo), "rev-parse", "HEAD"], text=True).strip() == expected_head
    if action == "set":
        minor = ".".join(version.split(".")[:2])
        for file in ["README.md", "extensions/letmeknow.ts"]:
            path = repo / file
            path.write_text(path.read_text().replace("0.15", minor))
        if subprocess.check_output([real_git, "-C", str(repo), "diff", "--name-only"], text=True):
            subprocess.check_call([real_git, "-C", str(repo), "commit", "-qam", "Release: fixture pin"])
    else:
        assert action == "preflight"
elif name == "npm":
    assert args == ["view", "@letmeknow/cli@" + os.environ["VERSION"], "version", "--prefer-online", "--registry=https://registry.npmjs.org"]
    print(os.environ.get("MOCK_PACKAGE", os.environ["VERSION"]))
    sys.exit(int(os.environ.get("MOCK_NPM_EXIT", "0")))
elif name == "gh":
    repo, version = "spoj/letmeknow", os.environ["VERSION"]
    sha = subprocess.check_output([real_git, "rev-parse", "HEAD"], text=True).strip()
    if args[:2] == ["repo", "view"]:
        print(repo)
    elif args[:2] == ["run", "list"]:
        print(123)
    elif args[:2] == ["run", "watch"]:
        if os.environ.get("MOCK_PI_COMMIT_DURING_WAIT"):
            pi = pathlib.Path(os.environ["LETMEKNOW_PI_REPO"])
            (pi / "unrelated").write_text("preserve new work during publication\n")
            subprocess.check_call([real_git, "-C", str(pi), "add", "unrelated"])
            subprocess.check_call([real_git, "-C", str(pi), "commit", "-qm", "Fixture: during workflow wait"])
        sys.exit(int(os.environ.get("MOCK_WATCH_FAILURE", "0")))
    elif args[:2] == ["release", "edit"]:
        pass
    elif args[0] == "api":
        path = args[1]
        if path.endswith("actions/workflows/release.yml"):
            result = {"id": 17, "path": ".github/workflows/release.yml"}
        elif path.endswith("actions/runs/123"):
            result = {"workflow_id": 17, "path": ".github/workflows/release.yml", "repository": {"full_name": repo},
                      "head_repository": {"full_name": repo}, "status": "completed", "conclusion": "success",
                      "event": "push", "head_branch": "v" + version, "head_sha": sha}
            result.update(json.loads(os.environ.get("MOCK_METADATA", "{}")))
        else:
            assert path == f"repos/{repo}/git/ref/tags/v{version}"
            result = {"object": {"type": "commit", "sha": os.environ.get("MOCK_TAG_SHA", sha)}}
        print(json.dumps(result))
    else:
        raise AssertionError(args)
else:
    assert name == "sleep"
'''


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="lmk-release-")
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.app, self.pi, self.bin = [self.root / name for name in ("app", "pi", "bin")]
        for directory in (self.app, self.pi, self.bin):
            directory.mkdir()
        for name in FILES:
            dest = self.app / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        subprocess.run([sys.executable, "deploy/version-pins.py", "set", "0.15.1"], cwd=self.app, check=True)
        (self.app / "Cargo.lock").write_text("fixture lock 0.15.1\n")
        (self.app / "existing.rs").write_text("preserve existing app code\n")
        (self.pi / "scripts").mkdir()
        (self.pi / "scripts/pin.mjs").write_text("mocked only at the release boundary\n")
        (self.pi / "extensions").mkdir()
        (self.pi / "extensions/letmeknow.ts").write_text('const MINOR = "0.15";\nconst existing = true;\n')
        (self.pi / "README.md").write_text("stable 0.15.x and cached stable 0.15.x\n")
        for repo in (self.app, self.pi):
            self.git(repo, "init", "-b", "main")
            self.git(repo, "config", "user.name", "Release test")
            self.git(repo, "config", "user.email", "test@example.invalid")
            self.git(repo, "config", "commit.gpgsign", "false")
            self.git(repo, "config", "core.hooksPath", str(self.root / "no-hooks"))
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-qm", "Fixture: existing changes")
            self.git(repo, "remote", "add", "origin", "https://invalid.example/no-network")
        self.log = self.root / "calls"
        self.log.write_text("")
        self.notes = self.root / "notes"
        self.notes.write_text("reviewed notes\n")
        for name in ("git", "gh", "npm", "cargo", "node", "sleep"):
            path = self.bin / name
            path.write_text(f"#!{sys.executable}\n" + MOCK)
            path.chmod(0o755)
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"], "REAL_GIT": GIT,
                    "MOCK_LOG": str(self.log), "LETMEKNOW_PI_REPO": str(self.pi)}

    def git(self, repo, *args):
        return subprocess.check_output([GIT, "-C", str(repo), *args], text=True, stderr=subprocess.PIPE).strip()

    def release(self, version="0.16.0", **env):
        return subprocess.run(["sh", "deploy/release.sh", version, str(self.notes)], cwd=self.app,
                              env={**self.env, "VERSION": version, **env}, text=True, capture_output=True, timeout=30)

    def pins(self, *args):
        return subprocess.run([sys.executable, "deploy/version-pins.py", *args], cwd=self.app, capture_output=True, text=True)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_all_pins_check_update_and_preserve_every_other_byte(self):
        before = {name: (self.app / name).read_bytes() for name in FILES}
        self.assertEqual(self.pins("check").returncode, 0)
        result = self.pins("set", "0.16.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.pins("check").returncode, 0)
        for name, content in before.items():
            expected = content
            if name == "Cargo.toml":
                expected = expected.replace(b'0.15.1', b'0.16.0')
            elif name in ("README.md", "SKILL.md", "AGENTS.md", "web/src/index.html"):
                expected = expected.replace(b'@letmeknow/cli@0.15', b'@letmeknow/cli@0.16').replace(b'0.15.x', b'0.16.x')
            self.assertEqual((self.app / name).read_bytes(), expected, name)

    def test_every_stale_or_missing_pin_fails(self):
        for name in ("README.md", "SKILL.md", "AGENTS.md", "web/src/index.html"):
            original = (self.app / name).read_text()
            count = original.count("@letmeknow/cli@0.15")
            for index in range(count):
                for bad in ("@letmeknow/cli@0.14", "removed"):
                    with self.subTest(file=name, occurrence=index, bad=bad):
                        pieces = original.split("@letmeknow/cli@0.15")
                        changed = "@letmeknow/cli@0.15".join(pieces[:index + 1]) + bad + "@letmeknow/cli@0.15".join(pieces[index + 1:])
                        (self.app / name).write_text(changed)
                        self.assertNotEqual(self.pins("check").returncode, 0)
            (self.app / name).write_text(original)
        original = (self.app / "AGENTS.md").read_text()
        (self.app / "AGENTS.md").write_text(original.replace("0.15.x", "0.14.x"))
        self.assertNotEqual(self.pins("check").returncode, 0)
        (self.app / "AGENTS.md").write_text(original)
        cargo = self.app / "Cargo.toml"
        cargo.write_text(cargo.read_text().replace('version = "0.15.1"', 'version = "0.16.0"'))
        self.assertNotEqual(self.pins("check").returncode, 0)

    def test_invalid_versions_never_mutate(self):
        head = self.git(self.app, "rev-parse", "HEAD")
        for version in ("0.16", "v0.16.0", "0.16.0-beta.1", "00.16.0", "0.16.0\necho bad", "0.16.0;echo bad", "4294967296.0.0"):
            with self.subTest(version=version):
                self.assertNotEqual(self.pins("set", version).returncode, 0)
                self.assertNotEqual(self.release(version).returncode, 0)
                self.assertEqual(self.git(self.app, "status", "--porcelain"), "")
                self.assertEqual(self.git(self.app, "rev-parse", "HEAD"), head)
                self.assertFalse(any("push" in call for call in self.calls()))

    def test_preflight_and_wrong_or_dirty_branch_refuse_before_mutation(self):
        self.assertNotEqual(self.release(LETMEKNOW_PI_REPO="").returncode, 0)
        self.assertNotEqual(self.release(MOCK_PREFLIGHT_FAIL="1").returncode, 0)
        self.assertEqual(self.git(self.app, "status", "--porcelain"), "")
        self.git(self.pi, "checkout", "-qb", "work")
        self.assertNotEqual(self.release().returncode, 0)
        self.git(self.pi, "checkout", "-q", "main")
        self.git(self.app, "checkout", "-qb", "work")
        self.assertNotEqual(self.release().returncode, 0)
        self.git(self.app, "checkout", "-q", "main")
        (self.app / "operator-work").write_text("keep")
        self.assertNotEqual(self.release().returncode, 0)
        self.assertEqual((self.app / "operator-work").read_text(), "keep")
        self.assertFalse(any("push" in call for call in self.calls()))
        self.assertEqual(self.git(self.pi, "log", "-1", "--format=%s"), "Fixture: existing changes")

    def test_failed_publication_provenance_and_unavailable_npm_do_not_move_pi(self):
        original = self.git(self.pi, "rev-parse", "HEAD")
        failures = [dict(MOCK_WATCH_FAILURE="1"), dict(MOCK_METADATA='{"conclusion":"failure"}'),
                    dict(MOCK_METADATA='{"status":"in_progress"}'), dict(MOCK_METADATA='{"workflow_id":99}'),
                    dict(MOCK_METADATA='{"path":".github/workflows/copied.yml"}'), dict(MOCK_METADATA='{"event":"workflow_dispatch"}'),
                    dict(MOCK_METADATA='{"head_sha":"wrong"}'), dict(MOCK_METADATA='{"head_branch":"wrong"}'),
                    dict(MOCK_METADATA='{"head_repository":{"full_name":"fork/repo"}}'), dict(MOCK_TAG_SHA="f" * 40),
                    dict(MOCK_PACKAGE="0.16.1"), dict(MOCK_PACKAGE=""), dict(MOCK_NPM_EXIT="1"),
                    dict(MOCK_NPM_EXIT="1", MOCK_PACKAGE="")]
        for env in failures:
            with self.subTest(env=env):
                self.log.write_text("")
                result = self.release(**env)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(self.git(self.pi, "rev-parse", "HEAD"), original)
                self.assertFalse(any(call[0] == "node" and call[2] == "set" for call in self.calls()))
                self.assertFalse(any(call[0] == "git" and "-C" in call and "push" in call for call in self.calls()))
        self.assertEqual(self.git(self.app, "status", "--porcelain"), "")
        head = self.git(self.app, "rev-parse", "HEAD")
        result = self.release()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git(self.app, "rev-parse", "HEAD"), head)
        self.assertNotEqual(self.git(self.pi, "rev-parse", "HEAD"), original)

    def test_success_order_coherent_commit_and_retry_after_pi_push_failure(self):
        original_pi = self.git(self.pi, "rev-parse", "HEAD")
        result = self.release(MOCK_PI_PUSH_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        calls = self.calls()
        preflight = next(i for i, call in enumerate(calls) if call[0] == "node" and call[2] == "preflight")
        commit = next(i for i, call in enumerate(calls) if call[:2] == ["git", "commit"])
        app_push = next(i for i, call in enumerate(calls) if call[:2] == ["git", "push"])
        watch = next(i for i, call in enumerate(calls) if call[:3] == ["gh", "run", "watch"])
        provenance = next(i for i, call in enumerate(calls) if call[0] == "gh" and "git/ref/tags" in " ".join(call))
        npm = next(i for i, call in enumerate(calls) if call[0] == "npm")
        pin = next(i for i, call in enumerate(calls) if call[0] == "node" and call[2] == "set")
        self.assertLess(preflight, commit)
        self.assertLess(commit, app_push)
        self.assertLess(app_push, watch)
        self.assertLess(watch, provenance)
        self.assertLess(provenance, npm)
        self.assertLess(npm, pin)
        changed = set(self.git(self.app, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").splitlines())
        self.assertEqual(changed, set(FILES[:6]))
        self.assertEqual((self.app / "existing.rs").read_text(), "preserve existing app code\n")
        self.assertEqual((self.pi / "extensions/letmeknow.ts").read_text(), 'const MINOR = "0.16";\nconst existing = true;\n')
        app_head, pi_head = [self.git(repo, "rev-parse", "HEAD") for repo in (self.app, self.pi)]
        self.assertNotEqual(pi_head, original_pi)
        result = self.release()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Published 0.16.0", result.stdout)
        self.assertEqual(self.git(self.app, "rev-parse", "HEAD"), app_head)
        self.assertEqual(self.git(self.pi, "rev-parse", "HEAD"), pi_head)
        self.assertEqual(self.git(self.app, "rev-parse", "v0.16.0^{commit}"), app_head)

    def test_clean_pi_commit_during_workflow_wait_refuses_followup(self):
        original = self.git(self.pi, "rev-parse", "HEAD")
        result = self.release(MOCK_PI_COMMIT_DURING_WAIT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Pi HEAD changed since preflight", result.stderr)
        self.assertNotEqual(self.git(self.pi, "rev-parse", "HEAD"), original)
        self.assertEqual(self.git(self.pi, "rev-parse", "HEAD^"), original)
        self.assertEqual(self.git(self.pi, "status", "--porcelain"), "")
        self.assertEqual((self.pi / "unrelated").read_text(), "preserve new work during publication\n")
        self.assertIn('const MINOR = "0.15";', (self.pi / "extensions/letmeknow.ts").read_text())
        self.assertFalse(any(call[0] == "node" and call[2] == "set" for call in self.calls()))
        self.assertFalse(any(call[0] == "git" and "-C" in call and "push" in call for call in self.calls()))

    def test_already_desired_version_with_no_tag_or_lock_diff_tags_existing_head(self):
        self.assertEqual(self.pins("set", "0.16.0").returncode, 0)
        (self.app / "Cargo.lock").write_text("fixture lock 0.16.0\n")
        self.git(self.app, "commit", "-qam", "Fixture: coherent version already desired")
        head = self.git(self.app, "rev-parse", "HEAD")
        self.assertEqual(self.git(self.app, "tag", "--list"), "")
        result = self.release()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git(self.app, "rev-parse", "HEAD"), head)
        self.assertEqual(self.git(self.app, "rev-parse", "v0.16.0^{commit}"), head)
        self.assertEqual(self.git(self.app, "status", "--porcelain"), "")
        self.assertFalse(any(call[:2] == ["git", "commit"] for call in self.calls()))
        self.assertIn(["git", "push", "-q", "origin", "v0.16.0"], self.calls())

    def test_existing_tag_at_another_commit_is_never_moved(self):
        self.assertEqual(self.pins("set", "0.16.0").returncode, 0)
        self.git(self.app, "commit", "-qam", "Fixture: release version")
        self.git(self.app, "tag", "v0.16.0")
        old_tag = self.git(self.app, "rev-parse", "v0.16.0")
        (self.app / "existing.rs").write_text("later code\n")
        self.git(self.app, "commit", "-qam", "Fixture: later code")
        result = self.release()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.git(self.app, "rev-parse", "v0.16.0"), old_tag)
        self.assertFalse(any("push" in call for call in self.calls()))

    def test_existing_tag_with_wrong_cargo_version_cannot_publish(self):
        self.git(self.app, "tag", "v0.16.0")
        result = self.release()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing tag has a different Cargo version", result.stderr)
        self.assertEqual(self.git(self.app, "status", "--porcelain"), "")
        self.assertFalse(any("push" in call for call in self.calls()))

    def test_patch_does_not_require_or_move_pi(self):
        result = self.release("0.15.2", LETMEKNOW_PI_REPO="/missing")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call[0] == "node" for call in self.calls()))
        self.assertEqual(self.git(self.pi, "log", "-1", "--format=%s"), "Fixture: existing changes")


if __name__ == "__main__":
    unittest.main(verbosity=2)
