#!/usr/bin/env python3
import base64
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.error

import compatibility as c
import e2e


INTEGRITY = "sha512-" + base64.b64encode(bytes(64)).decode()


def releases(versions):
    cli = {"name": c.CLI, "versions": {}}
    native = {"name": c.PLATFORM, "versions": {}}
    for version in versions:
        for name, data in ((c.CLI, cli), (c.PLATFORM, native)):
            data["versions"][version] = {
                "name": name, "version": version, "dist": {"tarball": c.REGISTRY + "artifact.tgz", "integrity": INTEGRITY},
                "optionalDependencies": {c.PLATFORM: version}, "os": ["linux", "android"], "cpu": ["x64"]}
    return cli, native


class Resolver(unittest.TestCase):
    def setUp(self):
        self.cli, self.native = releases(["0.14.9", "0.15.0", "0.15.1"])

    def test_equal_cargo_version_selected(self):
        self.assertEqual(c.select("0.15.1", self.cli, self.native), {"same_minor": "0.15.1", "previous": "0.14.9"})

    def test_first_minor_absent_successful_metadata(self):
        self.assertEqual(c.select("0.16.0", self.cli, self.native), {"same_minor": None, "previous": "0.15.1"})

    def test_highest_stable_numeric_not_dist_tag(self):
        cli, native = releases(["0.14.9", "0.15.2", "0.15.10", "0.15.12-beta.1", "0.16.0-rc.1"])
        cli["dist-tags"] = {"latest": "0.14.9"}
        self.assertEqual(c.select("0.15.2", cli, native)["same_minor"], "0.15.10")

    def test_highest_previous_minor(self):
        cli, native = releases(["0.13.99", "0.14.99", "0.15.1", "0.15.2"])
        self.assertEqual(c.select("0.16.0", cli, native)["previous"], "0.15.2")

    def test_patch_without_baseline_fails(self):
        with self.assertRaisesRegex(AssertionError, "patch candidate"):
            c.select("0.16.1", self.cli, self.native)

    def test_missing_previous_fails(self):
        cli, native = releases(["0.16.0"])
        with self.assertRaisesRegex(AssertionError, "previous"):
            c.select("0.16.0", cli, native)

    def test_platform_missing_is_not_absence(self):
        del self.native["versions"]["0.15.1"]
        with self.assertRaisesRegex(AssertionError, "missing"):
            c.select("0.16.0", self.cli, self.native)

    def test_cli_missing_platform_present_is_not_absence(self):
        self.native["versions"]["0.16.0"] = self.native["versions"]["0.15.1"]
        with self.assertRaisesRegex(AssertionError, "without CLI"):
            c.select("0.16.0", self.cli, self.native)

    def test_wrong_optional_dependency(self):
        self.cli["versions"]["0.15.1"]["optionalDependencies"][c.PLATFORM] = "0.15.0"
        with self.assertRaisesRegex(AssertionError, "CLI/native"):
            c.select("0.16.0", self.cli, self.native)

    def test_wrong_platform(self):
        self.native["versions"]["0.15.1"]["cpu"] = ["arm64"]
        with self.assertRaisesRegex(AssertionError, "platform"):
            c.select("0.16.0", self.cli, self.native)

    def test_malformed_platform_os_is_not_absence(self):
        for wrong in ("linux", ["linux", "win32"], ["darwin"]):
            self.native["versions"]["0.15.1"]["os"] = wrong
            with self.subTest(wrong=wrong), self.assertRaisesRegex(AssertionError, "platform metadata"):
                c.select("0.16.0", self.cli, self.native)

    def test_wrong_metadata_identity(self):
        self.native["versions"]["0.15.1"]["name"] = "@other/linux-x64"
        with self.assertRaisesRegex(AssertionError, "package/version"):
            c.select("0.16.0", self.cli, self.native)

    def test_missing_integrity(self):
        del self.native["versions"]["0.15.1"]["dist"]["integrity"]
        with self.assertRaises(KeyError):
            c.select("0.16.0", self.cli, self.native)

    def test_invalid_integrity(self):
        self.native["versions"]["0.15.1"]["dist"]["integrity"] = "sha1-AAAA"
        with self.assertRaises(AssertionError):
            c.select("0.16.0", self.cli, self.native)

    def test_foreign_tarball(self):
        self.native["versions"]["0.15.1"]["dist"]["tarball"] = "https://example.com/other.tgz"
        with self.assertRaisesRegex(AssertionError, "registry"):
            c.select("0.16.0", self.cli, self.native)

    def test_noncanonical_versions(self):
        for value in ["01.15.1", "0.15", "0.15.1-rc.1", "0.15.1+build", "latest", "0.15.1\n"]:
            with self.subTest(value=value), self.assertRaises(AssertionError):
                c.version(value)

    def test_successful_metadata_records_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            body = json.dumps(self.cli).encode()
            data, source = c.metadata(c.CLI, Path(directory), lambda _: body)
            self.assertEqual(data, self.cli)
            self.assertEqual(c.sha(source["path"]), source["sha256"])

    def test_metadata_failures_are_not_absence(self):
        errors = [TimeoutError("timeout"), urllib.error.HTTPError("url", 404, "missing", {}, None),
                  urllib.error.HTTPError("url", 503, "unavailable", {}, None)]
        with tempfile.TemporaryDirectory() as directory:
            for error in errors:
                with self.subTest(error=error), patch.object(c.urllib.request.OpenerDirector, "open", side_effect=error):
                    with self.assertRaises(type(error)):
                        c.metadata(c.CLI, Path(directory))

    def test_pack_failure_never_becomes_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            failed = subprocess.CompletedProcess([], 1, "", "HTTP 404")
            with patch.object(e2e, "execute", return_value=failed):
                with self.assertRaisesRegex(AssertionError, "npm pack failed"):
                    c.download(self.cli, self.native, "0.15.1", "previous-incompatible", Path(directory), c.environment(Path(directory) / "env"))

    def test_future_minor_can_declare_previous_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = root / "contract.json"
            c.save(contract, {"candidate_minor": "0.17", "previous_minor": "0.16", "previous_policy": "compatible"})
            cli, native = releases(["0.15.1", "0.16.3"])
            args = SimpleNamespace(action="resolve", out=str(root / "baselines.json"), contract=str(contract), candidate_version="0.17.0")
            with patch.object(c, "metadata", side_effect=[(cli, {}), (native, {})]), \
                    patch.object(c, "download", side_effect=lambda cli, native, v, role, *args: {"version": v, "role": role}):
                c.resolve(args)
            resolved = json.loads(Path(args.out).read_text())
            self.assertEqual(resolved["artifacts"], [{"version": "0.16.3", "role": "previous-compatible"}])
            self.assertEqual(resolved["same_minor"], "absent-first-release")

    def test_contract_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = root / "contract.json"
            c.save(contract, {"candidate_minor": "0.16", "previous_minor": "0.15", "previous_policy": "incompatible"})
            args = SimpleNamespace(action="resolve", out=str(root / "baselines.json"), contract=str(contract), candidate_version="0.15.1")
            with patch.object(c, "metadata", side_effect=[(self.cli, {}), (self.native, {})]):
                with self.assertRaisesRegex(AssertionError, "candidate/contract"):
                    c.resolve(args)

    def test_malformed_metadata_is_not_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            for body in (b"{", b"null", b'{}', b'{"name":"@letmeknow/cli","versions":{}}'):
                with self.subTest(body=body), self.assertRaises((ValueError, TypeError, KeyError, AssertionError)):
                    c.metadata(c.CLI, Path(directory), lambda _: body)


class Packages(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.tarball = self.root / "fixture.tgz"
        self.pkg = {"name": c.PLATFORM, "version": "0.15.1", "os": ["linux"], "cpu": ["x64"]}

    def tearDown(self):
        self.tmp.cleanup()

    def pack(self, extra=None):
        with tarfile.open(self.tarball, "w:gz") as tar:
            files = {"package/package.json": json.dumps(self.pkg).encode(),
                     "package/bin/letmeknow": b"#!/bin/sh\necho letmeknow 0.15.1\n",
                     "package/bin/letmeknow-kind-doc": b"unchanged adjacent plugin\x00"}
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size, member.mode = len(data), 0o755
                tar.addfile(member, io.BytesIO(data))
            if extra:
                tar.addfile(extra)
        return "sha512-" + base64.b64encode(hashlib.sha512(self.tarball.read_bytes()).digest()).decode()

    def test_integrity_and_layout(self):
        integrity = self.pack()
        c.unpack(self.tarball, self.root / "extract", c.PLATFORM, "0.15.1", integrity)
        self.assertEqual((self.root / "extract/package/bin/letmeknow-kind-doc").read_bytes(), b"unchanged adjacent plugin\x00")
        c.binary_version(self.root / "extract/package/bin/letmeknow", "0.15.1", c.environment(self.root / "env"))

    def test_bad_integrity_before_extraction(self):
        self.pack()
        with self.assertRaisesRegex(AssertionError, "integrity mismatch"):
            c.unpack(self.tarball, self.root / "extract", c.PLATFORM, "0.15.1", INTEGRITY)
        self.assertFalse((self.root / "extract").exists())

    def test_wrong_package_version(self):
        with self.assertRaisesRegex(AssertionError, "package/version"):
            c.unpack(self.tarball, self.root / "extract", c.PLATFORM, "0.15.2", self.pack())

    def test_wrong_package_name(self):
        self.pkg["name"] = "@other/linux-x64"
        with self.assertRaisesRegex(AssertionError, "package/version"):
            c.unpack(self.tarball, self.root / "extract", c.PLATFORM, "0.15.1", self.pack())

    def test_wrong_extracted_platform(self):
        self.pkg["cpu"] = ["arm64"]
        with self.assertRaisesRegex(AssertionError, "platform"):
            c.unpack(self.tarball, self.root / "extract", c.PLATFORM, "0.15.1", self.pack())

    def test_extracted_cli_native_dependency_mismatch(self):
        self.pkg["name"] = c.CLI
        self.pkg["optionalDependencies"] = {c.PLATFORM: "0.15.0"}
        with self.assertRaisesRegex(AssertionError, "CLI/native mismatch"):
            c.unpack(self.tarball, self.root / "extract", c.CLI, "0.15.1", self.pack())

    def test_path_traversal_and_symlinks(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                           ("package/link", tarfile.SYMTYPE), ("package/hard", tarfile.LNKTYPE),
                           ("package/bin/letmeknow", tarfile.REGTYPE), ("package/bin/./letmeknow", tarfile.REGTYPE)):
            member = tarfile.TarInfo(name)
            member.type, member.linkname = kind, "/etc/passwd"
            with self.subTest(name=name), self.assertRaisesRegex(AssertionError, "unsafe/duplicate"):
                c.unpack(self.tarball, self.root / "extract", c.PLATFORM, "0.15.1", self.pack(member))
        self.assertFalse((self.root / "extract").exists())

    def test_bad_tar_not_absence(self):
        self.tarball.write_bytes(b"not a tarball")
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(self.tarball.read_bytes()).digest()).decode()
        with self.assertRaises(tarfile.ReadError):
            c.unpack(self.tarball, self.root / "extract", c.PLATFORM, "0.15.1", integrity)

    def test_changed_plugin_is_not_a_verified_package(self):
        integrity = self.pack()
        dest = self.root / "extract"
        c.unpack(self.tarball, dest, c.PLATFORM, "0.15.1", integrity)
        package = {"tarball": str(self.tarball), "sha256": c.sha(self.tarball), "integrity": integrity,
                   "root": str(dest / "package"), "files": c.tree(dest / "package"), "name": c.PLATFORM}
        artifact = {"packages": [package], "version": "0.15.1"}
        (dest / "package/bin/letmeknow-kind-doc").write_bytes(b"changed plugin")
        with self.assertRaisesRegex(AssertionError, "package bytes/modes changed"):
            c.verify(artifact, c.environment(self.root / "env"))

    def test_changed_download_is_not_a_verified_package(self):
        integrity = self.pack()
        package = {"tarball": str(self.tarball), "sha256": c.sha(self.tarball), "integrity": integrity}
        self.tarball.write_bytes(b"changed")
        with self.assertRaisesRegex(AssertionError, "download SHA-256 changed"):
            c.verify({"packages": [package]}, c.environment(self.root / "env"))

    def test_binary_version_not_trusted_from_package(self):
        c.unpack(self.tarball, self.root / "extract", c.PLATFORM, "0.15.1", self.pack())
        with self.assertRaisesRegex(AssertionError, "expected 0.16.0"):
            c.binary_version(self.root / "extract/package/bin/letmeknow", "0.16.0", c.environment(self.root / "env"))

    def test_missing_binary_has_no_path_fallback(self):
        env = c.environment(self.root / "env")
        env["PATH"] = str(self.root)
        (self.root / "letmeknow").write_text("never run this")
        with self.assertRaisesRegex(AssertionError, "missing absolute"):
            c.binary_version(self.root / "missing/letmeknow", "0.15.1", env)
        with self.assertRaisesRegex(AssertionError, "absolute"):
            c.binary_version("letmeknow", "0.15.1", env)

    def test_environment_no_inherited_home_proxy_plugins(self):
        with patch.dict(os.environ, {"LETMEKNOW_HOME": "/forbidden", "HTTPS_PROXY": "http://forbidden", "PATH": "/forbidden"}):
            env = c.environment(self.root / "env")
        self.assertNotIn("LETMEKNOW_HOME", env)
        self.assertNotIn("HTTPS_PROXY", env)
        self.assertEqual(env["PATH"], "/usr/bin:/bin")

    def test_full_tree_detects_unknown_plugin_blob_and_mode_changes(self):
        home = self.root / "home"
        (home / "files").mkdir(parents=True)
        (home / "files/data").write_bytes(b"ciphertext")
        (home / "unknown").write_bytes(b"sentinel")
        before = c.tree(home)
        (home / "unknown").chmod(0o400)
        self.assertNotEqual(before, c.tree(home))
        (home / "unknown").chmod(before["unknown"]["mode"])
        (home / "files/data").write_bytes(b"different!")
        self.assertNotEqual(before, c.tree(home))

    def test_retention_rejects_deleted_values_and_permits_explicit_attempt_index_extensions(self):
        path = self.root / "test.db"
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE lmk (key BLOB PRIMARY KEY, value BLOB)")
            db.execute("INSERT INTO lmk VALUES (?,?)", (b"node/groups", b'["existing"]'))
            db.execute("INSERT INTO lmk VALUES (?,?)", (b"evidence", b"held bytes"))
        before = c.logical_tree(self.root)
        with sqlite3.connect(path) as db:
            db.execute("UPDATE lmk SET value=? WHERE key=?", (b'["attempt", "existing"]', b"node/groups"))
        c.retained(before, c.logical_tree(self.root))
        with sqlite3.connect(path) as db:
            db.execute("DELETE FROM lmk WHERE key=?", (b"evidence",))
        with self.assertRaisesRegex(AssertionError, "pre-existing durable value changed"):
            c.retained(before, c.logical_tree(self.root))

    def test_attempt_group_index_preserves_every_old_field(self):
        path = self.root / "sessions/agent/groups.json"
        path.parent.mkdir(parents=True)
        original = {"group": "old", "kind": "doc", "unknown": ["kept"]}
        c.save(path, [original])
        before = c.logical_tree(self.root)
        c.save(path, [original, {"group": "attempt", "kind": "chat"}])
        c.retained(before, c.logical_tree(self.root))
        c.save(path, [{**original, "unknown": []}])
        with self.assertRaisesRegex(AssertionError, "pre-existing group index changed"):
            c.retained(before, c.logical_tree(self.root))
        c.save(path, [original, original])
        with self.assertRaisesRegex(AssertionError, "duplicate session group"):
            c.logical_tree(self.root)

    def test_retention_preserves_duplicate_sql_rows(self):
        path = self.root / "test.db"
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE unknown (value BLOB)")
            db.executemany("INSERT INTO unknown VALUES (?)", [(b"same",), (b"same",)])
        before = c.logical_tree(self.root)
        with sqlite3.connect(path) as db:
            db.execute("DELETE FROM unknown WHERE rowid = 1")
        with self.assertRaisesRegex(AssertionError, "pre-existing durable value changed"):
            c.retained(before, c.logical_tree(self.root))

    def test_logical_snapshot_includes_every_table_and_bytes(self):
        path = self.root / "test.db"
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE evidence (key BLOB, value BLOB)")
            db.execute("INSERT INTO evidence VALUES (?,?)", (b"key", b"\x00\xff"))
        before = c.logical_tree(self.root)
        self.assertIn('"bytes": "00ff"', before["test.db"]["tables"]["evidence"][0])
        with sqlite3.connect(path) as db:
            db.execute("UPDATE evidence SET value = ?", (b"changed",))
        self.assertNotEqual(before, c.logical_tree(self.root))


@unittest.skipUnless(c.platform.system() == "Linux", "Linux process gate")
class Processes(unittest.TestCase):
    def setUp(self):
        ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        for proc in list(e2e.PROCESSES):
            e2e.stop(proc)
        self.tmp.cleanup()

    def test_timeout_reaps_process_and_plugin(self):
        pidfile = self.root / "child"
        with self.assertRaises(subprocess.TimeoutExpired):
            e2e.execute(["/bin/sh", "-c", f"sleep 90 & echo $! > {pidfile}; wait"], env=c.environment(self.root / "env"), timeout=0.3)
        self.assertEqual(e2e.PROCESSES, [])
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)

    def test_timeout_reaps_descendant_in_its_own_process_group(self):
        pidfile = self.root / "child"
        with self.assertRaises(subprocess.TimeoutExpired):
            e2e.execute(["/bin/sh", "-c", f"setsid sleep 90 & echo $! > {pidfile}; wait"],
                        env=c.environment(self.root / "env"), timeout=0.3)
        self.assertEqual(e2e.PROCESSES, [])
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)

    def test_service_constructor_failure_reaps_descendant(self):
        binary, pidfile = self.root / "fake-service", self.root / "child"
        binary.write_text(f"#!/bin/sh\nsleep 90 & echo $! > {pidfile}\necho not-a-membership-address\nwait\n")
        binary.chmod(0o755)
        with patch.object(e2e, "execute", return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaisesRegex(AssertionError, "service did not start"):
                c.Service(binary, self.root / "service", False)
        self.assertEqual(e2e.PROCESSES, [])
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)

    def test_constructor_failure_reaps_plugin(self):
        binary, pidfile = self.root / "letmeknow", self.root / "child"
        binary.write_text(f"#!/bin/sh\nsleep 90 & echo $! > {pidfile}\nprintf '%s\\n' '{{\"type\":\"ready\",\"bin\":\"/bin/false\"}}'\nwait\n")
        binary.chmod(0o755)
        with self.assertRaisesRegex(AssertionError, "ready.bin"):
            e2e.Listener("test", bin=str(binary), env=c.environment(self.root / "env"), log=self.root / "log")
        self.assertEqual(e2e.PROCESSES, [])
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)

    def test_early_exit_not_event_timeout(self):
        with self.assertRaisesRegex(AssertionError, "eof"):
            e2e.Listener("test", bin="/bin/false", env=c.environment(self.root / "env"), log=self.root / "log")
        self.assertEqual(e2e.PROCESSES, [])

    def test_error_results_are_retained(self):
        results, output = [], self.root / "results.json"
        with self.assertRaises(AssertionError):
            c.case(results, "wrong namespace", lambda: c.require(False, "namespace collision"), output)
        recorded = json.loads(output.read_text())
        self.assertEqual(recorded[0]["status"], "failed")
        self.assertIn("namespace collision", recorded[0]["error"])

    def test_candidate_version_mismatch_is_recorded_before_startup(self):
        manifest = {"candidate_version": "0.16.0", "contract": {"candidate_minor": "0.16"}}
        args = SimpleNamespace(action="run", bin="/bin/true", baselines=str(self.root / "baselines.json"), alpn_probe=None)
        with patch.object(c, "load_manifest", return_value=manifest), patch.object(c, "Service") as service, \
                patch.object(c.tomllib, "loads", return_value={"workspace": {"package": {"version": "0.15.1"}}}):
            with self.assertRaisesRegex(AssertionError, "Cargo/manifest version mismatch"):
                c.run_matrix(args)
            service.assert_not_called()
        self.assertEqual(json.loads((self.root / "run/results.json").read_text())[0]["status"], "failed")

    def test_pending_message_uses_the_committed_id_and_position(self):
        peer = SimpleNamespace(cmd=Mock(return_value={"id": "pending-id", "pending": True}),
                               expect=Mock(return_value={"answered": "pending-id", "id": "committed-id", "pos": 19}))
        sent = c.send(peer, "body")
        self.assertEqual(sent, {"id": "committed-id", "pos": 19, "pending": False})
        kind, matches = peer.expect.call_args.args
        self.assertEqual(kind, "sent")
        self.assertTrue(matches({"answered": "pending-id"}))
        self.assertFalse(matches({"answered": "committed-id"}))

    def test_command_success_is_not_refusal(self):
        peer = object.__new__(c.Peer)
        peer.bin, peer.session = "/bin/true", "test"
        peer.env, peer.commands = c.environment(self.root / "env"), self.root / "commands.jsonl"
        with self.assertRaisesRegex(AssertionError, "unexpected command success"):
            peer.cmd("send", "forbidden", ok=False)


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, c.timeout_handler)
    signal.alarm(90)
    unittest.main(verbosity=2)
