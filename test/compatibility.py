#!/usr/bin/env python3
"""Linux published-native compatibility gate. No installs or historical source builds."""
import argparse
import base64
from collections import Counter
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import tarfile
import threading
import time
import tomllib
import urllib.request

import e2e

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "https://registry.npmjs.org/"
CLI = "@letmeknow/cli"
PLATFORM = "@letmeknow/linux-x64"
LEGACY_READY = set()
STABLE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def version(value):
    require(isinstance(value, str) and STABLE.fullmatch(value), f"not a stable numeric version: {value!r}")
    return tuple(map(int, value.split(".")))


def sha(path):
    with open(path, "rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def provenance(root, args):
    sources = root / "runner-source"
    sources.mkdir(exist_ok=True)
    files = {}
    for source in (Path(__file__), Path(e2e.__file__)):
        digest = sha(source)
        target = sources / f"{digest}-{source.name}"
        shutil.copyfile(source, target)
        files[source.name] = {"sha256": digest, "copy": str(target)}
    save(root / f"{args.action}-provenance.json", {"arguments": vars(args), "python": platform.python_version(), "sources": files})


def environment(root):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_DATA_HOME": str(root / "data"),
            "XDG_CONFIG_HOME": str(root / "config"), "XDG_CACHE_HOME": str(root / "cache"),
            "TMPDIR": str(root), "LANG": "C.UTF-8", "NO_PROXY": "localhost,127.0.0.1",
            "RUST_LOG": "warn", "TOKIO_WORKER_THREADS": "2"}


def binary_version(binary, expected, env):
    binary = Path(binary)
    require(binary.is_absolute() and binary.is_file(), f"missing absolute executable: {binary}")
    got = e2e.execute([binary, "--version"], env=env, timeout=10)
    require(got.returncode == 0 and got.stdout.strip() == f"letmeknow {expected}",
            f"{binary}: expected {expected}, got {got.stdout!r} {got.stderr!r}")


def metadata(package, directory, fetch=None):
    url = REGISTRY + package.replace("/", "%2f")
    if fetch is None:
        def fetch(url):
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            started = time.monotonic()
            remaining = signal.alarm(25)
            try:
                with opener.open(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=20) as response:
                    require(response.status == 200 and response.url == url, "registry status/redirect")
                    body = response.read(20 * 1024 * 1024 + 1)
                    require(len(body) <= 20 * 1024 * 1024, "registry metadata too large")
                    return body
            finally:
                signal.alarm(max(1, remaining - int(time.monotonic() - started)) if remaining else 0)
    body = fetch(url)
    raw = directory / (package.rsplit("/", 1)[1] + "-metadata.json")
    raw.write_bytes(body)
    data = json.loads(body)
    require(data["name"] == package and isinstance(data["versions"], dict) and data["versions"],
            f"malformed metadata for {package}")
    return data, {"url": url, "path": str(raw), "sha256": sha(raw)}


def select(candidate, cli, native):
    target = version(candidate)
    stable = {version(v): v for v in cli["versions"] if STABLE.fullmatch(v)}
    same = [v for v in stable if v[:2] == target[:2]]
    previous = [v for v in stable if v[:2] < target[:2]]
    require(previous, "no published previous minor")
    require(same or target[2] == 0, "patch candidate has no published same-minor baseline")
    chosen = {"same_minor": stable[max(same)] if same else None, "previous": stable[max(previous)]}
    # Partial platform publication is an error, not absence (in either direction).
    for v in native["versions"]:
        if STABLE.fullmatch(v) and version(v)[:2] == target[:2]:
            require(v in cli["versions"], f"platform release without CLI: {v}")
    for v in chosen.values():
        if v is not None:
            release_metadata(cli, native, v)
    return chosen


def release_metadata(cli, native, v):
    for package, data in ((CLI, cli), (PLATFORM, native)):
        require(v in data["versions"], f"{package}@{v} missing from successful metadata")
        release = data["versions"][v]
        require(release["name"] == package and release["version"] == v, "metadata package/version mismatch")
        dist = release["dist"]
        require(dist["tarball"].startswith(REGISTRY), "tarball outside authoritative registry")
        digest = dist["integrity"].removeprefix("sha512-")
        require(dist["integrity"].startswith("sha512-") and len(base64.b64decode(digest, validate=True)) == 64,
                "missing/invalid sha512 integrity")
    require(cli["versions"][v]["optionalDependencies"][PLATFORM] == v, "CLI/native version mismatch")
    release = native["versions"][v]
    require(isinstance(release["os"], list) and "linux" in release["os"]
            and set(release["os"]) <= {"linux", "android"} and release["cpu"] == ["x64"], "wrong platform metadata")


def tree(root, timestamps=False):
    result = {}
    for path in sorted(Path(root).rglob("*")):
        info = path.lstat()
        item = {"mode": stat.S_IMODE(info.st_mode)}
        if timestamps:
            item.update(mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)
        if path.is_symlink():
            item.update(type="link", target=os.readlink(path))
        elif path.is_dir():
            item.update(type="directory")
        else:
            require(path.is_file(), f"unexpected special file {path}")
            item.update(type="file", size=info.st_size, sha256=sha(path))
        result[str(path.relative_to(root))] = item
    return result


def unpack(tarball, directory, package, v, integrity):
    expected = base64.b64decode(integrity.removeprefix("sha512-"), validate=True)
    require(integrity.startswith("sha512-") and len(expected) == 64, "invalid integrity")
    with open(tarball, "rb") as file:
        require(hashlib.file_digest(file, "sha512").digest() == expected, "tarball integrity mismatch")
    with tarfile.open(tarball, "r:gz") as archive:
        members = archive.getmembers()
        names = set()
        require(sum(m.size for m in members) <= 512 * 1024 * 1024, "oversized package")
        for m in members:
            path = Path(m.name)
            require(path.parts and path.parts[0] == "package" and ".." not in path.parts
                    and not path.is_absolute() and (m.isfile() or m.isdir()) and str(path) not in names,
                    f"unsafe/duplicate tar member {m.name}")
            require(not m.mode & 0o7000, "privileged package mode")
            names.add(str(path))
        archive.extractall(directory, members=members, filter="data")
    pkg = json.loads((directory / "package/package.json").read_text())
    require(pkg["name"] == package and pkg["version"] == v, "extracted package/version mismatch")
    if package == PLATFORM:
        require(isinstance(pkg["os"], list) and "linux" in pkg["os"]
                and set(pkg["os"]) <= {"linux", "android"} and pkg["cpu"] == ["x64"], "extracted platform mismatch")
    else:
        require(pkg["optionalDependencies"][PLATFORM] == v, "extracted CLI/native mismatch")


def download(cli, native, v, role, directory, env):
    release_metadata(cli, native, v)
    packages = []
    npm, node = shutil.which("npm"), shutil.which("node")
    require(npm and node, "npm and node must already be available (no installation)")
    for package, data in ((CLI, cli), (PLATFORM, native)):
        dest = directory / v / package.rsplit("/", 1)[1]
        dest.mkdir(parents=True)
        dist = data["versions"][v]["dist"]
        config = dest / "empty-global.npmrc"
        config.write_text("")
        args = [node, str(Path(npm).resolve()), "--userconfig=/dev/null", f"--globalconfig={config}", f"--cache={directory / 'npm-cache'}",
                "--registry=" + REGISTRY, "--fetch-retries=0", "--fetch-timeout=20000", "pack", "--ignore-scripts",
                "--json", "--pack-destination", dest, f"{package}@{v}"]
        result = e2e.execute(args, env=env, timeout=90)
        (dest / "pack.stdout").write_text(result.stdout)
        (dest / "pack.stderr").write_text(result.stderr)
        require(result.returncode == 0, f"npm pack failed for {package}@{v}: {result.stderr}")
        report = json.loads(result.stdout)
        packed, = report.values() if isinstance(report, dict) else report
        require(Path(packed["filename"]).name == packed["filename"], "invalid pack filename")
        require(packed["name"] == package and packed["version"] == v and packed["integrity"] == dist["integrity"],
                "npm pack identity/integrity mismatch")
        tarball = dest / packed["filename"]
        unpack(tarball, dest, package, v, dist["integrity"])
        packages.append({"name": package, "version": v, "tarball_url": dist["tarball"], "integrity": dist["integrity"],
                         "tarball": str(tarball), "sha256": sha(tarball), "pack_command": list(map(str, args)), "root": str(dest / "package"),
                         "files": tree(dest / "package")})
    binary = Path(packages[1]["root"]) / "bin/letmeknow"
    binary_version(binary, v, env)
    for kind in ("doc", "table"):
        require((binary.parent / f"letmeknow-kind-{kind}").is_file(), f"missing published {kind} plugin")
    return {"role": role, "version": v, "packages": packages, "bin": str(binary), "binary_sha256": sha(binary)}


def verify(artifact, env):
    for pkg in artifact["packages"]:
        require(sha(pkg["tarball"]) == pkg["sha256"], "download SHA-256 changed")
        with open(pkg["tarball"], "rb") as file:
            require("sha512-" + base64.b64encode(hashlib.file_digest(file, "sha512").digest()).decode() == pkg["integrity"],
                    "download integrity changed")
        require(tree(pkg["root"]) == pkg["files"], "extracted package bytes/modes changed")
        identity = json.loads((Path(pkg["root"]) / "package.json").read_text())
        require(identity["name"] == pkg["name"] and identity["version"] == artifact["version"], "package identity changed")
    require(Path(artifact["bin"]) == Path(artifact["packages"][1]["root"]) / "bin/letmeknow", "binary outside published package")
    require(sha(artifact["bin"]) == artifact["binary_sha256"], "binary hash changed")
    binary_version(artifact["bin"], artifact["version"], env)


def resolve(args):
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    provenance(out.parent, args)
    env = environment(out.parent / "resolver-home")
    contract = json.loads(Path(args.contract).read_text())
    require(".".join(map(str, version(args.candidate_version)[:2])) == contract["candidate_minor"], "candidate/contract minor mismatch")
    require(contract["previous_policy"] in ("compatible", "incompatible"), "explicit previous policy required")
    cli, cli_source = metadata(CLI, out.parent)
    native, native_source = metadata(PLATFORM, out.parent)
    chosen = select(args.candidate_version, cli, native)
    require(".".join(map(str, version(chosen["previous"])[:2])) == contract["previous_minor"], "resolved previous minor differs from contract")
    manifest = {"schema": 1, "candidate_version": args.candidate_version, "contract": contract,
                "registry": REGISTRY, "platform": PLATFORM, "prereleases": "excluded", "metadata": [cli_source, native_source],
                "same_minor": "published" if chosen["same_minor"] else "absent-first-release", "artifacts": []}
    save(out, manifest)
    for key, role in (("same_minor", "same-minor-positive"), ("previous", "previous-" + contract["previous_policy"])):
        if chosen[key]:
            manifest["artifacts"].append(download(cli, native, chosen[key], role, out.parent / "packages", env))
            save(out, manifest)
    manifest["resolved"] = True
    save(out, manifest)
    print(json.dumps({"manifest": str(out), "same_minor": manifest["same_minor"], "selected": chosen}))


def load_manifest(path):
    manifest = json.loads(Path(path).read_text())
    require(manifest["schema"] == 1 and manifest.get("resolved") is True, "unresolved manifest")
    require(manifest["platform"] == PLATFORM and manifest["registry"] == REGISTRY, "wrong registry/platform")
    metadata_values = []
    for source in manifest["metadata"]:
        require(sha(source["path"]) == source["sha256"], "metadata changed")
        metadata_values.append(json.loads(Path(source["path"]).read_text()))
    selected = select(manifest["candidate_version"], *metadata_values)
    contract = manifest["contract"]
    require(manifest["candidate_version"].rsplit(".", 1)[0] == contract["candidate_minor"], "candidate/contract minor mismatch")
    require(selected["previous"].rsplit(".", 1)[0] == contract["previous_minor"], "previous/contract minor mismatch")
    require(manifest["same_minor"] == ("published" if selected["same_minor"] else "absent-first-release"), "false baseline absence")
    require(contract["previous_policy"] in ("compatible", "incompatible"), "missing previous contract")
    roles = {"previous-" + contract["previous_policy"]: selected["previous"]}
    if selected["same_minor"]:
        roles["same-minor-positive"] = selected["same_minor"]
    require({a["role"]: a["version"] for a in manifest["artifacts"]} == roles
            and len(manifest["artifacts"]) == len(roles), "missing/substituted baseline")
    env = environment(Path(path).resolve().parent / "verify-home")
    for artifact in manifest["artifacts"]:
        release_metadata(*metadata_values, artifact["version"])
        for pkg, data in zip(artifact["packages"], metadata_values, strict=True):
            dist = data["versions"][artifact["version"]]["dist"]
            require(pkg["name"] == data["name"] and pkg["version"] == artifact["version"]
                    and pkg["integrity"] == dist["integrity"] and pkg["tarball_url"] == dist["tarball"], "provenance differs from metadata")
        verify(artifact, env)
    return manifest


def wait(produce, accept, label, timeout=40):
    value = e2e.until(produce, accept, timeout=timeout)
    require(accept(value), f"{label}: last value {value!r}")
    return value


class Service:
    def __init__(self, binary, root, initialize):
        self.root, self.bin = root, binary
        root.mkdir(parents=True)
        self.env = environment(root / "env")
        cert, key = root / "cert.pem", root / "key.pem"
        generated = e2e.execute(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                                 "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                                 "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", key, "-out", cert], env=self.env, timeout=20)
        require(generated.returncode == 0, generated.stderr)
        port = e2e.free_port()
        self.state = root / "state"
        if initialize:
            result = e2e.execute([binary, "serve", "--initialize", "--domain", "localhost", "--state", self.state], env=self.env)
            (root / "initialize.log").write_text(result.stdout + result.stderr)
            require(result.returncode == 0, f"explicit service initializer failed: {result.stderr}")
        self.log = open(root / "service.log", "w")
        self.membership_port = e2e.free_port()
        args = [binary, "serve", "--domain", "localhost", "--https-port", str(port), "--http-port", str(e2e.free_port()),
                "--membership-port", str(self.membership_port), "--qad-port", str(e2e.free_port()), "--state", self.state,
                "--cert", cert, "--key", key]
        self.proc = None
        try:
            self.proc = e2e.spawn([str(a) for a in args], env=self.env, stdout=subprocess.PIPE, stderr=self.log, text=True)
            lines = queue.Queue()
            threading.Thread(target=lambda: lines.put(self.proc.stdout.readline()), daemon=True).start()
            first = lines.get(timeout=30).strip()
            require(re.fullmatch(r"membership: [0-9a-f]{64}@https://localhost:[0-9]+", first), f"service did not start: {first}; {root}")
            self.env.update(LETMEKNOW_CA=str(cert), LETMEKNOW_RELAY=f"https://localhost:{port}",
                            LETMEKNOW_MEMBERSHIP=first.removeprefix("membership: "))
            (root / "public-address.txt").write_text(first + "\n")
        except BaseException:
            self.stop()
            raise

    def stop(self):
        if self.proc is not None and self.proc in e2e.PROCESSES:
            e2e.stop(self.proc)
            self.proc.stdout.close()
        self.log.close()


class Peer(e2e.Listener):
    def __init__(self, binary, root, service, handle="agent", *, home=None, default=False, env=None):
        self.root, self.service = root, service
        root.mkdir(parents=True, exist_ok=True)
        env = dict(env or environment(root / "env"))
        env["PATH"] = str(root / "no-path-plugins")
        env.update({k: service.env[k] for k in ("LETMEKNOW_CA", "LETMEKNOW_RELAY", "LETMEKNOW_MEMBERSHIP")})
        self.home = Path(home or root / "home")
        if not default:
            env["LETMEKNOW_HOME"] = str(self.home)
        self.commands = root / "commands.jsonl"
        self.event_file, self.saved_events = root / "events.jsonl", 0
        super().__init__(handle, bin=str(binary), env=env, log=root / "listen.log", keep_log=True,
                         ready_bin=sha(binary) not in LEGACY_READY)

    def cmd(self, *args, binary=None, ok=True, timeout=60):
        try:
            result = e2e.execute([binary or self.bin, "--session", self.session, *args], env=self.env, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            with self.commands.open("a") as file:
                file.write(json.dumps({"args": list(map(str, args)), "bin": str(binary or self.bin), "timeout": timeout}) + "\n")
            raise error
        with self.commands.open("a") as file:
            file.write(json.dumps({"args": list(map(str, args)), "bin": str(binary or self.bin),
                                   "code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}) + "\n")
        if ok:
            require(result.returncode == 0, f"{self.session} {args}: {result.stderr}")
            return json.loads(result.stdout)
        require(result.returncode > 0, f"unexpected command success or signal: {args}: {result.stdout}")
        return result.stderr

    def stop(self):
        super().stop()
        with self.event_file.open("a") as file:
            for event in self.events[self.saved_events:]:
                file.write(json.dumps({"bin": self.bin, "event": event}) + "\n")
        self.saved_events = len(self.events)


def send(peer, *args):
    sent = peer.cmd("send", *args)
    if sent.get("pending"):
        committed = peer.expect("sent", lambda e, answered=sent["id"]: e["answered"] == answered)
        sent.update(id=committed["id"], pos=committed["pos"], pending=False)
    require(isinstance(sent.get("pos"), int), f"message did not commit: {sent}")
    return sent


def message(sender, receiver, group, text, *, reply=None, attach=None, after=0):
    args = [f"--group={group}", text]
    if reply:
        args += ["--reply-to", reply]
    if attach:
        args += ["--attach", str(attach)]
    sent = send(sender, *args)
    require(sent["pos"] > after, "global chat position did not advance")
    got = receiver.expect("message", lambda e: e["content"] == text)
    require((got["id"], got["pos"], got["content"]) == (sent["id"], sent["pos"], text), "message ID/position/content")
    if reply:
        require(got["reply_to"] == reply, "reply target changed")
    if attach:
        arrived = got["attachment"]
        if "path" not in arrived:
            arrived = receiver.expect("attachment", lambda e: e["message"] == got["id"])
        require(Path(arrived["path"]).read_bytes() == Path(attach).read_bytes(), "attachment bytes differ")
        require(Path(receiver.cmd("fetch", got["attachment"]["link"])["path"]).read_bytes() == Path(attach).read_bytes(), "fetched bytes differ")
    return sent


def edit_doc(peer, other, path, other_path, text):
    start = len(other.events)
    path.write_text(text)
    peer.cmd("groups")
    wait(lambda: other_path.read_text(), lambda value: value == text, "exact doc convergence")
    other.expect("edited", lambda e: Path(e["file"]) == other_path and any(e is new for new in other.events[start:]))
    require(path.read_text() == text, "source doc changed during convergence")


def groups(peer, expected):
    return wait(lambda: peer.cmd("groups"), lambda gs: {g["group"] for g in gs} == set(expected), "group set")


def join_pair(a, b, root, identity=True):
    if identity:
        a.cmd("identity", "create", "Compatibility")
        b.cmd("identity", "join", a.cmd("identity", "invite")["link"])
    invite = a.cmd("invite", "--name", "Chat")
    chat = invite["group"]
    require(b.cmd("join", invite["link"])["group"] == chat, "chat join")
    ap, bp = root / "a.md", root / "b.md"
    ap.write_text("initial α\nsecond line\n")
    doc = a.cmd("invite", "--kind", "doc", "--name", "Doc", str(ap))
    require(b.cmd("join", doc["link"], str(bp))["kind"] == "doc", "doc join")
    wait(lambda: bp.read_text(), lambda value: value == ap.read_text(), "initial doc state")
    blob = root / "payload.bin"
    blob.write_bytes(bytes(range(256)) * 137 + b"\x00\xffcompatibility\n")
    links, last = [], 0
    for i, (sender, receiver, src, dest) in enumerate(((a, b, ap, bp), (b, a, bp, ap))):
        sent = message(sender, receiver, chat, f"message-{i}", attach=blob, after=last)
        replied = message(receiver, sender, chat, f"reply-{i}", reply=sent["id"], after=sent["pos"])
        last = replied["pos"]
        linked = sender.cmd("doc", "attach", f"--group={doc['group']}", str(blob))
        links.append(linked["link"])
        edit_doc(sender, receiver, src, dest, src.read_text() + f"edit-{i} α\n" + linked["markdown"] + "\n")
        require(Path(receiver.cmd("fetch", linked["link"])["path"]).read_bytes() == blob.read_bytes(), "doc linked bytes differ")
    return {"chat": chat, "doc": doc["group"], "ap": ap, "bp": bp, "blob": blob, "links": links, "last": last}


def exercise_pair(a_bin, b_bin, service, root):
    a = Peer(a_bin, root / "a", service, "a")
    b = Peer(b_bin, root / "b", service, "b")
    try:
        state = join_pair(a, b, root)
        chat, doc = state["chat"], state["doc"]
        for i, (actor, observer) in enumerate(((a, b), (b, a))):
            for gid in (chat, doc):
                epoch = next(g["epoch"] for g in actor.cmd("groups") if g["group"] == gid)
                name = f"epoch-{i}-{gid[:6]}"
                actor.cmd("name", f"--group={gid}", name)
                wait(lambda: observer.cmd("groups"), lambda gs: any(g["group"] == gid and g.get("name") == name for g in gs), "settings across versions")
                handle = f"guest{i}-{gid[:6]}"
                guest = Peer(observer.bin, root / handle, service, handle)
                try:
                    guest.cmd("identity", "join", actor.cmd("identity", "invite")["link"])
                    wait(lambda: actor.cmd("identity", "list"), lambda ids: any(handle in d.get("sessions", []) for d in ids["devices"]), "guest presence")
                    actor.cmd("add", handle, f"--group={gid}")
                    joined_groups = groups(guest, [gid])
                    if gid == doc:
                        guest_path = Path(joined_groups[0]["file"])
                        wait(lambda: guest_path.read_text(), lambda text: text == state["ap"].read_text(), "added doc snapshot applied")
                        src, dest = (state["ap"], state["bp"]) if i == 0 else (state["bp"], state["ap"])
                        text = guest_path.read_text() + f"added guest edit {handle}\n"
                        edit_doc(guest, actor, guest_path, src, text)
                        wait(lambda: dest.read_text(), lambda value: value == text, "observer applied guest edit")
                        observer.expect("edited", lambda e: any(handle in by for by in e.get("by", [])))
                    wait(lambda: observer.cmd("members", f"--group={gid}"), lambda ms: len(ms["members"]) == 3, "Add epoch observed")
                    actor.cmd("remove", guest.ready["fp"], f"--group={gid}")
                    groups(guest, [])
                    wait(lambda: observer.cmd("members", f"--group={gid}"), lambda ms: len(ms["members"]) == 2, "remove epoch observed")
                    rejoined = guest.cmd("join", actor.cmd("invite", f"--group={gid}")["link"])
                    if gid == doc:
                        guest_path = Path(rejoined["file"])
                        wait(lambda: guest_path.read_text(), lambda text: text == state["ap"].read_text(), "rejoined doc snapshot applied")
                        text = guest_path.read_text() + f"rejoined guest edit {handle}\n"
                        edit_doc(guest, actor, guest_path, src, text)
                        wait(lambda: dest.read_text(), lambda value: value == text, "observer applied rejoined edit")
                        observer.expect("edited", lambda e: any(handle in by for by in e.get("by", [])))
                    guest.cmd("leave", f"--group={gid}")
                    groups(guest, [])
                    wait(lambda: observer.cmd("members", f"--group={gid}"), lambda ms: len(ms["members"]) == 2, "leave observed")
                    advanced = next(g["epoch"] for g in actor.cmd("groups") if g["group"] == gid)
                    require(advanced > epoch, "membership/settings did not advance epoch")
                    wait(lambda: observer.cmd("groups"), lambda gs: any(g["group"] == gid and g["epoch"] == advanced for g in gs), "epoch agreement")
                finally:
                    guest.stop()
            state["last"] = message(actor, observer, chat, f"after-epochs-{i}", after=state["last"])["pos"]
            src, dest = (state["ap"], state["bp"]) if i == 0 else (state["bp"], state["ap"])
            edit_doc(actor, observer, src, dest, src.read_text() + f"after epochs {i}\n")
        fp = b.ready["fp"]
        b.stop()
        a.cmd("name", f"--group={chat}", "Missed epoch")
        missed = send(a, f"--group={chat}", "offline catchup")
        require(missed["pos"] > state["last"], "offline epoch reset the global position")
        text = state["ap"].read_text() + "missed doc change\n"
        state["ap"].write_text(text)
        a.cmd("groups")
        b = Peer(b_bin, root / "b", service, "b")
        require(b.ready["fp"] == fp, "restart changed session")
        got = b.expect("message", lambda e: e["content"] == "offline catchup", timeout=60)
        require((got["id"], got["pos"], got["group"]) == (missed["id"], missed["pos"], "Missed epoch"), "restart catchup state")
        wait(lambda: state["bp"].read_text(), lambda value: value == text, "restarted plugin state")
        for link in state["links"]:
            require(Path(b.cmd("fetch", link)["path"]).read_bytes() == state["blob"].read_bytes(), "restart doc blob")
        message(b, a, chat, "after restart", after=missed["pos"])
    finally:
        a.stop()
        b.stop()


def sequential(a_bin, b_bin, service, root):
    a = Peer(a_bin, root / "a", service, "same-handle")
    b = Peer(b_bin, root / "b", service, "remote")
    try:
        state = join_pair(a, b, root)
        fp, name = a.ready["fp"], a.ready["name"]
        identity = a.cmd("identity", "list")["identity"]
        device = (a.home / "device.json").read_bytes()
        hashes = {link.removeprefix("lmk:").split(".")[0] for link in state["links"]}
        ciphertext = {str(p.relative_to(a.home)): sha(p) for p in a.home.rglob("*.data") if p.stem in hashes}
        require(len(ciphertext) == len(hashes), "same-handle fixture is missing linked native ciphertext")
        save(root / "ciphertext-before.json", ciphertext)
        for i, binary in enumerate((b_bin, a_bin)):
            a.stop()
            text = state["bp"].read_text() + f"offline switch {i}\n"
            state["bp"].write_text(text)
            b.cmd("groups")
            sent = send(b, f"--group={state['chat']}", f"switch {i}")
            require(sent["pos"] > state["last"], "switch reset the global position")
            a = Peer(binary, root / "a", service, "same-handle")
            require((a.ready["fp"], a.ready["name"]) == (fp, name), "same handle/device identity changed")
            require((a.home / "device.json").read_bytes() == device and a.cmd("identity", "list")["identity"] == identity, "device/identity changed on version switch")
            got = a.expect("message", lambda e: e["content"] == f"switch {i}", timeout=60)
            require(got["id"] == sent["id"] and got["pos"] == sent["pos"], "switch lost chat state")
            groups(a, [state["chat"], state["doc"]])
            wait(lambda: state["ap"].read_text(), lambda text: text == state["bp"].read_text(), "same-handle plugin catchup")
            for link in state["links"]:
                require(Path(a.cmd("fetch", link)["path"]).read_bytes() == state["blob"].read_bytes(), "switch lost ciphertext")
            for path, digest in ciphertext.items():
                require(sha(a.home / path) == digest, f"switch changed native ciphertext {path}")
            state["last"] = message(a, b, state["chat"], f"switched reply {i}", reply=sent["id"], after=sent["pos"])["pos"]
    finally:
        a.stop()
        b.stop()


def device_owner(peer, expected):
    info = (peer.home / "device.lock").stat()
    identity = f"{os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}:{info.st_ino}"
    locks = [line.split() for line in Path("/proc/locks").read_text().splitlines()]
    owners = [int(row[4]) for row in locks if row[5] == identity]
    require(owners == [expected.proc.pid], f"expected exactly one device owner {expected.proc.pid}, got {owners}")


def concurrent(a_bin, b_bin, service, root):
    owner = Peer(a_bin, root / "owner", service, "owner")
    follower = Peer(b_bin, root / "follower", service, "follower", home=owner.home)
    remote = Peer(b_bin, root / "remote", service, "remote")
    try:
        state = join_pair(owner, remote, root)
        device_owner(follower, owner)
        follower.cmd("identity", "rename", "Shared identity")
        require(owner.cmd("identity", "list")["name"] == "Shared identity", "follower did not use other-version device owner")
        for gid in (state["chat"], state["doc"]):
            follower.cmd("join", remote.cmd("invite", f"--group={gid}")["link"])
        def presence(peer, handles):
            expected = {(state["chat"], "chat"), (state["doc"], "doc")}
            return wait(lambda: peer.cmd("identity", "list"),
                        lambda ids: sorted(h for d in ids["devices"] for h in d.get("sessions", [])) == sorted(handles)
                        and all({(g["group"], g["kind"]) for d in ids["devices"] for g in d.get("groups", [])
                                 if g.get("session") == handle} == expected for handle in handles), "live identity handles/groups")
        presence(remote, ["owner", "follower", "remote"])
        presence(follower, ["owner", "follower", "remote"])
        device = (owner.home / "device.json").read_bytes()
        endpoint = (owner.home / "device-endpoint").read_bytes()
        owner.proc.kill()
        owner.stop()
        wait(lambda: (owner.home / "device-endpoint").read_bytes() if (owner.home / "device-endpoint").exists() else b"",
             lambda value: bool(value) and value != endpoint, "device owner takeover", timeout=45)
        device_owner(follower, follower)
        require((follower.home / "device.json").read_bytes() == device, "takeover changed device key")
        follower.cmd("identity", "rename", "After takeover")
        wait(lambda: remote.cmd("identity", "list"), lambda ids: ids["name"] == "After takeover", "takeover identity operation")
        presence(remote, ["follower", "remote"])
        sent = message(follower, remote, state["chat"], "takeover chat", after=state["last"])
        message(remote, follower, state["chat"], "takeover reply", after=sent["pos"])
        fdoc = Path(next(g["file"] for g in follower.cmd("groups") if g["group"] == state["doc"]))
        edit_doc(follower, remote, fdoc, state["bp"], fdoc.read_text() + "takeover doc\n")
        successor = (owner.home / "device-endpoint").read_bytes()
        owner = Peer(a_bin, root / "owner", service, "owner")
        presence(remote, ["owner", "follower", "remote"])
        device_owner(owner, follower)
        require((owner.home / "device-endpoint").read_bytes() == successor, "second owner replaced incumbent")
        require((owner.home / "device.json").read_bytes() == device, "restart changed device identity")
        watcher = Peer(b_bin, root / "remote-watch", service, "remote-watch", home=remote.home)
        try:
            for gid in (state["chat"], state["doc"]):
                watcher.cmd("join", owner.cmd("invite", f"--group={gid}")["link"])
            presence(owner, ["owner", "follower", "remote", "remote-watch"])
            remote.stop()
            presence(owner, ["owner", "follower", "remote-watch"])
            follower.cmd("identity", "rename", "Remote offline")
            remote = Peer(b_bin, root / "remote", service, "remote")
            presence(owner, ["owner", "follower", "remote", "remote-watch"])
            wait(lambda: remote.cmd("identity", "list"), lambda ids: ids["name"] == "Remote offline", "remote identity catchup")
        finally:
            watcher.stop()
        presence(owner, ["owner", "follower", "remote"])
    finally:
        owner.stop()
        follower.stop()
        remote.stop()


def unsupported(a_bin, b_bin, service, root):
    fixture = root / "plugin-disabled"
    fixture.mkdir(parents=True)
    isolated = fixture / "letmeknow"
    shutil.copy2(b_bin, isolated)
    require(sha(isolated) == sha(b_bin), "plugin-disabled binary changed")
    env = environment(root / "disabled-env")
    env["PATH"] = str(fixture)
    target = Peer(isolated, root / "target", service, "target", env=env)
    inviter = Peer(a_bin, root / "inviter", service, "inviter")
    unrelated = Peer(a_bin, root / "unrelated", service, "unrelated")
    try:
        doc = inviter.cmd("invite", "--kind", "doc")
        unrelated.cmd("join", inviter.cmd("invite", f"--group={doc['group']}")["link"])
        inviter.expect("joined", lambda e: e["member"] == unrelated.ready["fp"])
        before = inviter.cmd("members", f"--group={doc['group']}")
        epoch = inviter.cmd("groups")[0]["epoch"]
        event_start = len(inviter.events)
        error = target.cmd("join", doc["link"], ok=False)
        require("does not support doc groups" in error, f"not a targeted kind refusal: {error}")
        require(target.cmd("groups") == [], "unsupported kind installed a group")
        require(inviter.cmd("members", f"--group={doc['group']}") == before, "unsupported kind admitted a member")
        warning = inviter.expect("warning")
        require("does not support doc groups" in json.dumps(warning), f"wrong admission warning: {warning}")
        target.cmd("groups")
        unrelated.cmd("groups")
        require(not any(e["type"] == "warning" for e in target.events + unrelated.events), "warning leaked beyond inviter")
        require(inviter.cmd("groups")[0]["epoch"] == epoch, "unsupported kind advanced the epoch")
        require(not any(e["type"] == "joined" for e in inviter.events[event_start:] + target.events), "unsupported kind emitted joined")
        require(sum(e["type"] == "warning" for e in inviter.events) == 1, "unexpected additional inviter warning")
    finally:
        target.stop()
        inviter.stop()
        unrelated.stop()


def case(results, name, operation, output):
    started = time.monotonic()
    record = {"case": name, "status": "running"}
    results.append(record)
    save(output, results)
    print(f"RUN {name}", flush=True)
    try:
        operation()
        record["status"] = "passed"
    except BaseException as error:
        record.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        record["seconds"] = round(time.monotonic() - started, 3)
        save(output, results)
        print(f"{record['status'].upper()} {name} ({record['seconds']}s)", flush=True)


def positive(a_bin, b_bin, service, root, results, output, label):
    for order, (a, b) in enumerate(((a_bin, b_bin), (b_bin, a_bin))):
        for name, operation in (("chat-doc-epochs-restart", exercise_pair), ("same-handle-roundtrip", sequential),
                                ("device-owner-presence-takeover", concurrent), ("unsupported-kind", unsupported)):
            dest = root / f"{order}-{name}"
            case(results, f"{label}/{order}/{name}", lambda op=operation, a=a, b=b, dest=dest: op(a, b, service, dest), output)


def logical_tree(root):
    physical = tree(root)
    result = dict(physical)
    for name, item in physical.items():
        path = Path(root) / name
        if item["type"] != "file":
            continue
        parts = Path(name).parts
        if len(parts) == 3 and parts[0] == "sessions" and parts[2] == "groups.json":
            listed = json.loads(path.read_text())
            indexed = {group["group"]: group for group in listed}
            require(len(indexed) == len(listed), "duplicate session group index entry")
            result[name] = {"type": "group-index", "mode": item["mode"], "groups": indexed}
            continue
        with path.open("rb") as file:
            header = file.read(16)
        if header != b"SQLite format 3\x00":
            continue
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2) as db:
            db.execute("BEGIN")
            schema = db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name").fetchall()
            tables = {}
            for kind, table, _, _ in schema:
                if kind == "table":
                    quoted = '"' + table.replace('"', '""') + '"'
                    rows = db.execute(f"SELECT * FROM {quoted}").fetchall()
                    tables[table] = sorted(json.dumps(row, default=lambda b: {"bytes": b.hex()}) for row in rows)
            result[name] = {"type": "sqlite", "mode": item["mode"], "schema": schema, "tables": tables}
        for suffix in ("-wal", "-shm", "-journal"):
            result.pop(name + suffix, None)
    return result


def snapshot(peers, destination, logical=False):
    inventory = {}
    for i, peer in enumerate(peers):
        inventory[str(i)] = logical_tree(peer.home) if logical else tree(peer.home, timestamps=True)
        info = peer.home.stat()
        inventory[str(i)]["."] = {"type": "directory", "mode": stat.S_IMODE(info.st_mode)}
        if not logical:
            inventory[str(i)]["."].update(mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)
    save(destination, inventory)
    if logical:
        save(Path(destination).with_suffix(".raw.json"), {str(i): tree(peer.home, timestamps=True) for i, peer in enumerate(peers)})
    return inventory


def refused_open(binary, peer):
    result = e2e.execute([binary, "--session", peer.session, "listen"], env=peer.env, timeout=15)
    with (peer.root / "refused-opens.jsonl").open("a") as file:
        file.write(json.dumps({"bin": str(binary), "code": result.returncode, "out": result.stdout, "err": result.stderr}) + "\n")
    require(result.returncode > 0 and '"type":"ready"' not in result.stdout.replace(" ", ""), "incompatible open succeeded or crashed")
    require(re.search(r"incompatible|format|holds the state of an earlier letmeknow", result.stderr, re.I), f"not a format refusal: {result.stderr}")


def refused_commands(binary, peer, state):
    for args in (("send", f"--group={state['chat']}", "FORBIDDEN cross-version send"),
                 ("identity", "rename", "FORBIDDEN identity"),
                 ("doc", "attach", f"--group={state['doc']}", str(state["blob"])),
                 ("sessions", "remove", peer.session)):
        error = peer.cmd(*args, binary=binary, ok=False, timeout=15)
        require(re.search(r"home|format|incompatible|channel|missing field|closed|connection|response", error, re.I),
                f"not a home/channel refusal: {error}")
        require(peer.proc.poll() is None, "old command stopped the receiver")
        require(peer.cmd("identity", "list")["name"] == "Compatibility", "old command mutated identity")
        groups(peer, [state["chat"], state["doc"]])


def default_isolation(a_bin, b_bin, a_service, b_service, a_name, b_name, root):
    env = environment(root / "env")
    homes = [Path(env["XDG_DATA_HOME"]) / name for name in (a_name, b_name)]
    a = Peer(a_bin, root / "first", a_service, "default", home=homes[0], default=True, env=env)
    try:
        require(homes[0].is_dir(), f"wrong default namespace, expected {homes[0]}")
        a.cmd("identity", "create", "First default")
        doc = a.cmd("invite", "--kind", "doc", "--name", "Retained default")
        a.stop()
        before = tree(homes[0], timestamps=True)
        b = Peer(b_bin, root / "second", b_service, "default", home=homes[1], default=True, env=env)
        try:
            require(homes[1].is_dir() and homes[0] != homes[1], "default homes collide")
            require(tree(homes[0], timestamps=True) == before, "default startup changed other version's home")
            b.cmd("identity", "create", "Second default")
            a = Peer(a_bin, root / "first", a_service, "default", home=homes[0], default=True, env=env)
            require(a.ready["fp"] != b.ready["fp"], "defaults adopted one session")
            groups(a, [doc["group"]])
            require(a.cmd("identity", "list")["name"] == "First default", "default identity not isolated")
            require(b.cmd("identity", "list")["name"] == "Second default", "default identity not isolated")
        finally:
            b.stop()
    finally:
        a.stop()


def retained(before, after):
    for name, item in before.items():
        require(name in after, f"pre-existing path disappeared: {name}")
        if item["type"] == "group-index":
            require(item["mode"] == after[name]["mode"], f"group index mode changed: {name}")
            for gid, group in item["groups"].items():
                require(after[name]["groups"].get(gid) == group, f"pre-existing group index changed: {name}/{gid}")
            continue
        if item["type"] != "sqlite":
            require(item == after[name], f"pre-existing file/mode changed: {name}")
            continue
        newer = after[name]
        require(item["schema"] == newer["schema"] and item["mode"] == newer["mode"], f"schema/mode changed: {name}")
        for table, rows in item["tables"].items():
            for row in (Counter(rows) - Counter(newer["tables"][table])).elements():
                values = json.loads(row)
                # A deliberately uncertain new-group attempt may extend these indexes, never shrink them.
                if table == "lmk" and values[0] in ({"bytes": b"node/groups".hex()}, {"bytes": b"node/logs".hex()}):
                    matching, = [json.loads(r) for r in newer["tables"][table] if json.loads(r)[0] == values[0]]
                    old_ids = json.loads(bytes.fromhex(values[1]["bytes"]))
                    new_ids = json.loads(bytes.fromhex(matching[1]["bytes"]))
                    require(len(new_ids) == len(set(new_ids)) and set(old_ids) <= set(new_ids), f"attempt lost/duplicated index entries: {name}/{values[0]}")
                else:
                    raise AssertionError(f"pre-existing durable value changed: {name}/{table}: {row}")


def cross_service(peers, states, service, old_service, root, probe, contract):
    services = (service, old_service)
    before = snapshot(peers, root / "cross-before.json", logical=True)
    stores = [logical_tree(s.state) for s in services]
    save(root / "cross-service-before.json", stores)
    save(root / "cross-service-before.raw.json", [tree(s.state, timestamps=True) for s in services])
    outcomes = []
    for peer, other in ((peers[0], old_service), (peers[2], service)):
        try:
            error = peer.cmd("invite", "--name", "uncertain cross-service attempt", "--membership",
                             other.env["LETMEKNOW_MEMBERSHIP"], ok=False, timeout=45)
            require(re.search(r"unavailable|protocol|connect|transport|refus", error, re.I), f"not a service refusal: {error}")
            outcome = "explicit-refusal"
        except subprocess.TimeoutExpired:
            # The unchanged old client can keep retrying. This is NOT rejection evidence:
            # both direct ALPN controls below and every preservation assertion must still pass.
            outcome = "bounded-uncertain"
        outcomes.append({"bin": peer.bin, "service": other.env["LETMEKNOW_MEMBERSHIP"], "outcome": outcome})
        save(root / "cross-rpc-results.json", outcomes)
    after = snapshot(peers, root / "cross-after.json", logical=True)
    for i in before:
        retained(before[i], after[i])
    for s, old in zip(services, stores, strict=True):
        require(logical_tree(s.state) == old, "cross-service attempt changed service rows/anchors")
    save(root / "cross-service-after.json", [logical_tree(s.state) for s in services])
    save(root / "cross-service-after.raw.json", [tree(s.state, timestamps=True) for s in services])
    probe_results = []
    for i, server in enumerate(services):
        own = contract["candidate_alpn" if i == 0 else "previous_alpn"]
        other = contract["previous_alpn" if i == 0 else "candidate_alpn"]
        targets = [(server.env["LETMEKNOW_MEMBERSHIP"].split("@")[0], f"127.0.0.1:{server.membership_port}")]
        for path in (peers[i*2].home / "addresses").glob("*.json"):
            addresses = json.loads(path.read_text())["addrs"]
            require(addresses, "no actual application endpoint addresses")
            # Replace the discovered local interface IP, not the bound UDP port.
            port = addresses[0].rsplit(":", 1)[1]
            targets.append((path.stem, f"127.0.0.1:{port}"))
        require(len(targets) >= 2, "no native application ALPN target")
        for key, address in targets:
            for alpn, expected in ((own, "accept"), (other, "refuse")):
                result = e2e.execute([probe, key, address, alpn, expected], env=server.env, timeout=15)
                probe_results.append({"key": key, "address": address, "alpn": alpn, "expect": expected,
                                      "code": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
                save(root / "alpn-results.json", probe_results)
                evidence = "accepted" if expected == "accept" else "refused: TLS no_application_protocol (0x178)"
                require(result.returncode == 0 and result.stdout.strip() == evidence, f"direct ALPN {expected} failed: {result.stderr} {result.stdout}")
    after_alpn = snapshot(peers, root / "cross-after-alpn.json", logical=True)
    for i in before:
        retained(before[i], after_alpn[i])
    for server, old in zip(services, stores, strict=True):
        require(logical_tree(server.state) == old, "ALPN probes changed service rows/anchors")
    for i, state in enumerate(states):
        a, b = peers[2*i:2*i+2]
        message(a, b, state["chat"], "after cross-service refusal", after=state["last"])
        for link in state["links"]:
            require(Path(a.cmd("fetch", link)["path"]).read_bytes() == state["blob"].read_bytes(), "cross-service lost blob")


def incompatible(candidate, published, service, root, contract, results, output, probe):
    old_service = Service(published, root / "published-service", contract["previous_service_initialize"])
    bundle = root / "local-test-ca.pem"
    bundle.write_bytes((service.root / "cert.pem").read_bytes() + (old_service.root / "cert.pem").read_bytes())
    for server in (service, old_service):
        server.env["LETMEKNOW_CA"] = str(bundle)
    peers = []
    try:
        states = []
        for label, binary, server in (("candidate", candidate, service), ("published", published, old_service)):
            a = Peer(binary, root / label / "a", server, "primary")
            peers.append(a)
            b = Peer(binary, root / label / "b", server, "witness")
            peers.append(b)
            states.append(join_pair(a, b, a.home))
            (a.home / "unknown-sentinel").write_bytes(b"preserve unknown state\x00\xff")
        def home_opens():
            for peer in peers:
                peer.stop()
            before = snapshot(peers, root / "homes-before.json")
            for binary, peer in ((published, peers[0]), (candidate, peers[2])):
                refused_open(binary, peer)
                after = snapshot(peers, root / f"homes-after-{peer.root.parent.name}.json")
                require(before == after, "reciprocal refused open changed a populated home")
            for i, peer in enumerate(peers):
                peers[i] = Peer(peer.bin, peer.root, peer.service, peer.session, home=peer.home)
                require(peers[i].ready["fp"] == peer.ready["fp"], "own reopen changed session fingerprint")
            for i, state in enumerate(states):
                a, b = peers[2*i:2*i+2]
                groups(a, [state["chat"], state["doc"]])
                require(a.cmd("identity", "list")["name"] == "Compatibility", "own reopen lost identity")
                for link in state["links"]:
                    require(Path(a.cmd("fetch", link)["path"]).read_bytes() == state["blob"].read_bytes(), "own reopen lost native blob")
                state["last"] = message(a, b, state["chat"], "usable after reciprocal refusal", after=state["last"])["pos"]
        case(results, "previous-incompatible/reciprocal-complete-homes", home_opens, output)
        def commands():
            before = snapshot(peers, root / "commands-before.json", logical=True)
            for binary, peer, state in ((published, peers[0], states[0]), (candidate, peers[2], states[1])):
                refused_open(binary, peer)
                refused_commands(binary, peer, state)
            after = snapshot(peers, root / "commands-after.json", logical=True)
            require(before == after, "refused caller/Stop changed durable logical records or blobs")
            for peer in peers:
                require(not any("FORBIDDEN" in json.dumps(e) for e in peer.events), "old caller reached application handler")
        case(results, "previous-incompatible/live-callers-and-receivers", commands, output)
        def invites():
            links = []
            for peer, state in ((peers[0], states[0]), (peers[2], states[1])):
                links.append((peer.cmd("invite", f"--group={state['chat']}")["link"], peer.cmd("identity", "invite")["link"]))
            before = snapshot(peers, root / "invites-before.json", logical=True)
            for peer, (group, device) in ((peers[2], links[0]), (peers[0], links[1])):
                for args in (("join", group), ("identity", "join", device)):
                    error = peer.cmd(*args, ok=False, timeout=15)
                    require(re.search(r"version|incompatible", error, re.I), f"not an explicit invite version refusal: {error}")
            after = snapshot(peers, root / "invites-after.json", logical=True)
            require(before == after, "incompatible invite changed either client's durable state")
        case(results, "previous-incompatible/group-and-device-invites", invites, output)
        for i, ordered in enumerate(((published, candidate, old_service, service, contract["previous_default_home"], contract["candidate_default_home"]),
                                     (candidate, published, service, old_service, contract["candidate_default_home"], contract["previous_default_home"]))):
            case(results, f"previous-incompatible/defaults-{i}", lambda ordered=ordered, i=i: default_isolation(*ordered, root / f"defaults-{i}"), output)
        def service_boundary():
            for peer in peers:
                peer.stop()
            original = snapshot(peers, root / "transport-original-homes-before.json")
            transport, transport_states = [], []
            try:
                # Anonymous populated clients keep an uncertain new-group attempt from publishing
                # identity-presence changes. The original identity homes remain quiescent and byte-checked.
                for label, binary, server in (("candidate", candidate, service), ("published", published, old_service)):
                    a = Peer(binary, root / "transport" / label / "a", server, "primary")
                    transport.append(a)
                    b = Peer(binary, root / "transport" / label / "b", server, "witness")
                    transport.append(b)
                    transport_states.append(join_pair(a, b, a.home, identity=False))
                cross_service(transport, transport_states, service, old_service, root, probe, contract)
            finally:
                for peer in transport:
                    peer.stop()
                require(snapshot(peers, root / "transport-original-homes-after.json") == original, "cross-service work changed original identity homes")
        case(results, "previous-incompatible/cross-service-and-alpn", service_boundary, output)
    finally:
        for peer in peers:
            peer.stop()
        old_service.stop()


def guard_controls(binary, service, root, results, output):
    def wrong_namespace():
        try:
            default_isolation(binary, binary, service, service, "letmeknow-v5", "letmeknow", root / "namespace")
        except AssertionError as error:
            require("wrong default namespace" in str(error), f"wrong negative-control failure: {error}")
        else:
            raise AssertionError("wrong namespace control was not detected")
    case(results, "control/detect-wrong-default-namespace", wrong_namespace, output)
    def wrong_receiver():
        a = Peer(binary, root / "receiver-a", service, "receiver-a")
        b = Peer(binary, root / "receiver-b", service, "receiver-b")
        try:
            state = join_pair(a, b, root)
            try:
                refused_commands(binary, a, state)
            except AssertionError as error:
                require("unexpected command success" in str(error), f"wrong negative-control failure: {error}")
            else:
                raise AssertionError("unguarded receiver control was not detected")
            b.expect("message", lambda e: e["content"] == "FORBIDDEN cross-version send")
        finally:
            a.stop()
            b.stop()
    case(results, "control/detect-unguarded-real-receiver", wrong_receiver, output)


def control_run(args):
    root = Path(args.out).resolve()
    root.mkdir(parents=True)
    provenance(root, args)
    env = environment(root / "resolver-home")
    if args.artifacts:
        manifest = json.loads(Path(args.artifacts).read_text())
        require(manifest["kind"] == "published-positive-control-not-candidate", "not a control manifest")
        artifacts = manifest["artifacts"]
        require([a["version"] for a in artifacts] == ["0.15.0", "0.15.1"], "wrong control versions")
        for source in manifest["metadata"]:
            require(sha(source["path"]) == source["sha256"], "control metadata changed")
    else:
        cli, cs = metadata(CLI, root)
        native, ns = metadata(PLATFORM, root)
        artifacts = [download(cli, native, v, "published-positive-control", root / "packages", env) for v in ("0.15.0", "0.15.1")]
        manifest = {"kind": "published-positive-control-not-candidate", "metadata": [cs, ns], "artifacts": artifacts}
    save(root / "control-manifest.json", manifest)
    metadata_values = [json.loads(Path(s["path"]).read_text()) for s in manifest["metadata"]]
    for artifact in artifacts:
        release_metadata(*metadata_values, artifact["version"])
        for pkg, data in zip(artifact["packages"], metadata_values, strict=True):
            dist = data["versions"][artifact["version"]]["dist"]
            require(pkg["name"] == data["name"] and pkg["version"] == artifact["version"]
                    and pkg["integrity"] == dist["integrity"] and pkg["tarball_url"] == dist["tarball"], "control package provenance changed")
        verify(artifact, env)
    # 0.15.0 predates ready.bin; only this digest-verified control permits its absence.
    LEGACY_READY.add(artifacts[0]["binary_sha256"])
    service = Service(artifacts[1]["bin"], root / "service", False)
    try:
        results, output = [], root / "results.json"
        positive(artifacts[0]["bin"], artifacts[1]["bin"], service, root / "matrix", results, output, "published-0.15.0-0.15.1")
        guard_controls(artifacts[1]["bin"], service, root / "guard-controls", results, output)
    finally:
        service.stop()


def old_writer(args):
    manifest = load_manifest(args.baselines)
    minor = manifest["contract"]["old_writer_minor"]
    if minor is None:
        status = {"status": "not-applicable", "reason": "explicit contract disables the legacy service-writer test"}
        save(Path(args.baselines).resolve().parent / "old-writer-result.json", status)
        print(json.dumps(status))
        return
    require(minor == "0.15", "the old_writer fixture specifically exercises 0.15")
    artifact, = [a for a in manifest["artifacts"] if a["version"].rsplit(".", 1)[0] == minor]
    env = {**os.environ, "LMK_0_15_BIN": artifact["bin"], "CARGO_BUILD_JOBS": "4"}
    result = e2e.execute(["cargo", "test", "-p", "lmk-membership", "--test", "old_writer", "--", "--ignored"], env=env, timeout=1100)
    log = Path(args.baselines).resolve().parent / "old-writer.log"
    log.write_text(result.stdout + result.stderr)
    passed = result.returncode == 0 and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", result.stdout) is not None
    save(log.with_name("old-writer-result.json"), {"status": "passed" if passed else "failed", "bin": artifact["bin"], "log": str(log)})
    require(passed, f"published service old-writer gate failed: {log}")
    print(f"PASS published service old-writer: {artifact['bin']}; {log}")


def run_matrix(args):
    manifest = load_manifest(args.baselines)
    root = Path(args.baselines).resolve().parent / "run"
    root.mkdir()
    provenance(root, args)
    results, output = [], root / "results.json"
    save(output, results)
    require(Path(args.bin).is_absolute(), "candidate --bin must be an explicit absolute path")
    binary = Path(args.bin).resolve(strict=True)
    env = environment(root / "env")
    def candidate_identity():
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
        require(cargo == manifest["candidate_version"], "Cargo/manifest version mismatch (no version overrides)")
        require(cargo.rsplit(".", 1)[0] == manifest["contract"]["candidate_minor"], "Cargo/contract minor mismatch")
        binary_version(binary, cargo, env)
        for kind in ("doc", "table"):
            require((binary.parent / f"letmeknow-kind-{kind}").is_file(), f"missing candidate {kind} plugin")
        identity = {"bin": str(binary), "version": cargo, "sha256": sha(binary),
                    "plugins": {p.name: sha(p) for p in binary.parent.glob("letmeknow-kind-*")}}
        if manifest["contract"]["previous_policy"] == "incompatible":
            require(args.alpn_probe and Path(args.alpn_probe).is_absolute() and Path(args.alpn_probe).is_file(),
                    "explicit ALPN fixture executable required")
            identity["alpn_fixture"] = {"bin": args.alpn_probe, "sha256": sha(args.alpn_probe)}
        save(root / "candidate.json", identity)
    case(results, "candidate-identity", candidate_identity, output)
    service = Service(binary, root / "candidate-service", manifest["contract"]["candidate_service_initialize"])
    try:
        positive(binary, binary, service, root / "self", results, output, "candidate-candidate")
        for artifact in manifest["artifacts"]:
            if artifact["role"] in ("same-minor-positive", "previous-compatible"):
                positive(binary, artifact["bin"], service, root / artifact["role"], results, output, artifact["role"])
            else:
                incompatible(binary, artifact["bin"], service, root / "incompatible", manifest["contract"], results, output, args.alpn_probe)
    finally:
        service.stop()


def timeout_handler(signum, frame):
    raise TimeoutError("compatibility network/job deadline exceeded")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    resolver = sub.add_parser("resolve")
    resolver.add_argument("--candidate-version", required=True)
    resolver.add_argument("--contract", default=str(ROOT / "test/compatibility-contract.json"))
    resolver.add_argument("--out", required=True)
    runner = sub.add_parser("run")
    runner.add_argument("--bin", required=True)
    runner.add_argument("--baselines", required=True)
    runner.add_argument("--alpn-probe", help="explicit built compatibility_alpn fixture; required for incompatible previous minor")
    control = sub.add_parser("positive-control")
    control.add_argument("--out", required=True)
    control.add_argument("--artifacts", help="explicit verified control-manifest reuse; never a CI resolver fallback")
    writer = sub.add_parser("old-writer")
    writer.add_argument("--baselines", required=True)
    args = parser.parse_args()
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "this gate is Linux x64 only")
    require(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0, "cannot enable descendant reaping")
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.signal(signal.SIGTERM, timeout_handler)
    # Leave the rest of the 20-minute CI bound for reaping the at-most-eight process groups.
    signal.alarm(1020)
    try:
        if args.action == "resolve":
            resolve(args)
        elif args.action == "positive-control":
            control_run(args)
        elif args.action == "old-writer":
            old_writer(args)
        else:
            run_matrix(args)
    finally:
        signal.alarm(0)
        for proc in list(reversed(e2e.PROCESSES)):
            e2e.stop(proc)


if __name__ == "__main__":
    main()
