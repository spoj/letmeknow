#!/usr/bin/env python3
"""Native sessions and a separately served HTTPS frontend use the real local membership/iroh relay.
--no-browser skips the frontend. LMK_E2E_BIN tests an already-built native artifact."""
import functools, http.server, json, os, queue, shutil, signal, socket, ssl, subprocess, sys, tempfile, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("LMK_E2E_BIN") or os.path.join(ROOT, os.environ.get("CARGO_TARGET_DIR", "target"), "debug", "letmeknow" + (".exe" if os.name == "nt" else ""))
WEB = os.path.join(ROOT, "web")
BROWSER = "--no-browser" not in sys.argv
TMP = None
PROCESSES = []
ENV = {**os.environ, "NO_PROXY": "localhost,127.0.0.1"}
ENV.pop("LETMEKNOW_SESSION", None)


def free_port():
    """A port free on every address for UDP and TCP alike, as `serve` binds them."""
    for _ in range(100):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            udp.bind(("", 0))
            port = udp.getsockname()[1]
            try:
                tcp.bind(("", port))
                return port
            except OSError:
                pass
    raise RuntimeError("no free TCP/UDP port after 100 attempts")


def spawn(args, **kwargs):
    proc = subprocess.Popen(args, start_new_session=os.name != "nt", **kwargs)
    PROCESSES.append(proc)
    return proc


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    if os.name != "nt":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        # The Linux compatibility runner is a subreaper, including orphaned plugins.
        deadline = time.monotonic() + 5
        while True:
            try:
                pid, _ = os.waitpid(-proc.pid, os.WNOHANG)
            except ChildProcessError:
                break
            if not pid:
                if time.monotonic() > deadline:
                    raise RuntimeError(f"descendants of {proc.pid} did not exit")
                time.sleep(0.01)
        if sys.platform == "linux":
            deadline = time.monotonic() + 5
            while True:
                with open(f"/proc/self/task/{os.getpid()}/children") as children:
                    orphaned = set(map(int, children.read().split())) - {p.pid for p in PROCESSES}
                if not orphaned:
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError(f"orphaned descendants did not exit: {orphaned}")
                for pid in orphaned:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, os.WNOHANG)
                time.sleep(0.01)
    PROCESSES.remove(proc)


def execute(args, *, env, timeout=60, input=None):
    proc = spawn([str(a) for a in args], env=env, stdin=subprocess.PIPE,
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        stdout, stderr = proc.communicate(input, timeout=timeout)
        return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)
    finally:
        stop(proc)
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is not None:
                pipe.close()


def check(condition, message):
    if not condition:
        sys.exit(f"FAIL: {message}")
    print(f"ok - {message}")


def home(name):
    return os.path.join(TMP, name)


def run(session, *args, ok=True, input=None, device=None, bin=BIN):
    env = {**ENV, "LETMEKNOW_HOME": home(device or session)}
    result = execute([bin, "--session", session, *args], env=env, input=input, timeout=120)
    if ok and result.returncode:
        sys.exit(f"{session} {args}: {result.stderr}")
    return json.loads(result.stdout) if result.returncode == 0 else result.stderr


class Listener:
    """A session process, in its own home (its own device) unless it shares `device`'s."""

    def __init__(self, session, device=None, bin=BIN, *, env=None, log=None, keep_log=False, ready_bin=True):
        self.session, self.lines, self.events = session, queue.Queue(), []
        self.bin = os.path.abspath(bin)
        self.env = env if env is not None else {**ENV, "LETMEKNOW_HOME": home(device or session)}
        args = [self.bin, "--session", session, "listen", "--hold", "0"]
        if keep_log:
            args.append("--keep-log")
        self.log = open(log or os.path.join(TMP, f"{session}.log"), "a")
        self.proc = None
        try:
            self.proc = spawn(args, env=self.env, stdout=subprocess.PIPE, stderr=self.log, text=True, encoding="utf-8")
            self.reader = threading.Thread(target=self.read, daemon=True)
            self.reader.start()
            self.ready = self.expect("ready")
            if ready_bin and not os.path.samefile(self.ready["bin"], self.bin):
                raise AssertionError(f"ready.bin is not {self.bin}: {self.ready}")
        except BaseException:
            self.stop()
            raise

    def read(self):
        try:
            for line in self.proc.stdout:
                self.log.write(line)
                self.log.flush()
                event = json.loads(line)
                self.events.append(event)
                self.lines.put(event)
        except (ValueError, OSError) as error:
            self.lines.put({"type": "reader-error", "error": str(error)})
        finally:
            self.lines.put({"type": "eof"})

    def expect(self, kind, predicate=lambda e: True, timeout=30):
        deadline, seen = time.monotonic() + timeout, []
        while time.monotonic() < deadline:
            try:
                event = self.lines.get(timeout=max(0, deadline - time.monotonic()))
            except queue.Empty:
                break
            if event["type"] == kind and predicate(event):
                return event
            if event["type"] in ("warning", "reader-error", "eof"):
                raise AssertionError(f"{self.session} waiting for {kind}: {event}; log {self.log.name}")
            seen.append(event)
        raise AssertionError(f"{self.session}: no {kind} event, only {seen}; log {self.log.name}")

    def stop(self):
        if self.proc is not None and self.proc in PROCESSES:
            stop(self.proc)
            self.reader.join(timeout=5)
            self.proc.stdout.close()
        self.log.close()


def write(name, text):
    path = os.path.join(TMP, name)
    with open(path, "wb") as f:
        f.write(text if isinstance(text, bytes) else text.encode())
    return path


def content(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def until(produce, accept, timeout=20):
    deadline = time.time() + timeout
    while True:
        result = produce()
        if accept(result) or time.time() > deadline:
            return result
        time.sleep(0.3)


def serve():
    """A local `letmeknow serve` with a self-signed certificate; returns it and its membership address."""
    cert, key = os.path.join(TMP, "cert.pem"), os.path.join(TMP, "key.pem")
    subprocess.run(["cargo", "run", "-q", "-p", "letmeknow", "--example", "self_signed", "--", cert, key], cwd=ROOT, check=True)
    https = free_port()
    args = [BIN, "serve", "--domain", "localhost", "--https-port", str(https), "--http-port", str(free_port()), "--membership-port", str(free_port()),
            "--qad-port", str(free_port()), "--state", os.path.join(TMP, "serve"), "--cert", cert, "--key", key]
    proc = spawn(args, env=ENV, stdout=subprocess.PIPE, stderr=open(os.path.join(TMP, "serve.log"), "w"), text=True)
    membership = proc.stdout.readline().strip().removeprefix("membership: ")
    ENV.update(LETMEKNOW_CA=cert, LETMEKNOW_RELAY=f"https://localhost:{https}", LETMEKNOW_MEMBERSHIP=membership)
    return proc


def main():
    global TMP
    TMP = tempfile.mkdtemp(prefix="lmk-e2e-")
    if "LMK_E2E_BIN" not in os.environ:
        subprocess.run(["cargo", "build", "-q", "-p", "letmeknow", "-p", "lmk-kinds"], cwd=ROOT, check=True)
    server = serve()
    frontend = None
    listeners = []
    passed = False
    try:
        if BROWSER:
            config = write("frontend.json", json.dumps({"membershipKey": ENV["LETMEKNOW_MEMBERSHIP"].split("@")[0], "relay": ENV["LETMEKNOW_RELAY"]}))
            dist = os.path.join(TMP, "frontend")
            subprocess.run([shutil.which("npm"), "run", "build"], cwd=WEB,
                           env={**ENV, "LMK_FRONTEND_CONFIG": config, "LMK_FRONTEND_OUT": dist}, check=True)
            subprocess.run([shutil.which("node"), "artifact-test.mjs", dist], cwd=WEB,
                           env={**ENV, "LMK_FRONTEND_CONFIG": config}, check=True)
            with open(os.path.join(dist, "blank.html"), "w") as f:
                f.write("<!doctype html><title>Test setup only</title>")
            frontend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(http.server.SimpleHTTPRequestHandler, directory=dist))
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(os.path.join(TMP, "cert.pem"), os.path.join(TMP, "key.pem"))
            frontend.socket = tls.wrap_socket(frontend.socket, server_side=True)
            frontend_thread = threading.Thread(target=frontend.serve_forever)
            frontend_thread.start()
            ENV.update(URL=f"https://localhost:{frontend.server_port}", FRONTEND_DIST=dist)
        alice, bob, carol = (Listener(s) for s in ("alice", "bob", "carol"))
        listeners += [alice, bob, carol]
        check(os.path.samefile(alice.ready["bin"], BIN), "ready names the session's program, which runs the other commands")
        for name in ("alice", "bob", "carol"):
            run(name, "identity", "create", name.title())
        check(run("bob", "identity", "list")["devices"][0]["you"], "an identity starts with this device on its list")

        # An invite, and chat.
        invite = run("alice", "invite", "--name", "Plans")
        check(invite["link"].startswith("https://letmeknow.dev/i#4.g.") and invite["kind"] == "chat", "invite gives a link to a new chat")
        group = invite["group"]
        check("serve" in run("alice", "groups")[0]["membership"], "its log is on the local letmeknow serve")
        joined = run("bob", "join", invite["link"])
        check(joined["group"] == group and len(joined["members"]) == 2, "bob joins through the link")
        event = alice.expect("joined")
        check(event["member"] == f"Bob · {bob.ready['name']}" and event["how"] == "invite", "alice sees bob join by invite, as his identity claims")
        check("unknown, used or expired" in run("carol", "join", invite["link"], ok=False), "an invite link works once")
        seen = next(m for m in run("alice", "members")["members"] if m["handle"] == "bob")
        check(seen["identity"]["name"] == "Bob" and seen["identity"]["how"] == "unknown", "another identity is known by its own name, a claim")

        sent = run("alice", "send", "hello bob")
        check(isinstance(sent.get("pos"), int), "send answers the message's position in the group's log")
        got = bob.expect("message")
        check(got["content"] == "hello bob" and got["from"] == f"Alice · {alice.ready['name']}", "bob receives it from alice, as her identity claims")
        reply = run("bob", "send", "--reply-to", got["id"], "hi alice")["id"]
        answer = alice.expect("message")
        check(answer["reply_to"] == got["id"] and "direct" not in answer, "a reply names what it answers")
        history = run("alice", "read", reply, "--ancestors", "1")
        check([m["id"] for m in history] == [sent["id"], reply], "read follows what the sender had read")

        # An attachment.
        token = write("token.txt", "s3cret")
        sent = run("alice", "send", "--attach", token, "the token")
        check(sent["attachment"]["held_by"] == [f"Bob · {bob.ready['name']}"], "an attachment is held by another member before send returns")
        message = bob.expect("message", lambda e: e["content"] == "the token")
        arrived = bob.expect("attachment") if "path" not in message["attachment"] else message["attachment"]
        check(content(arrived["path"]) == "s3cret", "the attachment arrives as a private file")
        check(content(run("bob", "fetch", message["attachment"]["link"])["path"]) == "s3cret", "fetch gives the same file")

        # A doc edited as a file by two sessions.
        notes = write("notes.md", "- [ ] alpha\n- [ ] beta\n")
        doc = run("alice", "invite", "--kind", "doc", "--name", "Notes", notes)
        bob_notes = os.path.join(TMP, "bob-notes.md")
        check(run("bob", "join", doc["link"], bob_notes)["kind"] == "doc", "bob joins the doc into a file of his")
        check(until(lambda: content(bob_notes), lambda text: text == "- [ ] alpha\n- [ ] beta\n"), "the doc's text reaches the joiner")
        with open(bob_notes, "ab") as f:
            f.write(b"- [ ] gamma @alice\n")
        edited = alice.expect("edited", lambda e: e["group"] == "Notes")
        check(edited["by"] == [f"Bob · {bob.ready['name']}"] and edited["direct"], "alice is told bob edited, mentioning her")
        check(content(notes) == "- [ ] alpha\n- [ ] beta\n- [ ] gamma @alice\n", "and her file has his line")
        write("notes.md", "- [x] alpha\n- [ ] beta\n- [ ] gamma @alice\n")
        check(until(lambda: content(bob_notes), lambda text: text.startswith("- [x] alpha")) == "- [x] alpha\n- [ ] beta\n- [ ] gamma @alice\n", "her edit reaches his file")
        attached = run("alice", "doc", "attach", f"--group={doc['group']}", token)
        check(attached["markdown"].startswith("[token.txt](lmk:"), "the doc plugin answers `letmeknow doc attach`")
        with open(notes, "a") as f:
            f.write(attached["markdown"] + "\n")
        until(lambda: content(bob_notes), lambda text: attached["link"] in text)
        check(content(run("bob", "fetch", attached["link"])["path"]) == "s3cret", "and a member fetches the file the doc links")

        # Carol joins through bob; the chat is then opened to bob's identity.
        joined = run("carol", "join", run("bob", "invite", f"--group={group}")["link"])
        check(len(joined["members"]) == 3, "a member invites another")
        alice.expect("joined", lambda e: e["member"] == f"Carol · {carol.ready['name']}" and e["by"] == f"Bob · {bob.ready['name']}")
        desk = Listener("desk", device="bob")
        check(run("desk", "identity", "list", device="bob")["name"] == "Bob", "another session on bob's machine shares his identity")
        desk.stop()

        # A device link: bob's tablet joins his identity.
        link = run("bob", "identity", "invite")["link"]
        check("#4.d." in link, "identity invite gives a device link")
        tablet = Listener("tablet")
        listeners.append(tablet)
        check("device" in run("tablet", "identity", "join", link), "the tablet joins bob's identity")
        check(len(run("bob", "identity", "list")["devices"]) == 2, "bob's identity lists two devices")
        bob_id = run("tablet", "identity", "list")["identity"]

        # Bob's tablet joins the chat by a link, as a device of his identity.
        joined = run("tablet", "join", run("bob", "invite", f"--group={group}")["link"])
        check(len(joined["members"]) == 4, "the tablet joins the chat")
        alice.expect("joined", lambda e: e["member"] == f"Bob · {tablet.ready['name']} (tablet)")
        seen = next(m for m in run("alice", "members", f"--group={group}")["members"] if m["handle"] == "tablet")
        check(seen["identity"]["id"] == bob_id, "as a device of bob's identity, by its handle beside his session on a device of the same name")

        # A removal.
        carol_fp = next(m["fp"] for m in run("alice", "members", f"--group={group}")["members"] if m["handle"] == "carol")
        run("alice", "remove", f"--group={group}", carol_fp)
        check(carol.expect("removed")["by"] == f"Alice · {alice.ready['name']}", "carol is told alice removed her")
        alice.expect("left", lambda e: e["member"] == f"Carol · {carol.ready['name']}")
        check(run("carol", "groups") == [], "and is in no group")

        # Any member that holds an invite admits by it: erin gets in while bob, who made her link, is stopped.
        link = run("bob", "invite", f"--group={group}")["link"]
        erin = Listener("erin")
        listeners.append(erin)

        # A restart: bob misses a message and a commit, and catches up when he is back.
        stopping = time.time()
        bob.stop()
        check(time.time() - stopping < 1.5, "a session in groups with peers online stops at once")
        listeners.remove(bob)
        joined = run("erin", "join", link)
        check(joined["group"] == group and len(joined["members"]) == 4, "a joiner gets in while the inviter is stopped")
        check(alice.expect("joined", lambda e: e["member"] == erin.ready["fp"])["by"] != f"Bob · {bob.ready['name']} (bob)", "admitted by another member")
        run("alice", "name", f"--group={group}", "Release")
        missed = run("alice", "send", f"--group={group}", "while you were away")
        check(isinstance(missed.get("pos"), int), "the group's log takes what bob misses")
        bob = Listener("bob")
        listeners.append(bob)
        got = bob.expect("message", lambda e: e["content"] == "while you were away", timeout=60)
        check(got["group"] == "Release" and got["pos"] == missed["pos"], "a restarted session catches up on what it missed, at its position")
        renamed = until(lambda: run("bob", "groups"), lambda gs: any(g.get("name") == "Release" for g in gs))
        check(any(g.get("name") == "Release" for g in renamed), "and on the commits it missed")

        # Bob takes his tablet off his identity while it is stopped: its session leaves his groups all the same.
        key = next(d["key"] for d in run("tablet", "identity", "list")["devices"] if d.get("you"))
        tablet.stop()
        listeners.remove(tablet)
        run("bob", "identity", "remove", "--", key)
        # Alice may hear that the tablet is off bob's identity before it leaves, and then it shows by fingerprint.
        left = alice.expect("left", lambda e: e["member"] in (tablet.ready["fp"], f"Bob · {tablet.ready['name']} (tablet)"), timeout=60)
        check(left["group"] == "Release", "a device taken off its identity while it is stopped leaves its groups")
        if BROWSER and subprocess.run([shutil.which("node"), "e2e.mjs"], cwd=WEB, env={**ENV, "BIN": BIN}).returncode:
            sys.exit("FAIL: the browser test")
        print("all ok")
        passed = True
    finally:
        for proc in list(reversed(PROCESSES)):
            stop(proc)
        if frontend:
            frontend.shutdown()
            frontend.server_close()
            frontend_thread.join()
        # A failed run keeps its sessions' logs.
        if passed:
            shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    main()
