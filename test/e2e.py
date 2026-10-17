#!/usr/bin/env python3
"""Native sessions use the real local membership service and iroh relay. LMK_E2E_BIN tests an already-built native
artifact."""
import json, os, queue, shutil, socket, subprocess, sys, tempfile, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("LMK_E2E_BIN") or os.path.join(ROOT, os.environ.get("CARGO_TARGET_DIR", "target"), "debug", "letmeknow" + (".exe" if os.name == "nt" else ""))
TMP = tempfile.mkdtemp(prefix="lmk-e2e-")
# No session asks the real registry whether a newer release is out.
ENV = {**os.environ, "NO_PROXY": "localhost,127.0.0.1", "LETMEKNOW_REGISTRY": "http://127.0.0.1:1"}
ENV.pop("LETMEKNOW_SESSION", None)


def free_port():
    """A port free on every address for UDP and TCP alike, as `serve` binds them."""
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            udp.bind(("", 0))
            port = udp.getsockname()[1]
            try:
                tcp.bind(("", port))
                return port
            except OSError:
                pass


def check(condition, message):
    if not condition:
        sys.exit(f"FAIL: {message}")
    print(f"ok - {message}")


def home(name):
    return os.path.join(TMP, name)


def run(session, *args, ok=True, input=None, device=None, bin=BIN):
    env = {**ENV, "LETMEKNOW_HOME": home(device or session)}
    result = subprocess.run([bin, "--session", session, *args], env=env, input=input, capture_output=True, text=True, encoding="utf-8", timeout=120)
    if ok and result.returncode:
        sys.exit(f"{session} {args}: {result.stderr}")
    return json.loads(result.stdout) if result.returncode == 0 else result.stderr


class Listener:
    """A session process, in its own home (its own device) unless it shares `device`'s."""

    def __init__(self, session, device=None, bin=BIN):
        self.session, self.lines = session, queue.Queue()
        env = {**ENV, "LETMEKNOW_HOME": home(device or session)}
        args = [bin, "--session", session, "listen", "--hold", "0"]
        self.log = open(os.path.join(TMP, f"{session}.log"), "a")
        self.proc = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=self.log, text=True, encoding="utf-8")
        threading.Thread(target=self.read, daemon=True).start()
        self.ready = self.expect("ready")

    def read(self):
        for line in self.proc.stdout:
            self.lines.put(json.loads(line))

    def expect(self, kind, predicate=lambda e: True, timeout=30):
        deadline, seen = time.time() + timeout, []
        while time.time() < deadline:
            try:
                event = self.lines.get(timeout=deadline - time.time())
            except queue.Empty:
                break
            if event["type"] == kind and predicate(event):
                return event
            if event["type"] == "warning":
                text = event["text"]
                if text.startswith(("First locally observed identity claim:", "Previously observed identity-name change or shared name:")):
                    check("not been independently verified" in text, "identity observation is not human verification")
                else:
                    sys.exit(f"{self.session} warning: {event}")
            seen.append(event)
        sys.exit(f"{self.session}: no {kind} event, only {seen}")

    def stop(self):
        # SIGTERM where there are signals; on Windows, the process ends at once.
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            sys.exit(f"{self.session}: listen did not stop")


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
    """A local `letmeknow serve` with a self-signed certificate; returns it. Sessions name its domain. Its directory names
    two URLs of its relay: the name and 127.0.0.1."""
    cert, key = os.path.join(TMP, "cert.pem"), os.path.join(TMP, "key.pem")
    subprocess.run(["cargo", "run", "-q", "-p", "letmeknow", "--example", "self_signed", "--", cert, key], cwd=ROOT, check=True)
    https = free_port()
    args = [BIN, "serve", "--domain", "localhost", "--https-port", str(https), "--http-port", str(free_port()),
            "--qad-port", str(free_port()), "--state", os.path.join(TMP, "serve"), "--cert", cert, "--key", key]
    subprocess.run(args + ["--initialize"], env=ENV, check=True, stdout=subprocess.DEVNULL)
    proc = subprocess.Popen(args + ["--relays", f"https://localhost:{https}", f"https://127.0.0.1:{https}"], env=ENV, stdout=subprocess.PIPE, stderr=open(os.path.join(TMP, "serve.log"), "w"), text=True)
    domain = proc.stdout.readline().strip().removeprefix("membership: ")
    proc.stdout.readline()  # key: its public key, which the directory names
    ENV.update(LETMEKNOW_CA=cert, LETMEKNOW_RELAY=f"https://localhost:{https}", LETMEKNOW_OTHER_RELAY=f"https://127.0.0.1:{https}", LETMEKNOW_MEMBERSHIP=domain)
    return proc


def main():
    if "LMK_E2E_BIN" not in os.environ:
        subprocess.run(["cargo", "build", "-q", "-p", "letmeknow"], cwd=ROOT, check=True)
    server = serve()
    listeners = []
    passed = False
    try:
        alice, bob, carol = (Listener(s) for s in ("alice", "bob", "carol"))
        listeners += [alice, bob, carol]
        check(os.path.samefile(alice.ready["bin"], BIN), "ready names the session's program, which runs the other commands")
        for name in ("alice", "bob", "carol"):
            run(name, "identity", "create", name.title())
        check(run("bob", "identity", "list")["devices"][0]["you"], "an identity starts with this device on its list")

        # An invite, and chat.
        invite = run("alice", "invite", "--name", "Plans")
        check(invite["link"].startswith("https://letmeknow.dev/i#9.g."), "invite gives a link to a new chat")
        group = invite["group"]
        check("serve" in run("alice", "groups")[0]["membership"], "its log is on the local letmeknow serve")
        joined = run("bob", "join", invite["link"])
        check(joined["group"] == group and len(joined["members"]) == 2, "bob joins through the link")
        event = alice.expect("joined")
        check(event["member"] == f"Bob · {bob.ready['name']}" and event["how"] == "invite", "alice sees bob join by invite, as his identity claims")
        check("unknown, used or expired" in run("carol", "join", invite["link"], ok=False), "an invite link works once")
        seen = next(m for m in run("alice", "members")["members"] if m["handle"] == "bob")
        check(seen["identity"]["name"] == "Bob" and seen["identity"]["how"] == "observed", "another identity is known by its own name, a claim")

        sent = run("alice", "send", "hello bob")
        check(sent.get("id") and "pos" not in sent, "send answers the message's id at once")
        got = bob.expect("message")
        check(got["content"] == "hello bob" and got["from"] == f"Alice · {alice.ready['name']}", "bob receives it from alice, as her identity claims")
        reply = run("bob", "send", "--reply-to", got["id"], "hi alice")["id"]
        answer = alice.expect("message")
        check(answer["reply_to"] == got["id"] and "direct" not in answer, "a reply names what it answers")
        history = run("alice", "read", reply, "--ancestors", "1")
        check([m["id"] for m in history] == [sent["id"], reply], "read shows a message after the latest in its causal past")

        # An attachment.
        token = write("token.txt", "s3cret")
        sent = run("alice", "send", "--attach", token, "the token")
        check(sent["attachment"]["held_by"] == [f"Bob · {bob.ready['name']}"], "an attachment is held by another member before send returns")
        message = bob.expect("message", lambda e: e["content"] == "the token")
        arrived = bob.expect("attachment") if "path" not in message["attachment"] else message["attachment"]
        check(content(arrived["path"]) == "s3cret", "the attachment arrives as a private file")
        check(content(run("bob", "fetch", message["attachment"]["link"])["path"]) == "s3cret", "fetch gives the same file")

        # Carol joins through bob; the chat is then opened to bob's identity.
        joined = run("carol", "join", run("bob", "invite", f"--group={group}")["link"])
        check(len(joined["members"]) == 3, "a member invites another")
        alice.expect("joined", lambda e: e["member"] == f"Carol · {carol.ready['name']}" and e["by"] == f"Bob · {bob.ready['name']}")
        desk = Listener("desk", device="bob")
        check(run("desk", "identity", "list", device="bob")["name"] == "Bob", "another session on bob's machine shares his identity")
        desk.stop()

        # A device link: bob's tablet joins his identity.
        link = run("bob", "identity", "invite")["link"]
        check("#9.d." in link, "identity invite gives a device link")
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
        check("id" in missed, "alice sends while bob is away")
        bob = Listener("bob")
        listeners.append(bob)
        got = bob.expect("message", lambda e: e["content"] == "while you were away", timeout=60)
        check(got["group"] == "Release" and got["id"] == missed["id"], "a restarted session catches up on what it missed")
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
        print("all ok")
        passed = True
    finally:
        for listener in listeners:
            listener.proc.kill()
        server.kill()
        for listener in listeners:
            listener.proc.wait()
        server.wait()
        # A failed run keeps its sessions' logs.
        if passed:
            shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    main()
