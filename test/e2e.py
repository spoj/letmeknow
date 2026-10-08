#!/usr/bin/env python3
"""End-to-end test: a local `letmeknow serve` (membership service and relay, with a self-signed certificate) and several
`letmeknow listen` processes, each its own device. --no-browser is the default: there is no browser client yet."""
import json, os, queue, signal, socket, subprocess, sys, tempfile, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target", "debug", "letmeknow" + (".exe" if os.name == "nt" else ""))
TMP = tempfile.mkdtemp(prefix="lmk-e2e-")
ENV = {**os.environ, "NO_PROXY": "localhost,127.0.0.1"}
ENV.pop("LETMEKNOW_SESSION", None)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


def check(condition, message):
    if not condition:
        sys.exit(f"FAIL: {message}")
    print(f"ok - {message}")


def home(name):
    return os.path.join(TMP, name)


def run(session, *args, ok=True, input=None):
    env = {**ENV, "LETMEKNOW_HOME": home(session)}
    result = subprocess.run([BIN, "--session", session, *args], env=env, input=input, capture_output=True, text=True, timeout=120)
    if ok and result.returncode:
        sys.exit(f"{session} {args}: {result.stderr}")
    return json.loads(result.stdout) if result.returncode == 0 else result.stderr


class Listener:
    """A session process, in its own home: its own device."""

    def __init__(self, session):
        self.session, self.lines = session, queue.Queue()
        env = {**ENV, "LETMEKNOW_HOME": home(session)}
        args = [BIN, "--session", session, "listen", "--name", session.title(), "--hold", "0"]
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
                sys.exit(f"{self.session} warning: {event}")
            seen.append(event)
        sys.exit(f"{self.session}: no {kind} event, only {seen}")

    def stop(self):
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            sys.exit(f"{self.session}: listen ignored SIGTERM")


def write(name, text):
    path = os.path.join(TMP, name)
    with open(path, "wb") as f:
        f.write(text if isinstance(text, bytes) else text.encode())
    return path


def content(path):
    with open(path) as f:
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
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", cert,
                    "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE"],
                   check=True, capture_output=True)
    https = free_port()
    args = [BIN, "serve", "--domain", "localhost", "--https-port", str(https), "--http-port", str(free_port()), "--membership-port", str(free_port()),
            "--qad-port", str(free_port()), "--state", os.path.join(TMP, "serve"), "--cert", cert, "--key", key]
    proc = subprocess.Popen(args, env=ENV, stdout=subprocess.PIPE, stderr=open(os.path.join(TMP, "serve.log"), "w"), text=True)
    membership = proc.stdout.readline().strip().removeprefix("membership: ")
    ENV.update(LETMEKNOW_CA=cert, LETMEKNOW_RELAY=f"https://localhost:{https}", LETMEKNOW_MEMBERSHIP=membership)
    return proc


def main():
    subprocess.run(["cargo", "build", "-q", "-p", "letmeknow"], cwd=ROOT, check=True)
    server = serve()
    listeners = []
    try:
        alice, bob, carol = (Listener(s) for s in ("alice", "bob", "carol"))
        listeners += [alice, bob, carol]
        for name in ("alice", "bob", "carol"):
            run(name, "identity", "create", name.title())
        check(run("bob", "identity", "list")["identities"][0]["devices"][0]["you"], "an identity starts with this device on its list")

        # An invite, and chat.
        invite = run("alice", "invite", "--name", "Plans", "--for", "Bob (Acme)")
        check(invite["link"].startswith("https://letmeknow.dev/i#1.g.") and invite["kind"] == "chat", "invite gives a link to a new chat")
        group = invite["group"]
        check("serve" in run("alice", "groups")[0]["membership"], "its log is on the local letmeknow serve")
        joined = run("bob", "join", invite["link"])
        check(joined["group"] == group and len(joined["members"]) == 2, "bob joins through the link")
        event = alice.expect("joined")
        check(event["member"]["name"] == "Bob" and event["how"] == "invite", "alice sees bob join by invite")
        check("unknown, used or expired" in run("carol", "join", invite["link"], ok=False), "an invite link works once")
        alice.expect("warning", lambda e: "refused a join" in e["text"])
        seen = next(m for m in run("alice", "members")["members"] if m["name"] == "Bob")
        check(seen["identity"]["name"] == "Bob (Acme)" and seen["identity"]["how"] == "verified", "whoever redeems a link --for a name becomes that contact, verified")
        bob.expect("introduced", lambda e: e["identity"]["name"] == "Bob (Acme)")

        sent = run("alice", "send", "hello bob")
        check(sent["held_by"][0]["name"] == "Bob", "send reports who holds the message")
        got = bob.expect("message")
        check(got["content"] == "hello bob" and got["from"]["identity"]["how"] == "unknown", "bob receives it; alice is only her own claim to him")
        reply = run("bob", "send", "--reply-to", got["id"], "hi alice")["id"]
        answer = alice.expect("message")
        check(answer["reply_to"] == got["id"] and answer["direct"] is False, "a reply names what it answers")
        history = run("alice", "read", reply, "--ancestors", "1")
        check([m["id"] for m in history] == [sent["id"], reply], "read follows what the sender had read")

        # An attachment.
        token = write("token.txt", "s3cret")
        sent = run("alice", "send", "--attach", token, "the token")
        check(sent["attachment"]["held_by"][0]["name"] == "Bob", "an attachment is held by another member before send returns")
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
        with open(bob_notes, "a") as f:
            f.write("- [ ] gamma @alice\n")
        edited = alice.expect("edited", lambda e: e["group"] == doc["group"])
        check(edited["by"][0]["name"] == "Bob" and edited["direct"], "alice is told bob edited, mentioning her")
        check(content(notes) == "- [ ] alpha\n- [ ] beta\n- [ ] gamma @alice\n", "and her file has his line")
        write("notes.md", "- [x] alpha\n- [ ] beta\n- [ ] gamma @alice\n")
        check(until(lambda: content(bob_notes), lambda text: text.startswith("- [x] alpha")) == "- [x] alpha\n- [ ] beta\n- [ ] gamma @alice\n", "her edit reaches his file")

        # Carol joins through bob, who means the link for her; the chat is then opened to bob's identity.
        joined = run("carol", "join", run("bob", "invite", "--group", group, "--for", "Carol")["link"])
        check(len(joined["members"]) == 3, "a member invites another")
        alice.expect("joined", lambda e: e["member"]["name"] == "Carol" and e["by"]["name"] == "Bob")
        check(any(c["name"] == "Carol" for c in run("bob", "contacts")["contacts"]), "carol is bob's contact")

        # A device link: bob's tablet joins his identity, and his contacts reach it.
        link = run("bob", "invite", "--identity", "Bob")["link"]
        check("#1.d." in link, "invite --identity gives a device link")
        tablet = Listener("tablet")
        listeners.append(tablet)
        check("device" in run("tablet", "join", link), "the tablet joins bob's identity")
        check(len(run("bob", "identity", "list")["identities"][0]["devices"]) == 2, "bob's identity lists two devices")
        contacts = until(lambda: run("tablet", "contacts")["contacts"], lambda c: any(x["name"] == "Carol" for x in c))
        check(any(c["name"] == "Carol" and c["how"] == "verified" for c in contacts), "bob's contacts reach his tablet")

        # An open group: the chat is opened to bob's identity, and his tablet joins it without an invite.
        opened = run("alice", "open", "--group", group, "Bob (Acme)")
        check(opened["settings"]["open"][0]["name"] == "Bob (Acme)", "alice opens the chat to bob's identity")
        listed = until(lambda: run("tablet", "groups"), lambda groups: any(g["group"] == group for g in groups))
        check(any(g["group"] == group and g.get("joined") is False for g in listed), "the tablet sees the chat open to it")
        joined = run("tablet", "join", group)
        check(len(joined["members"]) == 4, "the tablet joins the open chat")
        event = alice.expect("joined", lambda e: e["member"]["name"] == "Tablet")
        check(event["how"] == "open" and event["member"]["identity"]["name"] == "Bob (Acme)", "as a device of the identity it is open to")

        # A removal.
        carol_fp = next(m["fp"] for m in run("alice", "members", "--group", group)["members"] if m["name"] == "Carol")
        run("alice", "remove", "--group", group, carol_fp)
        check(carol.expect("removed")["by"]["name"] == "Alice", "carol is told alice removed her")
        alice.expect("left", lambda e: e["member"]["name"] == "Carol")
        check(run("carol", "groups") == [], "and is in no group")

        # A restart: bob misses a message and a commit, and catches up when he is back.
        bob.stop()
        listeners.remove(bob)
        run("alice", "name", "--group", group, "Release")
        missed = run("alice", "send", "--group", group, "while you were away")
        check("held_by" in missed, "the tablet holds what bob misses")
        bob = Listener("bob")
        listeners.append(bob)
        got = bob.expect("message", lambda e: e["content"] == "while you were away", timeout=60)
        check(got["group"] == group, "a restarted session catches up on what it missed")
        renamed = until(lambda: run("bob", "groups"), lambda gs: any(g.get("name") == "Release" for g in gs))
        check(any(g.get("name") == "Release" for g in renamed), "and on the commits it missed")
        print("all ok")
    finally:
        for listener in listeners:
            listener.proc.kill()
        server.kill()


if __name__ == "__main__":
    main()
