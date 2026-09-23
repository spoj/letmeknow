#!/usr/bin/env python3
"""End-to-end test: local relay (wrangler dev) plus several session processes."""
import json, os, queue, shutil, subprocess, sys, tempfile, threading, time, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "client", "target", "debug", "letmeknow" + (".exe" if os.name == "nt" else ""))
PORT = 8798
RELAY = f"http://localhost:{PORT}"
HOME = tempfile.mkdtemp(prefix="lmk-e2e-")
ENV = {**os.environ, "LETMEKNOW_HOME": HOME, "LETMEKNOW_RELAY": RELAY, "NO_PROXY": "localhost,127.0.0.1"}


def run(session, *args, ok=True, env=ENV):
    flags = ["--session", session] if session else []
    result = subprocess.run([BIN, *flags, *args], env=env, capture_output=True, text=True, timeout=60)
    if ok and result.returncode:
        sys.exit(f"{session} {args}: {result.stderr}")
    return json.loads(result.stdout) if result.returncode == 0 else result.stderr


class Listener:
    def __init__(self, session, env=ENV):
        self.session, self.lines = session, queue.Queue()
        flags = ["--session", session, "listen", "--name", session.title()] if session else ["listen"]
        self.proc = subprocess.Popen([BIN, *flags], env=env, stdout=subprocess.PIPE, text=True, encoding="utf-8")
        threading.Thread(target=self.read, daemon=True).start()
        self.ready = self.expect(lambda e: e["type"] == "ready")

    def read(self):
        for line in self.proc.stdout:
            self.lines.put(json.loads(line))

    def expect(self, predicate, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                event = self.lines.get(timeout=deadline - time.time())
            except queue.Empty:
                break
            if event["type"] == "warning":
                sys.exit(f"{self.session} warning: {event}")
            if predicate(event):
                return event
        sys.exit(f"{self.session}: expected event not seen")

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            sys.exit(f"{self.session}: listen ignored SIGTERM")


def check(condition, message):
    if not condition:
        sys.exit(f"FAIL: {message}")
    print(f"ok - {message}")


def main():
    subprocess.run(["cargo", "build", "-q"], cwd=os.path.join(ROOT, "client"), check=True)
    subprocess.run([shutil.which("npm"), "install", "--silent"], cwd=os.path.join(ROOT, "relay"), check=True)
    relay = subprocess.Popen([shutil.which("npx"), "wrangler", "dev", "--port", str(PORT)], cwd=os.path.join(ROOT, "relay"),
                             env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    listeners = []
    try:
        for _ in range(60):
            try:
                urllib.request.build_opener(urllib.request.ProxyHandler({})).open(RELAY, timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        alice, bob, carol = (Listener(s) for s in ("alice", "bob", "carol"))
        listeners += [alice, bob, carol]

        link = run("alice", "invite")["link"]
        joined = run("bob", "join", link)
        group = joined["group"]
        check(len(joined["members"]) == 2, "bob joins alice's group through the link")
        check("invite already used" in run("carol", "join", link, ok=False), "an invite link works once")
        alice.expect(lambda e: e["type"] == "joined" and e["member"]["name"] == "Bob")
        fp = {m["name"]: m["fp"] for m in joined["members"]}

        hello = run("alice", "send", "hello bob")["id"]
        got = bob.expect(lambda e: e["type"] == "message")
        check(got["id"] == hello and got["content"] == "hello bob", "bob receives alice's message")

        reply = run("bob", "send", "--reply-to", hello, "hi alice")["id"]
        got = alice.expect(lambda e: e["type"] == "message")
        check(got["reply_to"] == hello, "alice receives bob's reply")
        history = run("alice", "read", reply, "--ancestors", "1")
        check([m["id"] for m in history] == [hello, reply], "bob's read frontier covers alice's message")

        run("carol", "join", run("bob", "invite", "--group", group)["link"])
        alice.expect(lambda e: e["type"] == "joined" and e["member"]["name"] == "Carol" and e["by"]["name"] == "Bob")
        check(True, "any member can invite; others see who added whom")

        run("carol", "send", "--to", fp["Alice"], "question for alice")
        check(alice.expect(lambda e: e["type"] == "message")["direct"], "direct message is marked direct for its target")
        check(not bob.expect(lambda e: e["type"] == "message")["direct"], "and visible but not direct for others")

        carol_fp = next(m["fp"] for m in run("alice", "members")["members"] if m["name"] == "Carol")
        run("alice", "remove", carol_fp)
        carol.expect(lambda e: e["type"] == "removed")
        bob.expect(lambda e: e["type"] == "left" and e["member"]["name"] == "Carol")
        check(True, "removed member is told; others see it")

        run("bob", "leave")
        alice.expect(lambda e: e["type"] == "left" and e["member"]["name"] == "Bob")
        bob.expect(lambda e: e["type"] == "removed")
        check([m["name"] for m in run("alice", "members")["members"]] == ["Alice"], "leaving is committed by a remaining member")

        dave = Listener("dave")
        listeners.append(dave)
        run("dave", "join", run("alice", "invite", "--group", group)["link"])
        alice.expect(lambda e: e["type"] == "joined" and e["member"]["name"] == "Dave")
        alice.stop()
        for i in range(22):
            run("dave", "send", f"message {i}")
        alice = Listener("alice")
        listeners.append(alice)
        omitted = alice.expect(lambda e: e["type"] == "omitted")
        first = alice.expect(lambda e: e["type"] == "message")
        check(omitted["count"] == 2 and first["content"] == "message 2", "restart catches up on the last 20 messages")

        check("several sessions are running" in run(None, "groups", ok=False), "without --session, several running sessions are ambiguous")
        solo_env = {**ENV, "LETMEKNOW_HOME": os.path.join(HOME, "solo")}
        check("no session is running" in run(None, "groups", ok=False, env=solo_env), "without --session, none running is an error")
        solo = Listener(None, env=solo_env)
        listeners.append(solo)
        handle = solo.ready["session"]
        check(len(handle.split("-")) == 2, f"listen without --session picks a handle ({handle})")
        check(run(None, "groups", env=solo_env) == [], "commands use the one running session")
        print("all passed")
    finally:
        for listener in listeners:
            listener.stop()
        relay.terminate()
        shutil.rmtree(HOME)


main()
