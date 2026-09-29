#!/usr/bin/env python3
"""End-to-end test: local relay (wrangler dev) plus several session processes."""
import hashlib, json, os, queue, shutil, subprocess, sys, tempfile, threading, time, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "client", "target", "debug", "letmeknow" + (".exe" if os.name == "nt" else ""))
PORT = 8798
RELAY = f"http://localhost:{PORT}"
HOME = tempfile.mkdtemp(prefix="lmk-e2e-")
ENV = {**os.environ, "LETMEKNOW_HOME": HOME, "LETMEKNOW_RELAY": RELAY, "NO_PROXY": "localhost,127.0.0.1"}


def run(session, *args, ok=True, env=ENV, cwd=None):
    flags = ["--session", session] if session else []
    result = subprocess.run([BIN, *flags, *args], env=env, cwd=cwd, capture_output=True, text=True, timeout=60)
    if ok and result.returncode:
        sys.exit(f"{session} {args}: {result.stderr}")
    return json.loads(result.stdout) if result.returncode == 0 else result.stderr


class Listener:
    def __init__(self, session, env=ENV, hold=0):
        self.session, self.lines = session, queue.Queue()
        flags = ["--session", session, "listen", "--name", session.title()] if session else ["listen"]
        self.proc = subprocess.Popen([BIN, *flags, "--hold", str(hold)], env=env, stdout=subprocess.PIPE, text=True, encoding="utf-8")
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
            if predicate(event):
                return event
            if event["type"] == "warning":
                sys.exit(f"{self.session} warning: {event}")
        sys.exit(f"{self.session}: expected event not seen")

    def poll(self, timeout):
        try:
            return self.lines.get(timeout=timeout)
        except queue.Empty:
            return None

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

        invite = run("alice", "invite")
        link, code = invite["link"], invite["code"]
        slot, words = code.split("-", 1)
        check(link == f"{RELAY}/i/{slot}#{words}" and len(words.split("-")) == 2, f"invite gives a short code ({code}) and its link")
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

        slot = run("bob", "invite", "--group", group)["code"].split("-")[0]
        check("wrong invite code" in run("carol", "join", f"{slot}-wrong-guess", ok=False), "a wrong code fails for the joiner")
        bob.expect(lambda e: e["type"] == "warning" and "wrong invite code" in e["text"])
        check("invite already used" in run("carol", "join", f"{slot}-other-guess", ok=False), "and uses up the invite")

        run("carol", "join", run("bob", "invite", "--group", group)["code"].upper())
        alice.expect(lambda e: e["type"] == "joined" and e["member"]["name"] == "Carol" and e["by"]["name"] == "Bob")
        check(True, "a typed code works, in any case; any member can invite; others see who added whom")

        run("carol", "send", "--to", fp["Alice"], "question for alice")
        check(alice.expect(lambda e: e["type"] == "message")["direct"], "direct message is marked direct for its target")
        check(not bob.expect(lambda e: e["type"] == "message")["direct"], "and visible but not direct for others")
        run("carol", "send", "--to", fp["Alice"], "--to", fp["Bob"], "for both")
        check(alice.expect(lambda e: e["type"] == "message")["to"] == [fp["Alice"], fp["Bob"]], "--to can address several members")
        check(bob.expect(lambda e: e["type"] == "message")["direct"], "and each of them is addressed")

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

        folder = os.path.join(HOME, "shared", "chat")
        erin, frank = Listener("erin"), Listener("frank")
        listeners += [erin, frank]
        erin_fp, frank_fp = erin.ready["member"]["fp"], frank.ready["member"]["fp"]
        check(run("erin", "join", folder)["group"] == folder and os.path.isdir(folder), "joining a folder creates it; the group is its path")
        erin.expect(lambda e: e["type"] == "joined" and e["group"] == folder)
        check(os.path.samefile(run("frank", "join", "shared/chat", cwd=HOME)["group"], folder), "a relative path is resolved where the command runs")
        check(run("frank", "members", "--group", "shared/chat", cwd=HOME)["group"] == run("frank", "groups")[0]["group"], "and so is --group")
        got = frank.expect(lambda e: e["type"] == "message")
        check(got["from"]["fp"] == erin_fp and got["content"] == "joined", "joining a folder posts 'joined'")
        erin.expect(lambda e: e["type"] == "message" and e["from"]["fp"] == frank_fp)
        check([m["fp"] for m in run("frank", "members")["members"]] == [frank_fp, erin_fp], "so a member who has not spoken yet is listed")

        hello = run("erin", "send", "--to", frank_fp, "hello frank")["id"]
        got = frank.expect(lambda e: e["type"] == "message")
        check(got["id"] == hello and got["from"]["name"] == "Erin" and got["direct"], "and can be addressed")
        check("is not a member" in run("frank", "send", "--to", "0123456789abcdef", "x", ok=False), "--to must be a known member")

        reply = run("frank", "send", "--to", erin_fp, "--reply-to", hello, "hi erin")["id"]
        got = erin.expect(lambda e: e["type"] == "message")
        check(got["id"] == reply and got["direct"] and got["reply_to"] == hello, "erin receives frank's direct reply")
        check([m["id"] for m in run("erin", "read", reply, "--ancestors", "1")] == [hello, reply], "frank's read frontier covers erin's message")
        with open(os.path.join(folder, reply + ".json"), "rb") as f:
            data = f.read()
        check(hashlib.sha256(data).hexdigest() == reply and json.loads(data) == {"from": {"name": "Frank", "fp": frank_fp},
              "content": "hi erin", "after": [hello], "to": [erin_fp], "reply_to": hello}, "the file is the message plus from, named by its hash")

        hand = {"from": {"name": "Hand", "fp": "00"}, "after": []}
        partial, temp = (json.dumps({**hand, "content": text}).encode() for text in ("was partial", "was temp"))
        named = lambda data: os.path.join(folder, hashlib.sha256(data).hexdigest() + ".json")
        with open(named(partial), "wb") as f:
            f.write(partial[:20])
        with open(os.path.join(folder, ".temp.tmp"), "wb") as f:
            f.write(temp)
        run("frank", "send", "after the partial file")
        check(erin.expect(lambda e: e["type"] == "message")["content"] == "after the partial file", "partial and temp files are not delivered")
        with open(named(partial), "wb") as f:
            f.write(partial)
        os.replace(os.path.join(folder, ".temp.tmp"), named(temp))
        got = {erin.expect(lambda e: e["type"] == "message")["content"] for _ in range(2)}
        check(got == {"was partial", "was temp"}, "once complete, they are delivered")
        misnamed = os.path.join(folder, "0" * 64 + ".json")
        with open(misnamed, "wb") as f:
            f.write(json.dumps({**hand, "content": "misnamed"}).encode())
        warning = erin.expect(lambda e: e["type"] == "warning")
        check(os.path.basename(misnamed) in warning["text"], "a file not named by its hash is ignored with a warning")
        os.remove(misnamed)
        old = json.dumps({**hand, "content": "from 0.4", "to": erin_fp}).encode()
        with open(named(old), "wb") as f:
            f.write(old)
        got = erin.expect(lambda e: e["type"] == "message")
        check(got["content"] == "from 0.4" and got["to"] == [erin_fp] and got["direct"], "a 0.4 file with a single fingerprint in to still reads")

        erin.stop()
        for i in range(22):
            run("frank", "send", f"folder {i}")
        erin = Listener("erin")
        listeners.append(erin)
        omitted = erin.expect(lambda e: e["type"] == "omitted")
        got = [erin.expect(lambda e: e["type"] == "message")["content"] for _ in range(20)]
        check(omitted["count"] == 2 and got == [f"folder {i}" for i in range(2, 22)], "restart catches up on the folder's last 20 messages, in order")
        check(run("frank", "leave")["left"] and run("frank", "groups") == [], "leaving a folder group")

        board = os.path.join(HOME, "board")
        gina, hank = Listener("gina", hold=600), Listener("hank")
        listeners += [gina, hank]
        gina_fp, hank_fp = gina.ready["member"]["fp"], hank.ready["member"]["fp"]
        run("gina", "join", board)
        gina.expect(lambda e: e["type"] == "joined")
        run("hank", "join", board)
        check(gina.poll(2) is None, "a message not addressed to the session waits")
        for _ in range(20):
            if len(run("gina", "members")["members"]) == 2:
                break
            time.sleep(0.5)
        check(gina.expect(lambda e: e["type"] == "message")["from"]["fp"] == hank_fp, "until the agent runs a command")

        run("hank", "send", "for everyone")
        check(gina.poll(2) is None, "a message to the group waits too")
        run("hank", "send", "--to", gina_fp, "for gina")
        got = [gina.expect(lambda e: e["type"] == "message")["content"] for _ in range(2)]
        check(got == ["for everyone", "for gina"], "a message addressed to the session wakes it, after the held ones")
        run("hank", "send", "--urgent", "all hands")
        check(gina.expect(lambda e: e["type"] == "message")["urgent"], "so does an urgent message")
        question = run("gina", "send", "any news?")["id"]
        hank.expect(lambda e: e.get("id") == question)
        run("hank", "send", "--reply-to", question, "yes")
        got = gina.expect(lambda e: e["type"] == "message")
        check(got["reply_to"] == question and not got["direct"], "and a reply to one of its messages")

        jill = Listener("jill", hold=2)
        listeners.append(jill)
        run("jill", "join", board)
        jill.expect(lambda e: e.get("content") == "yes")
        start = time.time()
        run("hank", "send", "later")
        jill.expect(lambda e: e.get("content") == "later")
        check(time.time() - start >= 2, "a held message is printed once --hold runs out")

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
