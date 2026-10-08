#!/usr/bin/env python3
"""End-to-end test: local relay (wrangler dev) plus several session processes, then the browser client in Chromium
(web/e2e.mjs). --no-browser skips building and testing the browser client, which is the same on every OS."""
import hashlib, http.client, http.server, json, os, queue, shutil, socket, struct, subprocess, sys, tempfile, threading, time, urllib.error, urllib.parse, urllib.request, zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "client", "target", "debug", "letmeknow" + (".exe" if os.name == "nt" else ""))
def free_port():
    with socket.socket() as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


# A free port, so that several checkouts can run this test at once.
PORT = free_port()
RELAY = f"http://localhost:{PORT}"
HOME = tempfile.mkdtemp(prefix="lmk-e2e-")
BROWSER = "--no-browser" not in sys.argv
ENV = {**os.environ, "LETMEKNOW_HOME": HOME, "LETMEKNOW_RELAY": RELAY, "NO_PROXY": "localhost,127.0.0.1"}


def run(session, *args, ok=True, env=ENV, cwd=None, input=None):
    flags = ["--session", session] if session else []
    result = subprocess.run([BIN, *flags, *args], env=env, cwd=cwd, input=input, capture_output=True, text=True, timeout=60)
    if ok and result.returncode:
        sys.exit(f"{session} {args}: {result.stderr}")
    return json.loads(result.stdout) if result.returncode == 0 else result.stderr


class Listener:
    def __init__(self, session, env=ENV, hold=0, extra=()):
        self.session, self.lines = session, queue.Queue()
        flags = ["--session", session, "listen", "--name", session.title()] if session else ["listen"]
        self.proc = subprocess.Popen([BIN, *flags, "--hold", str(hold), *extra], env=env, stdout=subprocess.PIPE, text=True, encoding="utf-8")
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


class Proxy(http.server.BaseHTTPRequestHandler):
    """A forward proxy to the relay that can lose one answer (`lose`: method and path prefix): the relay takes the request,
    the client never hears."""
    protocol_version = "HTTP/1.1"
    lose = None

    @classmethod
    def start(cls):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), cls)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return {**ENV, "HTTP_PROXY": f"http://127.0.0.1:{server.server_port}", "NO_PROXY": ""}

    def log_message(self, *args):
        pass

    def forward(self):
        url = urllib.parse.urlsplit(self.path)
        path = url.path + (f"?{url.query}" if url.query else "")
        if self.headers.get("Upgrade"):
            upstream = socket.create_connection(("localhost", PORT))
            head = "".join(f"{k}: {v}\r\n" for k, v in self.headers.items() if not k.lower().startswith("proxy-"))
            upstream.sendall(f"{self.command} {path} HTTP/1.1\r\n{head}\r\n".encode())
            threading.Thread(target=self.pipe, args=(self.connection, upstream), daemon=True).start()
            self.pipe(upstream, self.connection)
            self.close_connection = True
            return
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        relay = http.client.HTTPConnection("localhost", PORT, timeout=60)
        relay.request(self.command, path, body, {k: v for k, v in self.headers.items() if k.lower() not in ("connection", "proxy-connection")})
        response = relay.getresponse()
        data = response.read()
        if Proxy.lose and f"{self.command} {url.path}".startswith(Proxy.lose):
            Proxy.lose = None
            self.close_connection = True
            return
        self.send_response(response.status)
        for k, v in response.getheaders():
            if k.lower() not in ("connection", "transfer-encoding", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = forward

    @staticmethod
    def pipe(source, sink):
        try:
            while chunk := source.recv(65536):
                sink.sendall(chunk)
        except OSError:
            pass
        for end in (source, sink):
            try:
                end.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def in_state(listener, *texts):
    """Whether any of `texts` appears in the files of the listener's state directory."""
    state = listener.ready["state"]
    files = [os.path.join(state, f) for f in os.listdir(state)]
    return any(text in open(f, "rb").read() for f in files if os.path.isfile(f) for text in texts)


def until(produce, accept, timeout=10):
    """Calls `produce` until `accept` takes its result; folder groups see other members' files a moment later."""
    deadline = time.time() + timeout
    while True:
        result = produce()
        if accept(result) or time.time() > deadline:
            return result
        time.sleep(0.3)


def write(name, text):
    path = os.path.join(HOME, name)
    with open(path, "wb") as f:
        f.write(text if isinstance(text, bytes) else text.encode())
    return path


def content(path):
    with open(path, "rb") as f:
        return f.read().decode()


def png(width, height):
    chunk = lambda kind, data: struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    rows = b"".join(b"\0" + bytes([200, 40, 40]) * width for _ in range(height))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")


def check(condition, message):
    if not condition:
        sys.exit(f"FAIL: {message}")
    print(f"ok - {message}")


def main():
    subprocess.run(["cargo", "build", "-q"], cwd=os.path.join(ROOT, "client"), check=True)
    subprocess.run([shutil.which("npm"), "install", "--silent"], cwd=os.path.join(ROOT, "relay"), check=True)
    web = os.path.join(ROOT, "web")
    if BROWSER:
        subprocess.run([shutil.which("npm"), "install", "--silent"], cwd=web, check=True)
        subprocess.run([shutil.which("node"), "build.mjs"], cwd=web, check=True)
    else:
        os.makedirs(os.path.join(ROOT, "relay", "public"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "relay", ".wrangler"), exist_ok=True)
    log = open(os.path.join(ROOT, "relay", ".wrangler", "e2e.log"), "w")
    relay = subprocess.Popen([shutil.which("npx"), "wrangler", "dev", "--port", str(PORT), "--inspector-port", str(free_port())], cwd=os.path.join(ROOT, "relay"),
                             env=ENV, stdout=log, stderr=subprocess.STDOUT)
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

        invite = run("alice", "invite", "--name", "Plans")
        link, code = invite["link"], invite["code"]
        slot, words = code.split("-", 1)
        check(link == f"{RELAY}/i/{slot}#{words}" and len(words.split("-")) == 2, f"invite gives a short code ({code}) and its link")
        check(invite["kind"] == "chat", "a new group is a chat unless asked otherwise")
        joined = run("bob", "join", link)
        group = joined["group"]
        check(len(joined["members"]) == 2, "bob joins alice's group through the link")
        check(joined["kind"] == "chat" and joined["name"] == "Plans", "and learns what it is from the invite's welcome")
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
        check([m["content"] for m in history] == [None, None], "the text of delivered messages is not kept")
        check(not in_state(alice, b"hello bob", b"hi alice"), "not even in the session's files")

        token = os.path.join(HOME, "token.txt")
        with open(token, "w") as f:
            f.write("s3cret-token")
        run("alice", "send", "--attach", token, "the staging token")
        got = bob.expect(lambda e: e["type"] == "message")
        check(got["attachment"]["name"] == "token.txt" and got["attachment"]["size"] == 12, "an attachment arrives with its name and size")
        attachment = got["attachment"]["path"]
        check(content(attachment) == "s3cret-token" and attachment.endswith("token.txt"), "and as a file, named like it")
        check(os.name == "nt" or os.stat(attachment).st_mode & 0o777 == 0o600, "that only its owner can read")
        check(not in_state(alice, b"s3cret") and not in_state(bob, b"s3cret"), "and that is its only copy")
        check(run("bob", "fetch", got["attachment"]["link"])["path"] == attachment, "fetch gives the same file again")
        big = os.urandom(3 * 1024 * 1024)
        run("alice", "send", "--attach", write("big.bin", big), "a large file")
        with open(bob.expect(lambda e: e["type"] == "message")["attachment"]["path"], "rb") as f:
            check(f.read() == big, "an attachment holds up to 10 MiB")
        check("files go up to" in run("alice", "send", "--attach", write("huge.bin", os.urandom(10 * 1024 * 1024 + 1)), "too much", ok=False), "and no more")
        check("is a chat group" in run("alice", "attach", "--group", group, token, ok=False), "a chat refuses what is for docs")
        check("only a doc has a file" in run("alice", "invite", write("chat.md", ""), ok=False), "and has no file")

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
        check(alice.expect(lambda e: e["type"] == "message")["to"] == sorted([fp["Alice"], fp["Bob"]]), "--to can address several members")
        check(bob.expect(lambda e: e["type"] == "message")["direct"], "and each of them is addressed")
        check(run("carol", "send", "--to", "alice", "by name")["to"] == [fp["Alice"]], "--to also takes a member's name, in any case")
        check(alice.expect(lambda e: e["type"] == "message")["direct"] and not bob.expect(lambda e: e["type"] == "message")["direct"], "which addresses that member")
        run("carol", "send", "hey @bob, look")
        check(bob.expect(lambda e: e["type"] == "message")["direct"] and not alice.expect(lambda e: e["type"] == "message")["direct"], "and so does @name in the text")

        carol_fp = next(m["fp"] for m in run("alice", "members")["members"] if m["name"] == "Carol")
        run("alice", "remove", carol_fp)
        carol.expect(lambda e: e["type"] == "removed")
        bob.expect(lambda e: e["type"] == "left" and e["member"]["name"] == "Carol")
        check(True, "removed member is told; others see it")

        run("bob", "leave")
        left = alice.expect(lambda e: e["type"] == "left" and e["member"]["name"] == "Bob")
        check(left["by"]["name"] == "Bob", "a member that leaves is shown leaving, not removed by whoever committed it")
        bob.expect(lambda e: e["type"] == "removed")
        check([m["name"] for m in run("alice", "members")["members"]] == ["Alice"], "leaving is committed by a remaining member")
        check(not os.path.exists(attachment), "attachments are deleted when the session leaves the group")

        dave = Listener("dave")
        listeners.append(dave)
        run("dave", "join", run("alice", "invite", "--group", group)["link"])
        alice.expect(lambda e: e["type"] == "joined" and e["member"]["name"] == "Dave")
        epoch = run("alice", "groups")[0]["epoch"]
        alice.stop()
        for i in range(22):
            run("dave", "send", f"message {i}")
        alice = Listener("alice")
        listeners.append(alice)
        omitted = alice.expect(lambda e: e["type"] == "omitted")
        first = alice.expect(lambda e: e["type"] == "message")
        check(omitted["count"] == 2 and first["content"] == "message 2", "restart catches up on the last 20 messages")
        check(run("alice", "groups")[0]["epoch"] == epoch + 1, "then replaces its keys with a commit")
        run("dave", "send", "after the update")
        alice.expect(lambda e: e.get("content") == "after the update")
        run("alice", "send", "seen it")
        check(dave.expect(lambda e: e["type"] == "message")["content"] == "seen it", "and both sides still read each other")

        # The relay takes a commit but its answer is lost: the session must still move to the epoch it made.
        lossy_env = Proxy.start()
        lost = Listener("lost", env=lossy_env)
        kate, liam = Listener("kate"), Listener("liam")
        listeners += [lost, kate, liam]
        lossy = run("lost", "invite", env=lossy_env)
        run("kate", "join", lossy["link"])
        run("liam", "join", run("lost", "invite", "--group", lossy["group"], env=lossy_env)["link"])
        kate.expect(lambda e: e["type"] == "joined" and e["member"]["name"] == "Liam")
        Proxy.lose = f"POST /g/{lossy['group']}/messages"
        liam_fp = liam.ready["member"]["fp"]
        run("lost", "remove", liam_fp, ok=False, env=lossy_env)
        liam.expect(lambda e: e["type"] == "removed")
        until(lambda: run("lost", "members", env=lossy_env)["members"], lambda members: len(members) == 2)
        run("lost", "send", "after the lost answer", env=lossy_env)
        check(kate.expect(lambda e: e["type"] == "message")["content"] == "after the lost answer", "a commit the relay took though its answer was lost still counts for its sender")
        lost.expect(lambda e: e["type"] == "left" and e["member"]["name"] == "Liam")
        invite = run("lost", "invite", "--group", lossy["group"], env=lossy_env)
        Proxy.lose = f"GET /i/{invite['code'].split('-')[0]}/join"
        run("liam", "join", invite["link"])
        check(Proxy.lose is None, "an inviter whose wait for the joiner fails once waits again")
        gone = run("kate", "invite")
        run("kate", "leave", "--group", gone["group"])
        refused = run("liam", "join", gone["link"], ok=False)
        check("could not admit" in refused and "unknown group" in refused, "a joiner the inviter could not add is told why at once")

        folder = os.path.join(HOME, "shared", "chat")
        erin, frank = Listener("erin", extra=["--keep-log"]), Listener("frank")
        listeners += [erin, frank]
        erin_fp, frank_fp = erin.ready["member"]["fp"], frank.ready["member"]["fp"]
        check(run("erin", "join", folder)["group"] == folder and os.path.isdir(folder), "joining a folder creates it; the group is its path")
        erin.expect(lambda e: e["type"] == "joined" and e["group"] == folder)
        check(os.path.samefile(run("frank", "join", "shared/chat", cwd=HOME)["group"], folder), "a relative path is resolved where the command runs")
        check(run("frank", "members", "--group", "shared/chat", cwd=HOME)["group"] == run("frank", "groups")[0]["group"], "and so is --group")
        frank.expect(lambda e: e["type"] == "joined" and e["member"]["fp"] == erin_fp)
        erin.expect(lambda e: e["type"] == "joined" and e["member"]["fp"] == frank_fp)
        check(True, "joining a folder tells its members")
        check([m["fp"] for m in run("frank", "members")["members"]] == [frank_fp, erin_fp], "so a member who has not spoken yet is listed")

        hello = run("erin", "send", "--to", frank_fp, "hello frank")["id"]
        got = frank.expect(lambda e: e["type"] == "message")
        check(got["id"] == hello and got["from"]["name"] == "Erin" and got["direct"], "and can be addressed")
        check("has the fingerprint or name" in run("frank", "send", "--to", "0123456789abcdef", "x", ok=False), "--to must be a known member")

        reply = run("frank", "send", "--to", erin_fp, "--reply-to", hello, "hi erin")["id"]
        got = erin.expect(lambda e: e["type"] == "message")
        check(got["id"] == reply and got["direct"] and got["reply_to"] == hello, "erin receives frank's direct reply")
        history = run("erin", "read", reply, "--ancestors", "1")
        check([m["id"] for m in history] == [hello, reply], "frank's read frontier covers erin's message")
        check([m["content"] for m in history] == ["hello frank", "hi erin"], "listen --keep-log keeps it")
        with open(os.path.join(folder, reply + ".json"), "rb") as f:
            data = f.read()
        record = json.loads(data)
        check(hashlib.sha256(data).hexdigest() == reply and abs(record.pop("at") / 1000 - time.time()) < 60 and record == {"from": {"name": "Frank", "fp": frank_fp},
              "type": "message", "content": "hi erin", "after": [hello], "to": [erin_fp], "reply_to": hello}, "the file is the message plus from and when, named by its hash")
        run("frank", "send", "--attach", "-", "from stdin", input="piped")
        with open(run("erin", "fetch", erin.expect(lambda e: e["type"] == "message")["attachment"]["link"])["path"]) as f:
            check(f.read() == "piped", "--attach - reads stdin; folder groups carry attachments too, in the folder")

        hand = {"from": {"name": "Hand", "fp": "00"}, "at": 0, "type": "message", "after": []}
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

        notes = os.path.join(HOME, "shared", "notes")
        erin_file = run("erin", "join", "--kind", "doc", notes)["file"]
        check(content(erin_file) == "", "a new folder group can be a doc, which the session keeps in a file")
        frank_file = os.path.join(HOME, "frank", "notes.md")
        check(run("frank", "join", notes, frank_file)["file"] == frank_file, "and stays one for whoever joins it, in the file they name")
        check(next(g for g in run("frank", "groups") if g["group"] == notes)["file"] == frank_file, "which groups lists")
        write(erin_file, "one\ntwo\n")
        check(until(lambda: content(frank_file), lambda t: t == "one\ntwo\n") == "one\ntwo\n", "what a member writes to its file reaches the others' files")
        run("frank", "send", "still one chat")
        check(erin.expect(lambda e: e.get("content") == "still one chat"), "chat commands find the one chat")
        attached = run("erin", "attach", write("photo.png", png(8, 8)))
        check(attached["markdown"] == "![photo.png](attachments/photo.png)", "attach finds the one doc; in a folder group, an image from elsewhere is copied into the folder and linked by its path")
        write(erin_file, content(erin_file) + attached["markdown"] + "\n")
        until(lambda: content(frank_file), lambda t: attached["link"] in t)
        with open(run("frank", "fetch", attached["link"])["path"], "rb") as f:
            check(f.read() == png(8, 8), "which members find there, by its link")
        with open(os.path.join(notes, "chart.png"), "wb") as f:
            f.write(png(4, 4))
        check(run("erin", "attach", os.path.join(notes, "chart.png"))["link"] == "chart.png", "a file already in the folder is linked where it is")
        check("no message or doc here links that" in run("frank", "fetch", "../secret.txt", ok=False), "fetch reaches only what a message or doc links")

        erin.stop()
        for i in range(22):
            run("frank", "send", f"folder {i}")
        write(frank_file, content(frank_file).replace("two", "two\nthree"))
        run("frank", "groups")
        write(erin_file, content(erin_file).replace("one", "ONE"))
        erin = Listener("erin")
        listeners.append(erin)
        caught = [erin.expect(lambda e: e["type"] in ("omitted", "message", "edited")) for _ in range(22)]
        omitted = next(e for e in caught if e["type"] == "omitted")
        got = [e["content"] for e in caught if e["type"] == "message"]
        check(omitted["count"] == 2 and got == [f"folder {i}" for i in range(2, 22)], "restart catches up on the folder's last 20 messages, in order")
        edited = next(e for e in caught if e["type"] == "edited")
        merged = f"ONE\ntwo\nthree\n{attached['markdown']}\n"
        check(edited["by"][0]["fp"] == frank_fp and edited["lines"] == 1 and edited["file"] == erin_file, "and on what others edited in the doc, once its file is in step")
        check(content(erin_file) == merged and until(lambda: content(frank_file), lambda t: t == merged) == merged, "where what each changed meanwhile is merged, line by line")
        check(run("frank", "leave", "--group", "shared/chat", cwd=HOME)["left"] and run("frank", "leave", "--group", notes)["left"] and run("frank", "groups") == [], "leaving folder groups")
        check(content(frank_file) == merged, "leaves a file the member named")
        run("erin", "leave", "--group", notes)
        check(not os.path.exists(erin_file), "and deletes one the session made")

        board = os.path.join(HOME, "board")
        gina, hank = Listener("gina", hold=600), Listener("hank")
        listeners += [gina, hank]
        gina_fp, hank_fp = gina.ready["member"]["fp"], hank.ready["member"]["fp"]
        run("gina", "join", board)
        gina.expect(lambda e: e["type"] == "joined")
        run("hank", "join", board)
        check(gina.expect(lambda e: e["type"] == "joined")["member"]["fp"] == hank_fp, "a member joining wakes the session")
        run("hank", "send", "for everyone")
        check(gina.poll(2) is None, "a message not addressed to the session waits")
        run("gina", "members")
        check(gina.expect(lambda e: e["type"] == "message")["content"] == "for everyone", "until the agent runs a command")

        run("hank", "send", "for the room")
        check(gina.poll(2) is None, "and waits again")
        run("hank", "send", "--to", gina_fp, "for gina")
        got = [gina.expect(lambda e: e["type"] == "message")["content"] for _ in range(2)]
        check(got == ["for the room", "for gina"], "a message addressed to the session wakes it, after the held ones")
        run("hank", "send", "--urgent", "all hands")
        check(gina.expect(lambda e: e["type"] == "message")["urgent"], "so does an urgent message")
        question = run("gina", "send", "any news?")["id"]
        hank.expect(lambda e: e.get("id") == question)
        run("hank", "send", "--reply-to", question, "yes")
        got = gina.expect(lambda e: e["type"] == "message")
        check(got["reply_to"] == question and not got["direct"], "and a reply to one of its messages")
        run("hank", "send", "@Gina, look")
        check(gina.expect(lambda e: e["type"] == "message")["direct"], "and a message that mentions it")
        plan = os.path.join(HOME, "plan")
        gina_plan = run("gina", "join", "--kind", "doc", plan)["file"]
        gina.expect(lambda e: e["type"] == "joined" and e["group"] == plan)
        hank_plan = run("hank", "join", plan)["file"]
        gina.expect(lambda e: e["type"] == "joined" and e["group"] == plan)
        write(hank_plan, "- [ ] ship it\n")
        run("hank", "groups")
        check(gina.poll(3) is None and content(gina_plan) == "- [ ] ship it\n", "an edit by others waits, like a message not addressed to the session")
        write(hank_plan, "- [ ] ship it\n- [ ] @gina review it\n")
        run("hank", "groups")
        edited = gina.expect(lambda e: e["type"] == "edited" and e["direct"])
        check(edited["by"][0]["fp"] == hank_fp and content(gina_plan) == "- [ ] ship it\n- [ ] @gina review it\n", "unless a line it changed mentions the session, whose file is in step when it wakes")

        jill = Listener("jill", hold=2)
        listeners.append(jill)
        run("jill", "join", board)
        jill.expect(lambda e: e.get("content") == "yes")
        start = time.time()
        run("hank", "send", "later")
        jill.expect(lambda e: e.get("content") == "later")
        check(time.time() - start >= 2, "a held message is printed once --hold runs out")

        # Each letmeknow home is a device; an entity lists devices, and every session on them speaks as it.
        homes = {d: {**ENV, "LETMEKNOW_HOME": os.path.join(HOME, d)} for d in ("laptop", "server", "elsewhere")}
        lap, srv, kim = Listener("lap", env=homes["laptop"]), Listener("srv", env=homes["server"]), Listener("kim", env=homes["elsewhere"])
        listeners += [lap, srv, kim]
        on = lambda listener, *args, **kw: run(listener.session, *args, env=homes[{"lap": "laptop", "srv": "server", "kim": "elsewhere"}[listener.session]], **kw)
        matthew = on(lap, "entity", "create", "Matthew")["entity"]
        link = on(lap, "invite", "--entity", "Matthew")
        check(link["entity"] == matthew and on(srv, "join", link["link"])["entity"] == matthew, "a device link adds another device to an entity")
        devices = on(srv, "entity", "list")
        listed = devices["entities"][0]["members"]
        check([m["you"] for m in listed] == [False, True] and devices["device"]["id"] == listed[1]["id"], "both devices are on its list")
        srv_device = devices["device"]["id"]

        group = on(lap, "invite")
        seen = {m["name"]: m.get("entity") for m in on(kim, "join", group["link"])["members"]}
        check(seen["Lap"]["name"] == "Matthew" and seen["Lap"]["new"] and seen["Kim"] is None, "others see which entity a session speaks as, and that they have not met it")
        on(srv, "join", on(lap, "invite", "--group", group["group"])["link"])
        joined = kim.expect(lambda e: e["type"] == "joined" and e["member"]["name"] == "Srv")
        check(joined["member"]["entity"]["id"] == matthew and not joined["member"]["entity"]["new"], "a session on another of its devices is the same entity, met before")
        on(kim, "send", "hello Matthew")
        on(srv, "send", "--to", kim.ready["member"]["fp"], "from the server")
        got = kim.expect(lambda e: e["type"] == "message" and e["content"] == "from the server")
        check(got["from"]["entity"]["name"] == "Matthew" and not got["from"]["entity"]["yours"], "a message shows its sender's entity")
        got = lap.expect(lambda e: e["type"] == "message" and e["content"] == "from the server")
        check(got["from"]["entity"]["yours"], "and whether that entity is yours")

        alone = Listener("lap-alone", env=homes["server"])
        listeners.append(alone)
        on_alone = lambda *args, **kw: run("lap-alone", *args, env=homes["server"], **kw)
        on_alone("join", "--as", "self", on(lap, "invite", "--group", group["group"])["link"])
        joined = kim.expect(lambda e: e["type"] == "joined" and e["member"]["name"] == "Lap-Alone")
        check("entity" not in joined["member"] and "device" not in joined["member"], "--as self speaks as the session alone")
        sent = on(kim, "send", "--to", "MATTHEW", "for every device of Matthew")
        check(sorted(sent["to"]) == sorted([lap.ready["member"]["fp"], srv.ready["member"]["fp"]]), "--to with an entity's name addresses each of its devices")
        check(lap.expect(lambda e: e.get("content") == "for every device of Matthew")["direct"] and srv.expect(lambda e: e.get("content") == "for every device of Matthew")["direct"], "which each wake")
        check("could be any of" in on(kim, "send", "--to", "lap", "x", ok=False), "a name that members of different entities answer to is refused")

        later = Listener("later", env=homes["elsewhere"])
        listeners.append(later)
        on(lap, "name", "Priorities")
        check(kim.expect(lambda e: e["type"] == "settings")["settings"]["name"] == "Priorities", "a group can be named, for everyone in it")
        on(lap, "open", "Matthew")
        tick = Listener("tick", env=homes["server"])
        listeners.append(tick)
        on_tick = lambda *args, **kw: run("tick", *args, env=homes["server"], **kw)
        listed = [g for g in on_tick("groups") if g.get("joined") is False]
        check([(g["group"], g["name"], g["open_to"]) for g in listed] == [(group["group"], "Priorities", "Matthew")], "a group opened to an entity is listed for its sessions")
        check(len(on_tick("join", group["group"])["members"]) == 5, "and any of them joins it without an invite, once a member admits it")
        joined = kim.expect(lambda e: e["type"] == "joined" and e["member"]["name"] == "Tick")
        check(joined["member"]["entity"]["name"] == "Matthew", "the others see who it speaks for")
        check(next(g for g in on_tick("groups") if g["group"] == group["group"])["name"] == "Priorities", "the member who admits it passes on the group's settings")
        check("not open to any entity" in run("later", "join", group["group"], env=homes["elsewhere"], ok=False), "the group is not open to other entities")

        # Docs: a CRDT text that every member edits, each in a file of its own that its session keeps in step.
        lap_file = write("list.md", "- [ ] alpha\n- [ ] beta\n- [ ] gamma\n")
        doc = on(lap, "invite", "--kind", "doc", "--name", "List", lap_file)
        check(doc["kind"] == "doc" and doc["file"] == lap_file, "a doc group is made by inviting into one, from a file that holds its first text")
        check("exists" in on(kim, "join", doc["link"], lap_file, ok=False), "a member joins into a new file, as the doc has its text already")
        kim_file = on(kim, "join", doc["link"])["file"]
        check(os.path.basename(kim_file).startswith("List-"), "or into one its session makes, named after the doc")
        check(until(lambda: content(kim_file), bool) == content(lap_file), "which gets the text")
        tick_file = os.path.join(HOME, "tick", "list.md")
        on_tick("join", on(lap, "invite", "--group", doc["group"])["link"], tick_file)
        check("is a doc group" in on(kim, "send", "--group", doc["group"], "hi", ok=False), "a doc refuses what is for chats")
        on(kim, "send", "one chat, one doc")
        check(lap.expect(lambda e: e.get("content") == "one chat, one doc"), "chat commands find the one chat of a session in a chat and a doc")
        until(lambda: content(tick_file), bool)
        tick.stop()
        write(kim_file, "- [x] alpha\n- [ ] beta\n- [ ] gamma\n")
        until(lambda: content(lap_file), lambda t: t.startswith("- [x]"))
        write(lap_file, "- [ ] gamma\n- [x] alpha\n- [ ] beta (asked Bob)\n")
        on(lap, "groups")
        write(tick_file, "- [ ] alpha\n- [x] beta\n- [x] gamma\n- [ ] delta\n")
        tick = Listener("tick", env=homes["server"])
        listeners.append(tick)
        lost = tick.expect(lambda e: e["type"] == "warning")
        final = "- [x] gamma\n- [ ] delta\n- [x] alpha\n- [ ] beta (asked Bob)\n"
        check(content(tick_file) == final, "an edit to a file while others changed the doc lands on the lines where they are now; their changes stay")
        check("- [x] beta" in lost["text"] and lost["group"] == doc["group"], "a change to a line someone else changed meanwhile is lost, with a warning")
        check(until(lambda: content(kim_file), lambda t: t == final) == final == until(lambda: content(lap_file), lambda t: t == final), "every member's file converges on the same text")
        edited = tick.expect(lambda e: e["type"] == "edited")
        check(sorted(m["name"] for m in edited["by"]) == ["Kim", "Lap"] and edited["file"] == tick_file, "the agent is told who else edited the doc")
        write(lap_file, final.replace("\n", "\r\n") + "- [ ] epsilon\r\n")
        final += "- [ ] epsilon\n"
        check(until(lambda: content(kim_file), lambda t: t == final) == final, "the text is LF only: CRLF an agent writes is converted")

        # Files in a doc: an agent uploads one and links it; the others fetch it from the relay, and keep it.
        attached = on(lap, "attach", write("chart.png", png(40, 30)))
        check(attached["markdown"] == f"![chart.png]({attached['link']})", "attach uploads an image and gives its markdown link")
        notes_link = on(lap, "attach", write("notes.txt", "plain notes"))["markdown"]
        check(notes_link.startswith("[notes.txt](lmk:"), "and any other file, as a plain link")
        write(lap_file, content(lap_file) + attached["markdown"] + "\n")
        check(attached["link"] in until(lambda: content(kim_file), lambda t: attached["link"] in t), "a doc's file holds the link, not the image")
        url = f"{RELAY}/g/{doc['group']}/blobs/{attached['link'][4:68]}"
        sealed = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url).read()
        check(png(40, 30) not in sealed, "the relay holds it encrypted")
        check(until(lambda: in_state(kim, sealed), bool), "members keep the files their doc links")
        fetched = on(kim, "fetch", attached["link"])
        with open(fetched["path"], "rb") as f:
            check(f.read() == png(40, 30) and fetched["path"].endswith(".png"), "another member fetches the image into a file")
        check(os.name == "nt" or os.stat(fetched["path"]).st_mode & 0o777 == 0o600, "that only its owner can read")
        check("files go up to" in on(lap, "attach", write("huge.bin", os.urandom(10 * 1024 * 1024 + 1)), ok=False), "a file over 10 MiB is refused")

        listed = on(lap, "entity", "remove", srv_device)["members"]
        check([m["name"] for m in listed] == [devices["entities"][0]["members"][0]["name"]], "a member can be taken off an entity's list")
        run("later", "join", on(lap, "invite", "--group", group["group"])["link"], env=homes["elsewhere"])
        seen = {m["name"]: m.get("entity") for m in run("later", "members", env=homes["elsewhere"])["members"]}
        check(seen["Srv"]["error"] == "not on Matthew's list" and seen["Lap"]["name"] == "Matthew", "after which its sessions no longer count as the entity")
        later_file = run("later", "join", on(lap, "invite", "--group", doc["group"])["link"], env=homes["elsewhere"])["file"]
        text = until(lambda: content(later_file), bool)
        check(text == final + attached["markdown"] + "\n", "a member added later gets the text from a snapshot, as it cannot read what came before")
        with open(run("later", "fetch", attached["link"], env=homes["elsewhere"])["path"], "rb") as f:
            check(f.read() == png(40, 30), "and the files it links")

        check("several sessions are running" in run(None, "groups", ok=False), "without --session, several running sessions are ambiguous")
        solo_env = {**ENV, "LETMEKNOW_HOME": os.path.join(HOME, "solo")}
        check("no session is running" in run(None, "groups", ok=False, env=solo_env), "without --session, none running is an error")
        solo = Listener(None, env=solo_env)
        listeners.append(solo)
        handle = solo.ready["session"]
        check(len(handle.split("-")) == 2, f"listen without --session picks a handle ({handle})")
        check(run(None, "groups", env=solo_env) == [], "commands use the one running session")
        if BROWSER and subprocess.run([shutil.which("node"), "e2e.mjs"], cwd=web, env={**ENV, "RELAY": RELAY, "BIN": BIN}).returncode:
            sys.exit("browser test failed")
        # Requests the relay refuses before reading their bodies must not fault it.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for method, path in (("POST", f"/g/{'0' * 32}/nope"), ("PUT", f"/b/{'0' * 32}"), ("POST", f"/b/{'0' * 32}/ws")):
            try:
                opener.open(urllib.request.Request(RELAY + path, data=os.urandom(256 * 1024), method=method), timeout=10)
            except urllib.error.HTTPError:
                pass
        time.sleep(1)
        with open(os.path.join(ROOT, "relay", ".wrangler", "e2e.log"), encoding="utf-8", errors="replace") as f:
            uncaught = [line for line in f if "Uncaught" in line]
        check(not uncaught, f"the relay threw nothing uncaught {uncaught[:1]}")
        print("all passed")
    finally:
        for listener in listeners:
            listener.stop()
        relay.terminate()
        shutil.rmtree(HOME)


main()
