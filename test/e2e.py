#!/usr/bin/env python3
"""End-to-end test: a local `letmeknow serve` (membership service, relay and web client, with a self-signed certificate)
and several `letmeknow listen` processes, each its own device; then the browser client in Chromium (web/e2e.mjs) with
native sessions of its own. --no-browser skips building and testing the browser client, which is the same on every OS."""
import json, os, queue, shutil, socket, subprocess, sys, tempfile, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target", "debug", "letmeknow" + (".exe" if os.name == "nt" else ""))
# git finds git-remote-lmk on PATH.
ENV_PATH = os.path.dirname(BIN) + os.pathsep + os.environ["PATH"]
WEB = os.path.join(ROOT, "web")
BROWSER = "--no-browser" not in sys.argv
TMP = tempfile.mkdtemp(prefix="lmk-e2e-")
ENV = {**os.environ, "NO_PROXY": "localhost,127.0.0.1", "PATH": ENV_PATH, "GIT_AUTHOR_NAME": "e2e", "GIT_AUTHOR_EMAIL": "e2e@example.com",
       "GIT_COMMITTER_NAME": "e2e", "GIT_COMMITTER_EMAIL": "e2e@example.com"}
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
        args = [bin, "--session", session, "listen", "--name", session.title(), "--hold", "0"]
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


def git(session, *args, cwd=None, ok=True, alias=False, bin=BIN):
    """git, as an agent of `session` runs it: lmk:: remotes reach that session, through the git-remote-lmk beside `bin`
    or, with `alias`, through the git alias that npm installs need."""
    env = {**ENV, "LETMEKNOW_HOME": home(session), "LETMEKNOW_SESSION": session, "PATH": os.path.dirname(bin) + os.pathsep + os.environ["PATH"]}
    config = ["-c", "init.defaultBranch=main"]
    if alias:
        env["PATH"] = os.environ["PATH"]
        config += ["-c", f"alias.remote-lmk=!'{bin}' git-remote-lmk"]
    result = subprocess.run(["git", *config, *args], cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
    if ok and result.returncode:
        sys.exit(f"{session} git {args}: {result.stderr}")
    return result


def git_kind(alice, bob, dave, listeners):
    """A git group: clone, push and fetch between two sessions, a race on one branch, a push with no other member online,
    chat beside the pushes, and a joiner that gets the whole history. Returns bob's session, which it restarts."""
    made = run("alice", "invite", "--kind", "git", "--name", "Repo")
    check(made["kind"] == "git" and made["remote"] == f"lmk::{made['group']}", "invite --kind git makes a git group and names its remote")
    run("bob", "join", made["link"])
    alice.expect("joined", lambda e: e["group"] == made["group"])
    ours, theirs = os.path.join(TMP, "alice-repo"), os.path.join(TMP, "bob-repo")
    git("alice", "init", "-q", ours)
    write("alice-repo/README.md", "hello\n")
    git("alice", "add", "README.md", cwd=ours)
    git("alice", "commit", "-qm", "first commit", cwd=ours)
    git("alice", "remote", "add", "team", "lmk::Repo", cwd=ours)
    git("alice", "push", "-q", "team", "main", cwd=ours)
    pushed = bob.expect("pushed", lambda e: e["group"] == made["group"])
    check(pushed["ref"] == "refs/heads/main" and pushed["subjects"] == ["first commit"] and pushed["by"]["name"] == "Alice", "a push reaches the other member as a pushed event")
    git("bob", "clone", "-q", "lmk::Repo", theirs, alias=True)
    check(content(os.path.join(theirs, "README.md")) == "hello\n", "the other member clones it with git, through the git alias")
    write("bob-repo/NOTES.md", "notes\n")
    git("bob", "add", "NOTES.md", cwd=theirs)
    git("bob", "commit", "-qm", "bob's notes", cwd=theirs)
    git("bob", "push", "-q", "origin", "main", cwd=theirs)
    alice.expect("pushed", lambda e: e["subjects"] == ["bob's notes"])
    git("alice", "pull", "-q", "--ff-only", "team", "main", cwd=ours)
    check(os.path.exists(os.path.join(ours, "NOTES.md")), "and pushes back, which the first fetches")

    # Both push onto the same tip at once: the log takes one first, and the other is told to fetch first.
    for who, repo in (("alice", ours), ("bob", theirs)):
        write(os.path.join(repo, f"{who}.txt"), who)
        git(who, "add", f"{who}.txt", cwd=repo)
        git(who, "commit", "-qm", f"{who}'s change", cwd=repo)
    results = {}
    racers = [threading.Thread(target=lambda who, repo: results.update({who: git(who, "push", "team" if who == "alice" else "origin", "main", cwd=repo, ok=False)}), args=a)
              for a in (("alice", ours), ("bob", theirs))]
    for racer in racers:
        racer.start()
    for racer in racers:
        racer.join()
    won = [who for who, result in results.items() if result.returncode == 0]
    lost = [who for who, result in results.items() if result.returncode != 0]
    check(len(won) == 1 and "fetch first" in results[lost[0]].stderr, "of two pushes onto one tip, one wins and the other is told to fetch first")
    loser, repo = lost[0], ours if lost[0] == "alice" else theirs
    remote = "team" if loser == "alice" else "origin"
    git(loser, "pull", "-q", "--rebase", remote, "main", cwd=repo)
    git(loser, "push", "-q", remote, "main", cwd=repo)
    check(git(loser, "log", "--format=%s", "-n", "2", cwd=repo).stdout.split("\n")[1] == f"{won[0]}'s change", "the other fetches, rebases and pushes")
    check(git(loser, "push", "-f", remote, "HEAD~1:main", cwd=repo, ok=False).returncode != 0, "a force push is refused")

    # Chat in the same group.
    run("alice", "send", f"--group={made['group']}", "@bob the build is green")
    check(bob.expect("message", lambda e: e["content"] == "@bob the build is green")["group"] == made["group"], "a git group carries chat")

    # With no other member online, a push fails and says so.
    tip = git(loser, "rev-parse", "HEAD", cwd=repo).stdout.strip()
    head = lambda: (git("alice", "pull", "-q", "--ff-only", "team", "main", cwd=ours, ok=False), git("alice", "rev-parse", "HEAD", cwd=ours).stdout.strip())[1]
    check(until(head, lambda h: h == tip) == tip, "both members end at the same tip")
    bob.stop()
    listeners.remove(bob)
    write("alice-repo/late.txt", "late")
    git("alice", "add", "late.txt", cwd=ours)
    git("alice", "commit", "-qm", "while bob is away", cwd=ours)
    failed = git("alice", "push", "team", "main", cwd=ours, ok=False)
    check(failed.returncode != 0 and "no other member is online" in failed.stderr, "a push with no other member online fails and says so")
    bob = Listener("bob")
    listeners.append(bob)
    until(lambda: git("alice", "push", "-q", "team", "main", cwd=ours, ok=False).returncode, lambda code: code == 0, timeout=60)
    bob.expect("pushed", lambda e: e["subjects"] == ["while bob is away"], timeout=60)

    # A joiner gets the whole history as the group's state.
    run("dave", "join", run("alice", "invite", f"--group={made['group']}")["link"])
    cloned = os.path.join(TMP, "dave-repo")
    until(lambda: git("dave", "clone", "-q", "lmk::Repo", cloned, ok=False).returncode, lambda code: code == 0)
    history = git("dave", "log", "--format=%s", cwd=cloned).stdout.strip().split("\n")
    check(len(history) == 5 and history[0] == "while bob is away" and history[-1] == "first commit", "a joiner gets the whole history")
    return bob


def serve():
    """A local `letmeknow serve` with a self-signed certificate; returns it and its membership address."""
    cert, key = os.path.join(TMP, "cert.pem"), os.path.join(TMP, "key.pem")
    subprocess.run(["cargo", "run", "-q", "-p", "letmeknow", "--example", "self_signed", "--", cert, key], cwd=ROOT, check=True)
    https = free_port()
    args = [BIN, "serve", "--domain", "localhost", "--https-port", str(https), "--http-port", str(free_port()), "--membership-port", str(free_port()),
            "--qad-port", str(free_port()), "--state", os.path.join(TMP, "serve"), "--cert", cert, "--key", key]
    if BROWSER:
        args += ["--web", os.path.join(WEB, "dist")]
    proc = subprocess.Popen(args, env=ENV, stdout=subprocess.PIPE, stderr=open(os.path.join(TMP, "serve.log"), "w"), text=True)
    membership = proc.stdout.readline().strip().removeprefix("membership: ")
    ENV.update(LETMEKNOW_CA=cert, LETMEKNOW_RELAY=f"https://localhost:{https}", LETMEKNOW_MEMBERSHIP=membership)
    return proc


def main():
    subprocess.run(["cargo", "build", "-q", "-p", "letmeknow", "-p", "letmeknow-kind-doc", "-p", "letmeknow-kind-git"], cwd=ROOT, check=True)
    if BROWSER:
        subprocess.run([shutil.which("npm"), "run", "build"], cwd=WEB, check=True)
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
        check(invite["link"].startswith("https://letmeknow.dev/i#2.g.") and invite["kind"] == "chat", "invite gives a link to a new chat")
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
        with open(bob_notes, "ab") as f:
            f.write(b"- [ ] gamma @alice\n")
        edited = alice.expect("edited", lambda e: e["group"] == doc["group"])
        check(edited["by"][0]["name"] == "Bob" and edited["direct"], "alice is told bob edited, mentioning her")
        check(content(notes) == "- [ ] alpha\n- [ ] beta\n- [ ] gamma @alice\n", "and her file has his line")
        write("notes.md", "- [x] alpha\n- [ ] beta\n- [ ] gamma @alice\n")
        check(until(lambda: content(bob_notes), lambda text: text.startswith("- [x] alpha")) == "- [x] alpha\n- [ ] beta\n- [ ] gamma @alice\n", "her edit reaches his file")
        attached = run("alice", "doc", "attach", f"--group={doc['group']}", token)
        check(attached["markdown"].startswith("[token.txt](lmk:"), "the doc plugin answers `letmeknow doc attach`")
        with open(notes, "a") as f:
            f.write(attached["markdown"] + "\n")
        until(lambda: content(bob_notes), lambda text: attached["link"] in text)
        check(content(run("bob", "fetch", attached["link"])["path"]) == "s3cret", "and a member fetches the file the doc links")

        dave = Listener("dave")
        listeners.append(dave)
        bob = git_kind(alice, bob, dave, listeners)

        # Carol joins through bob, who means the link for her; the chat is then opened to bob's identity.
        joined = run("carol", "join", run("bob", "invite", f"--group={group}", "--for", "Carol")["link"])
        check(len(joined["members"]) == 3, "a member invites another")
        alice.expect("joined", lambda e: e["member"]["name"] == "Carol" and e["by"]["name"] == "Bob")
        check(any(c["name"] == "Carol" for c in run("bob", "contacts")["contacts"]), "carol is bob's contact")
        desk = Listener("desk", device="bob")
        check(any(c["name"] == "Carol" for c in run("desk", "contacts", device="bob")["contacts"]), "another session on bob's machine sees his contacts")
        desk.stop()

        # A device link: bob's tablet joins his identity, and his contacts reach it.
        link = run("bob", "invite", "--identity", "Bob")["link"]
        check("#2.d." in link, "invite --identity gives a device link")
        tablet = Listener("tablet")
        listeners.append(tablet)
        check("device" in run("tablet", "join", link), "the tablet joins bob's identity")
        check(len(run("bob", "identity", "list")["identities"][0]["devices"]) == 2, "bob's identity lists two devices")
        contacts = until(lambda: run("tablet", "contacts")["contacts"], lambda c: any(x["name"] == "Carol" for x in c))
        check(any(c["name"] == "Carol" and c["how"] == "verified" for c in contacts), "bob's contacts reach his tablet")

        # An open group: the chat is opened to bob's identity, and his tablet joins it without an invite.
        opened = run("alice", "open", f"--group={group}", "Bob (Acme)")
        check(opened["settings"]["open"][0]["name"] == "Bob (Acme)", "alice opens the chat to bob's identity")
        listed = until(lambda: run("tablet", "groups"), lambda groups: any(g["group"] == group for g in groups))
        check(any(g["group"] == group and g.get("joined") is False for g in listed), "the tablet sees the chat open to it")
        joined = run("tablet", "join", "--", group)
        check(len(joined["members"]) == 4, "the tablet joins the open chat")
        event = alice.expect("joined", lambda e: e["member"]["name"] == "Tablet")
        check(event["how"] == "open" and event["member"]["identity"]["name"] == "Bob (Acme)", "as a device of the identity it is open to")

        # A removal.
        carol_fp = next(m["fp"] for m in run("alice", "members", f"--group={group}")["members"] if m["name"] == "Carol")
        run("alice", "remove", f"--group={group}", carol_fp)
        check(carol.expect("removed")["by"]["name"] == "Alice", "carol is told alice removed her")
        alice.expect("left", lambda e: e["member"]["name"] == "Carol")
        check(run("carol", "groups") == [], "and is in no group")

        # Any member that holds an invite admits by it: erin gets in while bob, who made her link, is stopped.
        link = run("bob", "invite", f"--group={group}")["link"]
        erin = Listener("erin")
        listeners.append(erin)

        # A restart: bob misses a message and a commit, and catches up when he is back.
        bob.stop()
        listeners.remove(bob)
        joined = run("erin", "join", link)
        check(joined["group"] == group and len(joined["members"]) == 4, "a joiner gets in while the inviter is stopped")
        check(alice.expect("joined", lambda e: e["member"]["name"] == "Erin")["by"]["name"] != "Bob", "admitted by another member")
        run("alice", "name", f"--group={group}", "Release")
        missed = run("alice", "send", f"--group={group}", "while you were away")
        check("held_by" in missed, "the tablet holds what bob misses")
        bob = Listener("bob")
        listeners.append(bob)
        got = bob.expect("message", lambda e: e["content"] == "while you were away", timeout=60)
        check(got["group"] == group, "a restarted session catches up on what it missed")
        renamed = until(lambda: run("bob", "groups"), lambda gs: any(g.get("name") == "Release" for g in gs))
        check(any(g.get("name") == "Release" for g in renamed), "and on the commits it missed")

        # Bob takes his tablet off his identity while it is stopped: its session leaves his groups all the same.
        key = next(d["key"] for d in run("tablet", "identity", "list")["identities"][0]["devices"] if d["you"])
        tablet.stop()
        listeners.remove(tablet)
        run("bob", "identity", "remove", "--", key)
        left = alice.expect("left", lambda e: e["member"]["name"] == "Tablet", timeout=60)
        check(left["group"] == group, "a device taken off its identity while it is stopped leaves its groups")
        if BROWSER and subprocess.run([shutil.which("node"), "e2e.mjs"], cwd=WEB, env={**ENV, "URL": ENV["LETMEKNOW_RELAY"], "BIN": BIN}).returncode:
            sys.exit("FAIL: the browser test")
        print("all ok")
    finally:
        for listener in listeners:
            listener.proc.kill()
        server.kill()


if __name__ == "__main__":
    main()
