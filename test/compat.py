#!/usr/bin/env python3
"""Cross-version check: sessions of the last release, whose binaries are in the directory LETMEKNOW_OLD names, beside
sessions of this build, on a local `letmeknow serve` of this build: invites both ways, chat both ways with a file, a doc
and a git group, identities with a device of each, a device taken off its identity while a member of the last release is
in its group, a device of this build renamed and leaving an identity with a device of the last release, and a home of the
last release that this build resumes."""
import os, subprocess

import e2e
from e2e import BIN, ROOT, TMP, Listener, check, content, git, run, until, write

OLD = os.path.join(os.environ["LETMEKNOW_OLD"], "letmeknow" + (".exe" if os.name == "nt" else ""))
VERSION = subprocess.run([OLD, "--version"], capture_output=True, text=True, check=True).stdout.split()[-1]


def text(path):
    return content(path) if os.path.exists(path) else None


def member(session, group, name, bin=BIN):
    return next((m for m in run(session, "members", f"--group={group}", bin=bin)["members"] if m["name"] == name), None)


def main():
    subprocess.run(["cargo", "build", "-q", "-p", "letmeknow", "-p", "letmeknow-kind-doc", "-p", "letmeknow-kind-git"], cwd=ROOT, check=True)
    e2e.BROWSER = False
    server = e2e.serve()
    listeners = []
    try:
        ann, ben = Listener("ann", bin=OLD), Listener("ben")
        listeners += [ann, ben]
        run("ann", "identity", "create", "Ann", bin=OLD)
        run("ben", "identity", "create", "Ben")

        # Invites both ways.
        chat = run("ann", "invite", "--name", "Plans", "--for", "Ben", bin=OLD)
        run("ben", "join", chat["link"])
        check(ann.expect("joined")["member"]["name"] == "Ben", f"this build joins by an invite of {VERSION}")
        back = run("ben", "invite", "--name", "Back", "--for", "Ann")
        run("ann", "join", back["link"], bin=OLD)
        check(ben.expect("joined", lambda e: e["group"] == back["group"])["member"]["name"] == "Ann", f"{VERSION} joins by an invite of this build")

        # Chat both ways, with a file.
        for sender, receiver, bin in (("ann", ben, OLD), ("ben", ann, BIN)):
            said = f"@{receiver.session} from {sender}"
            run(sender, "send", f"--group={chat['group']}", "--attach", write(f"{sender}.txt", f"{sender}'s file"), said, bin=bin)
            message = receiver.expect("message", lambda e: e["content"] == said)
            arrived = message["attachment"] if "path" in message["attachment"] else receiver.expect("attachment")
            check(content(arrived["path"]) == f"{sender}'s file", f"a message with a file from {VERSION if bin == OLD else 'this build'} arrives")

        # A doc, made by the last release.
        notes, ben_notes = write("ann-notes.md", "- one\n"), os.path.join(TMP, "ben-notes.md")
        doc = run("ann", "invite", "--kind", "doc", "--name", "Notes", notes, bin=OLD)
        run("ben", "join", doc["link"], ben_notes)
        check(until(lambda: text(ben_notes), lambda t: t == "- one\n") == "- one\n", f"this build joins a doc of {VERSION}")
        with open(ben_notes, "ab") as f:
            f.write(b"- two\n")
        check(until(lambda: text(notes), lambda t: t == "- one\n- two\n") == "- one\n- two\n", "and edits it")
        write("ann-notes.md", "- one\n- two\n- three\n")
        check(until(lambda: text(ben_notes), lambda t: "three" in t) == "- one\n- two\n- three\n", "and takes its edits")

        # A git group, made by this build.
        made = run("ben", "invite", "--kind", "git", "--name", "Repo")
        run("ann", "join", made["link"], bin=OLD)
        ben.expect("joined", lambda e: e["group"] == made["group"])
        ours, theirs = os.path.join(TMP, "ben-repo"), os.path.join(TMP, "ann-repo")
        git("ben", "init", "-q", ours)
        write("ben-repo/README.md", "hello\n")
        git("ben", "add", "README.md", cwd=ours)
        git("ben", "commit", "-qm", "first commit", cwd=ours)
        git("ben", "remote", "add", "team", "lmk::Repo", cwd=ours)
        git("ben", "push", "-q", "team", "main", cwd=ours)
        ann.expect("pushed", lambda e: e["subjects"] == ["first commit"])
        until(lambda: git("ann", "clone", "-q", "lmk::Repo", theirs, ok=False, bin=OLD).returncode, lambda code: code == 0)
        check(text(os.path.join(theirs, "README.md")) == "hello\n", f"{VERSION} clones a git group of this build")
        write("ann-repo/NOTES.md", "notes\n")
        git("ann", "add", "NOTES.md", cwd=theirs, bin=OLD)
        git("ann", "commit", "-qm", "ann's notes", cwd=theirs, bin=OLD)
        git("ann", "push", "-q", "origin", "main", cwd=theirs, bin=OLD)
        ben.expect("pushed", lambda e: e["subjects"] == ["ann's notes"])
        git("ben", "pull", "-q", "--ff-only", "team", "main", cwd=ours)
        check(os.path.exists(os.path.join(ours, "NOTES.md")), "and pushes to it")

        # An identity of each with a device of the other: Ben's tablet runs the last release, Ann's pad this build.
        tab, pad = Listener("tab", bin=OLD), Listener("pad")
        listeners += [tab, pad]
        run("tab", "join", run("ben", "invite", "--identity", "Ben")["link"], bin=OLD)
        run("pad", "join", run("ann", "invite", "--identity", "Ann", bin=OLD)["link"])
        for session, bin, contact in (("tab", OLD, "Ann"), ("pad", BIN, "Ben")):
            contacts = until(lambda: run(session, "contacts", bin=bin)["contacts"], lambda c: any(x["name"] == contact for x in c))
            check(any(x["name"] == contact for x in contacts), f"a device of {VERSION if bin == OLD else 'this build'} joins an identity of the other, and takes its contacts")
        run("tab", "join", run("ben", "invite", f"--group={chat['group']}")["link"], bin=OLD)
        run("pad", "join", run("ann", "invite", f"--group={chat['group']}", bin=OLD)["link"])
        for session, bin, name, identity in (("ann", OLD, "Tab", "Ben"), ("ben", BIN, "Pad", "Ann")):
            seen = until(lambda: member(session, chat["group"], name, bin), lambda m: m and m["identity"].get("name") == identity and "error" not in m["identity"], timeout=60)
            check(seen and "error" not in seen["identity"], f"their sessions speak as their identities, as {session} sees them")

        # Ben takes his phone, of this build, off his identity while it is stopped, with Ann of the last release in the chat.
        phone = Listener("phone")
        listeners.append(phone)
        run("phone", "join", run("ben", "invite", "--identity", "Ben")["link"])
        run("phone", "join", run("ben", "invite", f"--group={chat['group']}")["link"])
        until(lambda: member("ben", chat["group"], "Phone"), lambda m: m and "error" not in m["identity"], timeout=60)
        phone.stop()
        listeners.remove(phone)
        run("ben", "identity", "remove", "--", phone.ready["member"]["device"]["key"])
        check(ann.expect("left", lambda e: e["member"]["name"] == "Phone", timeout=60)["group"] == chat["group"], f"a device taken off its identity leaves a group with a member of {VERSION}")
        # Ben's sessions renew their certificates with the new key, his tablet's by the last release; Ann takes nothing
        # from a member whose certificate she does not hold valid, and her release syncs it only at the next resync.
        for session, bin in (("ben", BIN), ("ann", OLD)):
            valid = lambda: all("error" not in m["identity"] for m in run(session, "members", f"--group={chat['group']}", bin=bin)["members"])
            check(until(valid, bool, timeout=60), f"Ben's sessions of both versions renew with the new key, as {session} sees them")
        run("ben", "send", f"--group={chat['group']}", "@ann after the phone left")
        ann.expect("message", lambda e: e["content"] == "@ann after the phone left")
        tab.expect("message", lambda e: e["content"] == "@ann after the phone left")

        # Ann's pad, of this build, renames itself. Her devices group has a device of the last release, which refuses an
        # update that changes a credential, so the pad keeps its name there; the certificates it signs name the new one.
        devices = lambda session, bin: sorted(d["name"] for d in run(session, "identity", "list", bin=bin)["identities"][0]["devices"])
        before = devices("ann", OLD)
        run("pad", "identity", "rename", "pad-renamed")
        for session, bin in (("ben", BIN), ("ann", OLD)):
            seen = until(lambda: member(session, chat["group"], "Pad", bin), lambda m: m and m["device"] == "pad-renamed", timeout=60)
            check(seen and seen["device"] == "pad-renamed", f"a renamed device's sessions show its new name, as {session} sees them")
        check(devices("ann", OLD) == devices("pad", BIN) == before, f"a devices group with a device of {VERSION} keeps the old name, on both")

        # The pad leaves Ann's identity: its session leaves the chat first, and Ann's device of the last release commits its
        # removal, without replacing her key.
        left = run("pad", "identity", "leave", "Ann")
        check(left["left"] == [chat["group"]] and left["ended"] is False, "a device of this build leaves an identity, its session leaving its group first")
        ben.expect("left", lambda e: e["member"]["name"] == "Pad", timeout=60)
        remaining = until(lambda: devices("ann", OLD), lambda d: len(d) == 1, timeout=60)
        check(len(remaining) == 1, f"{VERSION} commits the removal of a device that left its identity")

        # Ann's home, of the last release, resumed by this build.
        ann.stop()
        listeners.remove(ann)
        ann = Listener("ann")
        listeners.append(ann)
        check({g.get("name") for g in run("ann", "groups")} >= {"Plans", "Back", "Notes", "Repo"}, f"this build resumes a home of {VERSION}")
        run("ann", "send", f"--group={chat['group']}", "@ben from ann, now of this build")
        ben.expect("message", lambda e: e["content"] == "@ben from ann, now of this build", timeout=60)
        run("tab", "send", f"--group={chat['group']}", "@ann from the tablet", bin=OLD)
        check(ann.expect("message", lambda e: e["content"] == "@ann from the tablet", timeout=60)["from"]["identity"]["name"] == "Ben", "and talks with both")
        print("all ok")
    finally:
        for listener in listeners:
            listener.proc.kill()
        server.kill()


if __name__ == "__main__":
    main()
