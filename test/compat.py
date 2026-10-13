#!/usr/bin/env python3
"""The previous minor's latest release and this build share one `letmeknow serve`: its sessions still create a group, invite
and chat, and this build refuses its invite links and home with a message. Outside CI, skips when npm is unreachable."""
import json, os, pathlib, queue, re, socket, subprocess, sys, tarfile, tempfile, threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="lmk-compat-")
ENV = {**os.environ, "NO_PROXY": "localhost,127.0.0.1"}
ENV.pop("LETMEKNOW_SESSION", None)
major, minor = re.search(r'^version = "(\d+)\.(\d+)\.\d+"', (ROOT / "Cargo.toml").read_text(), re.M).groups()
PREVIOUS = f"{major}.{int(minor) - 1}"


def check(condition, message):
    if not condition:
        sys.exit(f"FAIL: {message}")
    print(f"ok - {message}")


def npm(*args):
    return subprocess.run(["npm", *args], capture_output=True, text=True, timeout=120, check=True).stdout


def previous_binary():
    """The latest release of the previous minor: the `letmeknow` in its linux-x64 package, as release.yml publishes it."""
    listed = json.loads(npm("view", f"@letmeknow/cli@{PREVIOUS}", "version", "--json"))
    latest = max(listed if isinstance(listed, list) else [listed], key=lambda v: tuple(map(int, v.split("."))))
    package = os.path.join(TMP, "previous")
    os.mkdir(package)
    archive = npm("pack", f"@letmeknow/linux-x64@{latest}", "--pack-destination", package).split()[-1]
    with tarfile.open(os.path.join(package, archive)) as tar:
        tar.extractall(package, filter="data")
    print(f"previous minor {PREVIOUS}: letmeknow {latest}")
    return os.path.join(package, "package", "bin", "letmeknow")


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


def serve(bin):
    cert, key = os.path.join(TMP, "cert.pem"), os.path.join(TMP, "key.pem")
    subprocess.run(["cargo", "run", "-q", "-p", "letmeknow", "--example", "self_signed", "--", cert, key], cwd=ROOT, check=True)
    https = free_port()
    args = [bin, "serve", "--domain", "localhost", "--https-port", str(https), "--http-port", str(free_port()), "--membership-port", str(free_port()),
            "--qad-port", str(free_port()), "--state", os.path.join(TMP, "serve"), "--cert", cert, "--key", key]
    subprocess.run(args + ["--initialize"], env=ENV, check=True, stdout=subprocess.DEVNULL)
    proc = subprocess.Popen(args, env=ENV, stdout=subprocess.PIPE, stderr=open(os.path.join(TMP, "serve.log"), "w"), text=True)
    membership = proc.stdout.readline().strip().removeprefix("membership: ")
    ENV.update(LETMEKNOW_CA=cert, LETMEKNOW_RELAY=f"https://localhost:{https}", LETMEKNOW_MEMBERSHIP=membership)
    return proc


def home(name):
    return os.path.join(TMP, name)


class Listener:
    """A session of one release, in its own home (its own device)."""

    def __init__(self, bin, session):
        self.session, self.lines = session, queue.Queue()
        env = {**ENV, "LETMEKNOW_HOME": home(session)}
        self.log = open(os.path.join(TMP, f"{session}.log"), "a")
        self.proc = subprocess.Popen([bin, "--session", session, "listen", "--hold", "0"], env=env, stdout=subprocess.PIPE, stderr=self.log, text=True, encoding="utf-8")
        threading.Thread(target=self.read, daemon=True).start()
        self.expect("ready")

    def read(self):
        for line in self.proc.stdout:
            self.lines.put(json.loads(line))

    def expect(self, kind, timeout=30):
        while True:
            event = self.lines.get(timeout=timeout)
            if event["type"] == kind:
                return event

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)


def run(bin, session, *args):
    env = {**ENV, "LETMEKNOW_HOME": home(session)}
    result = subprocess.run([bin, "--session", session, *args], env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
    if result.returncode:
        sys.exit(f"{session} {args}: {result.stderr}")
    return json.loads(result.stdout)


def refused(bin, session, *args):
    """The message of a refusal: an error exit, not a crash."""
    env = {**ENV, "LETMEKNOW_HOME": home(session)}
    result = subprocess.run([bin, "--session", session, *args], env=env, capture_output=True, text=True, encoding="utf-8", timeout=60)
    if not result.returncode or "panicked" in result.stderr:
        sys.exit(f"{session} {args}: expected a refusal, got {result.returncode}: {result.stderr}")
    print(result.stderr.strip())
    return result.stderr


def main():
    try:
        old = previous_binary()
    except (OSError, subprocess.SubprocessError) as error:
        if os.environ.get("CI"):
            raise
        print(f"skip - npm is unreachable, so {PREVIOUS} is not checked: {error}")
        sys.exit(0)
    subprocess.run(["cargo", "build", "-q", "-p", "letmeknow", "-p", "lmk-kinds"], cwd=ROOT, check=True)
    new = os.path.join(ROOT, os.environ.get("CARGO_TARGET_DIR", "target"), "debug", "letmeknow")
    server = serve(new)
    listeners = []
    try:
        alice, bob = Listener(old, "alice"), Listener(old, "bob")
        listeners += [alice, bob]
        invite = run(old, "alice", "invite", "--name", "Plans")
        check(invite["kind"] == "chat" and invite["link"], f"{PREVIOUS} alice makes a chat through the new service")
        check(len(run(old, "bob", "join", invite["link"])["members"]) == 2, f"{PREVIOUS} bob joins it through the link")
        run(old, "alice", "send", "hello bob")
        check(bob.expect("message")["content"] == "hello bob", f"{PREVIOUS} bob receives alice's message")
        run(old, "bob", "send", "hi alice")
        check(alice.expect("message")["content"] == "hi alice", f"{PREVIOUS} alice receives bob's reply")
        unused = run(old, "alice", "invite")["link"]
        carol = Listener(new, "carol")
        listeners.append(carol)
        message = refused(new, "carol", "join", unused)
        check("another version of letmeknow" in message, f"this build refuses {PREVIOUS}'s invite link, with its reason")
        for listener in listeners:
            listener.stop()
        listeners.clear()
        message = refused(new, "alice", "listen", "--hold", "0")
        check("earlier letmeknow" in message, f"this build refuses {PREVIOUS}'s home, with its reason")
    finally:
        for listener in listeners:
            listener.stop()
        server.terminate()
    print(f"ok - {PREVIOUS} and this build meet only through the service")


if __name__ == "__main__":
    main()
