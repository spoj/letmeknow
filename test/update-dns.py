#!/usr/bin/env python3
"""Linux process regression: isolated real DNS, no npm/backend connections. Pass a built CLI."""
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

binary = str(Path(sys.argv[1]).resolve())
if sys.argv[2:] != ["--isolated"]:
    subprocess.run(["unshare", "--user", "--map-root-user", "--net", "--mount",
                    sys.executable, __file__, binary, "--isolated"], check=True, timeout=60)
    sys.exit(0)

subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
with tempfile.TemporaryDirectory(prefix="lmk-update-dns-") as directory:
    root = Path(directory)
    for name, content in {
        "resolv.conf": "nameserver 127.0.0.1\noptions timeout:30 attempts:5\n",
        "nsswitch.conf": "hosts: files dns\n",
        "hosts": "127.0.0.1 localhost\n::1 localhost\n",
    }.items():
        source = root / name
        source.write_text(content)
        subprocess.run(["mount", "--bind", str(source), f"/etc/{name}"], check=True)

    # Answering control proves the real production hostname reaches our loopback TLS port.
    # Held mode must time out, serve commands, durably stop, AND exit while DNS never answers.
    for held in (False, True):
        packets, connections = [], []
        stop = threading.Event()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 53))
        tls = socket.socket()
        tls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tls.bind(("127.0.0.1", 443))
        tls.listen()

        def serve():
            while not stop.is_set():
                for ready in select.select([udp, tls], [], [], 0.05)[0]:
                    if ready is tls:
                        connection, _ = tls.accept()
                        connections.append(time.monotonic())
                        connection.close()
                        continue
                    query, address = udp.recvfrom(4096)
                    offset, labels = 12, []
                    while query[offset]:
                        size = query[offset]
                        labels.append(query[offset + 1:offset + 1 + size].decode("ascii"))
                        offset += size + 1
                    end = offset + 5
                    name = ".".join(labels).lower()
                    packets.append((time.monotonic(), name))
                    if held or name != "registry.npmjs.org":
                        continue
                    kind = struct.unpack("!H", query[offset + 1:offset + 3])[0]
                    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton("127.0.0.1") if kind == 1 else b""
                    response = query[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(answer), 0, 0) + query[12:end] + answer
                    udp.sendto(response, address)

        server = threading.Thread(target=serve)
        server.start()
        home = root / ("held" if held else "answered")
        env = {key: value for key, value in os.environ.items() if key not in ("LETMEKNOW_SESSION", "RUST_LOG")}
        command = [binary, "--home", str(home), "--session", "dns-test"]
        started = time.monotonic()
        with (root / "stderr").open("w+") as stderr:
            child = subprocess.Popen([*command, "listen", "--relay", "http://127.0.0.1:1"],
                                     env=env, stdout=subprocess.PIPE, stderr=stderr)
            try:
                assert select.select([child.stdout], [], [], 8)[0], "ready deadline exceeded"
                event = json.loads(child.stdout.readline())
                elapsed = time.monotonic() - started
                assert event["type"] == "ready", event
                assert event["bin"] == binary, event
                assert event["version_check_error"] == ("timeout" if held else "network"), event
                assert "newer_version" not in event and "start_command" not in event, event
                assert any(name == "registry.npmjs.org" for _, name in packets), packets
                if held:
                    assert 2 <= elapsed < 8, elapsed
                    assert not connections, connections
                else:
                    assert connections, "DNS control did not reach loopback TLS"
                print(f"{'held' if held else 'answered'} DNS: ready after {elapsed:.3f}s ({event['version_check_error']})", flush=True)
                for args in (["groups"], ["status"], ["sessions"]):
                    result = subprocess.run([*command, *args], env=env, capture_output=True, text=True, check=True, timeout=5)
                    answer = json.loads(result.stdout)
                    if args[0] == "groups":
                        assert answer == [], answer
                    elif args[0] == "status":
                        assert "error" not in answer and answer.get("groups", []) == [], answer
                    else:
                        assert answer == {"sessions": [{"handle": "dns-test", "groups": [], "running": True}]}, answer
                    print(f"usable command: {args[0]}", flush=True)
                stopped = time.monotonic()
                endpoint = json.loads((home / "sessions" / "dns-test" / "endpoint").read_text())
                with socket.create_connection(("127.0.0.1", endpoint["port"]), timeout=5) as channel:
                    request = {"token": endpoint["token"], "home_format": int((home / "format").read_text()), "request": {"cmd": "stop"}}
                    channel.sendall((json.dumps(request) + "\n").encode())
                    with channel.makefile("rb") as response:
                        assert json.loads(response.readline()) == {"stopped": True}
                print("STOP acknowledged", flush=True)
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    raise AssertionError("STOP acknowledged but native process still alive: DNS teardown linger") from None
                assert child.returncode == 0, child.returncode
                print(f"process exited normally {time.monotonic() - stopped:.3f}s after STOP", flush=True)
                if held:
                    assert not connections, connections
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)
                child.stdout.close()
                stop.set()
                server.join(timeout=2)
                udp.close()
                tls.close()
                stderr.seek(0)
                assert stderr.read() == "", "unexpected native stderr"
print("actual native DNS process regression passed", flush=True)
