#!/usr/bin/env python3
import pathlib
import re
import sys
import tomllib

root = pathlib.Path(__file__).resolve().parent.parent
if len(sys.argv) not in (2, 3):
    sys.exit("usage: version-pins.py check | set X.Y.Z")
action, *args = sys.argv[1:]
if action not in ("check", "set") or (args if action == "check" else len(args) != 1):
    sys.exit("usage: version-pins.py check | set X.Y.Z")
version = args[0] if args else None
stable = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
if version is not None and (not re.fullmatch(stable, version) or any(int(part) > 0xffffffff for part in version.split("."))):
    sys.exit("expected stable X.Y.Z version")
original = {name: (root / name).read_text() for name in ["Cargo.toml", "README.md", "SKILL.md", "AGENTS.md", "web/src/index.html"]}
current = tomllib.loads(original["Cargo.toml"])["workspace"]["package"]["version"]
if not re.fullmatch(stable, current):
    sys.exit("Cargo workspace version must be stable X.Y.Z")
minor = ".".join(current.split(".")[:2])
next_minor = ".".join(version.split(".")[:2]) if version else minor
updated = dict(original)
for name, count in [("README.md", 2), ("SKILL.md", 1), ("AGENTS.md", 1), ("web/src/index.html", 1)]:
    pattern = r"@letmeknow/cli@([^\s`\"<>]+)"
    pins = re.findall(pattern, original[name])
    if pins != [minor] * count:
        sys.exit(f"{name}: expected {count} CLI pins at {minor}")
    updated[name] = re.sub(pattern, f"@letmeknow/cli@{next_minor}", original[name])
pattern = r"\b[0-9]+\.[0-9]+\.x\b"
if re.findall(pattern, original["AGENTS.md"]) != [f"{minor}.x"]:
    sys.exit("AGENTS.md: expected one matching patch-range description")
updated["AGENTS.md"] = re.sub(pattern, f"{next_minor}.x", updated["AGENTS.md"])
if action == "set":
    updated["Cargo.toml"], count = re.subn(f'^version = "{re.escape(current)}"$', f'version = "{version}"', original["Cargo.toml"], flags=re.M)
    if count != 1:
        sys.exit("expected one Cargo workspace version line")
    try:
        for name, content in updated.items():
            (root / name).write_text(content)
    except Exception:
        for name, content in original.items():
            (root / name).write_text(content)
        raise
