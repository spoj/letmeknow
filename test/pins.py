#!/usr/bin/env python3
"""Every `@letmeknow/cli@N.M` pin in the files deploy/release.sh rewrites names Cargo.toml's minor version."""
import pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FILES = ["README.md", "SKILL.md", "web/src/index.html", "AGENTS.md"]
minor = re.search(r'^version = "(\d+\.\d+)\.\d+"', (ROOT / "Cargo.toml").read_text(), re.M).group(1)
stale = [f"{name}:{number}: {line.strip()}" for name in FILES
         for number, line in enumerate((ROOT / name).read_text().splitlines(), 1)
         for pin in re.findall(r"@letmeknow/cli@(\d+\.\d+)", line) if pin != minor]
if stale:
    sys.exit(f"pins not at {minor}:\n" + "\n".join(stale))
print(f"ok - every @letmeknow/cli pin is {minor}")
