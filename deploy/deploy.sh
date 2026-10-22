#!/bin/sh
# Install the backend artifact from a successful release run; never build or restore state.
set -eu
host=$1 domain=$2 repo=$3 run=$4 tag=$5 sha=$6
case "$domain" in ''|*[!a-zA-Z0-9.-]*) echo 'invalid domain' >&2; exit 1;; esac
cd "$(dirname "$0")/.."
python3 deploy/release-run.py "$repo" "$run" "$tag" "$sha"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
gh run download "$run" --repo "$repo" --name archive-x86_64-unknown-linux-musl --dir "$tmp"
tar -xzf "$tmp"/letmeknow-*-x86_64-unknown-linux-musl.tar.gz --strip-components=1 -C "$tmp"
python3 - "$tmp/backend.json" "$domain" <<'PY'
import json, sys
if json.load(open(sys.argv[1]))["domain"] != sys.argv[2]:
    sys.exit("selected artifact targets a different backend domain")
PY
ssh "$host" 'set -eu
  if systemctl is-active --quiet litestream || systemctl is-enabled --quiet litestream; then
    echo "stop and disable Litestream at the reviewed cutover first" >&2
    exit 1
  fi
  id letmeknow >/dev/null
  test -s /var/lib/letmeknow/membership.ready
'
scp -q "$tmp/letmeknow" "$host:/usr/local/bin/letmeknow.new"
sed "s|@DOMAIN@|$domain|" "$tmp/letmeknow.service" > "$tmp/service"
scp -q "$tmp/service" "$host:/etc/systemd/system/letmeknow.service"
ssh "$host" 'set -eu
  systemctl daemon-reload
  systemctl stop letmeknow
  chmod 755 /usr/local/bin/letmeknow.new
  mv /usr/local/bin/letmeknow.new /usr/local/bin/letmeknow
  systemctl enable --now letmeknow
'
python3 deploy/check-backend.py "$tmp/backend.json" "$tag"
