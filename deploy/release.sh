#!/bin/sh
# deploy/release.sh <X.Y.Z> <notes file>: releases letmeknow X.Y.Z from a clean main. It commits the version and pushes
# it with its tag; .github/workflows/release.yml then runs CI, builds five platforms, and publishes the GitHub release and
# the npm packages. It waits for that, puts in the notes, waits until npm serves the version, and deploys letmeknow.dev.
set -eu
version=$1 notes=$2
cd "$(dirname "$0")/.."
[ "$(git branch --show-current)" = main ] || { echo "release from main" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "commit or stash your changes first" >&2; exit 1; }
[ -f "$notes" ] || { echo "no notes file $notes" >&2; exit 1; }
sed -i "0,/^version = \".*\"/s//version = \"$version\"/" Cargo.toml
cargo update -w --offline
git commit -qam "$version"
git push -q origin main
git tag -a "v$version" -m "letmeknow $version"
git push -q origin "v$version"
# What deploy.sh builds, meanwhile.
cargo build -q --release --target x86_64-unknown-linux-musl -p letmeknow &
built=$!
run=
until [ -n "$run" ]; do
  sleep 5
  run=$(gh run list --workflow release.yml --branch "v$version" --limit 1 --json databaseId --jq '.[0].databaseId // empty')
done
echo "waiting for https://github.com/$(gh repo view --json nameWithOwner --jq .nameWithOwner)/actions/runs/$run"
gh run watch "$run" --exit-status --interval 30 >/dev/null
gh release edit "v$version" --notes-file "$notes"
until [ "$(npm view @letmeknow/cli version --prefer-online)" = "$version" ]; do sleep 10; done
wait "$built"
deploy/deploy.sh root@129.212.227.207 letmeknow.dev
echo "letmeknow $version is out"
