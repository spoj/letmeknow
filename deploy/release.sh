#!/bin/sh
# deploy/release.sh <X.Y.Z> <notes file>: releases letmeknow X.Y.Z from a clean main. It commits the version and pushes
# it with its tag; .github/workflows/release.yml then runs CI, builds five platforms, and publishes the GitHub release and
# the npm packages. Deployment is a separate operator-reviewed action using those artifacts.
set -eu
version=$1 notes=$2
printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || { echo 'expected X.Y.Z version' >&2; exit 1; }
cd "$(dirname "$0")/.."
[ "$(git branch --show-current)" = main ] || { echo "release from main" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "commit or stash your changes first" >&2; exit 1; }
[ -f "$notes" ] || { echo "no notes file $notes" >&2; exit 1; }
sed -i "0,/^version = \".*\"/s//version = \"$version\"/" Cargo.toml
cargo update -w --offline
git commit -qam "$version"
sha=$(git rev-parse HEAD)
repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
git push -q origin main
git tag -a "v$version" -m "letmeknow $version"
git push -q origin "v$version"
run=
until [ -n "$run" ]; do
  sleep 5
  run=$(gh run list --repo "$repo" --workflow release.yml --branch "v$version" --limit 1 --json databaseId --jq '.[0].databaseId // empty')
done
echo "waiting for https://github.com/$repo/actions/runs/$run"
gh run watch "$run" --repo "$repo" --exit-status --interval 30 >/dev/null
python3 deploy/release-run.py "$repo" "$run" "v$version" "$sha"
gh release edit "v$version" --repo "$repo" --notes-file "$notes"
[ "$(npm view "@letmeknow/cli@$version" version --prefer-online)" = "$version" ]
echo "Published $version; review deploy/README.md before rollout."
echo "Backend: deploy/deploy.sh root@129.212.227.207 relay.letmeknow.dev $repo $run v$version $sha"
echo "Frontend: gh workflow run pages.yml --repo $repo -f release_run=$run -f release_tag=v$version -f release_sha=$sha"
