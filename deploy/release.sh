#!/bin/sh
# deploy/release.sh <X.Y.Z> <notes file>: releases letmeknow X.Y.Z from a clean main. It commits the version and pushes
# it with its tag; .github/workflows/release.yml then runs CI, builds five platforms, and publishes the GitHub release and
# the npm packages. Rolling it out is separate (deploy/README.md).
set -eu
version=$1 notes=$2
printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || { echo 'expected X.Y.Z version' >&2; exit 1; }
cd "$(dirname "$0")/.."
[ "$(git branch --show-current)" = main ] || { echo "release from main" >&2; exit 1; }
dirty=$(git status --porcelain)
[ -z "$dirty" ] || { printf 'commit or stash your changes first:\n%s\n' "$dirty" >&2; exit 1; }
[ -f "$notes" ] || { echo "no notes file $notes" >&2; exit 1; }
sed -i "0,/^version = \".*\"/s//version = \"$version\"/" Cargo.toml
minor=${version%.*}
if [ "${version##*.}" = 0 ]; then
  sed -i "s#@letmeknow/cli@[0-9]*\.[0-9]*#@letmeknow/cli@$minor#g" README.md SKILL.md site/index.html AGENTS.md
fi
cargo update -w --offline
git commit -q --allow-empty -am "$version"
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
echo "Published $version. Rollout (deploy/README.md):"
echo "Backend: deploy/deploy.sh root@129.212.227.207 relay.letmeknow.dev $repo $run v$version $sha"
echo "Site: gh workflow run pages.yml --repo $repo -f release_tag=v$version"
if [ "${version##*.}" = 0 ]; then
  echo "pi-letmeknow, by hand: MINOR = \"$minor\" in extensions/letmeknow.ts"
  echo "claude-letmeknow, by hand: @letmeknow/cli@$minor in hooks/letmeknow.js"
fi
