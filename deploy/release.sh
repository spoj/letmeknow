#!/bin/sh
# Publish from clean main; rollout remains a separate operator-reviewed action.
set -eu
[ "$#" = 2 ] || { echo 'usage: deploy/release.sh X.Y.Z <notes file>' >&2; exit 1; }
version=$1 notes=$2
printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || { echo 'expected X.Y.Z version' >&2; exit 1; }
[ -f "$notes" ] || { echo "no notes file $notes" >&2; exit 1; }
notes=$(cd "$(dirname "$notes")" && pwd)/$(basename "$notes")
cd "$(dirname "$0")/.."
[ "$(git branch --show-current)" = main ] || { echo "release from main" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "release requires a clean tree" >&2; exit 1; }
python3 deploy/version-pins.py check
current=$(python3 - "$version" <<'PY'
import sys, tomllib
version = tuple(map(int, sys.argv[1].split('.')))
with open('Cargo.toml', 'rb') as source:
    current = tuple(map(int, tomllib.load(source)['workspace']['package']['version'].split('.')))
if any(part > 0xffffffff for part in version) or version < current:
    sys.exit('version must not decrease or exceed 32-bit components')
print('.'.join(map(str, current)))
PY
)
pi=
case "$version" in
  *.0)
    pi=${LETMEKNOW_PI_REPO:?set LETMEKNOW_PI_REPO to the reviewed local pi-letmeknow checkout}
    pi=$(cd "$pi" && pwd)
    git -C "$pi" remote get-url origin >/dev/null
    node "$pi/scripts/pin.mjs" preflight "$version"
    ;;
esac
tag="v$version"
if git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
  [ "$current" = "$version" ] || { echo 'existing tag has a different Cargo version' >&2; exit 1; }
  [ "$(git rev-parse "$tag^{commit}")" = "$(git rev-parse HEAD)" ] || { echo 'existing tag must name HEAD; tags are never moved' >&2; exit 1; }
else
  python3 deploy/version-pins.py set "$version"
  cargo update -w --offline
  if ! git diff --quiet; then
    git commit --only -m "Release: $version" -- Cargo.toml Cargo.lock README.md SKILL.md AGENTS.md web/src/index.html
  fi
fi
sha=$(git rev-parse HEAD)
repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
git push -q origin main
if ! git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
  git tag -a "$tag" -m "letmeknow $version"
fi
git push -q origin "$tag"
run=
until [ -n "$run" ]; do
  sleep 5
  run=$(gh run list --repo "$repo" --workflow release.yml --branch "$tag" --limit 1 --json databaseId --jq '.[0].databaseId // empty')
done
echo "waiting for https://github.com/$repo/actions/runs/$run"
gh run watch "$run" --repo "$repo" --exit-status --interval 30 >/dev/null
python3 deploy/release-run.py "$repo" "$run" "$tag" "$sha"
gh release edit "$tag" --repo "$repo" --notes-file "$notes"
[ "$(npm view "@letmeknow/cli@$version" version --prefer-online --registry=https://registry.npmjs.org)" = "$version" ]
if [ -n "$pi" ]; then
  node "$pi/scripts/pin.mjs" set "$version"
  git -C "$pi" push origin main
fi
echo "Published $version; review deploy/README.md before rollout."
echo "Backend: deploy/deploy.sh root@129.212.227.207 relay.letmeknow.dev $repo $run $tag $sha"
echo "Frontend: gh workflow run pages.yml --repo $repo -f release_run=$run -f release_tag=$tag -f release_sha=$sha"
