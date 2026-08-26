#!/usr/bin/env bash
set -euo pipefail

port="${PORT:-8787}"
base="${BASE_URL:-http://127.0.0.1:${port}}"
state_dir="$(mktemp -d)"
log_file="$(mktemp)"
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; fi
  rm -rf "$state_dir" "$log_file"
}
trap cleanup EXIT

npx wrangler d1 migrations apply letmeknow --local --persist-to "$state_dir" >/dev/null
npx wrangler dev --local --ip 127.0.0.1 --port "$port" --persist-to "$state_dir" --show-interactive-dev-session=false >"$log_file" 2>&1 &
server_pid=$!

for _ in {1..60}; do
  if curl -fsS "$base/" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "$base/" >/dev/null

create=$(curl -fsS -X POST "$base/questions" \
  -H 'Content-Type: application/json' \
  -d '{"title":"Smoke test","fields":[{"id":"approve","label":"Continue?","type":"choice","options":["Yes","No"]},{"id":"notes","label":"Notes","type":"text"}]}')
question_url=$(node -e 'console.log(JSON.parse(process.argv[1]).question_url)' "$create")
status_url=$(node -e 'console.log(JSON.parse(process.argv[1]).status_url)' "$create")

status_code=$(curl -sS -o /tmp/letmeknow-smoke-status -w '%{http_code}' "$status_url")
[[ "$status_code" == "202" ]]
node -e 'if (JSON.parse(process.argv[1]).status !== "pending") process.exit(1)' "$(cat /tmp/letmeknow-smoke-status)"

answer_code=$(curl -sS -o /tmp/letmeknow-smoke-answer -w '%{http_code}' -X POST "$question_url" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'field_approve=Yes' \
  --data-urlencode 'field_notes=Works locally')
[[ "$answer_code" == "200" ]]
grep -q 'Answer received' /tmp/letmeknow-smoke-answer

status_code=$(curl -sS -o /tmp/letmeknow-smoke-status -w '%{http_code}' "$status_url")
[[ "$status_code" == "200" ]]
node -e 'const x=JSON.parse(process.argv[1]); if(x.status!=="answered" || x.answers.approve!=="Yes" || x.answers.notes!=="Works locally") process.exit(1)' "$(cat /tmp/letmeknow-smoke-status)"

duplicate_code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$question_url" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'field_approve=No' \
  --data-urlencode 'field_notes=Duplicate')
[[ "$duplicate_code" == "409" ]]

echo "Smoke test passed"
