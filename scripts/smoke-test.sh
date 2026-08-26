#!/usr/bin/env bash
set -euo pipefail

port="${PORT:-8787}"
base="${BASE_URL:-http://127.0.0.1:${port}}"
state_dir="$(mktemp -d)"
log_file="$(mktemp)"
status_file="$state_dir/status.json"
longpoll_body="$state_dir/longpoll.json"
longpoll_code="$state_dir/longpoll.code"
server_pid=""
longpoll_pid=""

cleanup() {
  if [[ -n "$longpoll_pid" ]]; then kill "$longpoll_pid" 2>/dev/null || true; fi
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; fi
  rm -rf "$state_dir" "$log_file"
}
trap cleanup EXIT

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

status_code=$(curl -sS -o "$status_file" -w '%{http_code}' "$status_url")
[[ "$status_code" == "202" ]]
node -e 'if (JSON.parse(process.argv[1]).status !== "pending") process.exit(1)' "$(cat "$status_file")"

curl -sS --max-time 20 -o "$longpoll_body" -w '%{http_code}' "$status_url?wait=10" >"$longpoll_code" &
longpoll_pid=$!
sleep 1

answer_code=$(curl -sS -o "$state_dir/answer.html" -w '%{http_code}' -X POST "$question_url" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'field_approve=Yes' \
  --data-urlencode 'field_notes=Works locally')
[[ "$answer_code" == "200" ]]
grep -q 'Answer received' "$state_dir/answer.html"

wait "$longpoll_pid"
longpoll_pid=""
[[ "$(cat "$longpoll_code")" == "200" ]]
node -e 'const x=JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); if(x.status!=="answered" || x.answers.approve!=="Yes" || x.answers.notes!=="Works locally") process.exit(1)' "$longpoll_body"

status_code=$(curl -sS -o "$status_file" -w '%{http_code}' "$status_url")
[[ "$status_code" == "200" ]]
node -e 'const x=JSON.parse(process.argv[1]); if(x.status!=="answered" || x.answers.approve!=="Yes" || x.answers.notes!=="Works locally") process.exit(1)' "$(cat "$status_file")"

status_code=$(curl -sS -o "$state_dir/status-repeat.json" -w '%{http_code}' "$status_url")
[[ "$status_code" == "200" ]]
node -e 'const x=JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); if(x.status!=="answered" || x.answers.approve!=="Yes") process.exit(1)' "$state_dir/status-repeat.json"

duplicate_code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$question_url" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'field_approve=No' \
  --data-urlencode 'field_notes=Duplicate')
[[ "$duplicate_code" == "409" ]]

echo "Smoke test passed"
