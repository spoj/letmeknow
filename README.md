# LetMeKnow

## API

Set `BASE_URL` to the deployed Worker URL.

Create a question:

```bash
curl -sS -X POST "$BASE_URL/questions" \
  -H 'Content-Type: application/json' \
  -d '{"title":"Release approval","fields":[{"id":"approve","label":"Deploy this release?","type":"choice","options":["Yes","No"]},{"id":"notes","label":"Anything else?","type":"text"}]}'
```

The request body contains a title and one or more fields. A field is either a `choice` with an array of string `options`, or a `text` field. The `201` response is:

```json
{
  "question_url": "<origin>/q/<question-id>/<answer-token>",
  "status_url": "<origin>/s/<question-id>/<status-token>",
  "expires_at": "<ISO>"
}
```

Give the public `question_url` to the human. The human can `GET` it and `POST` one valid answer; later submissions return `409`.

Keep `status_url` private and poll it with bounded long polling:

```bash
curl -i "$STATUS_URL?wait=25"
```

`wait` is optional and must be an integer from `0` through `25`; it defaults to `25` seconds. The agent endpoint returns:

- `200` with `{"status":"answered","answers":{...},"answered_at":"<ISO>"}` when answered.
- `202` with `{"status":"pending"}` and `Retry-After: 3` when still pending at the wait timeout.
- `410` with `{"status":"expired"}` when the question expires. A `404` after cleanup is also terminal.

Both capability URLs expire logically after 24 hours.

## Local development and tests

```bash
npm install
npm run dev
npm test
```

## Deployment

Cloudflare Workers Git integration is configured for this repository. Its one-time deploy credential is stored as the encrypted `CLOUDFLARE_API_TOKEN` build secret; never commit or share it. Push to the configured production branch to deploy.
