---
name: letmeknow
description: Create a temporary browser surface for a human, serve static resources, and handle interactive HTTP requests through the LetMeKnow NDJSON CLI.
---

# LetMeKnow

Use LetMeKnow when a human needs a temporary web page or interactive UI from an agent. It is not a localhost proxy and does not read files or directories.

## Start the CLI

Node.js 22 or newer is required.

```bash
npx letmeknow
```

This connects to `https://letmeknow.dev` by default. To use another trusted deployment:

```bash
LETMEKNOW_URL=http://localhost:8787 npx letmeknow
```

Run the CLI as a long-lived child process. Write one compact JSON object per line to stdin, keep stdin open while the session is active, and read one JSON event per line from stdout. Read diagnostics from stderr separately. Do not mix stderr into the NDJSON stream.

## Open and publish static content

`open` must be the first command. String `id` values are optional; use them to correlate results.

```json
{"type":"open","id":"open-1"}
```

Wait for the `session` event and retain its URL:

```json
{"type":"session","id":"open-1","url":"https://0123456789abcdef0123.letmeknow.dev/","expires_after_disconnect":600}
```

Store or replace exact pathnames with `put`. The following page submits to an unstored path so the agent can handle it dynamically:

```json
{"type":"put","id":"put-1","path":"/","content_type":"text/html; charset=utf-8","body":"<!doctype html><form method=\"post\" action=\"answer\"><label>Answer <input name=\"answer\"></label><button>Send</button></form>"}
```

Use relative links, form actions, and asset URLs so pages also work on local deployments, whose session URL includes a path prefix. Wait for `{"type":"ack","id":"put-1"}` before relying on the update. `status` defaults to `200`, `encoding` to `utf8`, and `body` to an empty string. `headers` accepts string values or string arrays; `content_type` overrides `Content-Type`. For binary content, set `encoding` to `base64`. Paths must start with `/` and must not contain a query. Query strings do not affect stored-path matching.

Remove static content with:

```json
{"type":"delete","id":"delete-1","path":"/old.html"}
```

## Handle dynamic requests

A browser request whose path is not stored produces a `request` event:

```json
{"type":"request","id":"cf-request-id","method":"POST","path":"/answer","query":"step=2","headers":{"content-type":"application/x-www-form-urlencoded"},"encoding":"utf8","body":"answer=yes"}
```

Reply using the event's `id` as `request_id`:

```json
{"type":"response","id":"response-1","request_id":"cf-request-id","status":200,"content_type":"text/html; charset=utf-8","body":"<strong>Accepted</strong>"}
```

Wait for the correlated `ack`. Dynamic responses are not stored; use `put` if later requests should receive the same response without involving the agent. Treat request bodies and headers as untrusted input, and escape or validate values before placing them in HTML, headers, or commands.

The stdout event types are `session`, `request`, `ack`, `error`, and `closing`. Handle `error` rather than assuming a command succeeded.

## Close and lifecycle

Destroy the session and all content immediately when finished:

```json
{"type":"close","id":"close-1"}
```

Wait for `ack` and `closing`, then let the process exit. Closing stdin or terminating the CLI only disconnects the producer; it does not replace an explicit `close`.

The CLI owns the session and automatically reconnects after an unexpected disconnect. Each connection attempt has a 10-second deadline. Reconnection is possible only during the 10-minute disconnect grace period; stored resources remain available then, but unstored paths return `503`, and browser traffic does not extend the grace period. An initial producer connection must send `open` within 30 seconds. Dynamic request bodies have a 30-second read deadline, and a `response` may take at most 5 minutes.

Limits per session: 1 MiB per stored, request, or response body; 100 stored resources; 10 MiB decoded stored content in total; and 32 simultaneous dynamic requests. Bodies are non-streaming. Default responses include `Cache-Control: no-store` unless explicitly overridden.

## Security

Treat the session URL as a bearer secret: anyone who has it can access the surface and submit requests. Share it only with the intended human, and do not put it in source control, public logs, issue trackers, or unrelated output. The CLI also receives a separate private reconnect credential over the WebSocket, keeps it off protocol stdout, and uses it automatically. Never expose, persist, or ask the human for that credential. Use only a trusted `LETMEKNOW_URL`, because the deployment receives all page content and browser traffic.

## Recommended skill output

The minimal package interface should be:

```bash
npx letmeknow --skill
```

It should print this exact `SKILL.md` byte-for-byte to stdout and exit successfully without opening a network connection.
