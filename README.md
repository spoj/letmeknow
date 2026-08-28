# LetMeKnow

LetMeKnow gives an agent a temporary interactive web surface for a human. It is not a localhost proxy and does not read directories. A Node CLI carries newline-delimited JSON between stdin/stdout and a Cloudflare Durable Object over one persistent WebSocket.

## CLI

Node 22 or newer is required.

```bash
npm install
./bin/letmeknow.js
```

The deployed service is used by default. Set `LETMEKNOW_URL` for local development:

```bash
LETMEKNOW_URL=http://localhost:8787 ./bin/letmeknow.js
```

stdin contains one compact JSON command per line. stdout contains one JSON event per line. Diagnostics go to stderr.

Start a session:

```json
{"type":"open","id":"1"}
```

stdout returns the URL to share with the human:

```json
{"type":"session","id":"1","url":"https://0123456789abcdef0123.letmeknow.dev/","expires_after_disconnect":600}
```

There is no initial bundle. Initial resources and later updates are the same `put` command:

```json
{"type":"put","id":"2","path":"/","content_type":"text/html; charset=utf-8","body":"<h1>Hello</h1>"}
{"type":"put","id":"3","path":"/app.js","content_type":"text/javascript","body":"document.body.append(' ready')"}
```

## Protocol

### Commands: stdin to LetMeKnow

- `open` creates the session and emits `session`.
- `put` stores or replaces an exact pathname.
- `delete` removes a stored pathname.
- `response` answers one pending browser request.
- `close` immediately destroys the session.

All commands accept an optional string `id`. Successful `put`, `delete`, `response`, and `close` commands emit a correlated `ack`.

A resource supports `status`, `headers`, `content_type`, `encoding`, and `body`. `status` defaults to `200`, `encoding` to `utf8`, and `body` to an empty string. Header values may be strings or string arrays; arrays preserve repeated headers such as `Set-Cookie`. `content_type` overrides any `Content-Type` header. Binary bodies use base64:

```json
{"type":"put","path":"/logo.png","content_type":"image/png","encoding":"base64","body":"iVBORw0KGgo..."}
```

Delete a resource:

```json
{"type":"delete","id":"4","path":"/old.html"}
```

Destroy everything immediately:

```json
{"type":"close","id":"5"}
```

### Events: LetMeKnow to stdout

- `session` contains the public URL and disconnect grace period.
- `request` describes a browser request that did not match a stored resource.
- `ack` confirms a command.
- `error` reports a command or protocol error.
- `closing` reports explicit destruction.

Unknown paths are sent to the producer:

```json
{"type":"request","id":"cf-request-id","method":"POST","path":"/answer","query":"step=2","headers":{"content-type":"application/x-www-form-urlencoded","hx-request":"true"},"encoding":"utf8","body":"answer=yes"}
```

Answer with the request event's `id` as `request_id`:

```json
{"type":"response","id":"6","request_id":"cf-request-id","status":200,"headers":{"content-type":"text/html; charset=utf-8","hx-trigger":"answered"},"body":"<strong>Accepted</strong>"}
```

Dynamic responses are not stored. Send a separate `put` to serve a path without involving the producer next time.

Production sessions use isolated `*.letmeknow.dev` origins, so root-relative links, forms, and asset URLs work normally. Local sessions use `/s/<code>/`; use relative URLs there. Stored paths ignore the URL query when matching. Dynamic events contain pathname and query separately. Methods, forms, cookies, HTMX headers, SPA API requests, status, response headers, and text or binary bodies pass through generically. Browser request bodies use UTF-8 only for recognized textual media types; absent, unrecognized, or invalid UTF-8 bodies use base64. Request, response, and stored-resource bodies are bounded to 1 MiB and are non-streaming; a dynamic browser request times out after 30 seconds. Stored and dynamic responses default to `Cache-Control: no-store`; an explicit producer header overrides that default. A session accepts at most 100 stored resources (10 MiB decoded total) and 32 simultaneous dynamic requests.

## Lifecycle

The active CLI connection owns the session. The CLI receives an unguessable private reconnect credential in a private WebSocket message, keeps it off protocol stdout, and sends it as the WebSocket subprotocol on reconnect. The reconnect URL contains only the public session code. If the connection drops unexpectedly, it reconnects with that credential during the ten-minute grace period without requiring another `open` command; each connection attempt has a ten-second deadline, and a failed initial attempt exits nonzero while reconnect attempts continue within the grace period. Stored resources remain available for ten minutes, while unknown paths return `503`. Browser traffic does not extend the grace period. After the alarm fires all resources are deleted. A producer connection that never sends `open` is cleaned up after a short deadline. `close` deletes everything immediately.

## Development

```bash
npm install
npm run dev
npm test
```

The Worker uses one Durable Object per session. The object owns the producer WebSocket, stored resources, pending browser requests, and disconnect alarm. No D1 or R2 binding is required.

Deploy with:

```bash
npm run deploy
```

Production subdomain URLs require a proxied `*.letmeknow.dev` DNS record and a Worker route for `*.letmeknow.dev/*` in Cloudflare. The apex `letmeknow.dev` remains the control endpoint.
