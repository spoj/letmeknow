---
name: letmeknow
description: Show one human a temporary HTML and CSS workspace and handle normalized form or button actions through the LetMeKnow NDJSON CLI.
---

# LetMeKnow

Use LetMeKnow when one human needs a temporary rich document, dashboard, report, preview, form, approval, quiz, table, or status view. The agent supplies semantic HTML and CSS. The browser sends only declared actions; typing and local UI state do not create events.

LetMeKnow is not a localhost proxy, persistent application, or arbitrary JavaScript environment.

## Start

Node.js 22 or newer is required.

```bash
npx letmeknow-cli
```

Run it as a long-lived child process. Write one compact JSON object per line to stdin, keep stdin open, and read one JSON event per line from stdout. Read stderr separately.

```json
{"type":"open","id":"open-1"}
```

Wait for the session URL:

```json
{"type":"session","id":"open-1","url":"https://0123456789abcdef0123.letmeknow.dev/","expires_after_disconnect":600}
```

The URL immediately serves a shell with a waiting message. One browser may use it at a time.

## Render HTML and CSS

```json
{"type":"render","id":"render-1","body":"<h1>Search invoices</h1><form id=\"search\" action=\"search\" method=\"post\" data-lmk-target=\"results\"><label>Customer<input name=\"customer\" required></label><button>Search</button></form><section id=\"results\"><p>Enter a customer.</p></section>","css":"#results { margin-top: 2rem; }"}
```

A connected browser receives the render immediately. Wait for its acknowledgement and retain the `render_id`:

```json
{"type":"ack","id":"render-1","render_id":"b87438c2-4f1c-44bd-9875-6cc64370b8aa"}
```

Use semantic HTML: headings, sections, paragraphs, lists, tables, `dl`, forms, labels, controls, buttons, `details`, progress, and images. Do not include `<html>`, `<head>`, `<body>`, `<main id="lmk-view">`, scripts, style elements, inline handlers, inline `style`, iframes, or HTMX attributes.

The optional `css` field supports modern CSS, including grid, flexbox, media queries, variables, transitions, and print styles. External stylesheets, `@import`, and remote resources do not work. Use relative session assets.

A full `render` intentionally replaces the current page, resets drafts, and cancels actions from the previous render. Use `response` rather than `render` after a user action.

## Forms

Interactive forms use standard HTML:

```html
<form id="decision" action="decide" method="post">
  <label>Reason<textarea name="reason" required></textarea></label>
  <button name="decision" value="approve" formaction="approve">Approve</button>
  <button name="decision" value="reject" formaction="reject">Reject</button>
</form>
```

Rules:

- Use `method="post"`.
- Give each form a stable, unique `id`.
- Give controls meaningful `name` values.
- Use an action identifier containing letters, digits, `.`, `_`, `:`, or `-`.
- A submit button's standard `formaction` may override the form action.
- Native `required`, input types, ranges, and patterns validate locally.

The runtime captures `FormData(form, submitter)` before disabling controls. Selected radios, checked boxes, ordinary controls, and the clicked submit button are included. Repeated names become string arrays. File inputs are rejected.

## Standalone actions

```html
<button type="button" data-lmk-action="refresh-status" data-lmk-target="status">
  Refresh
</button>
```

Use standalone actions for refresh, retry, cancel, generate, inspect, load-more, and export. Their events have `form_id: null`, empty `values`, and the button's optional `id`, `name`, and `value` in `trigger`.

## Whole and partial updates

Responses replace the whole workspace by default. To update a region, put `data-lmk-target="element-id"` on the form or action button:

```html
<form id="search" action="search" method="post" data-lmk-target="results">
  <input name="query">
  <button>Search</button>
</form>
<section id="results"></section>
```

The target is one bare element ID without `#`. Every update uses `innerHTML`. A submit button may override its form's target.

## Handle actions

```json
{"type":"action","id":"2ee81a6b-1035-40a7-a90d-c1e02f426baa","render_id":"b87438c2-4f1c-44bd-9875-6cc64370b8aa","action_id":"search","form_id":"search","target_id":"results","trigger":{"id":null,"name":null,"value":null},"values":{"query":"quarterly report"}}
```

Use:

- `id` to respond to this exact action.
- `render_id` to identify the page revision that produced it.
- `action_id` for user intent.
- `form_id` and `target_id` for context.
- `trigger` for the clicked button.
- `values` for the submitted form snapshot.

Validate actions and values. Treat values as untrusted and HTML-escape reflected text.

Respond with HTML for the target contents:

```json
{"type":"response","id":"response-1","request_id":"2ee81a6b-1035-40a7-a90d-c1e02f426baa","body":"<table><tr><th>Invoice</th><th>Amount</th></tr><tr><td>INV-42</td><td>$800</td></tr></table>"}
```

A response may include `css` to replace the page CSS. Omitting it preserves the existing CSS:

```json
{"type":"response","id":"response-2","request_id":"event-2","body":"<h1 class=\"success\">Approved</h1>","css":".success { color: green; }"}
```

Wait for the acknowledgement and its new `render_id`. An action remains pending until `response`, a superseding full `render`, or session close. Independent regions may be pending concurrently, so always match by action ID.

## One-browser behavior

The first browser claims the session with a private credential. Reload and laptop wake reconnect automatically. A second browser cannot connect while the first is active.

Liveness is checked only when another browser tries to claim, at most once every five seconds. After a browser disconnect, its credential has five seconds of exclusive reconnect priority. After that, the first old or new browser to connect wins.

A reconnect receives one canonical snapshot of committed HTML, CSS, render ID, and pending actions. It does not replay old user actions. Same-tab drafts are restored from `sessionStorage`; drafts do not transfer during takeover.

## Assets

```json
{"type":"put","id":"logo","path":"/assets/logo.png","content_type":"image/png","encoding":"base64","body":"iVBORw0KGgo..."}
```

Store resources only under `/assets/` and reference them relatively:

```html
<img src="assets/logo.png" alt="Company logo">
```

`encoding` is `utf8` by default or `base64` for binary data. Assets answer only `GET` and `HEAD`. There is no `delete`; another `put` replaces an asset.

## Close and lifecycle

```json
{"type":"close","id":"close-1"}
```

Wait for `ack` and `closing`. Closing stdin only disconnects the producer.

If the producer disconnects, the page remains visible, drafts remain, and actions are disabled. The CLI has ten minutes to reconnect. Browser traffic does not extend that period. Explicit close or expiry deletes HTML, CSS, credentials, actions, and assets.

Limits: 1 MiB per HTML, CSS, asset, or action body; 100 assets; 10 MiB decoded asset storage; and 32 pending actions.

Treat the URL as a bearer secret. Never expose either private reconnect credential.
