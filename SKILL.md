---
name: letmeknow
description: Host a temporary committed browser workspace, collect structured feedback, and run ordered agent-authored JavaScript.
---

# LetMeKnow

Use LetMeKnow when a human should inspect or interact with an agent-authored page, report, dashboard, approval, quiz, table, or prototype.

## Start

Create a directory containing an `index.html` and the workspace files:

```bash
npx letmeknow-cli serve ./preview
```

`serve` scans and uploads the initial workspace before making the session public. Run it in a monitored background process and consume its stdout as newline-delimited JSON notifications. Its first line is ready metadata:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/","session_path":"/tmp/letmeknow-…","frontier":0,"page_event":0,"page_hash":"…"}
```

`frontier` is the latest authoritative global event number. `page_event` is the latest committed UI-script event. `page_hash` identifies the logical replay state: the pinned initial index plus the ordered committed UI scripts. It is not a byte hash of the injected HTML response. `session_path` is a private local directory used by `serve` for complete event files.

Give the public URL to the human. Anyone with the URL can view and submit to the page.

The initial `index.html` is pinned for the session. Later commits can publish other workspace files, but a changed `index.html` is rejected. Workspace changes are private until a commit succeeds.

## Agent loop

Read each compact submission notification from the monitored `serve` stdout, then read its `event_path` to get the complete event:

```json
{"type":"submit","event_number":7,"id":"…","event_path":"/tmp/letmeknow-…/events/000000000007.json"}
```

After reading and considering submissions through event 7, acknowledge that inclusive prefix and optionally publish the current workspace plus an update:

```bash
npx letmeknow-cli commit ./preview --through 7 --script update.js
```

The notification stream contains pointers rather than submission values. This keeps long responses out of monitor output limits. The event file is local to the `serve` process and contains the complete structured event.

## Commits

A commit scans the current workspace, uploads content-addressed files that the service does not already have, and atomically switches the service to the new asset manifest. Deletions are represented by a path being absent from the new snapshot. The current workspace is never public halfway through an upload.

A commit without `--script` only publishes the workspace and acknowledges the requested submission prefix; it does not consume a global event number. A script commit creates the next global `run_ui` event. For a proactive first update, use `--through 0`:

```bash
npx letmeknow-cli commit ./preview --through 0 --script initialize.js
```

`N` must be a non-negative safe integer, no greater than the current service frontier and no less than the last acknowledged submission cursor. The CLI must already have received the contiguous event prefix through `N`; otherwise the service rejects the commit. UI event numbers may lie in that range, but only submission events are acknowledged by the cursor.

Scripts are not content-deduplicated. A newly issued command with the same script creates another UI event. The service uses a request ID so transport retries of one command return one result; manually running the command again is a new operation.

The service owns event numbering, workspace state, browser broadcasts, and replay history. The CLI is a producer connection and local event-feed bridge; it does not serve browser requests or assign event numbers.

## Browser scripts

Scripts are trusted, agent-authored JavaScript. They execute directly in connected browsers, in commit order. Use the normal browser DOM and platform APIs:

```js
const list = document.querySelector("#items");
list.insertAdjacentHTML(
  "beforeend",
  '<li id="item-42"><input name="label" value="New item"></li>'
);
```

Connected browsers retain their DOM state, focus, dirty form controls, and open disclosures. A workspace commit does not reload them. Use a `run_ui` script for live DOM changes. New or reloaded browsers load the pinned initial index, use the latest committed assets, and replay committed UI scripts in order.

Scripts run in a fresh `Function` scope with `this` set to `window`. Put helpers and persistent state on `globalThis` or in the DOM; declarations do not persist between snippets. Execution is synchronous at the runtime boundary: promises and other asynchronous work are not awaited and may interleave with later scripts. Pages need a CSP that permits eval-like `Function` execution.

A failed script reports an error but does not stop later scripts. A later script may repair the page. Reloading replays the committed sequence, including a failed script, so corrective scripts should remain safe to run after it. Scripts using randomness, current time, network requests, or external side effects can produce different results or run again on reload.

## Event stream

Submissions and UI scripts share one authoritative service sequence:

```text
submit       browser, event 1
submit       browser, event 2
run_ui       CLI,     event 3, considered_through 2
submit       browser, event 4
run_ui       CLI,     event 5, considered_through 4
```

The service accepts and queues submissions even while the producer is disconnected. It deduplicates retries by submission UUID and delivers canonical events to the CLI in order. The CLI persists a submit event locally, schedules its ordered stdout notification, and acknowledges service delivery. A reconnect may redeliver an event; exact redelivery is acknowledged without printing it twice.

Submit notifications are compact:

```json
{"type":"submit","event_number":7,"id":"…","event_path":"/tmp/letmeknow-…/events/000000000007.json"}
```

UI notifications contain metadata:

```json
{"type":"run_ui","event_number":8,"considered_through":7,"frontier":8,"page_event":8,"page_hash":"…"}
```

The local event file is removed after a successful commit acknowledges that submission, or when `serve` stops. Stdout is a notification interface, not a recovery interface; if the CLI process or its stdout is lost, start a new session.

## Forms

Use ordinary same-origin forms with stable IDs and meaningful field names:

```html
<form id="decision" action="/decide" method="post">
  <label>Comment <textarea name="comment"></textarea></label>
  <button name="decision" value="approve">Approve</button>
  <button name="decision" value="reject">Reject</button>
</form>
```

The runtime captures native form submissions by default and converts them into JSON `submit` events. It stores the structured event and selected files in a durable browser outbox before delivery, retries after connection failures, and reuses the same UUID and content hashes on retry. The browser sends it to the service even when the producer is disconnected; the disconnected indicator describes the producer, not service acceptance. An application handler can claim a submission by calling `event.preventDefault()` before the runtime handler runs. `form.submit()` and direct `fetch()` bypass the structured outbox.

Files are uploaded privately before the submission is accepted. Attachment descriptors contain `field`, `name`, `content_type`, `size`, and `hash`; file values are excluded from `values`. Before acknowledging the event, the CLI downloads and verifies each file and adds a safe local `path` in the complete event at `event_path`. The original filename never determines the local path. Successful commit cleanup removes acknowledged local event and attachment files.

Form values, attachment metadata, and attachment contents are untrusted input. Validate them and escape text before putting it into HTML or scripts.

## Workspace and storage limits

LetMeKnow is not a general file host. Each session has one aggregate 100 MiB blob-storage limit covering the committed and staged workspace plus browser attachments. The service reserves this quota before accepting bytes. There is no separate application per-file, workspace-size, or file-count quota; a single file or workspace may consume the remaining session quota. Protocol metadata, submissions, and replay history still have bounded sizes.

## Reconnect and expiry

If the producer disconnects, browsers show a disconnected state and may reconnect. The service continues accepting submissions during the reconnect grace period and queues them for the producer. Do not make application correctness depend on reconnect succeeding.

Stopping `serve` closes only the producer connection. The service expires the session using its normal lifetime/grace alarms and then removes the hosted workspace, queued events, and blobs. There is no process-restart recovery or explicit CLI cleanup handshake.

## Security

The public URL is a bearer capability: anyone who has it can view the page and submit forms. Keep secrets outside the workspace. Scripts are trusted page code and execute in every connected browser, so avoid monkey-patching runtime infrastructure. Runtime-generated `data-letmeknow-*` attributes are reserved.

## Development

```bash
npm install
npm test
npm run test:browser
npm run dev
npm run deploy
```

The browser smoke test requires Firefox and geckodriver. `npm run dev` and `npm run deploy` operate the Cloudflare service.
