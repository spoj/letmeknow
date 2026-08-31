# LetMeKnow

LetMeKnow gives an agent a temporary public browser surface for structured human feedback. The service hosts a committed workspace, receives browser submissions, and runs ordered agent-authored JavaScript in connected browsers.

## Quick start

Create a directory with an `index.html`, then run `serve` under the agent's process monitor:

```bash
npx letmeknow-cli serve ./preview
```

`serve` scans the workspace and uploads its initial snapshot before the session becomes public. It prints newline-delimited JSON. The first line contains the public URL and the authoritative event frontier:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/","session_path":"/tmp/letmeknow-…","frontier":0,"page_event":0,"page_hash":"…"}
```

Keep `serve` running and read its stdout stream. Accepted submissions appear as compact notifications; read the complete event from `event_path`, then use its event number when committing:

```json
{"type":"submit","event_number":1,"id":"…","event_path":"/tmp/letmeknow-…/events/000000000001.json"}
```

The notification stream intentionally contains pointers rather than submission values, so a long form response does not get truncated by the monitor. The `session_path` is private to the local `serve` process. The URL is a bearer capability: anyone who has it can view and submit to the page.

## Commands

```text
serve <dir>
commit <dir> --through <event-number> [--script FILE|-]
```

A commit scans the current workspace, uploads any new content-addressed files, and atomically publishes the resulting asset snapshot. It may also append one UI script event. `index.html` is pinned when the session starts; changing it causes the commit to fail. Other workspace changes are private until a successful commit.

A commit also declares that the agent considered every browser submission through the inclusive global event number. The cursor is monotonic but need not advance: repeated acknowledgements and periodic scripts may use the same number. For example:

```bash
npx letmeknow-cli commit ./preview --through 1 --script update.js
```

A script supplied with `--script -` is read from standard input. A commit without `--script` only publishes the workspace and acknowledges events. For a proactive first update, use `--through 0`:

```bash
npx letmeknow-cli commit ./preview --through 0 --script initialize.js
```

The service owns the session, workspace, event ordering, browser broadcast, and expiry. Stopping `serve` disconnects the producer; the service keeps the session during its normal reconnect grace period and then expires it. There is no process-restart recovery or public version-history interface.

## Browser scripts

Scripts are trusted, agent-authored JavaScript and run directly in each connected browser. Use the browser DOM normally:

```js
document.querySelector("#items").insertAdjacentHTML(
  "beforeend",
  '<li id="item-3">Three</li>'
);
```

Existing DOM nodes remain available, so scripts can preserve focus, dirty form controls, open disclosures, and other browser state. New or reloaded browsers start from the pinned `index.html`, load the latest committed assets, and replay committed scripts in order. Workspace commits do not reload connected browsers; use a UI script when the live DOM needs to change.

Scripts should generally be synchronous and replayable. Randomness, current time, network requests, and external side effects can produce different results or happen again whenever a browser reloads. Scripts execute through `Function`, so the page CSP must permit eval-like execution. A failed script reports an error but does not stop later scripts; a later script can correct the state.

The service's `page_hash` identifies the pinned initial index and ordered committed UI scripts. It is a logical replay-state hash, not a byte hash of the HTML response after runtime injection.

## Forms and security

Use ordinary same-origin forms with meaningful field names. The runtime captures native form submissions by default, stores each structured event and selected files in a durable browser outbox before delivery, retries after connection failures, and reuses the same UUID and content hashes on retry. The browser sends these events to the service even while the producer is disconnected; a disconnected indicator does not mean that an accepted service submission was lost. An application handler can claim a submission with `event.preventDefault()`. `form.submit()` and direct `fetch()` bypass the structured outbox.

The service validates and deduplicates submissions, assigns their global event numbers, and queues them for the CLI. Files are uploaded privately to the service before the JSON submission is accepted. Each attachment descriptor contains its form field, original name, media type, size, and SHA-256 hash; file values do not appear in `values`.

The CLI downloads attachments before acknowledging delivery, verifies their size and hash, and writes them under `session_path/attachments`. The complete event at `event_path` adds a safe local `path` to each attachment. Original filenames are metadata only and never determine local paths. A successful commit removes the acknowledged event and attachment files. The service releases stored attachment blobs after committed submissions no longer reference them; shared blobs remain while another pending submission uses them. Unsubmitted attachment reservations expire after 30 minutes. Stopping `serve` removes the whole private session directory.

Form values, attachment names, media types, and contents are untrusted input. Validate them and escape text before putting it into HTML or scripts. Keep secrets outside the workspace.

## Workspace limits

LetMeKnow is not a general file host. A session has one aggregate 100 MiB blob-storage limit for its committed and staged workspace plus browser attachments. The service reserves this quota before accepting bytes. A session can reserve at most 1,024 distinct browser attachment objects at once. There is no separate application file-size limit; a single file may consume the remaining session quota. Metadata, submission bodies, replay history, and protocol messages still have bounded sizes.

## Development

```bash
npm install
npm test
npm run test:browser
npm run dev
npm run deploy
```

The browser smoke test requires Firefox and geckodriver. `npm run dev` and `npm run deploy` operate the Cloudflare service. See [`SKILL.md`](SKILL.md) for the complete agent workflow and event semantics.
