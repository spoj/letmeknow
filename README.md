# LetMeKnow

LetMeKnow gives an agent a temporary public preview of a dedicated folder and receives structured input from a human. The CLI serves the folder over an outbound connection to the LetMeKnow relay; it does not listen on a network port.

## Start a session

Node.js 22.12 or newer is required. Pass the preview directory explicitly:

```bash
npx letmeknow-cli ./preview
```

The CLI prints JSON lines to stdout. The first line contains the public URL:

```json
{"type":"ready","url":"https://0123456789abcdef0123.letmeknow.dev/"}
```

Open the URL in one or more browsers. The URL is a bearer capability: anyone who has it can view the preview and submit its forms. Sessions are hosted at `letmeknow.dev` and are temporary. `--skill` prints instructions for an agent without starting a session. Diagnostics go to stderr.

The preview directory is public. Keep secrets and unrelated project files elsewhere. Use a dedicated directory containing only the files intended for the human.

## Live workspace

Create an ordinary static site in the directory, usually with `index.html`, plus its CSS, JavaScript, images, and other assets. The relay injects the small browser runtime into HTML pages. The CLI serves the workspace files unchanged.

Every file in the preview directory is part of the live artifact. A burst of changes is coalesced into one workspace revision. Each connected browser then performs a full-page reload.

The runtime preserves scroll position and the values of controls with stable, unique `id` attributes, including checked and selected state. Other browser state is not part of the preview contract. Use relative asset URLs and normal links between pages.

If a requested page does not exist, the live 404 page remains connected and recovers when the page is created. Connection status pages likewise reconnect and recover when the producer becomes available again.

## Forms

Use native HTML GET and POST forms with same-origin or relative actions:

```html
<form id="decision" action="/decide" method="post">
  <label>Comment <textarea name="comment"></textarea></label>
  <button name="decision" value="approve">Approve</button>
  <button name="decision" value="reject">Reject</button>
</form>
```

The runtime sends the submission to the CLI, which prints one `submit` event to stdout:

```json
{"type":"submit","id":"…","method":"POST","action":"/decide","form_id":"decision","trigger":{"id":null,"name":"decision","value":"approve"},"values":{"comment":"Looks good","decision":"approve"}}
```

Repeated field names become arrays, and native browser validation runs before delivery. POST forms may include file inputs; the total submission is limited to 1 MiB. Uploaded files are stored in a private temporary inbox and the event includes an `attachments` array with each field name, original filename, media type, size, and local path. Attachment paths remain available until the CLI stops and are never published unless the agent deliberately copies them into the preview directory.

The event ID identifies the submission; it is not a response handle. Read the event, treat values and attachments as untrusted input, update the workspace, and let the next revision show the result.

Submission feedback is automatic: **Sending…** or **Uploading…**, then **Sent. Waiting for an update…**, or **Couldn’t send. Try again.** Add `[data-letmeknow-status]` where a form or page needs a particular status location. Forms are accepted for asynchronous processing, so the transport response is `202 Accepted`.

## Security

The preview URL grants access to the session. The relay receives served files and submitted values. The preview folder is trusted code from the browser's perspective, so do not include secrets or credentials unless that is intentional. The CLI makes outbound relay connections only and accepts no inbound browser connections.

The CLI keeps requests inside the selected directory, including when files contain symlinks. Sensitive names such as `.env`, `.git`, private keys, and database files are excluded.

## Development

```bash
npm install
npm test
npm run dev
npm run deploy
```

`npm run dev` and `npm run deploy` operate the Cloudflare relay. The stdout contract is JSONL (`ready` and `submit` events); diagnostics belong on stderr.
