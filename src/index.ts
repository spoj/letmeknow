interface Env {
  QUESTIONS: DurableObjectNamespace;
  CREATE_RATE_LIMIT: RateLimitBinding;
}

interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

type ChoiceField = {
  id: string;
  label: string;
  type: "choice";
  options: string[];
};

type TextField = {
  id: string;
  label: string;
  type: "text";
};

type Field = ChoiceField | TextField;

type QuestionRecord = {
  answerHash: string;
  statusHash: string;
  title: string;
  fields: Field[];
  answers: Record<string, string> | null;
  expiresAt: number;
  answeredAt: number | null;
};

type QuestionInit = {
  answerHash: string;
  statusHash: string;
  title: string;
  fields: Field[];
  expiresAt: number;
};

const QUESTION_KEY = "question";
const MAX_BODY_BYTES = 16_384;
const MAX_TITLE_LENGTH = 120;
const MAX_LABEL_LENGTH = 300;
const MAX_ANSWER_LENGTH = 2_000;
const MAX_FIELDS = 8;
const MAX_OPTIONS = 8;
const MAX_OPTION_LENGTH = 100;
const QUESTION_TTL_MS = 10 * 60 * 1_000;
const MAX_WAIT_SECONDS = 25;
const MAX_WAITERS = 32;
const RETRY_AFTER_SECONDS = 3;
const ANSWER_TOKEN_BYTES = 8;
const ANSWER_TOKEN_LENGTH = 11;
const STATUS_TOKEN_BYTES = 32;
const STATUS_TOKEN_LENGTH = 43;
const encoder = new TextEncoder();

function baseHeaders(contentType: string): Headers {
  return new Headers({
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "X-Robots-Tag": "noindex, nofollow"
  });
}

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  const responseHeaders = baseHeaders("application/json; charset=utf-8");
  for (const [key, value] of Object.entries(extra)) responseHeaders.set(key, value);
  return new Response(`${JSON.stringify(body)}\n`, { status, headers: responseHeaders });
}

function text(body: string, status = 200): Response {
  return new Response(`${body.trim()}\n`, { status, headers: baseHeaders("text/plain; charset=utf-8") });
}

function html(title: string, body: string, status = 200): Response {
  const responseHeaders = baseHeaders("text/html; charset=utf-8");
  responseHeaders.set(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
  );
  return new Response(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>${escapeHtml(title)} · LetMeKnow</title>
  <style>
    *{box-sizing:border-box}
    body{margin:0;min-height:100vh;background:#008080;color:#000;font:13px/1.35 "MS Sans Serif","Microsoft Sans Serif",Tahoma,sans-serif}
    main{width:min(560px,calc(100% - 24px));margin:24px auto;padding-bottom:24px}
    .card{background:#c0c0c0;border:2px solid;border-color:#fff #000 #000 #fff;box-shadow:1px 1px 0 #808080;padding:0}
    .titlebar{display:flex;align-items:center;justify-content:space-between;gap:12px;background:#000080;color:#fff;font-weight:700;padding:2px 3px;min-height:20px}
    .window-controls{font-weight:400;letter-spacing:1px;white-space:nowrap}
    .window-body{padding:14px 16px 16px}
    h1{font-size:18px;line-height:1.2;margin:0 0 12px;font-weight:700}
    p{margin:0 0 16px;white-space:pre-wrap}
    fieldset{border:2px groove #fff;margin:0 0 12px;padding:8px 10px 7px}
    legend{padding:0 4px;font-weight:700}
    .choice{display:flex;align-items:center;gap:7px;margin:4px 0;cursor:pointer}
    .choice input{margin:0}
    .field{margin:0 0 12px}
    .field label{display:block;font-weight:700;margin-bottom:4px}
    textarea{display:block;width:100%;min-height:84px;resize:vertical;border:2px inset #fff;border-radius:0;background:#fff;color:#000;padding:4px;font:13px/1.3 "MS Sans Serif","Microsoft Sans Serif",Tahoma,sans-serif}
    textarea:focus{outline:1px dotted #000;outline-offset:-3px}
    button{border:2px outset #fff;border-radius:0;background:#c0c0c0;color:#000;min-width:88px;padding:4px 14px;font:700 13px "MS Sans Serif","Microsoft Sans Serif",Tahoma,sans-serif;cursor:pointer}
    button:focus{outline:1px dotted #000;outline-offset:-4px}
    button:active{border-style:inset;padding-top:5px;padding-bottom:3px}
    .dialog-actions{text-align:right;margin-top:14px}
    .error{color:#800000;margin:-2px 0 14px;font-weight:700}
    .muted{font-size:12px;color:#404040;margin:16px 0 0}
    @media (max-width:420px){main{width:calc(100% - 12px);margin:12px auto}.window-body{padding:12px}}
  </style>
</head>
<body class="windows-31"><main>${body}</main></body></html>`, { status, headers: responseHeaders });
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character] as string);
}

function token(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hash(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function readBody(request: Request): Promise<string> {
  const contentLength = request.headers.get("Content-Length");
  if (contentLength !== null && Number.isFinite(Number(contentLength)) && Number(contentLength) > MAX_BODY_BYTES) {
    try {
      await request.body?.cancel();
    } catch {
      // The body is already unusable; the size error is the useful response.
    }
    throw new Error("request too large");
  }

  const reader = request.body?.getReader();
  if (!reader) return "";

  const decoder = new TextDecoder();
  let body = "";
  let bytesRead = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytesRead += value.byteLength;
    if (bytesRead > MAX_BODY_BYTES) {
      try {
        await reader.cancel();
      } catch {
        // Keep returning the size error if cancellation races stream teardown.
      }
      throw new Error("request too large");
    }
    body += decoder.decode(value, { stream: true });
  }
  return body + decoder.decode();
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  const bodyText = await readBody(request);
  let body: unknown;
  try {
    body = JSON.parse(bodyText);
  } catch {
    throw new Error("invalid JSON");
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("body must be a JSON object");
  return body as Record<string, unknown>;
}

function questionPath(pathname: string, prefix: "/q/" | "/s/"): { routeToken: string; token: string } | null {
  if (!pathname.startsWith(prefix)) return null;
  const value = pathname.slice(prefix.length);
  if (prefix === "/q/") {
    if (value.length !== ANSWER_TOKEN_LENGTH || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
    return { routeToken: value, token: value };
  }
  const parts = value.split(".");
  if (parts.length !== 2 || parts[0].length !== ANSWER_TOKEN_LENGTH || parts[1].length !== STATUS_TOKEN_LENGTH) return null;
  if (![...parts[0], ...parts[1]].every((character) => /[A-Za-z0-9_-]/.test(character))) return null;
  return { routeToken: parts[0], token: parts[1] };
}

function questionForm(row: QuestionRecord, routeToken: string, submitted: URLSearchParams | undefined, error = ""): string {
  const remainingMinutes = Math.max(0, Math.ceil((row.expiresAt - Date.now()) / 60_000));
  const remaining = `${String(Math.floor(remainingMinutes / 60)).padStart(2, "0")}:${String(remainingMinutes % 60).padStart(2, "0")}`;
  const controls = row.fields.map((field) => {
    const name = `field_${field.id}`;
    const value = submitted?.get(name) ?? "";
    if (field.type === "choice") {
      return `<fieldset><legend>${escapeHtml(field.label)}</legend>${field.options.map((option) => `<label class="choice"><input type="radio" name="${escapeHtml(name)}" value="${escapeHtml(option)}"${value === option ? " checked" : ""} required><span>${escapeHtml(option)}</span></label>`).join("")}</fieldset>`;
    }
    return `<div class="field"><label for="${escapeHtml(name)}">${escapeHtml(field.label)}</label><textarea id="${escapeHtml(name)}" name="${escapeHtml(name)}" maxlength="${MAX_ANSWER_LENGTH}" required>${escapeHtml(value)}</textarea></div>`;
  }).join("");
  return `<section class="card"><div class="titlebar"><span>LetMeKnow</span><span class="window-controls" aria-hidden="true">▼ ▲</span></div><div class="window-body"><h1>${escapeHtml(row.title)}</h1>${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ""}<form method="post" action="/q/${escapeHtml(routeToken)}">${controls}<div class="dialog-actions"><button type="submit">Submit answer</button></div></form><p class="muted">link expires in ${remaining}</p></div></section>`;
}

function messagePage(title: string, message: string, status = 200): Response {
  return html(title, `<section class="card"><div class="titlebar"><span>LetMeKnow</span><span class="window-controls" aria-hidden="true">▼ ▲</span></div><div class="window-body"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></div></section>`, status);
}

function validateFields(value: unknown): Field[] | string {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_FIELDS) return `fields must contain 1-${MAX_FIELDS} items`;
  const ids = new Set<string>();
  const fields: Field[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return "each field must be an object";
    const field = item as Record<string, unknown>;
    const id = typeof field.id === "string" ? field.id.trim() : "";
    const label = typeof field.label === "string" ? field.label.trim() : "";
    if (!/^[a-z][a-z0-9_]{0,31}$/.test(id) || ids.has(id)) return "field ids must be unique and match [a-z][a-z0-9_]{0,31}";
    if (!label || label.length > MAX_LABEL_LENGTH) return `field labels must be non-empty and ${MAX_LABEL_LENGTH} characters or fewer`;
    ids.add(id);
    if (field.type === "text") {
      fields.push({ id, label, type: "text" });
      continue;
    }
    if (field.type !== "choice" || !Array.isArray(field.options) || field.options.length < 2 || field.options.length > MAX_OPTIONS) {
      return `choice fields need 2-${MAX_OPTIONS} options, and the other supported type is text`;
    }
    const options: string[] = [];
    for (const option of field.options) {
      if (typeof option !== "string") return "each option must be a string";
      const text = option.trim();
      if (!text || text.length > MAX_OPTION_LENGTH || options.includes(text)) return "options must be non-empty, unique, and within the length limit";
      options.push(text);
    }
    fields.push({ id, label, type: "choice", options });
  }
  return fields;
}

function parseWaitSeconds(url: URL): number | null {
  const value = url.searchParams.get("wait");
  if (value === null) return MAX_WAIT_SECONDS;
  if (!/^\d+$/.test(value)) return null;
  const seconds = Number(value);
  return Number.isSafeInteger(seconds) && seconds <= MAX_WAIT_SECONDS ? seconds : null;
}

function isLocalHost(url: URL): boolean {
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname.endsWith(".localhost");
}

function httpsRedirect(url: URL): Response {
  url.protocol = "https:";
  const headers = baseHeaders("text/plain; charset=utf-8");
  headers.set("Location", url.toString());
  return new Response("Redirecting to HTTPS.\n", { status: 307, headers });
}

export class Question {
  private readonly waiters = new Set<() => void>();

  constructor(private readonly state: DurableObjectState, _env: Env) {}

  private getQuestion(): Promise<QuestionRecord | undefined> {
    return this.state.storage.get<QuestionRecord>(QUESTION_KEY);
  }

  private async findBy(field: "answerHash" | "statusHash", value: string): Promise<QuestionRecord | undefined> {
    const valueHash = await hash(value);
    const question = await this.getQuestion();
    return question?.[field] === valueHash ? question : undefined;
  }

  private pendingResponse(): Response {
    return json({ status: "pending" }, 202, { "Retry-After": String(RETRY_AFTER_SECONDS) });
  }

  private statusResponse(row: QuestionRecord | undefined): Response {
    if (!row) return json({ error: "not found" }, 404);
    if (row.expiresAt <= Date.now()) return json({ status: "expired" }, 410);
    if (row.answers === null) return this.pendingResponse();
    return json({ status: "answered", answers: row.answers, answered_at: new Date(row.answeredAt!).toISOString() });
  }

  private addWaiter(timeoutMs: number): { promise: Promise<void>; resolve: () => void } | null {
    if (this.waiters.size >= MAX_WAITERS) return null;
    let finish!: () => void;
    let timer!: ReturnType<typeof setTimeout>;
    let settled = false;
    const promise = new Promise<void>((resolve) => {
      finish = () => {
        if (settled) return;
        settled = true;
        this.waiters.delete(finish);
        clearTimeout(timer);
        resolve();
      };
      this.waiters.add(finish);
      timer = setTimeout(finish, timeoutMs);
    });
    return { promise, resolve: finish };
  }

  private wakeWaiters(): void {
    for (const resolve of [...this.waiters]) resolve();
  }

  private async initialize(request: Request): Promise<Response> {
    if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
    const body = await request.json() as QuestionInit;
    const question: QuestionRecord = {
      answerHash: body.answerHash,
      statusHash: body.statusHash,
      title: body.title,
      fields: body.fields,
      answers: null,
      expiresAt: body.expiresAt,
      answeredAt: null
    };
    const initialized = await this.state.storage.transaction(async (transaction) => {
      if (await transaction.get<QuestionRecord>(QUESTION_KEY)) return false;
      await transaction.put(QUESTION_KEY, question);
      await transaction.setAlarm(body.expiresAt);
      return true;
    });
    if (!initialized) return json({ error: "already initialized" }, 409);
    return new Response(null, { status: 204, headers: baseHeaders("text/plain; charset=utf-8") });
  }

  private async showQuestion(routeToken: string, answerToken: string): Promise<Response> {
    const row = await this.findBy("answerHash", answerToken);
    if (!row) return messagePage("Not found", "This question link is invalid.", 404);
    if (row.expiresAt <= Date.now()) return messagePage("Expired", "This question link has expired.", 410);
    if (row.answers !== null) return messagePage("Already answered", "Thanks. This question has already received an answer.", 409);
    return html(row.title, questionForm(row, routeToken, undefined));
  }

  private async answerQuestion(request: Request, routeToken: string, answerToken: string): Promise<Response> {
    const row = await this.findBy("answerHash", answerToken);
    if (!row) return messagePage("Not found", "This question link is invalid.", 404);
    if (row.expiresAt <= Date.now()) return messagePage("Expired", "This question link has expired.", 410);
    if (!request.headers.get("Content-Type")?.startsWith("application/x-www-form-urlencoded")) return messagePage("Invalid answer", "Submit the form from the question page.", 400);

    let body: string;
    try {
      body = await readBody(request);
    } catch (error) {
      const message = error instanceof Error && error.message === "request too large" ? "That answer is too large." : "Could not read that answer.";
      return messagePage("Invalid answer", message, 400);
    }
    const form = new URLSearchParams(body);
    const answers: Record<string, string> = {};
    for (const field of row.fields) {
      const value = form.get(`field_${field.id}`);
      if (value === null) return html(row.title, questionForm(row, routeToken, form, "Please answer every field."), 400);
      const answer = value.trim();
      if (!answer || answer.length > MAX_ANSWER_LENGTH || (field.type === "choice" && !field.options.includes(answer))) {
        return html(row.title, questionForm(row, routeToken, form, "Please provide a valid answer for every field."), 400);
      }
      answers[field.id] = answer;
    }

    const result = await this.state.storage.transaction(async (transaction) => {
      const current = await transaction.get<QuestionRecord>(QUESTION_KEY);
      if (!current) return "missing" as const;
      const answeredAt = Date.now();
      if (current.expiresAt <= answeredAt) return "expired" as const;
      if (current.answers !== null) return "answered" as const;
      await transaction.put(QUESTION_KEY, { ...current, answers, answeredAt });
      return "accepted" as const;
    });
    if (result === "answered") return messagePage("Already answered", "Thanks. This question has already received an answer.", 409);
    if (result === "expired") return messagePage("Expired", "This question link has expired.", 410);
    if (result === "missing") return messagePage("Not found", "This question link is invalid.", 404);
    this.wakeWaiters();
    return messagePage("Answer received", "Thanks — the agent can now continue.");
  }

  private async showStatus(request: Request, statusToken: string): Promise<Response> {
    const waitSeconds = parseWaitSeconds(new URL(request.url));
    if (waitSeconds === null) return json({ error: "wait must be an integer from 0 through 25" }, 400);

    const row = await this.findBy("statusHash", statusToken);
    if (!row) return json({ error: "not found" }, 404);
    if (row.expiresAt <= Date.now()) return json({ status: "expired" }, 410);
    if (row.answers !== null) return this.statusResponse(row);
    if (waitSeconds === 0) return this.pendingResponse();

    const waiter = this.addWaiter(waitSeconds * 1_000);
    if (!waiter) return json({ error: "too many concurrent waiters" }, 429, { "Retry-After": String(RETRY_AFTER_SECONDS) });
    const latest = await this.getQuestion();
    if (!latest || latest.answers !== null || latest.expiresAt <= Date.now()) waiter.resolve();
    await waiter.promise;
    return this.statusResponse(await this.getQuestion());
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/initialize") return this.initialize(request);

    const question = questionPath(url.pathname, "/q/");
    if (question) {
      if (request.method === "GET") return this.showQuestion(question.routeToken, question.token);
      if (request.method === "POST") return this.answerQuestion(request, question.routeToken, question.token);
      return messagePage("Method not allowed", "Use GET or POST for this question link.", 405);
    }

    const status = questionPath(url.pathname, "/s/");
    if (status && request.method === "GET") return this.showStatus(request, status.token);
    if (status) return json({ error: "method not allowed" }, 405);
    return json({ error: "not found" }, 404);
  }

  async alarm(): Promise<void> {
    const now = Date.now();
    const result = await this.state.storage.transaction(async (transaction) => {
      const row = await transaction.get<QuestionRecord>(QUESTION_KEY);
      if (!row) return "missing" as const;
      if (row.expiresAt > now) return "future" as const;
      await transaction.delete(QUESTION_KEY);
      return "deleted" as const;
    });
    if (result === "future") {
      const row = await this.getQuestion();
      if (row) await this.state.storage.setAlarm(row.expiresAt);
      return;
    }
    this.wakeWaiters();
  }
}

async function createQuestion(request: Request, env: Env): Promise<Response> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const allowed = await env.CREATE_RATE_LIMIT.limit({ key: ip });
  if (!allowed.success) return json({ error: "too many questions; try again later" }, 429, { "Retry-After": "60" });

  let body: Record<string, unknown>;
  try {
    body = await readJson(request);
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : "invalid request" }, 400);
  }
  const title = typeof body.title === "string" ? body.title.trim() : "";
  if (!title || title.length > MAX_TITLE_LENGTH) return json({ error: `title is required and must be ${MAX_TITLE_LENGTH} characters or fewer` }, 400);
  const fields = validateFields(body.fields);
  if (typeof fields === "string") return json({ error: fields }, 400);

  const answerToken = token(ANSWER_TOKEN_BYTES);
  const statusToken = token(STATUS_TOKEN_BYTES);
  const expiresAt = Date.now() + QUESTION_TTL_MS;
  const objectId = env.QUESTIONS.idFromName(answerToken);
  const initialized = await env.QUESTIONS.get(objectId).fetch(new Request("https://question.internal/initialize", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      answerHash: await hash(answerToken),
      statusHash: await hash(statusToken),
      title,
      fields,
      expiresAt
    } satisfies QuestionInit)
  }));
  if (!initialized.ok) return json({ error: "could not create question" }, 500);

  const origin = new URL(request.url).origin;
  return json({
    question_url: `${origin}/q/${answerToken}`,
    status_url: `${origin}/s/${answerToken}.${statusToken}`,
    expires_at: new Date(expiresAt).toISOString()
  }, 201);
}

function home(origin: string): Response {
  return text(`# LetMeKnow

Ask a human, then poll for structured answer.

## Create a questionnaire

curl -sS -X POST ${origin}/questions \\
  -H 'Content-Type: application/json' \\
  -d '{"title":"Release approval","fields":[{"id":"approve","label":"Deploy this release?","type":"choice","options":["Yes","No"]},{"id":"notes","label":"Anything else?","type":"text"}]}'

The response contains a public answer URL and a private status URL:
- question_url: give this short anonymous URL to the human.
- status_url: keep this URL private and poll it from the agent.
- expires_at: both URLs expire after 10 minutes.

## Poll the answer

Use a bounded long poll and repeat the same curl request after each pending response:

status_url="${origin}/s/<answer-code>.<status-token>"
while response="$(curl -sS -w '\\n%{http_code}' "\${status_url}?wait=25")"; do
  status="\${response##*$'\\n'}"
  body="\${response%$'\\n'*}"
  printf '%s\\n' "$body"
  case "$status" in
    200|410|404) break ;;
    202) ;;
    *) printf 'unexpected HTTP status: %s\\n' "$status" >&2; exit 1 ;;
  esac
done

Each pending request waits up to 25 seconds. Repeat with wait=25 after a 202 response. Stop on a terminal response:
- 200 means {"status":"answered","answers":{...}} and the human has submitted.
- 410 means {"status":"expired"} and the question has logically expired.
- 404 means the capability was removed after expiry cleanup.

## Answer rules

- One to eight required fields per questionnaire.
- Supported field types: choice and text.
- Yes/no is a choice with options ["Yes", "No"].
- Accepts first submission.`);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.protocol === "http:" && !isLocalHost(url)) return httpsRedirect(url);
    try {
      if (url.pathname === "/" && request.method === "GET") return home(url.origin);
      if (url.pathname === "/questions" && request.method === "POST") return createQuestion(request, env);

      const question = questionPath(url.pathname, "/q/");
      if (question) {
        const id = env.QUESTIONS.idFromName(question.routeToken);
        if (request.method === "GET" || request.method === "POST") return env.QUESTIONS.get(id).fetch(request);
        return messagePage("Method not allowed", "Use GET or POST for this question link.", 405);
      }

      const status = questionPath(url.pathname, "/s/");
      if (status) {
        if (request.method !== "GET") return json({ error: "method not allowed" }, 405);
        const id = env.QUESTIONS.idFromName(status.routeToken);
        return env.QUESTIONS.get(id).fetch(request);
      }
      return json({ error: "not found" }, 404);
    } catch {
      return json({ error: "internal server error" }, 500);
    }
  }
};
