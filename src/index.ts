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

type QuestionRow = {
  answer_hash: string;
  status_hash: string;
  title: string;
  fields: string;
  answers: string | null;
  created_at: number;
  expires_at: number;
  answered_at: number | null;
};

type QuestionInit = {
  answerHash: string;
  statusHash: string;
  title: string;
  fields: Field[];
  createdAt: number;
  expiresAt: number;
};

const MAX_BODY_BYTES = 16_384;
const MAX_TITLE_LENGTH = 120;
const MAX_LABEL_LENGTH = 300;
const MAX_ANSWER_LENGTH = 2_000;
const MAX_FIELDS = 8;
const MAX_OPTIONS = 8;
const MAX_OPTION_LENGTH = 100;
const QUESTION_TTL_MS = 24 * 60 * 60 * 1_000;
const MAX_WAIT_SECONDS = 30;
const RETRY_AFTER_SECONDS = 3;
const encoder = new TextEncoder();

function baseHeaders(contentType: string): Headers {
  return new Headers({
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
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
    :root{color-scheme:dark;--bg:#0b120f;--panel:#111a15;--line:#294333;--text:#f5fff7;--muted:#a2b7a7;--accent:#78f2a1;--danger:#ffb0b0}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(700px 400px at 80% 0,#17442b 0,transparent 65%),var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,sans-serif}
    main{width:min(640px,calc(100% - 32px));margin:0 auto;padding:40px 0 64px}.brand{color:var(--accent);font-size:13px;font-weight:700;letter-spacing:.13em;text-transform:uppercase;margin-bottom:42px}
    .card{border:1px solid var(--line);background:#111a2fdd;border-radius:20px;padding:clamp(22px,5vw,42px);box-shadow:0 24px 80px #0004}h1{font-size:clamp(25px,5vw,38px);line-height:1.1;letter-spacing:-.04em;margin:0 0 14px}p{color:var(--muted);margin:0 0 28px;white-space:pre-wrap}
    fieldset{border:0;padding:0;margin:0 0 28px}legend{font-weight:650;margin-bottom:14px}.choice{display:flex;align-items:center;gap:12px;border:1px solid var(--line);border-radius:12px;padding:13px 15px;margin:9px 0;cursor:pointer}.choice:has(input:checked){border-color:var(--accent);background:#65e6dc12}.choice input{accent-color:var(--accent);width:17px;height:17px}
    .field{margin:0 0 24px}.field label{display:block;font-weight:650;margin-bottom:10px}textarea{display:block;width:100%;min-height:130px;resize:vertical;border:1px solid var(--line);border-radius:12px;background:#0a120d;color:var(--text);padding:14px;font:inherit;outline:none}textarea:focus{border-color:var(--accent)}button{border:0;border-radius:11px;background:var(--accent);color:#08121d;padding:12px 19px;font:700 15px system-ui;cursor:pointer}button:hover{filter:brightness(1.08)}.error{color:var(--danger);margin:-8px 0 20px}.muted{font-size:13px;color:var(--muted);margin-top:22px;margin-bottom:0}.home h1{font-size:32px}.home code{display:block;overflow:auto;border:1px solid var(--line);border-radius:10px;padding:14px;background:#080e1c;color:var(--accent);font-size:13px;margin-top:14px}
  </style>
</head>
<body><main><div class="brand">LetMeKnow</div>${body}</main></body></html>`, { status, headers: responseHeaders });
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

function token(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let result = "";
  for (const byte of bytes) result += String.fromCharCode(byte);
  return btoa(result).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hash(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  const contentLength = Number(request.headers.get("Content-Length") ?? 0);
  if (contentLength > MAX_BODY_BYTES) throw new Error("request too large");
  const bodyText = await request.text();
  if (encoder.encode(bodyText).byteLength > MAX_BODY_BYTES) throw new Error("request too large");
  let body: unknown;
  try {
    body = JSON.parse(bodyText);
  } catch {
    throw new Error("invalid JSON");
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("body must be a JSON object");
  return body as Record<string, unknown>;
}

function fieldsFromRow(row: QuestionRow): Field[] {
  return JSON.parse(row.fields) as Field[];
}

function questionPath(pathname: string, prefix: "/q/" | "/s/"): { id: string; token: string } | null {
  if (!pathname.startsWith(prefix)) return null;
  const parts = pathname.slice(prefix.length).split("/");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  return { id: parts[0], token: parts[1] };
}

function questionForm(row: QuestionRow, questionId: string, answerToken: string, error = ""): string {
  const fields = fieldsFromRow(row);
  const controls = fields.map((field) => {
    const name = `field_${field.id}`;
    if (field.type === "choice") {
      return `<fieldset><legend>${escapeHtml(field.label)}</legend>${field.options.map((option) => `<label class="choice"><input type="radio" name="${escapeHtml(name)}" value="${escapeHtml(option)}" required><span>${escapeHtml(option)}</span></label>`).join("")}</fieldset>`;
    }
    return `<div class="field"><label for="${escapeHtml(name)}">${escapeHtml(field.label)}</label><textarea id="${escapeHtml(name)}" name="${escapeHtml(name)}" maxlength="${MAX_ANSWER_LENGTH}" required></textarea></div>`;
  }).join("");
  return `<section class="card"><h1>${escapeHtml(row.title)}</h1>${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}<form method="post" action="/q/${escapeHtml(questionId)}/${escapeHtml(answerToken)}">${controls}<button type="submit">Submit answer</button></form><p class="muted">This link expires in 24 hours. No account is required.</p></section>`;
}

function messagePage(title: string, message: string, status = 200): Response {
  return html(title, `<section class="card"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></section>`, status);
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

function parseWaitSeconds(url: URL): number {
  const value = url.searchParams.get("wait");
  if (value === null || !/^\d+$/.test(value)) return 0;
  return Math.min(Number(value), MAX_WAIT_SECONDS);
}

export class Question {
  private readonly waiters = new Set<() => void>();

  constructor(private readonly state: DurableObjectState, _env: Env) {
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS question (
          answer_hash TEXT PRIMARY KEY,
          status_hash TEXT NOT NULL UNIQUE,
          title TEXT NOT NULL,
          fields TEXT NOT NULL,
          answers TEXT,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          answered_at INTEGER
        )
      `);
      this.state.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS lifecycle (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          expires_at INTEGER NOT NULL
        )
      `);
    });
  }

  private getQuestion(): QuestionRow | null {
    const rows = [...this.state.storage.sql.exec(`SELECT answer_hash, status_hash, title, fields, answers, created_at, expires_at, answered_at FROM question LIMIT 1`)] as QuestionRow[];
    return rows[0] ?? null;
  }

  private getExpiry(): number | null {
    const rows = [...this.state.storage.sql.exec(`SELECT expires_at FROM lifecycle WHERE id = 1`)] as Array<{ expires_at: number }>;
    return rows[0]?.expires_at ?? null;
  }

  private findBy(field: "answer_hash" | "status_hash", value: string): Promise<QuestionRow | null> {
    return hash(value).then((valueHash) => {
      const rows = [...this.state.storage.sql.exec(`SELECT answer_hash, status_hash, title, fields, answers, created_at, expires_at, answered_at FROM question WHERE ${field} = ?`, valueHash)] as QuestionRow[];
      return rows[0] ?? null;
    });
  }

  private expired(): boolean {
    const expiry = this.getExpiry();
    return expiry !== null && expiry <= Date.now();
  }

  private pendingResponse(): Response {
    return json({ status: "pending" }, 202, { "Retry-After": String(RETRY_AFTER_SECONDS) });
  }

  private statusResponse(row: QuestionRow | null): Response {
    if (!row) return json({ status: "expired" }, 410);
    if (row.expires_at <= Date.now()) return json({ status: "expired" }, 410);
    if (row.answers === null) return this.pendingResponse();
    return json({ status: "answered", answers: JSON.parse(row.answers), answered_at: new Date(row.answered_at!).toISOString() });
  }

  private addWaiter(timeoutMs: number): { promise: Promise<void>; resolve: () => void } {
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
    if (this.getQuestion()) return json({ error: "already initialized" }, 409);
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec(
        "INSERT INTO question (answer_hash, status_hash, title, fields, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        body.answerHash,
        body.statusHash,
        body.title,
        JSON.stringify(body.fields),
        body.createdAt,
        body.expiresAt
      );
      this.state.storage.sql.exec("INSERT INTO lifecycle (id, expires_at) VALUES (1, ?)", body.expiresAt);
    });
    await this.state.storage.setAlarm(body.expiresAt);
    return new Response(null, { status: 204 });
  }

  private async showQuestion(answerToken: string): Promise<Response> {
    const row = await this.findBy("answer_hash", answerToken);
    if (!row) return messagePage(this.expired() ? "Expired" : "Not found", this.expired() ? "This question link has expired." : "This question link is invalid.", this.expired() ? 410 : 404);
    if (row.expires_at <= Date.now()) return messagePage("Expired", "This question link has expired.", 410);
    if (row.answers !== null) return messagePage("Already answered", "Thanks. This question has already received an answer.", 409);
    return html(row.title, questionForm(row, this.state.id.toString(), answerToken));
  }

  private async answerQuestion(request: Request, answerToken: string): Promise<Response> {
    const row = await this.findBy("answer_hash", answerToken);
    if (!row) return messagePage(this.expired() ? "Expired" : "Not found", this.expired() ? "This question link has expired." : "This question link is invalid.", this.expired() ? 410 : 404);
    if (row.expires_at <= Date.now()) return messagePage("Expired", "This question link has expired.", 410);
    if (!request.headers.get("Content-Type")?.startsWith("application/x-www-form-urlencoded")) return messagePage("Invalid answer", "Submit the form from the question page.", 400);
    if (Number(request.headers.get("Content-Length") ?? 0) > MAX_BODY_BYTES) return messagePage("Invalid answer", "That answer is too large.", 400);

    const body = await request.text();
    if (encoder.encode(body).byteLength > MAX_BODY_BYTES) return messagePage("Invalid answer", "That answer is too large.", 400);
    const form = new URLSearchParams(body);
    const answers: Record<string, string> = {};
    for (const field of fieldsFromRow(row)) {
      const value = form.get(`field_${field.id}`);
      if (value === null) return html(row.title, questionForm(row, this.state.id.toString(), answerToken, "Please answer every field."), 400);
      const answer = value.trim();
      if (!answer || answer.length > MAX_ANSWER_LENGTH || (field.type === "choice" && !field.options.includes(answer))) {
        return html(row.title, questionForm(row, this.state.id.toString(), answerToken, "Please provide a valid answer for every field."), 400);
      }
      answers[field.id] = answer;
    }

    const answeredAt = Date.now();
    const result = this.state.storage.sql.exec(
      "UPDATE question SET answers = ?, answered_at = ? WHERE answer_hash = ? AND answers IS NULL AND expires_at > ?",
      JSON.stringify(answers),
      answeredAt,
      row.answer_hash,
      answeredAt
    );
    if (result.rowsWritten !== 1) {
      const latest = await this.findBy("answer_hash", answerToken);
      if (latest?.answers !== null) return messagePage("Already answered", "Thanks. This question has already received an answer.", 409);
      return messagePage("Expired", "This question link has expired.", 410);
    }
    this.wakeWaiters();
    return messagePage("Answer received", "Thanks — the agent can now continue.");
  }

  private async showStatus(request: Request, statusToken: string): Promise<Response> {
    const row = await this.findBy("status_hash", statusToken);
    if (!row) return this.expired() ? json({ status: "expired" }, 410) : json({ error: "not found" }, 404);
    if (row.expires_at <= Date.now()) return json({ status: "expired" }, 410);
    if (row.answers !== null) return this.statusResponse(row);

    const waitSeconds = parseWaitSeconds(new URL(request.url));
    if (waitSeconds === 0) return this.pendingResponse();

    const waiter = this.addWaiter(waitSeconds * 1_000);
    const latest = this.getQuestion();
    if (!latest || latest.answers !== null || latest.expires_at <= Date.now()) waiter.resolve();
    await waiter.promise;
    return this.statusResponse(this.getQuestion());
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/initialize") return this.initialize(request);

    const question = questionPath(url.pathname, "/q/");
    if (question) {
      if (request.method === "GET") return this.showQuestion(question.token);
      if (request.method === "POST") return this.answerQuestion(request, question.token);
      return messagePage("Method not allowed", "Use GET or POST for this question link.", 405);
    }

    const status = questionPath(url.pathname, "/s/");
    if (status && request.method === "GET") return this.showStatus(request, status.token);
    if (status) return json({ error: "method not allowed" }, 405);
    return json({ error: "not found" }, 404);
  }

  async alarm(): Promise<void> {
    const expiresAt = this.getExpiry();
    if (expiresAt === null) return;
    const now = Date.now();
    if (expiresAt > now) {
      await this.state.storage.setAlarm(expiresAt);
      return;
    }
    this.state.storage.sql.exec("DELETE FROM question WHERE expires_at <= ?", now);
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

  const answerToken = token();
  const statusToken = token();
  const createdAt = Date.now();
  const expiresAt = createdAt + QUESTION_TTL_MS;
  const objectId = env.QUESTIONS.newUniqueId();
  const questionId = objectId.toString();
  const initialized = await env.QUESTIONS.get(objectId).fetch(new Request("https://question.internal/initialize", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      answerHash: await hash(answerToken),
      statusHash: await hash(statusToken),
      title,
      fields,
      createdAt,
      expiresAt
    } satisfies QuestionInit)
  }));
  if (!initialized.ok) return json({ error: "could not create question" }, 500);

  const origin = new URL(request.url).origin;
  return json({
    question_url: `${origin}/q/${questionId}/${answerToken}`,
    status_url: `${origin}/s/${questionId}/${statusToken}`,
    expires_at: new Date(expiresAt).toISOString()
  }, 201);
}

function home(): Response {
  return text(`# LetMeKnow

Ask a human, then poll for structured answer.

## Create a questionnaire

curl -sS -X POST https://letmeknow.dev/questions \\
  -H 'Content-Type: application/json' \\
  -d '{"title":"Release approval","fields":[{"id":"approve","label":"Deploy this release?","type":"choice","options":["Yes","No"]},{"id":"notes","label":"Anything else?","type":"text"}]}'

The response contains two independent capability URLs:
- question_url: give this anonymous URL to the human.
- status_url: keep this URL private and poll it from the agent.
- expires_at: both URLs expire after 24 hours.

## Poll the answer

GET /s/<question-id>/<status-token>?wait=25

A pending request waits up to 25 seconds for an answer. It returns:
- 200 {"status":"answered","answers":{...}} when the human submits.
- 202 {"status":"pending"} with Retry-After when the bounded wait expires.
- 410 {"status":"expired"} when the question is gone.

Without wait, 202 means poll again after the Retry-After delay.

## Answer rules

- One to eight required fields per questionnaire.
- Supported field types: choice and text.
- Yes/no is a choice with options ["Yes", "No"].
- Accepts first submission.`);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/" && request.method === "GET") return home();
      if (url.pathname === "/questions" && request.method === "POST") return createQuestion(request, env);

      const question = questionPath(url.pathname, "/q/");
      if (question) {
        let id: DurableObjectId;
        try {
          id = env.QUESTIONS.idFromString(question.id);
        } catch {
          return messagePage("Not found", "This question link is invalid.", 404);
        }
        if (request.method === "GET" || request.method === "POST") return env.QUESTIONS.get(id).fetch(request);
        return messagePage("Method not allowed", "Use GET or POST for this question link.", 405);
      }

      const status = questionPath(url.pathname, "/s/");
      if (status) {
        if (request.method !== "GET") return json({ error: "method not allowed" }, 405);
        let id: DurableObjectId;
        try {
          id = env.QUESTIONS.idFromString(status.id);
        } catch {
          return json({ error: "not found" }, 404);
        }
        return env.QUESTIONS.get(id).fetch(request);
      }
      return json({ error: "not found" }, 404);
    } catch {
      return json({ error: "internal server error" }, 500);
    }
  }
};
