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
const THEMES = ["windows-95", "terminal", "blueprint", "paper", "candy"] as const;
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
  const theme = THEMES[Math.floor(Math.random() * THEMES.length)];
  return new Response(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>${escapeHtml(title)} · LetMeKnow</title>
  <style>
    *{box-sizing:border-box}
    body[data-theme="windows-95"]{--page-background:#008080;--page-image:none;--text:#000;--font:"MS Sans Serif","Microsoft Sans Serif","Segoe UI",Tahoma,sans-serif;--surface:#c0c0c0;--card-border:2px solid;--card-border-color:#fff #404040 #404040 #fff;--card-radius:0;--card-shadow:2px 2px 0 #000;--title-background:#000080;--title-color:#fff;--field-border:1px groove #fff;--input-background:#fff;--input-text:#000;--input-border:2px inset #fff;--input-radius:0;--button-background:#c0c0c0;--button-text:#000;--button-border:2px outset #fff;--button-radius:0;--accent:#000080;--muted:#404040;--error:#800000;--focus:#000}
    body[data-theme="terminal"]{--page-background:#06100a;--page-image:repeating-linear-gradient(0deg,transparent 0 3px,rgba(80,255,120,.035) 3px 4px);--text:#9cff9c;--font:"SFMono-Regular",Consolas,"Liberation Mono",monospace;--surface:#0b1a10;--card-border:1px solid;--card-border-color:#36d66b;--card-radius:2px;--card-shadow:0 0 24px rgba(54,214,107,.22);--title-background:#36d66b;--title-color:#031006;--field-border:1px solid #277f42;--input-background:#020704;--input-text:#9cff9c;--input-border:1px solid #36d66b;--input-radius:0;--button-background:#36d66b;--button-text:#031006;--button-border:1px solid #9cff9c;--button-radius:0;--accent:#36d66b;--muted:#6cab78;--error:#ff7b72;--focus:#fff}
    body[data-theme="blueprint"]{--page-background:#0b3d69;--page-image:linear-gradient(rgba(125,211,252,.12) 1px,transparent 1px),linear-gradient(90deg,rgba(125,211,252,.12) 1px,transparent 1px);--page-size:24px 24px;--text:#e0f2fe;--font:"Avenir Next","Segoe UI",sans-serif;--surface:#104e7a;--card-border:2px solid;--card-border-color:#7dd3fc;--card-radius:4px;--card-shadow:8px 8px 0 rgba(3,31,55,.55);--title-background:#082f49;--title-color:#bae6fd;--field-border:1px dashed #7dd3fc;--input-background:#e0f2fe;--input-text:#082f49;--input-border:2px solid #7dd3fc;--input-radius:2px;--button-background:#bae6fd;--button-text:#082f49;--button-border:2px solid #e0f2fe;--button-radius:2px;--accent:#7dd3fc;--muted:#bae6fd;--error:#fecaca;--focus:#fff}
    body[data-theme="paper"]{--page-background:#eadfca;--page-image:radial-gradient(rgba(91,67,47,.12) .7px,transparent .7px);--page-size:8px 8px;--text:#3f3025;--font:Georgia,"Times New Roman",serif;--surface:#fffaf0;--card-border:1px solid;--card-border-color:#8c735d;--card-radius:1px;--card-shadow:0 12px 28px rgba(76,54,36,.2);--title-background:#7d2f2f;--title-color:#fffaf0;--field-border:1px solid #b89b7d;--input-background:#fffdf8;--input-text:#3f3025;--input-border:1px solid #8c735d;--input-radius:1px;--button-background:#7d2f2f;--button-text:#fffaf0;--button-border:1px solid #5d2020;--button-radius:1px;--accent:#7d2f2f;--muted:#786553;--error:#9f1d1d;--focus:#7d2f2f}
    body[data-theme="candy"]{--page-background:#f8d8ed;--page-image:linear-gradient(135deg,rgba(255,255,255,.55) 25%,transparent 25% 50%,rgba(255,255,255,.55) 50% 75%,transparent 75%);--page-size:32px 32px;--text:#4c245c;--font:"Trebuchet MS","Segoe UI",sans-serif;--surface:#fff7fc;--card-border:3px solid;--card-border-color:#9b5de5;--card-radius:18px;--card-shadow:0 12px 0 #f15bb5;--title-background:linear-gradient(90deg,#9b5de5,#f15bb5);--title-color:#fff;--field-border:2px solid #f15bb5;--input-background:#fff;--input-text:#4c245c;--input-border:2px solid #9b5de5;--input-radius:10px;--button-background:#fee440;--button-text:#4c245c;--button-border:2px solid #9b5de5;--button-radius:999px;--accent:#9b5de5;--muted:#7a4b89;--error:#b5175b;--focus:#00bbf9}
    body{margin:0;min-height:100vh;background-color:var(--page-background);background-image:var(--page-image);background-size:var(--page-size,auto);color:var(--text);font:13px/1.35 var(--font)}
    main{width:min(560px,calc(100% - 24px));margin:24px auto;padding-bottom:24px}
    .card{background:var(--surface);border:var(--card-border);border-color:var(--card-border-color);border-radius:var(--card-radius);box-shadow:var(--card-shadow);padding:0;overflow:hidden}
    .titlebar{display:flex;align-items:center;justify-content:space-between;gap:12px;background:var(--title-background);color:var(--title-color);font-weight:700;padding:5px 8px;min-height:22px}
    .window-controls{font-weight:400;letter-spacing:1px;white-space:nowrap}
    .window-body{padding:14px 16px 16px}
    h1{font-size:18px;line-height:1.2;margin:0 0 12px;font-weight:700}
    p{margin:0 0 16px;white-space:pre-wrap}
    fieldset{border:var(--field-border);margin:0 0 12px;padding:8px 10px 7px}
    legend{padding:0 4px;font-weight:700}
    .choice{display:flex;align-items:center;gap:7px;margin:4px 0;cursor:pointer}
    .choice input{margin:0;accent-color:var(--accent)}
    .field{margin:0 0 12px}
    .field label{display:block;font-weight:700;margin-bottom:4px}
    textarea{display:block;width:100%;min-height:84px;resize:vertical;border:var(--input-border);border-radius:var(--input-radius);background:var(--input-background);color:var(--input-text);padding:6px;font:13px/1.3 var(--font)}
    textarea:focus{outline:2px dotted var(--focus);outline-offset:-4px}
    button{border:var(--button-border);border-radius:var(--button-radius);background:var(--button-background);color:var(--button-text);min-width:88px;padding:5px 14px;font:700 13px var(--font);cursor:pointer}
    button:focus{outline:2px dotted var(--focus);outline-offset:-4px}
    button:active{border-style:inset;transform:translateY(1px)}
    .dialog-actions{text-align:right;margin-top:14px}
    .error{color:var(--error);margin:-2px 0 14px;font-weight:700}
    .muted{font-size:12px;color:var(--muted);margin:16px 0 0}
    @media (max-width:420px){main{width:calc(100% - 12px);margin:12px auto}.window-body{padding:12px}}
  </style>
</head>
<body data-theme="${theme}"><main>${body}</main></body></html>`, { status, headers: responseHeaders });
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

function questionForm(row: QuestionRecord, routeToken: string, error = ""): string {
  const remainingMinutes = Math.max(0, Math.ceil((row.expiresAt - Date.now()) / 60_000));
  const remaining = `${String(Math.floor(remainingMinutes / 60)).padStart(2, "0")}:${String(remainingMinutes % 60).padStart(2, "0")}`;
  const controls = row.fields.map((field) => {
    const name = `field_${field.id}`;
    if (field.type === "choice") {
      return `<fieldset><legend>${escapeHtml(field.label)}</legend>${field.options.map((option) => `<label class="choice"><input type="radio" name="${escapeHtml(name)}" value="${escapeHtml(option)}" required><span>${escapeHtml(option)}</span></label>`).join("")}</fieldset>`;
    }
    return `<div class="field"><label for="${escapeHtml(name)}">${escapeHtml(field.label)}</label><textarea id="${escapeHtml(name)}" name="${escapeHtml(name)}" maxlength="${MAX_ANSWER_LENGTH}" required></textarea></div>`;
  }).join("");
  return `<section class="card"><div class="titlebar"><span>LetMeKnow</span><span class="window-controls" aria-hidden="true">_ □ ×</span></div><div class="window-body"><h1>${escapeHtml(row.title)}</h1>${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ""}<form method="post" action="/q/${escapeHtml(routeToken)}">${controls}<div class="dialog-actions"><button type="submit">Submit answer</button></div></form><p class="muted">link expires in ${remaining}</p></div></section>`;
}

function messagePage(title: string, message: string, status = 200): Response {
  return html(title, `<section class="card"><div class="titlebar"><span>LetMeKnow</span><span class="window-controls" aria-hidden="true">_ □ ×</span></div><div class="window-body"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></div></section>`, status);
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
    return html(row.title, questionForm(row, routeToken));
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
      if (value === null) return html(row.title, questionForm(row, routeToken, "Please answer every field."), 400);
      const answer = value.trim();
      if (!answer || answer.length > MAX_ANSWER_LENGTH || (field.type === "choice" && !field.options.includes(answer))) {
        return html(row.title, questionForm(row, routeToken, "Please provide a valid answer for every field."), 400);
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
