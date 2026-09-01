import { DurableObject } from "cloudflare:workers";
import clientSource from "./runtime.client.js";

interface Env {
  SESSIONS: DurableObjectNamespace<Session>;
  CREATE_RATE_LIMIT: RateLimitBinding;
  UPLOADS: R2Bucket;
}

interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

type Packet = Record<string, unknown>;
type ManifestEntry = { hash: string; size: number; content_type: string };
type Manifest = { files: Record<string, ManifestEntry> };
type AttachmentDescriptor = { field: string; name: string; content_type: string; size: number; hash: string };
type SubmitEvent = {
  type: "submit";
  id: string;
  event_number: number;
  page_event: number;
  form_id: string | null;
  action: string;
  trigger: Record<string, unknown> | null;
  values: Record<string, unknown>;
  attachments?: AttachmentDescriptor[];
};
type RunUIEvent = {
  type: "run_ui";
  event_number: number;
  considered_through: number;
  frontier: number;
  page_event: number;
  page_hash: string;
  script: string;
};
type CanonicalEvent = SubmitEvent | RunUIEvent;
type StoredEvent = { event: CanonicalEvent; received: boolean; sent: boolean; bytes: number };
type BlobRecord = { size: number; stored: boolean; kind: "workspace" | "browser" | "shared"; expires_at?: number };
type SubmissionRecord = { event_number: number; hash: string };
type ProducerAttachment = { role: "producer"; id: string; url: string; opened: boolean; closing: boolean };
type ClientAttachment = { role: "client" };
type Attachment = ProducerAttachment | ClientAttachment;
type AppendTarget = { append(content: string | ReadableStream<Uint8Array>, options?: { html?: boolean }): unknown };

const CODE_LENGTH = 20;
const PRODUCER_GRACE_MS = 10 * 60 * 1_000;
const OPEN_DEADLINE_MS = 30 * 1_000;
const SESSION_LIFETIME_MS = 24 * 60 * 60 * 1_000;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_SESSION_BLOB_BYTES = 100 * 1024 * 1024;
const MAX_QUEUED_EVENTS = 256;
const MAX_QUEUED_BYTES = 32 * 1024 * 1024;
const MAX_SESSION_SUBMISSIONS = 100_000;
const MAX_HISTORY_BYTES = MAX_BODY_BYTES;
const MAX_PACKET_BYTES = 6 * MAX_BODY_BYTES + 4096;
const MAX_MANIFEST_BYTES = 512 * 1024;
const MAX_ATTACHMENTS = 32;
const MAX_BROWSER_BLOB_RECORDS = 1024;
const ATTACHMENT_RESERVATION_LEASE_MS = 30 * 60 * 1_000;
const ATTACHMENT_RECLAIM_RETRY_MS = 60 * 1_000;
const MAX_ATTACHMENT_FIELD_BYTES = 256;
const MAX_ATTACHMENT_NAME_BYTES = 512;
const MAX_ATTACHMENT_CONTENT_TYPE_BYTES = 200;
const runtimePath = "/_letmeknow/client.js";
const clientSocketPath = "/_letmeknow/client";
const encoder = new TextEncoder();
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const hashPattern = /^[0-9a-f]{64}$/;
const privateNames = new Set([".env", ".git", ".ssh", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]);
const privateFilePattern = /^\.env\.|\.(?:key|pem|p12|ppk|p8|sqlite|sqlite3|db|db3)$|-(?:wal|shm|journal)$/i;

function error(message: string, status: number): Response {
  return Response.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
}

function token(length = CODE_LENGTH): string {
  let value = "";
  while (value.length < length) value += crypto.randomUUID().replaceAll("-", "");
  return value.slice(0, length);
}

function normalizedHostname(hostname: string): string {
  return hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
}

function isProductionHost(hostname: string): boolean {
  hostname = normalizedHostname(hostname);
  return hostname === "letmeknow.dev" || hostname.endsWith(".letmeknow.dev");
}

function publicTarget(url: URL): { code: string; path: string } | null {
  const hostname = normalizedHostname(url.hostname);
  const match = hostname.match(new RegExp(`^([a-f0-9]{${CODE_LENGTH}})\\.letmeknow\\.dev$`));
  return match ? { code: match[1], path: url.pathname } : null;
}

function sessionUrl(code: string): string {
  return `https://${code}.letmeknow.dev/`;
}

function runtimeTag(): string {
  return `<script type="module" src="${runtimePath}" data-letmeknow-runtime></script>`;
}

function runtimePage(title: string, message: string, status: number): Response {
  const kind = status === 503 ? "disconnected" : "missing";
  const body = `<!doctype html><html data-letmeknow-status-page="${kind}"><head><meta charset="utf-8"><title>${title}</title></head><body><h1>${title}</h1><p>${message}</p></body></html>`;
  return new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

function isDocumentRequest(request: Request): boolean {
  if (request.method !== "GET") return false;
  const destination = request.headers.get("sec-fetch-dest");
  if (destination !== null) return destination === "document";
  const accept = request.headers.get("accept");
  return accept === null || accept.toLowerCase().includes("text/html");
}

function historyStream(readEvent: (number: number) => Promise<StoredEvent | undefined>, frontier: number): ReadableStream<Uint8Array> {
  let number = 1;
  let first = true;
  let started = false;
  let finished = false;
  return new ReadableStream({
    async pull(controller) {
      if (finished) return;
      try {
        if (!started) {
          started = true;
          controller.enqueue(encoder.encode("["));
        }
        while (number <= frontier) {
          const stored = await readEvent(number++);
          if (stored?.event.type !== "run_ui") continue;
          const value = escapedEvent(stored.event);
          controller.enqueue(encoder.encode(`${first ? "" : ","}${value}`));
          first = false;
          return;
        }
        finished = true;
        controller.enqueue(encoder.encode("]"));
        controller.close();
      } catch (cause) {
        finished = true;
        controller.error(cause);
      }
    }
  });
}

function injectPage(response: Response, request: Request, readEvent: (number: number) => Promise<StoredEvent | undefined>, frontier: number): Response {
  const contentType = response.headers.get("content-type") || "";
  const document = request.method !== "HEAD" && isDocumentRequest(request) && response.status !== 204 && response.status !== 205 && response.status !== 304 && contentType.toLowerCase().startsWith("text/html");
  if (!document) return response;
  const headers = new Headers(response.headers);
  headers.delete("content-length");
  const rewriter = new HTMLRewriter();
  const history = historyStream(readEvent, frontier);
  let hasBody = false;
  const append = (target: AppendTarget) => {
    target.append('<script type="application/json" data-letmeknow-history>', { html: true });
    target.append(history, { html: true });
    target.append("</script>", { html: true });
    target.append(runtimeTag(), { html: true });
  };
  rewriter.on("body", { element(element) { hasBody = true; append(element); } });
  rewriter.onDocument({ end(documentEnd) { if (!hasBody) append(documentEnd); } });
  return rewriter.transform(new Response(response.body, { status: response.status, statusText: response.statusText, headers }));
}

async function sha256(value: Uint8Array | string): Promise<string> {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

function escapedEvent(event: RunUIEvent): string {
  return JSON.stringify(event).replace(/<\/script/gi, match => "\\u003c" + match.slice(1));
}

function historyBytes(event: RunUIEvent): number {
  return encoder.encode(escapedEvent(event)).byteLength;
}

async function initialPageHash(indexHash: string): Promise<string> {
  return sha256(JSON.stringify({ base_index_hash: indexHash, history: [] }));
}

async function chainedPageHash(previous: string, eventNumber: number, script: string): Promise<string> {
  return sha256(JSON.stringify({ previous, event_number: eventNumber, script }));
}

function safePublicPath(value: unknown): value is string {
  if (typeof value !== "string" || value === "" || value.startsWith("/") || value.includes("\\") || value.includes("\0")) return false;
  const parts = value.split("/");
  return parts.every(part => part !== "" && part !== "." && part !== ".." && !privateNames.has(part) && !privateFilePattern.test(part));
}

function attachmentDescriptors(value: unknown): AttachmentDescriptor[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > MAX_ATTACHMENTS) throw new Error("invalid attachments");
  return value.map(raw => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("invalid attachment");
    const input = raw as Record<string, unknown>;
    const field = input.field;
    const name = input.name;
    const contentType = input.content_type;
    const size = input.size;
    const hash = input.hash;
    if (typeof field !== "string" || field.length === 0 || encoder.encode(field).byteLength > MAX_ATTACHMENT_FIELD_BYTES || field.includes("\0")) throw new Error("invalid attachment field");
    if (typeof name !== "string" || name.length === 0 || encoder.encode(name).byteLength > MAX_ATTACHMENT_NAME_BYTES || name.includes("\0")) throw new Error("invalid attachment name");
    if (typeof contentType !== "string" || contentType.length === 0 || encoder.encode(contentType).byteLength > MAX_ATTACHMENT_CONTENT_TYPE_BYTES || contentType.includes("\0")) throw new Error("invalid attachment content type");
    if (!Number.isSafeInteger(size) || (size as number) < 0) throw new Error("invalid attachment size");
    if (typeof hash !== "string" || !hashPattern.test(hash)) throw new Error("invalid attachment hash");
    return { field, name, content_type: contentType, size: size as number, hash };
  });
}

function objectManifest(value: unknown): Manifest {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("manifest is required");
  const files = (value as Record<string, unknown>).files;
  if (!files || typeof files !== "object" || Array.isArray(files)) throw new Error("manifest files are required");
  if (encoder.encode(JSON.stringify(value)).byteLength > MAX_MANIFEST_BYTES) throw new Error("manifest is too large");
  const output: Record<string, ManifestEntry> = Object.create(null);
  for (const [path, raw] of Object.entries(files)) {
    if (!safePublicPath(path) || path === "index.html") throw new Error("invalid workspace path");
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("invalid workspace file");
    const entry = raw as Record<string, unknown>;
    if (typeof entry.hash !== "string" || !hashPattern.test(entry.hash)) throw new Error("invalid workspace hash");
    const size = entry.size;
    if (!Number.isSafeInteger(size) || (size as number) < 0) throw new Error("invalid workspace file size");
    if (typeof entry.content_type !== "string" || entry.content_type === "" || entry.content_type.length > 200) throw new Error("invalid workspace content type");
    output[path] = { hash: entry.hash, size: size as number, content_type: entry.content_type as string };
  }
  return { files: output };
}

function pathFromRequest(request: Request): string {
  const url = new URL(request.url);
  let pathname: string;
  try { pathname = decodeURIComponent(url.pathname); } catch { throw new Error("bad request"); }
  if (pathname.includes("\0") || pathname.includes("\\")) throw new Error("bad request");
  return pathname;
}

export class Session extends DurableObject<Env> {
  private stateMutation: Promise<void> = Promise.resolve();
  private activeBrowserUploads = new Map<string, number>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const route = request.headers.get("x-letmeknow-route");
    if (route === "producer") return this.mutate(() => this.acceptProducer(request));
    if (route === "workspace") return this.uploadWorkspace(request);
    if (route === "client") return this.mutate(() => this.acceptClient(request));
    if (route === "browser") return this.browserRequest(request);
    return error("not found", 404);
  }

  private async mutate<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.stateMutation;
    let release!: () => void;
    this.stateMutation = new Promise(resolve => { release = resolve; });
    await previous;
    try { return await operation(); } finally { release(); }
  }

  private producer(): WebSocket | undefined {
    return this.ctx.getWebSockets().find(socket => (socket.deserializeAttachment() as Attachment).role === "producer");
  }

  private clients(): WebSocket[] {
    return this.ctx.getWebSockets().filter(socket => (socket.deserializeAttachment() as Attachment).role === "client");
  }

  private async sessionCode(): Promise<string> {
    const code = await this.ctx.storage.get<string>("session_code");
    if (!code) throw new Error("session is not initialized");
    return code;
  }

  private async objectKey(hash: string): Promise<string> {
    return `sessions/${await this.sessionCode()}/objects/${hash}`;
  }

  private async sessionExpired(): Promise<boolean> {
    const expiresAt = await this.ctx.storage.get<number>("expires_at");
    return typeof expiresAt !== "number" || !Number.isSafeInteger(expiresAt) || expiresAt <= Date.now();
  }

  private async event(number: number): Promise<StoredEvent | undefined> {
    return this.ctx.storage.get<StoredEvent>(`event:${number}`);
  }

  private async eventFrontier(): Promise<number> {
    return (await this.ctx.storage.get<number>("next_event_number") ?? 1) - 1;
  }

  private async queuedStats(): Promise<{ count: number; bytes: number }> {
    return {
      count: await this.ctx.storage.get<number>("queued_event_count") ?? 0,
      bytes: await this.ctx.storage.get<number>("queued_event_bytes") ?? 0
    };
  }

  private async pageResponse(request: Request): Promise<Response> {
    const hash = await this.ctx.storage.get<string>("base_index_hash");
    if (!hash) throw new Error("session is not open");
    const object = await this.env.UPLOADS.get(await this.objectKey(hash));
    if (!object) throw new Error("index.html is missing");
    return new Response(request.method === "HEAD" ? null : object.body, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8", "Content-Length": String(object.size), "Cache-Control": "no-store" }
    });
  }

  private async validateObject(hash: string, size: number): Promise<void> {
    const object = await this.env.UPLOADS.head(await this.objectKey(hash));
    if (!object || object.size !== size) throw new Error("workspace object is missing or has the wrong size");
  }

  private async validateManifest(manifest: Manifest): Promise<void> {
    for (const entry of Object.values(manifest.files)) await this.validateObject(entry.hash, entry.size);
  }

  private async stagingHashes(): Promise<Set<string>> {
    const hashes = await this.ctx.storage.get<string[]>("staging_hashes") ?? [];
    return new Set(hashes);
  }

  private async blobRecords(): Promise<Record<string, BlobRecord>> {
    return await this.ctx.storage.get<Record<string, BlobRecord>>("blob_records") ?? {};
  }

  private async stageWorkspaceObjects(items: Array<{ hash: string; size: number }>): Promise<void> {
    const records = await this.blobRecords();
    const next = { ...records };
    let reserved = await this.ctx.storage.get<number>("reserved_blob_bytes") ?? 0;
    const current = new Set<string>();
    const base = await this.ctx.storage.get<string>("base_index_hash");
    if (base) current.add(base);
    const manifest = await this.ctx.storage.get<Manifest>("current_manifest");
    for (const entry of Object.values(manifest?.files || {})) current.add(entry.hash);
    const previous = await this.stagingHashes();
    const requested = new Map<string, number>();
    for (const item of items) {
      const prior = requested.get(item.hash);
      if (prior !== undefined && prior !== item.size) throw new Error("workspace object has the wrong size");
      requested.set(item.hash, item.size);
    }
    const remove: string[] = [];
    for (const hash of previous) {
      if (current.has(hash) || requested.has(hash)) continue;
      const record = next[hash];
      if (!record || record.kind !== "workspace") continue;
      remove.push(hash);
      reserved -= record.size;
      delete next[hash];
    }
    for (const [hash, size] of requested) {
      const existing = next[hash];
      if (existing) {
        if (existing.kind === "browser") next[hash] = { ...existing, kind: "shared" };
        else if (existing.kind !== "workspace" && existing.kind !== "shared") throw new Error("workspace hash is not a workspace object");
        if (existing.size !== size) throw new Error("workspace object has the wrong size");
        continue;
      }
      if (reserved + size > MAX_SESSION_BLOB_BYTES) throw new Error("session blob quota exceeded");
      next[hash] = { size, stored: false, kind: "workspace" };
      reserved += size;
    }
    if (remove.length) await this.env.UPLOADS.delete(await Promise.all(remove.map(hash => this.objectKey(hash))));
    await this.ctx.storage.transaction(async transaction => {
      await transaction.put("blob_records", next);
      await transaction.put("reserved_blob_bytes", Math.max(0, reserved));
      await transaction.put("staging_hashes", [...requested.keys()]);
    });
  }

  private async markWorkspaceObjectStored(hash: string, size: number): Promise<void> {
    const records = await this.blobRecords();
    const record = records[hash];
    if (!record || (record.kind !== "workspace" && record.kind !== "shared") || record.size !== size) throw new Error("workspace blob was not reserved");
    if (!record.stored) {
      records[hash] = { ...record, stored: true };
      await this.ctx.storage.put("blob_records", records);
    }
  }

  private async prepareBrowserUpload(hash: string): Promise<{ size: number; stored: boolean }> {
    return this.mutate(async () => {
      if (!(await this.ctx.storage.get<boolean>("opened"))) throw new Error("session not found");
      if (await this.sessionExpired()) { await this.expireSession(); throw new Error("session expired"); }
      await this.reclaimExpiredBrowserObjects();
      const records = await this.blobRecords();
      const record = records[hash];
      if (!record || (record.kind !== "browser" && record.kind !== "shared")) throw new Error("attachment was not reserved");
      const object = await this.env.UPLOADS.head(await this.objectKey(hash));
      if (object?.size === record.size) {
        if (!record.stored || record.expires_at !== undefined) {
          records[hash] = { ...record, stored: true, ...(record.expires_at === undefined ? {} : { expires_at: Date.now() + ATTACHMENT_RESERVATION_LEASE_MS }) };
          await this.ctx.storage.put("blob_records", records);
        }
        await this.scheduleAlarm();
        return { size: record.size, stored: true };
      }
      records[hash] = { ...record, stored: false, expires_at: Date.now() + ATTACHMENT_RESERVATION_LEASE_MS };
      await this.ctx.storage.put("blob_records", records);
      await this.scheduleAlarm();
      return { size: record.size, stored: false };
    });
  }

  private async markBrowserObjectStored(hash: string, size: number): Promise<void> {
    const records = await this.blobRecords();
    const record = records[hash];
    if (!record || (record.kind !== "browser" && record.kind !== "shared") || record.size !== size) throw new Error("attachment reservation changed");
    records[hash] = { ...record, stored: true, expires_at: Date.now() + ATTACHMENT_RESERVATION_LEASE_MS };
    await this.ctx.storage.put("blob_records", records);
    await this.scheduleAlarm();
  }

  private async referencedBrowserObjects(): Promise<Set<string>> {
    const referenced = new Set<string>();
    const events = await this.ctx.storage.list<StoredEvent>({ prefix: "event:" });
    for (const stored of events.values()) {
      if (stored.event.type !== "submit") continue;
      for (const attachment of stored.event.attachments || []) referenced.add(attachment.hash);
    }
    return referenced;
  }

  private async reclaimExpiredBrowserObjects(): Promise<void> {
    const records = await this.blobRecords();
    const referenced = await this.referencedBrowserObjects();
    const workspaceReferences = new Set<string>();
    const base = await this.ctx.storage.get<string>("base_index_hash");
    if (base) workspaceReferences.add(base);
    const manifest = await this.ctx.storage.get<Manifest>("current_manifest");
    for (const entry of Object.values(manifest?.files || {})) workspaceReferences.add(entry.hash);
    for (const hash of await this.stagingHashes()) workspaceReferences.add(hash);
    const now = Date.now();
    const expired = Object.entries(records).filter(([hash, record]) => {
      if ((this.activeBrowserUploads.get(hash) ?? 0) > 0 || (record.kind !== "browser" && record.kind !== "shared") || referenced.has(hash)) return false;
      return record.expires_at === undefined || record.expires_at <= now;
    });
    if (!expired.length) return;
    const next = { ...records };
    let reserved = await this.ctx.storage.get<number>("reserved_blob_bytes") ?? 0;
    const remove: Array<[string, BlobRecord]> = [];
    for (const [hash, record] of expired) {
      if (record.kind === "shared" && workspaceReferences.has(hash)) {
        next[hash] = { ...record, kind: "workspace" };
        delete next[hash].expires_at;
      } else {
        remove.push([hash, record]);
      }
    }
    if (remove.length) {
      const retryAt = Date.now() + ATTACHMENT_RECLAIM_RETRY_MS;
      await this.ctx.storage.put("cleanup_retry_at", retryAt);
      try {
        await this.env.UPLOADS.delete(await Promise.all(remove.map(([hash]) => this.objectKey(hash))));
        for (const [hash, record] of remove) {
          delete next[hash];
          reserved -= record.size;
        }
      } catch {
        for (const [hash, record] of remove) next[hash] = { ...record, expires_at: retryAt };
      }
    }
    try {
      await this.ctx.storage.transaction(async transaction => {
        await transaction.put("blob_records", next);
        await transaction.put("reserved_blob_bytes", Math.max(0, reserved));
      });
    } catch (cause) {
      await this.scheduleAlarm().catch(() => {});
      throw cause;
    }
    await this.scheduleAlarm().catch(() => {});
  }

  private async scheduleAlarm(): Promise<void> {
    const now = Date.now();
    const times: number[] = [];
    for (const key of ["open_deadline_at", "expires_at", "producer_grace_at"]) {
      const value = await this.ctx.storage.get<number>(key);
      if (typeof value === "number" && Number.isSafeInteger(value)) times.push(value);
    }
    const cleanupRetryAt = await this.ctx.storage.get<number>("cleanup_retry_at");
    const scheduledCleanupRetryAt = typeof cleanupRetryAt === "number" && Number.isSafeInteger(cleanupRetryAt)
      ? Math.max(cleanupRetryAt, now + ATTACHMENT_RECLAIM_RETRY_MS)
      : undefined;
    if (scheduledCleanupRetryAt !== undefined) times.push(scheduledCleanupRetryAt);
    const records = await this.blobRecords();
    for (const [hash, record] of Object.entries(records)) {
      if ((this.activeBrowserUploads.get(hash) ?? 0) > 0) continue;
      if (typeof record.expires_at !== "number" || !Number.isSafeInteger(record.expires_at)) continue;
      times.push(record.expires_at <= now && scheduledCleanupRetryAt !== undefined ? scheduledCleanupRetryAt : record.expires_at);
    }
    if (times.length) await this.ctx.storage.setAlarm(Math.min(...times));
  }

  private async reserveBrowserObjects(items: Array<{ hash: string; size: number }>): Promise<Array<{ hash: string; size: number }>> {
    await this.reclaimExpiredBrowserObjects();
    const records = await this.blobRecords();
    const next = { ...records };
    let reserved = await this.ctx.storage.get<number>("reserved_blob_bytes") ?? 0;
    let browserRecords = Object.values(next).filter(record => record.kind === "browser" || record.kind === "shared").length;
    const requested = new Map<string, number>();
    for (const item of items) {
      const prior = requested.get(item.hash);
      if (prior !== undefined && prior !== item.size) throw new Error("attachment hash has conflicting sizes");
      requested.set(item.hash, item.size);
    }
    for (const [hash, size] of requested) {
      const existing = next[hash];
      if (existing) {
        if (existing.kind === "workspace") {
          if (browserRecords >= MAX_BROWSER_BLOB_RECORDS) throw new Error("attachment object limit exceeded");
          next[hash] = { ...existing, kind: "shared", expires_at: Date.now() + ATTACHMENT_RESERVATION_LEASE_MS };
          browserRecords += 1;
        } else if (existing.kind !== "browser" && existing.kind !== "shared") throw new Error("attachment hash is not a browser object");
        if (existing.size !== size) throw new Error("attachment hash has the wrong size");
        continue;
      }
      if (browserRecords >= MAX_BROWSER_BLOB_RECORDS) throw new Error("attachment object limit exceeded");
      if (reserved + size > MAX_SESSION_BLOB_BYTES) throw new Error("session blob quota exceeded");
      next[hash] = { size, stored: false, kind: "browser", expires_at: Date.now() + ATTACHMENT_RESERVATION_LEASE_MS };
      reserved += size;
      browserRecords += 1;
    }
    const missing: Array<{ hash: string; size: number }> = [];
    for (const [hash, size] of requested) {
      const record = next[hash]!;
      const object = await this.env.UPLOADS.head(await this.objectKey(hash));
      if (object?.size === size) {
        if (!record.stored || record.expires_at !== undefined) next[hash] = { ...record, stored: true, expires_at: Date.now() + ATTACHMENT_RESERVATION_LEASE_MS };
      } else {
        next[hash] = { ...record, stored: false, expires_at: Date.now() + ATTACHMENT_RESERVATION_LEASE_MS };
        missing.push({ hash, size });
      }
    }
    await this.ctx.storage.transaction(async transaction => {
      await transaction.put("blob_records", next);
      await transaction.put("reserved_blob_bytes", reserved);
    });
    await this.scheduleAlarm();
    return missing;
  }

  private async validateBrowserAttachments(attachments: AttachmentDescriptor[]): Promise<Record<string, BlobRecord>> {
    const records = await this.blobRecords();
    for (const attachment of attachments) {
      const record = records[attachment.hash];
      if (!record || (record.kind !== "browser" && record.kind !== "shared") || !record.stored || record.size !== attachment.size) throw new Error("attachment is missing or has the wrong size");
    }
    return records;
  }

  private async cleanupObjects(keep: Set<string>): Promise<void> {
    const records = await this.blobRecords();
    const referenced = await this.referencedBrowserObjects();
    let reserved = await this.ctx.storage.get<number>("reserved_blob_bytes") ?? 0;
    const remove: string[] = [];
    let changed = false;
    for (const [hash, record] of Object.entries(records)) {
      if (keep.has(hash) || record.kind === "browser") continue;
      if (record.kind === "shared") {
        if (referenced.has(hash) || record.expires_at !== undefined) {
          records[hash] = { ...record, kind: "browser" };
          changed = true;
        } else {
          remove.push(hash);
          reserved -= record.size;
          delete records[hash];
        }
        continue;
      }
      if (record.kind !== "workspace") continue;
      remove.push(hash);
      reserved -= record.size;
      delete records[hash];
    }
    if (!remove.length && !changed) return;
    await this.ctx.storage.put("cleanup_retry_at", Date.now() + ATTACHMENT_RECLAIM_RETRY_MS);
    try {
      if (remove.length) await this.env.UPLOADS.delete(await Promise.all(remove.map(hash => this.objectKey(hash))));
      await this.ctx.storage.transaction(async transaction => {
        await transaction.put("blob_records", records);
        await transaction.put("reserved_blob_bytes", Math.max(0, reserved));
      });
    } catch (cause) {
      await this.scheduleAlarm().catch(() => {});
      throw cause;
    }
  }

  private async deleteUnreferencedObjects(manifest: Manifest, clearStaging = true): Promise<void> {
    const staging = await this.stagingHashes();
    const keep = new Set<string>([await this.ctx.storage.get<string>("base_index_hash") || "", ...Object.values(manifest.files).map(entry => entry.hash), ...staging]);
    await this.reclaimExpiredBrowserObjects();
    await this.cleanupObjects(keep);
    if (clearStaging) await this.ctx.storage.delete("staging_hashes");
    await this.ctx.storage.delete("cleanup_retry_at");
    await this.scheduleAlarm().catch(() => {});
  }

  private async deleteSessionObjects(): Promise<void> {
    let cursor: string | undefined;
    const prefix = `sessions/${await this.sessionCode()}/`;
    do {
      const listed = await this.env.UPLOADS.list({ prefix, ...(cursor ? { cursor } : {}) });
      if (listed.objects.length) await this.env.UPLOADS.delete(listed.objects.map(object => object.key));
      cursor = listed.truncated ? listed.cursor : undefined;
    } while (cursor);
  }

  private async expireSession(): Promise<void> {
    if (!(await this.ctx.storage.get<string>("session_code"))) return;
    for (const client of this.clients()) client.close(1000, "session expired");
    this.producer()?.close(1000, "session expired");
    await this.deleteSessionObjects();
    await this.ctx.storage.deleteAll();
  }

  private async sendNext(): Promise<void> {
    const socket = this.producer();
    if (!socket) return;
    const received = await this.ctx.storage.get<number>("producer_received") ?? 0;
    const frontier = await this.eventFrontier();
    if (received >= frontier) return;
    const number = received + 1;
    const stored = await this.event(number);
    if (!stored || stored.received || stored.sent) return;
    try {
      socket.send(JSON.stringify(stored.event));
      stored.sent = true;
      await this.ctx.storage.put(`event:${number}`, stored);
    } catch {
      stored.sent = false;
      await this.ctx.storage.put(`event:${number}`, stored);
    }
  }

  private async resetDelivery(): Promise<void> {
    const received = await this.ctx.storage.get<number>("producer_received") ?? 0;
    const frontier = await this.eventFrontier();
    if (received >= frontier) return;
    const stored = await this.event(received + 1);
    if (stored) { stored.sent = false; await this.ctx.storage.put(`event:${received + 1}`, stored); }
  }

  private async acceptProducer(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return error("websocket upgrade required", 426);
    const credential = request.headers.get("x-letmeknow-credential");
    const protocol = request.headers.get("sec-websocket-protocol");
    const storedCredential = await this.ctx.storage.get<string>("credential");
    const opened = await this.ctx.storage.get<boolean>("opened") ?? false;
    const reconnectRequested = request.headers.get("x-letmeknow-reconnect") === "true";
    const reconnect = storedCredential !== undefined;
    if (opened && await this.sessionExpired()) { await this.expireSession(); return error("session expired", 404); }
    if (reconnectRequested) {
      if (!reconnect || credential !== storedCredential || protocol !== credential) return error("invalid producer credential", 401);
    } else {
      if (reconnect || !credential || protocol !== null) return error("producer credential is required", 401);
      await this.ctx.storage.put("credential", credential);
      const code = request.headers.get("x-letmeknow-code");
      if (!code) throw new Error("session code is required");
      await this.ctx.storage.put("session_code", code);
      await this.ctx.storage.put("session_url", request.headers.get("x-letmeknow-url"));
      await this.ctx.storage.put("open_deadline_at", Date.now() + OPEN_DEADLINE_MS);
      await this.ctx.storage.put("staging_hashes", []);
      await this.ctx.storage.put("blob_records", {});
      await this.ctx.storage.put("reserved_blob_bytes", 0);
    }
    if (this.producer()) return error("a producer is already connected", 409);
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const url = request.headers.get("x-letmeknow-url") || await this.ctx.storage.get<string>("session_url");
    if (!url) throw new Error("session URL is required");
    const attachment: ProducerAttachment = { role: "producer", id: crypto.randomUUID(), url, opened: reconnect && opened, closing: false };
    server.serializeAttachment(attachment);
    this.ctx.acceptWebSocket(server);
    const expiresAt = reconnect && opened ? await this.ctx.storage.get<number>("expires_at") : undefined;
    if (!reconnect) {
      await this.scheduleAlarm();
      server.send(JSON.stringify({ type: "credential", credential }));
      server.send(JSON.stringify({ type: "provisioned", url }));
    } else {
      await this.scheduleAlarm();
    }
    if (reconnect && opened) {
      if (expiresAt === undefined) throw new Error("session expired");
      await this.ctx.storage.delete("producer_grace_at");
      await this.resetDelivery();
      await this.scheduleAlarm();
      server.send(JSON.stringify({ type: "session", url, frontier: await this.eventFrontier(), page_event: await this.ctx.storage.get<number>("page_event") ?? 0, page_hash: await this.ctx.storage.get<string>("page_hash") }));
      this.sendClients({ type: "producer", connected: true });
      await this.sendNext();
    }
    return new Response(null, { status: 101, webSocket: client, ...(protocol ? { headers: { "Sec-WebSocket-Protocol": protocol } } : {}) });
  }

  private async acceptClient(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return error("websocket upgrade required", 426);
    if (!(await this.ctx.storage.get<boolean>("opened"))) return error("session not found", 404);
    if (await this.sessionExpired()) { await this.expireSession(); return error("session expired", 404); }
    if (request.headers.get("Sec-WebSocket-Protocol")) return error("client credentials are not supported", 400);
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.serializeAttachment({ role: "client" } satisfies ClientAttachment);
    this.ctx.acceptWebSocket(server);
    server.send(JSON.stringify({ type: "connected", producer_connected: Boolean(this.producer()) }));
    return new Response(null, { status: 101, webSocket: client });
  }

  private async uploadWorkspace(request: Request): Promise<Response> {
    if (request.method !== "PUT") return error("method not allowed", 405);
    const path = pathFromRequest(request);
    const match = path.match(/^\/_letmeknow\/workspace\/([0-9a-f]{64})$/);
    if (!match) return error("not found", 404);
    const credential = request.headers.get("authorization")?.match(/^Bearer (.+)$/)?.[1];
    if (!credential || credential !== await this.ctx.storage.get<string>("credential") || !this.producer()) return error("unauthorized", 401);
    if ((await this.ctx.storage.get<boolean>("opened")) && await this.sessionExpired()) { await this.mutate(() => this.expireSession()); return error("session expired", 404); }
    const hash = match[1];
    const records = await this.blobRecords();
    const record = records[hash];
    if (!record || (record.kind !== "workspace" && record.kind !== "shared")) return error("workspace object was not reserved", 409);
    const key = await this.objectKey(hash);
    const existing = await this.env.UPLOADS.head(key);
    if (record.stored && existing?.size === record.size) return new Response(null, { status: 204 });
    const reader = request.body?.getReader();
    const fixed = new FixedLengthStream(record.size);
    const writer = fixed.writable.getWriter();
    let count = 0;
    const pump = async () => {
      try {
        while (reader) {
          const part = await reader.read();
          if (part.done) break;
          count += part.value.byteLength;
          if (count > record.size) throw new Error("workspace object size is invalid");
          await writer.write(part.value);
        }
        if (count !== record.size) throw new Error("workspace object size is invalid");
        await writer.close();
      } catch (cause) {
        await writer.abort(cause);
        throw cause;
      }
    };
    try {
      await Promise.all([this.env.UPLOADS.put(key, fixed.readable, { sha256: hash }), pump()]);
      await this.mutate(() => this.markWorkspaceObjectStored(hash, record.size));
      return new Response(null, { status: 204 });
    } catch {
      if (!(await this.ctx.storage.get<string>("session_code"))) await this.env.UPLOADS.delete(key).catch(() => {});
      return error("could not store workspace object", 503);
    }
  }

  private async attachmentRequest(request: Request): Promise<Response> {
    let path: string;
    try { path = pathFromRequest(request); } catch { return error("bad request", 400); }
    if (path === "/_letmeknow/attachments") {
      if (request.method !== "POST") return error("method not allowed", 405);
      let body: Uint8Array;
      try { body = await this.readBody(request); } catch { return error("attachments are too large", 413); }
      if ((request.headers.get("content-type") || "").split(";", 1)[0].trim().toLowerCase() !== "application/json") return error("JSON attachments are required", 400);
      let value: unknown;
      try { value = JSON.parse(new TextDecoder().decode(body)); } catch { return error("invalid attachments JSON", 400); }
      if (!value || typeof value !== "object" || Array.isArray(value) || !Array.isArray((value as Record<string, unknown>).hashes)) return error("attachment hashes are required", 400);
      const hashes = (value as Record<string, unknown>).hashes as unknown[];
      if (hashes.length > MAX_ATTACHMENTS) return error("too many attachments", 400);
      const items: Array<{ hash: string; size: number }> = [];
      try {
        for (const raw of hashes) {
          if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("invalid attachment hash");
          const item = raw as Record<string, unknown>;
          if (typeof item.hash !== "string" || !hashPattern.test(item.hash) || !Number.isSafeInteger(item.size) || (item.size as number) < 0) throw new Error("invalid attachment hash");
          items.push({ hash: item.hash, size: item.size as number });
        }
        const missing = await this.mutate(async () => {
          if (!(await this.ctx.storage.get<boolean>("opened"))) throw new Error("session not found");
          if (await this.sessionExpired()) { await this.expireSession(); throw new Error("session expired"); }
          return this.reserveBrowserObjects(items);
        });
        return Response.json({ missing }, { headers: { "Cache-Control": "no-store" } });
      } catch (cause) {
        const message = cause instanceof Error ? cause.message : "could not reserve attachments";
        const status = message === "session not found" || message === "session expired" ? 404
          : message === "session blob quota exceeded" || message === "attachment object limit exceeded" ? 413
          : message === "invalid attachment hash" || message.startsWith("attachment hash") ? 400 : 503;
        return error(message, status);
      }
    }
    const match = path.match(/^\/\_letmeknow\/attachments\/([0-9a-f]{64})$/);
    if (!match) return error("not found", 404);
    if (request.method === "GET") {
      const credential = request.headers.get("authorization")?.match(/^Bearer (.+)$/)?.[1];
      if (!credential || credential !== await this.ctx.storage.get<string>("credential") || !this.producer()) return error("unauthorized", 401);
      if (!(await this.ctx.storage.get<boolean>("opened"))) return error("session not found", 404);
      if (await this.sessionExpired()) { await this.mutate(() => this.expireSession()); return error("session expired", 404); }
      const record = (await this.blobRecords())[match[1]];
      if (!record || (record.kind !== "browser" && record.kind !== "shared") || !record.stored) return error("attachment not found", 404);
      const object = await this.env.UPLOADS.get(await this.objectKey(match[1]));
      if (!object) return error("attachment not found", 404);
      return new Response(object.body, { status: 200, headers: { "Content-Type": "application/octet-stream", "Content-Length": String(object.size), "Cache-Control": "no-store" } });
    }
    if (request.method !== "PUT") return error("method not allowed", 405);
    const hash = match[1];
    this.activeBrowserUploads.set(hash, (this.activeBrowserUploads.get(hash) ?? 0) + 1);
    try {
      let record: { size: number; stored: boolean };
      try {
        record = await this.prepareBrowserUpload(hash);
      } catch (cause) {
        const message = cause instanceof Error ? cause.message : "could not prepare attachment";
        const status = message === "session not found" || message === "session expired" ? 404 : message === "attachment was not reserved" ? 409 : 503;
        return error(message, status);
      }
      if (record.stored) return new Response(null, { status: 204 });
      const key = await this.objectKey(hash);
      const reader = request.body?.getReader();
      const fixed = new FixedLengthStream(record.size);
      const writer = fixed.writable.getWriter();
      let count = 0;
      let sizeError = false;
      const pump = async () => {
        try {
          while (reader) {
            const part = await reader.read();
            if (part.done) break;
            count += part.value.byteLength;
            if (count > record.size) {
              sizeError = true;
              throw new Error("attachment size is invalid");
            }
            await writer.write(part.value);
          }
          if (count !== record.size) {
            sizeError = true;
            throw new Error("attachment size is invalid");
          }
          await writer.close();
        } catch (cause) {
          await writer.abort(cause);
          throw cause;
        }
      };
      const pumpPromise = pump();
      try {
        await Promise.all([this.env.UPLOADS.put(key, fixed.readable, { sha256: hash }), pumpPromise]);
        await this.mutate(() => this.markBrowserObjectStored(hash, record.size));
        return new Response(null, { status: 204 });
      } catch (cause) {
        await pumpPromise.catch(() => {});
        if (!(await this.ctx.storage.get<string>("session_code"))) await this.env.UPLOADS.delete(key).catch(() => {});
        const checksumError = cause instanceof Error && cause.message.includes("checksum you specified did not match");
        const malformed = sizeError || checksumError;
        return error(malformed ? (sizeError ? "attachment size is invalid" : "attachment content is invalid") : "could not store attachment", malformed ? 400 : 503);
      }
    } finally {
      const count = this.activeBrowserUploads.get(hash) ?? 0;
      if (count > 1) this.activeBrowserUploads.set(hash, count - 1);
      else {
        this.activeBrowserUploads.delete(hash);
        await this.scheduleAlarm();
      }
    }
  }

  private async readBody(request: Request): Promise<Uint8Array> {
    const contentLength = request.headers.get("content-length");
    if (contentLength !== null && /^\d+$/.test(contentLength) && Number(contentLength) > MAX_BODY_BYTES) throw new Error("submission is too large");
    const chunks: Uint8Array[] = [];
    const reader = request.body?.getReader();
    let size = 0;
    while (reader) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new Error("submission is too large");
      }
      chunks.push(part.value);
    }
    const body = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
    return body;
  }

  private async acceptSubmission(request: Request): Promise<Response> {
    if (request.method !== "POST") return error("method not allowed", 405);
    if ((request.headers.get("content-type") || "").split(";", 1)[0].trim().toLowerCase() !== "application/json") return error("JSON submission is required", 400);
    let body: Uint8Array;
    try { body = await this.readBody(request); } catch (cause) { return error(cause instanceof Error && cause.message === "submission is too large" ? "submission is too large" : "invalid submission", cause instanceof Error && cause.message === "submission is too large" ? 413 : 400); }
    let value: unknown;
    try { value = JSON.parse(new TextDecoder().decode(body)); } catch { return error("invalid submission JSON", 400); }
    if (!value || typeof value !== "object" || Array.isArray(value)) return error("submission must be an object", 400);
    const input = value as Record<string, unknown>;
    if (typeof input.id !== "string" || !uuidPattern.test(input.id)) return error("submission id must be a UUID", 400);
    if (!Number.isSafeInteger(input.page_event) || (input.page_event as number) < 0) return error("page_event must be a non-negative integer", 400);
    if (input.form_id !== null && typeof input.form_id !== "string") return error("form_id must be text or null", 400);
    if (typeof input.action !== "string") return error("action is required", 400);
    if (input.trigger !== null && (!input.trigger || typeof input.trigger !== "object" || Array.isArray(input.trigger))) return error("trigger must be an object or null", 400);
    if (!input.values || typeof input.values !== "object" || Array.isArray(input.values)) return error("values are required", 400);
    let attachments: AttachmentDescriptor[] | undefined;
    try { attachments = attachmentDescriptors(input.attachments); }
    catch (cause) { return error(cause instanceof Error ? cause.message : "invalid attachments", 400); }
    const id = input.id as string;
    const hash = await sha256(body);
    return this.mutate(async () => {
      if (!(await this.ctx.storage.get<boolean>("opened"))) return error("session not found", 404);
      if (await this.sessionExpired()) { await this.expireSession(); return error("session expired", 404); }
      await this.reclaimExpiredBrowserObjects();
      const duplicate = await this.ctx.storage.get<SubmissionRecord>(`submission:${id}`);
      if (duplicate) return duplicate.hash === hash ? new Response(null, { status: 202 }) : error("submission id was already used", 409);
      let attachmentRecords: Record<string, BlobRecord> | undefined;
      try {
        if (attachments?.length) attachmentRecords = await this.validateBrowserAttachments(attachments);
      } catch (cause) { return error(cause instanceof Error ? cause.message : "invalid attachments", 400); }
      const stats = await this.queuedStats();
      if (stats.count >= MAX_QUEUED_EVENTS || stats.bytes + body.byteLength > MAX_QUEUED_BYTES) return error("submission queue is full", 503);
      const submissionCount = await this.ctx.storage.get<number>("submission_count") ?? 0;
      if (submissionCount >= MAX_SESSION_SUBMISSIONS) return error("session submission limit reached", 409);
      if (attachmentRecords && attachments) {
        attachmentRecords = { ...attachmentRecords };
        for (const attachment of attachments) {
          const record = attachmentRecords[attachment.hash];
          if (record) {
            attachmentRecords[attachment.hash] = { ...record };
            delete attachmentRecords[attachment.hash].expires_at;
          }
        }
      }
      const number = await this.eventFrontier() + 1;
      const event: SubmitEvent = { type: "submit", id, event_number: number, page_event: input.page_event as number, form_id: input.form_id as string | null, action: input.action as string, trigger: input.trigger as Record<string, unknown> | null, values: input.values as Record<string, unknown>, ...(attachments ? { attachments } : {}) };
      const stored: StoredEvent = { event, received: false, sent: false, bytes: body.byteLength };
      await this.ctx.storage.transaction(async transaction => {
        if (attachmentRecords) await transaction.put("blob_records", attachmentRecords);
        await transaction.put(`submission:${id}`, { event_number: number, hash });
        await transaction.put(`event:${number}`, stored);
        await transaction.put("next_event_number", number + 1);
        await transaction.put("submission_count", submissionCount + 1);
        await transaction.put("queued_event_count", stats.count + 1);
        await transaction.put("queued_event_bytes", stats.bytes + body.byteLength);
      });
      await this.sendNext();
      return new Response(null, { status: 202, headers: { "Cache-Control": "no-store" } });
    });
  }

  private async browserRequest(request: Request): Promise<Response> {
    let path: string;
    try { path = pathFromRequest(request); } catch { return error("bad request", 400); }
    if (path === "/_letmeknow/submit") return this.acceptSubmission(request);
    if (path === "/_letmeknow/attachments" || path.startsWith("/_letmeknow/attachments/")) return this.attachmentRequest(request);
    if (!(await this.ctx.storage.get<boolean>("opened"))) return isDocumentRequest(request) ? runtimePage("Session not found", "This preview is no longer available.", 404) : error("session not found", 404);
    if (await this.sessionExpired()) { await this.mutate(() => this.expireSession()); return isDocumentRequest(request) ? runtimePage("Session not found", "This preview is no longer available.", 404) : error("session not found", 404); }
    if (request.method !== "GET" && request.method !== "HEAD") return error("method not allowed", 405);
    const frontier = await this.eventFrontier();
    let response: Response;
    if (path === "/" || path === "/index.html") {
      try { response = await this.pageResponse(request); }
      catch { response = error("preview request failed", 500); }
    } else {
      const assetPath = path.slice(1);
      if (!safePublicPath(assetPath)) return error("forbidden", 403);
      const manifest = await this.ctx.storage.get<Manifest>("current_manifest");
      const entry = manifest?.files[assetPath];
      if (!entry) response = error("not found", 404);
      else {
        const object = await this.env.UPLOADS.get(await this.objectKey(entry.hash));
        if (!object) response = error("not found", 404);
        else response = new Response(request.method === "HEAD" ? null : object.body, { status: 200, headers: { "Content-Type": entry.content_type, "Content-Length": String(object.size), "Cache-Control": "no-store" } });
      }
    }
    response = injectPage(response, request, number => this.event(number), frontier);
    if (request.method === "HEAD") return new Response(null, { status: response.status, statusText: response.statusText, headers: response.headers });
    return response;
  }

  async webSocketMessage(socket: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const attachment = socket.deserializeAttachment() as Attachment;
    if (attachment.role === "producer") return this.producerMessage(socket, attachment, message);
  }

  private async producerMessage(socket: WebSocket, attachment: ProducerAttachment, message: string | ArrayBuffer): Promise<void> {
    let packet: Packet | undefined;
    try {
      packet = this.parseMessage(message);
      await this.mutate(() => this.producerCommand(socket, attachment, packet!));
    } catch (cause) {
      const text = cause instanceof Error ? cause.message : "invalid packet";
      try { socket.send(JSON.stringify({ type: "error", ...(typeof packet?.id === "string" ? { id: packet.id } : {}), message: text })); } catch {}
    }
  }

  private parseMessage(message: string | ArrayBuffer): Packet {
    if (typeof message !== "string") throw new Error("packets must be text");
    if (encoder.encode(message).byteLength > MAX_PACKET_BYTES) throw new Error("packet is too large");
    let value: unknown;
    try { value = JSON.parse(message); } catch { throw new Error("invalid JSON"); }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("packet must be a JSON object");
    return value as Packet;
  }

  private async workspaceHashes(packet: Packet): Promise<Array<{ hash: string; size: number }>> {
    if (!Array.isArray(packet.hashes)) throw new Error("workspace hashes are required");
    const hashes: Array<{ hash: string; size: number }> = [];
    const seen = new Set<string>();
    for (const raw of packet.hashes) {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("invalid workspace hash");
      const value = raw as Record<string, unknown>;
      if (typeof value.hash !== "string" || !hashPattern.test(value.hash) || !Number.isSafeInteger(value.size) || (value.size as number) < 0) throw new Error("invalid workspace hash");
      if (seen.has(value.hash)) continue;
      seen.add(value.hash);
      hashes.push({ hash: value.hash, size: value.size as number });
    }
    return hashes;
  }

  private async producerCommand(socket: WebSocket, attachment: ProducerAttachment, packet: Packet): Promise<void> {
    const active = this.producer();
    if (!active || (active.deserializeAttachment() as ProducerAttachment).id !== attachment.id) return;
    if (attachment.opened && await this.sessionExpired()) { await this.expireSession(); return; }
    if (typeof packet.type !== "string") throw new Error("type is required");
    if (attachment.closing) throw new Error("session is closing");
    if (packet.type === "workspace_manifest") {
      const hashes = await this.workspaceHashes(packet);
      let index: { hash: string; size: number } | undefined;
      if (packet.index !== undefined) {
        if (!packet.index || typeof packet.index !== "object" || Array.isArray(packet.index)) throw new Error("invalid index.html");
        const value = packet.index as Record<string, unknown>;
        if (typeof value.hash !== "string" || !hashPattern.test(value.hash) || !Number.isSafeInteger(value.size) || (value.size as number) < 0) throw new Error("invalid index.html");
        index = { hash: value.hash, size: value.size as number };
      }
      const requested = index ? [index, ...hashes] : hashes;
      await this.stageWorkspaceObjects(requested);
      const missing: Array<{ hash: string; size: number }> = [];
      for (const item of requested) {
        const object = await this.env.UPLOADS.head(await this.objectKey(item.hash));
        if (!object || object.size !== item.size) missing.push(item);
      }
      socket.send(JSON.stringify({ type: "workspace_manifest", ...(typeof packet.id === "string" ? { id: packet.id } : {}), missing }));
      return;
    }
    if (!attachment.opened) {
      if (packet.type !== "open") throw new Error("open must be the first command");
      const indexHash = packet.index_hash;
      const indexSize = packet.index_size;
      if (typeof indexHash !== "string" || !hashPattern.test(indexHash) || !Number.isSafeInteger(indexSize) || (indexSize as number) < 0) throw new Error("invalid index.html");
      const manifest = objectManifest(packet.manifest);
      const size = indexSize as number;
      await this.validateObject(indexHash, size);
      await this.validateManifest(manifest);
      const expiresAt = Date.now() + SESSION_LIFETIME_MS;
      const pageHash = await initialPageHash(indexHash);
      await this.ctx.storage.transaction(async transaction => {
        await transaction.delete("open_deadline_at");
        await transaction.delete("producer_grace_at");
        await transaction.put("opened", true);
        await transaction.put("expires_at", expiresAt);
        await transaction.put("base_index_hash", indexHash);
        await transaction.put("base_index_size", indexSize);
        await transaction.put("current_manifest", manifest);
        await transaction.put("workspace_version", 0);
        await transaction.put("next_event_number", 1);
        await transaction.put("producer_received", 0);
        await transaction.put("page_event", 0);
        await transaction.put("page_hash", pageHash);
        await transaction.put("history_bytes", 2);
        await transaction.put("queued_event_count", 0);
        await transaction.put("queued_event_bytes", 0);
        await transaction.put("submission_count", 0);
        await transaction.put("staging_hashes", []);
      });
      await this.deleteUnreferencedObjects(manifest).catch(() => {});
      attachment.opened = true;
      socket.serializeAttachment(attachment);
      await this.scheduleAlarm();
      socket.send(JSON.stringify({ type: "session", ...(typeof packet.id === "string" ? { id: packet.id } : {}), url: attachment.url, frontier: 0, page_event: 0, page_hash: pageHash, workspace_version: 0 }));
      return;
    }
    if (packet.type === "event_ack") {
      if (!Number.isSafeInteger(packet.event_number) || (packet.event_number as number) < 1) throw new Error("event_number is required");
      const received = await this.ctx.storage.get<number>("producer_received") ?? 0;
      const number = packet.event_number as number;
      if (number <= received) return;
      if (number !== received + 1) throw new Error("event acknowledgement is out of order");
      const stored = await this.event(number);
      if (!stored) throw new Error("event is missing");
      stored.received = true;
      stored.sent = true;
      const stats = await this.queuedStats();
      const bytes = stored.bytes;
      if (stored.event.type === "submit") stored.event = { ...stored.event, values: {} };
      await this.ctx.storage.transaction(async transaction => {
        await transaction.put(`event:${number}`, stored);
        await transaction.put("producer_received", number);
        await transaction.put("queued_event_count", Math.max(0, stats.count - 1));
        await transaction.put("queued_event_bytes", Math.max(0, stats.bytes - bytes));
      });
      await this.sendNext();
      return;
    }
    if (packet.type === "commit") {
      try { await this.commit(socket, attachment, packet); }
      catch (cause) {
        const current = await this.ctx.storage.get<Manifest>("current_manifest");
        if (current) {
          await this.ctx.storage.delete("staging_hashes");
          await this.deleteUnreferencedObjects(current).catch(() => {});
        }
        throw cause;
      }
      return;
    }
    throw new Error("unknown command type");
  }

  private async commit(socket: WebSocket, _attachment: ProducerAttachment, packet: Packet): Promise<void> {
    const commitId = typeof packet.request_id === "string" ? packet.request_id : packet.id;
    if (typeof commitId !== "string" || !uuidPattern.test(commitId)) throw new Error("commit id is required");
    const previous = await this.ctx.storage.get<Record<string, unknown>>(`commit:${commitId}`);
    if (previous) { socket.send(JSON.stringify({ ...previous, id: packet.id })); return; }
    if (!Number.isSafeInteger(packet.through) || (packet.through as number) < 0) throw new Error("through must be a non-negative safe integer");
    const through = packet.through as number;
    const received = await this.ctx.storage.get<number>("producer_received") ?? 0;
    const frontier = await this.eventFrontier();
    const committedThrough = await this.ctx.storage.get<number>("committed_through") ?? 0;
    if (through > received) throw new Error("through is beyond the producer-received frontier");
    if (through > frontier) throw new Error("through is beyond the current event frontier");
    if (through < committedThrough) throw new Error("through is before the acknowledged submission frontier");
    if (packet.script !== undefined && (typeof packet.script !== "string" || encoder.encode(packet.script).byteLength > MAX_BODY_BYTES)) throw new Error("script is too large");
    const indexHash = packet.index_hash;
    const indexSize = packet.index_size;
    if (typeof indexHash !== "string" || !hashPattern.test(indexHash) || !Number.isSafeInteger(indexSize) || (indexSize as number) < 0) throw new Error("invalid index.html");
    if (indexHash !== await this.ctx.storage.get<string>("base_index_hash") || indexSize !== await this.ctx.storage.get<number>("base_index_size")) throw new Error("index.html cannot change during a session");
    const manifest = objectManifest(packet.manifest);
    await this.validateManifest(manifest);
    const stats = await this.queuedStats();
    const hasScript = packet.script !== undefined;
    if (hasScript && (stats.count >= MAX_QUEUED_EVENTS || stats.bytes + encoder.encode(packet.script as string).byteLength > MAX_QUEUED_BYTES)) throw new Error("event queue is full");
    const currentVersion = await this.ctx.storage.get<number>("workspace_version") ?? 0;
    const nextVersion = currentVersion + 1;
    let runEvent: RunUIEvent | undefined;
    let nextPageHash = await this.ctx.storage.get<string>("page_hash");
    if (!nextPageHash) {
      const baseHash = await this.ctx.storage.get<string>("base_index_hash");
      if (!baseHash) throw new Error("session is not open");
      nextPageHash = await initialPageHash(baseHash);
    }
    let nextHistoryBytes = await this.ctx.storage.get<number>("history_bytes") ?? 2;
    const nextEventNumber = frontier + 1;
    if (hasScript) {
      runEvent = { type: "run_ui", event_number: nextEventNumber, considered_through: through, frontier: nextEventNumber, page_event: nextEventNumber, page_hash: "", script: packet.script as string };
      nextPageHash = await chainedPageHash(nextPageHash, nextEventNumber, runEvent.script);
      runEvent.page_hash = nextPageHash;
      nextHistoryBytes += (nextHistoryBytes > 2 ? 1 : 0) + historyBytes(runEvent);
      if (nextHistoryBytes > MAX_HISTORY_BYTES) throw new Error("page history is too large");
    }
    const currentPageEvent = await this.ctx.storage.get<number>("page_event") ?? 0;
    const committedIds: string[] = [];
    for (let number = committedThrough + 1; number <= through; number += 1) {
      const stored = await this.event(number);
      if (stored?.event.type === "submit") committedIds.push(stored.event.id);
    }
    if (runEvent) {
      const stored: StoredEvent = { event: runEvent, received: false, sent: false, bytes: encoder.encode(runEvent.script).byteLength };
      await this.ctx.storage.transaction(async transaction => {
        for (let number = committedThrough + 1; number <= through; number += 1) {
          const storedEvent = await transaction.get<StoredEvent>(`event:${number}`);
          if (storedEvent?.event.type === "submit") await transaction.delete(`event:${number}`);
        }
        await transaction.put(`event:${nextEventNumber}`, stored);
        await transaction.put("next_event_number", nextEventNumber + 1);
        await transaction.put("workspace_version", nextVersion);
        await transaction.put("current_manifest", manifest);
        await transaction.put("committed_through", through);
        await transaction.put("page_event", nextEventNumber);
        await transaction.put("page_hash", nextPageHash);
        await transaction.put("history_bytes", nextHistoryBytes);
        await transaction.put("queued_event_count", stats.count + 1);
        await transaction.put("queued_event_bytes", stats.bytes + stored.bytes);
        await transaction.put(`commit:${commitId}`, { ok: true, type: "committed", through, considered_through: through, frontier: nextEventNumber, page_event: nextEventNumber, page_hash: nextPageHash, events: committedIds, workspace_version: nextVersion, run_ui: { event_number: nextEventNumber, considered_through: through } });
      });
      await this.deleteUnreferencedObjects(manifest).catch(() => {});
    } else {
      await this.ctx.storage.transaction(async transaction => {
        for (let number = committedThrough + 1; number <= through; number += 1) {
          const storedEvent = await transaction.get<StoredEvent>(`event:${number}`);
          if (storedEvent?.event.type === "submit") await transaction.delete(`event:${number}`);
        }
        await transaction.put("workspace_version", nextVersion);
        await transaction.put("current_manifest", manifest);
        await transaction.put("committed_through", through);
        await transaction.put(`commit:${commitId}`, { ok: true, type: "committed", through, considered_through: through, frontier, page_event: currentPageEvent, page_hash: nextPageHash, events: committedIds, workspace_version: nextVersion });
      });
      await this.deleteUnreferencedObjects(manifest).catch(() => {});
    }
    if (runEvent) {
      this.sendClients(runEvent);
      await this.sendNext();
      socket.send(JSON.stringify({ ok: true, type: "committed", id: packet.id, through, considered_through: through, frontier: nextEventNumber, page_event: nextEventNumber, page_hash: nextPageHash, events: committedIds, workspace_version: nextVersion, run_ui: { event_number: nextEventNumber, considered_through: through } }));
    } else {
      socket.send(JSON.stringify({ ok: true, type: "committed", id: packet.id, through, considered_through: through, frontier, page_event: currentPageEvent, page_hash: nextPageHash, events: committedIds, workspace_version: nextVersion }));
    }
  }

  private sendClients(packet: Packet): void {
    const message = JSON.stringify(packet);
    for (const client of this.clients()) try { client.send(message); } catch {}
  }

  async webSocketClose(socket: WebSocket, code: number, reason: string): Promise<void> {
    const attachment = socket.deserializeAttachment() as Attachment;
    await this.mutate(async () => {
      if (attachment.role !== "producer") return;
      const active = this.producer();
      if (active && (active.deserializeAttachment() as ProducerAttachment).id !== attachment.id) return;
      await this.resetDelivery();
      this.sendClients({ type: "producer", connected: false });
      if (attachment.opened && await this.ctx.storage.get<boolean>("opened")) {
        await this.ctx.storage.put("producer_grace_at", Date.now() + PRODUCER_GRACE_MS);
        await this.scheduleAlarm();
      }
    });
    if (code === 1005 || code === 1006 || code === 1015) socket.close(); else socket.close(code, reason);
  }

  async webSocketError(socket: WebSocket): Promise<void> {
    await this.webSocketClose(socket, 1011, "WebSocket error");
  }

  async alarm(): Promise<void> {
    await this.mutate(async () => {
      const opened = await this.ctx.storage.get<boolean>("opened") ?? false;
      if (!opened) {
        await this.expireSession();
        return;
      }
      const now = Date.now();
      const cleanupRetryAt = await this.ctx.storage.get<number>("cleanup_retry_at");
      const current = await this.ctx.storage.get<Manifest>("current_manifest");
      if (current && typeof cleanupRetryAt === "number" && Number.isSafeInteger(cleanupRetryAt) && cleanupRetryAt <= now) {
        await this.deleteUnreferencedObjects(current, false).catch(() => {});
      } else {
        await this.reclaimExpiredBrowserObjects().catch(() => {});
      }
      const producer = this.producer();
      const expiresAt = await this.ctx.storage.get<number>("expires_at");
      let graceAt = await this.ctx.storage.get<number>("producer_grace_at");
      if (!producer && graceAt === undefined) {
        graceAt = now + PRODUCER_GRACE_MS;
        await this.ctx.storage.put("producer_grace_at", graceAt);
      }
      if (expiresAt === undefined || !Number.isSafeInteger(expiresAt) || expiresAt <= now || (!producer && graceAt !== undefined && graceAt <= now)) {
        await this.expireSession();
        return;
      }
      await this.scheduleAlarm().catch(() => {});
    });
  }
}

function home(): Response {
  return new Response(`# LetMeKnow\n\nServe a temporary browser page:\n\n  npx letmeknow-cli serve ./public\n\nThe service hosts committed workspace snapshots and delivers ordered browser events.\n`, { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.protocol === "http:" && isProductionHost(url.hostname)) {
      url.protocol = "https:";
      return new Response(null, { status: 308, headers: { Location: url.toString() } });
    }
    const target = publicTarget(url);
    if (target) {
      const headers = new Headers(request.headers);
      headers.set("x-letmeknow-code", target.code);
      if (target.path === clientSocketPath) headers.set("x-letmeknow-route", "client");
      else if (target.path === runtimePath) {
        if (request.method === "GET") return new Response(clientSource, { headers: { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store" } });
        if (request.method === "HEAD") return new Response(null, { headers: { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store" } });
        return new Response(null, { status: 405, headers: { Allow: "GET, HEAD", "Cache-Control": "no-store" } });
      } else if (target.path.startsWith("/_letmeknow/workspace/")) headers.set("x-letmeknow-route", "workspace");
      else headers.set("x-letmeknow-route", "browser");
      return env.SESSIONS.getByName(target.code).fetch(new Request(request, { headers }));
    }
    if (url.pathname === "/v2/connect") {
      if (normalizedHostname(url.hostname) !== "letmeknow.dev") return error("not found", 404);
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return error("websocket upgrade required", 426);
      const requestedCode = url.searchParams.get("code");
      if (requestedCode !== null && !new RegExp(`^[a-f0-9]{${CODE_LENGTH}}$`).test(requestedCode)) return error("invalid session code", 400);
      const reconnect = requestedCode !== null;
      if (url.searchParams.has("credential")) return error("invalid producer credentials", 401);
      const protocol = request.headers.get("sec-websocket-protocol");
      if (protocol && (protocol.includes(",") || protocol.trim() !== protocol)) return error("invalid producer credentials", 401);
      if (reconnect ? !protocol : protocol !== null) return error("invalid producer credentials", 401);
      if (!reconnect) {
        const ip = request.headers.get("cf-connecting-ip") || "unknown";
        if (!(await env.CREATE_RATE_LIMIT.limit({ key: ip })).success) return error("too many sessions", 429);
      }
      const code = requestedCode || token();
      const producerCredential = reconnect ? protocol! : token(CODE_LENGTH * 2);
      const headers = new Headers(request.headers);
      headers.set("x-letmeknow-route", "producer");
      headers.set("x-letmeknow-url", sessionUrl(code));
      headers.set("x-letmeknow-code", code);
      headers.set("x-letmeknow-credential", producerCredential);
      if (reconnect) headers.set("x-letmeknow-reconnect", "true");
      return env.SESSIONS.getByName(code).fetch(new Request(request, { headers }));
    }
    if (url.pathname === "/" && request.method === "GET") return home();
    return error("not found", 404);
  }
};
