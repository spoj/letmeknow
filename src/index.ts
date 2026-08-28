import { DurableObject } from "cloudflare:workers";

interface Env {
  SESSIONS: DurableObjectNamespace<Session>;
  CREATE_RATE_LIMIT: RateLimitBinding;
}

interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

type Packet = Record<string, unknown>;
type RenderedView = { id: string; html: string; css: string };
type StoredAsset = {
  contentType: string;
  encoding: "utf8" | "base64";
  body: string;
  bytes: number;
};
type ProducerAttachment = {
  role: "producer";
  url: string;
  opened: boolean;
  closing: boolean;
};
type ClientAttachment = { role: "client"; probedAt: number };
type CandidateAttachment = { role: "candidate" };
type Attachment = ProducerAttachment | ClientAttachment | CandidateAttachment;
type PendingAction = {
  renderId: string;
  actionId: string;
  formId: string | null;
  targetId: string;
};
type Probe = {
  socket: WebSocket;
  nonce: string;
  promise: Promise<boolean>;
  timer?: ReturnType<typeof setTimeout>;
  settle(active: boolean): void;
};

const CODE_LENGTH = 20;
const PRODUCER_GRACE_MS = 10 * 60 * 1_000;
const CLIENT_GRACE_MS = 5 * 1_000;
const OPEN_DEADLINE_MS = 30 * 1_000;
const CHALLENGE_TIMEOUT_MS = 2 * 1_000;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_ASSETS = 100;
const MAX_ASSET_BYTES = 10 * 1024 * 1024;
const MAX_PENDING_ACTIONS = 32;
const encoder = new TextEncoder();

function error(message: string, status: number): Response {
  return Response.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
}

function token(length = CODE_LENGTH): string {
  let value = "";
  while (value.length < length) value += crypto.randomUUID().replaceAll("-", "");
  return value.slice(0, length);
}

async function packetHtml(packet: Packet): Promise<string> {
  if (typeof packet.body !== "string") throw new Error("body must be a string");
  if (encoder.encode(packet.body).byteLength > MAX_BODY_BYTES) throw new Error("body is too large");
  return new HTMLRewriter()
    .on("script,style,iframe,object,embed,base,meta,link", {
      element(element) {
        element.remove();
      }
    })
    .on("*", {
      element(element) {
        const names = Array.from(element.attributes, ([name]) => name);
        for (const name of names) {
          const normalized = name.toLowerCase();
          if (normalized.startsWith("on")
            || normalized === "style"
            || normalized === "formmethod"
            || normalized === "formenctype"
            || normalized === "enctype"
            || normalized === "target"
            || normalized.startsWith("hx-")) {
            element.removeAttribute(name);
          }
        }
        for (const name of ["action", "formaction", "data-lmk-action"]) {
          const value = element.getAttribute(name);
          if (value !== null && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) element.removeAttribute(name);
        }
        const target = element.getAttribute("data-lmk-target");
        if (target !== null && !/^[A-Za-z][A-Za-z0-9_:-]{0,127}$/.test(target)) element.removeAttribute("data-lmk-target");
      }
    })
    .transform(new Response(packet.body))
    .text();
}

function packetCss(packet: Packet, required: boolean): string | undefined {
  if (packet.css === undefined && !required) return undefined;
  const css = packet.css ?? "";
  if (typeof css !== "string") throw new Error("css must be a string");
  if (encoder.encode(css).byteLength > MAX_BODY_BYTES) throw new Error("css is too large");
  return css;
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function assetData(packet: Packet): StoredAsset {
  if (typeof packet.content_type !== "string") throw new Error("content_type is required");
  new Headers([["content-type", packet.content_type]]);
  const encoding = packet.encoding ?? "utf8";
  if (encoding !== "utf8" && encoding !== "base64") throw new Error("encoding must be utf8 or base64");
  if (typeof packet.body !== "string") throw new Error("body must be a string");
  let bytes: Uint8Array;
  try {
    bytes = encoding === "base64" ? base64ToBytes(packet.body) : encoder.encode(packet.body);
  } catch {
    throw new Error("body is not valid base64");
  }
  if (bytes.byteLength > MAX_BODY_BYTES) throw new Error("body is too large");
  return { contentType: packet.content_type, encoding, body: packet.body, bytes: bytes.byteLength };
}

function assetResponse(asset: StoredAsset, head: boolean): Response {
  const body = asset.encoding === "base64" ? base64ToBytes(asset.body) : encoder.encode(asset.body);
  return new Response(head ? null : body, {
    headers: {
      "Content-Type": asset.contentType,
      "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; sandbox",
      "X-Content-Type-Options": "nosniff"
    }
  });
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
  const host = hostname.match(new RegExp(`^([a-f0-9]{${CODE_LENGTH}})\\.letmeknow\\.dev$`));
  if (host) return { code: host[1], path: url.pathname };
  const path = url.pathname.match(new RegExp(`^/s/([a-f0-9]{${CODE_LENGTH}})(/.*)?$`));
  if (!path || isProductionHost(url.hostname)) return null;
  return { code: path[1], path: path[2] || "/" };
}

function sessionUrl(url: URL, code: string): string {
  return normalizedHostname(url.hostname) === "letmeknow.dev"
    ? `https://${code}.letmeknow.dev/`
    : `${url.origin}/s/${code}/`;
}

function stringField(value: unknown, name: string, nullable = false): string | null {
  if (nullable && value === null) return null;
  if (typeof value !== "string" || value.length > 128) throw new Error(`${name} must be a string`);
  return value;
}

function actionPacket(value: Packet): Packet {
  const id = stringField(value.id, "id")!;
  const actionId = stringField(value.action_id, "action_id")!;
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(actionId)) throw new Error("invalid action_id");
  const targetId = stringField(value.target_id, "target_id")!;
  if (!/^[A-Za-z][A-Za-z0-9_:-]{0,127}$/.test(targetId)) throw new Error("invalid target_id");
  if (!value.values || typeof value.values !== "object" || Array.isArray(value.values)) throw new Error("values must be an object");
  const values: Record<string, string | string[]> = Object.create(null);
  for (const [name, field] of Object.entries(value.values)) {
    if (name.length > 128) throw new Error("field name is too long");
    if (typeof field === "string") values[name] = field;
    else if (Array.isArray(field) && field.every((item) => typeof item === "string")) values[name] = field;
    else throw new Error("field values must be strings");
  }
  if (!value.trigger || typeof value.trigger !== "object" || Array.isArray(value.trigger)) throw new Error("invalid trigger");
  const trigger = value.trigger as Packet;
  return {
    id,
    render_id: stringField(value.render_id, "render_id"),
    action_id: actionId,
    form_id: stringField(value.form_id, "form_id", true),
    target_id: targetId,
    trigger: {
      id: stringField(trigger.id, "trigger.id", true),
      name: stringField(trigger.name, "trigger.name", true),
      value: stringField(trigger.value, "trigger.value", true)
    },
    values
  };
}

const stylesheet = `
:root{color-scheme:light dark;font-family:system-ui,sans-serif}body{margin:0}#lmk-view{max-width:70rem;margin:auto;padding:1rem}input,select,textarea,button{font:inherit}img{max-width:100%;height:auto}:focus-visible{outline:2px solid Highlight;outline-offset:2px}[aria-busy=true]{opacity:.65}#lmk-status{position:fixed;right:1rem;bottom:1rem;padding:.5rem;background:CanvasText;color:Canvas}#lmk-status:empty{display:none}@media(prefers-reduced-motion:reduce){*{animation-duration:.01ms!important;transition-duration:.01ms!important}}
`;

const runtime = `
(()=>{
  const view=document.getElementById("lmk-view");
  const status=document.getElementById("lmk-status");
  const customStyle=document.getElementById("lmk-custom");
  const sessionKey=location.host+location.pathname;
  const key="letmeknow-client:"+sessionKey;
  const draftKey="letmeknow-draft:"+sessionKey;
  let credential=sessionStorage.getItem(key);
  let renderId="";
  let socket;
  let retryTimer;
  let producerConnected=false;
  let terminal=false;
  const pending=new Map();
  const pendingTargets=new Set();
  const validId=value=>/^[A-Za-z][A-Za-z0-9_:-]{0,127}$/.test(value);
  const validAction=value=>/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);
  const setStatus=message=>{status.textContent=message};
  const applyFull=message=>{view.innerHTML=message.html;customStyle.textContent=message.css??"";renderId=message.render_id};
  const applyUpdate=message=>{
    const target=document.getElementById(message.target_id);
    if(!target)throw new Error("Interaction target not found");
    target.innerHTML=message.html;
    if("css" in message)customStyle.textContent=message.css;
    renderId=message.render_id;
    saveDraft();
  };
  const draftControls=()=>[...view.querySelectorAll("input,select,textarea")].filter(control=>control.type!=="file");
  const draftEntries=()=>{
    const counts=Object.create(null);
    return draftControls().map(control=>{
      const base=control.id?"#"+control.id:(control.form?.id??"")+":"+control.name+":"+control.type;
      const key=control.id?base:base+":"+(counts[base]=(counts[base]??0)+1);
      return [key,control];
    });
  };
  const saveDraft=()=>{
    const state=Object.create(null);
    for(const [key,control] of draftEntries())state[key]={value:control.value,checked:control.checked,selected:control instanceof HTMLSelectElement?[...control.options].filter(option=>option.selected).map(option=>option.value):undefined};
    sessionStorage.setItem(draftKey,JSON.stringify({render_id:renderId,state}));
  };
  const restoreDraft=()=>{
    try{
      const draft=JSON.parse(sessionStorage.getItem(draftKey));
      if(draft?.render_id!==renderId)return;
      for(const [key,control] of draftEntries()){
        const state=draft.state[key];
        if(!state)continue;
        if(control instanceof HTMLSelectElement&&state.selected)for(const option of control.options)option.selected=state.selected.includes(option.value);
        else if(control.type==="checkbox"||control.type==="radio")control.checked=state.checked;
        else control.value=state.value;
      }
    }catch{}
  };
  document.addEventListener("input",saveDraft);
  document.addEventListener("change",saveDraft);
  const controls=scope=>[...(scope.matches("button,input,select,textarea")?[scope]:[]),...scope.querySelectorAll("button,input,select,textarea")];
  const setDisabled=(scope,on)=>{
    scope.setAttribute("aria-busy",String(on));
    for(const control of controls(scope)){
      if(on&&!control.disabled){control.dataset.lmkEnabled="";control.disabled=true}
      else if(!on&&"lmkEnabled" in control.dataset){delete control.dataset.lmkEnabled;control.disabled=false}
    }
  };
  const release=id=>{
    const item=pending.get(id);
    if(!item)return;
    pending.delete(id);
    pendingTargets.delete(item.target);
    if(item.scope.isConnected){delete item.scope.dataset.lmkPending;setDisabled(item.scope,false)}
  };
  const send=(scope,target,payload)=>{
    if(!producerConnected||socket?.readyState!==WebSocket.OPEN){setStatus("Agent disconnected — reconnecting");return}
    if(scope.dataset.lmkPending)return;
    for(const active of pendingTargets){if(active===target||active.contains(target)||target.contains(active))return}
    const id=crypto.randomUUID();
    payload.id=id;
    scope.dataset.lmkPending="true";
    setDisabled(scope,true);
    pendingTargets.add(target);
    pending.set(id,{scope,target});
    socket.send(JSON.stringify({type:"action",...payload}));
  };
  document.addEventListener("submit",event=>{
    const form=event.target;
    if(!(form instanceof HTMLFormElement))return;
    event.preventDefault();
    const submitter=event.submitter;
    const action=submitter?.getAttribute("formaction")??form.getAttribute("action")??"";
    const targetId=submitter?.dataset.lmkTarget??form.dataset.lmkTarget??"lmk-view";
    if(form.method.toLowerCase()!=="post"){alert("Only POST forms are supported");return}
    if(!form.id){alert("Interactive forms require an id");return}
    if(!validAction(action)){alert("Invalid form action");return}
    if(!validId(targetId)){alert("Invalid interaction target");return}
    const target=document.getElementById(targetId);
    if(!target){alert("Interaction target not found");return}
    const values=Object.create(null);
    const data=submitter instanceof HTMLButtonElement||submitter instanceof HTMLInputElement?new FormData(form,submitter):new FormData(form);
    for(const [name,value] of data){
      if(typeof value!=="string"){alert("File inputs are not supported");return}
      if(Object.prototype.hasOwnProperty.call(values,name))values[name]=Array.isArray(values[name])?[...values[name],value]:[values[name],value];
      else values[name]=value;
    }
    send(form,target,{render_id:renderId,action_id:action,form_id:form.id,target_id:targetId,trigger:{id:submitter?.id||null,name:submitter?.name||null,value:submitter?.value||null},values});
  });
  document.addEventListener("click",event=>{
    if(!(event.target instanceof Element))return;
    const source=event.target.closest("button[data-lmk-action]");
    if(!source)return;
    if(source.form&&source.type==="submit")return;
    event.preventDefault();
    const action=source.dataset.lmkAction??"";
    const targetId=source.dataset.lmkTarget??"lmk-view";
    if(!validAction(action)){alert("Invalid button action");return}
    if(!validId(targetId)){alert("Invalid interaction target");return}
    const target=document.getElementById(targetId);
    if(!target){alert("Interaction target not found");return}
    send(source,target,{render_id:renderId,action_id:action,form_id:null,target_id:targetId,trigger:{id:source.id||null,name:source.name||null,value:source.value||null},values:{}});
  });
  const connect=()=>{
    clearTimeout(retryTimer);
    retryTimer=undefined;
    const url=new URL("_letmeknow/client",location.href);
    url.protocol=url.protocol==="https:"?"wss:":"ws:";
    socket=credential?new WebSocket(url,credential):new WebSocket(url);
    socket.onmessage=event=>{
      const message=JSON.parse(event.data);
      if(message.type==="credential"){credential=message.credential;sessionStorage.setItem(key,credential);return}
      if(message.type==="challenge"){socket.send(JSON.stringify({type:"alive",nonce:message.nonce}));return}
      if(message.type==="busy"){setStatus("This session is open elsewhere");retryTimer=setTimeout(connect,message.retry_after*1000);return}
      if(message.type==="state"){
        producerConnected=message.producer_connected;
        for(const id of [...pending.keys()])release(id);
        applyFull(message.view);
        restoreDraft();
        for(const item of message.pending){
          const target=document.getElementById(item.target_id);
          const scope=item.form_id?document.getElementById(item.form_id):target;
          if(!target||!scope)continue;
          scope.dataset.lmkPending="true";
          setDisabled(scope,true);
          pendingTargets.add(target);
          pending.set(item.id,{scope,target});
        }
        setStatus(producerConnected?"":"Agent disconnected — reconnecting");
        return;
      }
      if(message.type==="render"){for(const id of [...pending.keys()])release(id);sessionStorage.removeItem(draftKey);applyFull(message);return}
      if(message.type==="update"){try{applyUpdate(message)}finally{release(message.request_id)}return}
      if(message.type==="action_error"){release(message.request_id);setStatus(message.message);return}
      if(message.type==="producer"){producerConnected=message.connected;setStatus(producerConnected?"":"Agent disconnected — reconnecting");return}
      if(message.type==="closed"){terminal=true;sessionStorage.removeItem(key);sessionStorage.removeItem(draftKey);setStatus(message.message);return}
    };
    socket.onclose=()=>{producerConnected=false;if(!terminal&&!retryTimer){setStatus("Reconnecting…");retryTimer=setTimeout(connect,1000)}};
    socket.onerror=()=>{};
  };
  connect();
})();
`;

function shell(): Response {
  const nonce = token(32);
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LetMeKnow</title><style nonce="${nonce}">${stylesheet}</style><style id="lmk-custom" nonce="${nonce}"></style></head><body><main id="lmk-view" aria-live="polite"><p>Waiting for the agent…</p></main><aside id="lmk-status" role="status"></aside><script nonce="${nonce}">${runtime}</script></body></html>`;
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

async function replaceTarget(html: string, targetId: string, fragment: string): Promise<string> {
  if (targetId === "lmk-view") return fragment;
  let found = false;
  const result = await new HTMLRewriter().on("*", {
    element(element) {
      if (!found && element.getAttribute("id") === targetId) {
        found = true;
        element.setInnerContent(fragment, { html: true });
      }
    }
  }).transform(new Response(html)).text();
  if (!found) throw new Error("interaction target no longer exists");
  return result;
}

export class Session extends DurableObject<Env> {
  private probe?: Probe;
  private stateMutation: Promise<void> = Promise.resolve();

  async fetch(request: Request): Promise<Response> {
    const action = request.headers.get("x-letmeknow-action");
    if (action === "producer") return this.mutate(() => this.acceptProducer(request));
    if (action === "client") return this.mutate(() => this.acceptClient(request));
    if (action === "browser") return this.browserRequest(request);
    return error("not found", 404);
  }

  private async mutate<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.stateMutation;
    let release!: () => void;
    this.stateMutation = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  private producer(): WebSocket | undefined {
    return this.ctx.getWebSockets().find((socket) => (socket.deserializeAttachment() as Attachment).role === "producer");
  }

  private client(): WebSocket | undefined {
    return this.ctx.getWebSockets().find((socket) => (socket.deserializeAttachment() as Attachment).role === "client");
  }

  private async acceptProducer(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return error("websocket upgrade required", 426);
    const credential = request.headers.get("x-letmeknow-credential");
    const protocol = request.headers.get("sec-websocket-protocol");
    const storedCredential = await this.ctx.storage.get<string>("credential");
    const opened = await this.ctx.storage.get<boolean>("opened") ?? false;
    const reconnectRequested = request.headers.get("x-letmeknow-reconnect") === "true";
    const reconnect = storedCredential !== undefined;
    if (reconnectRequested) {
      if (!reconnect || credential !== storedCredential || protocol !== credential) return error("invalid producer credential", 401);
    } else {
      if (reconnect || !credential || protocol !== null) return error("producer credential is required", 401);
      await this.ctx.storage.put("credential", credential);
    }
    if (this.producer()) return error("a producer is already connected", 409);

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const attachment: ProducerAttachment = {
      role: "producer",
      url: request.headers.get("x-letmeknow-url")!,
      opened: reconnect && opened,
      closing: false
    };
    server.serializeAttachment(attachment);
    this.ctx.acceptWebSocket(server);
    if (reconnect && opened) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(Date.now() + OPEN_DEADLINE_MS);
    if (!reconnect) server.send(JSON.stringify({ type: "credential", credential }));
    if (reconnect && opened) {
      server.send(JSON.stringify({ type: "session", url: attachment.url, expires_after_disconnect: PRODUCER_GRACE_MS / 1000 }));
      this.sendClient({ type: "producer", connected: true });
    }
    return new Response(null, {
      status: 101,
      webSocket: client,
      ...(protocol ? { headers: { "Sec-WebSocket-Protocol": protocol } } : {})
    });
  }

  private async challenge(socket: WebSocket): Promise<boolean> {
    const attachment = socket.deserializeAttachment() as ClientAttachment;
    if (Date.now() - attachment.probedAt < CLIENT_GRACE_MS) return true;
    if (this.probe?.socket === socket) return this.probe.promise;
    attachment.probedAt = Date.now();
    socket.serializeAttachment(attachment);
    const nonce = token(32);
    let resolvePromise!: (active: boolean) => void;
    const promise = new Promise<boolean>((resolve) => { resolvePromise = resolve; });
    const probe: Probe = {
      socket,
      nonce,
      promise,
      settle: (active): void => {
        if (this.probe !== probe) return;
        if (probe.timer) clearTimeout(probe.timer);
        this.probe = undefined;
        resolvePromise(active);
      }
    };
    probe.timer = setTimeout(() => probe.settle(false), CHALLENGE_TIMEOUT_MS);
    this.probe = probe;
    try {
      socket.send(JSON.stringify({ type: "challenge", nonce }));
    } catch {
      probe.settle(false);
    }
    return promise;
  }

  private busyClient(protocol: string | null, retryAfter: number): Response {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.serializeAttachment({ role: "candidate" } satisfies CandidateAttachment);
    this.ctx.acceptWebSocket(server);
    server.send(JSON.stringify({ type: "busy", retry_after: retryAfter }));
    server.close(4009, "session already open");
    return new Response(null, {
      status: 101,
      webSocket: client,
      ...(protocol ? { headers: { "Sec-WebSocket-Protocol": protocol } } : {})
    });
  }

  private async acceptClient(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return error("websocket upgrade required", 426);
    if (!(await this.ctx.storage.get<boolean>("opened"))) return error("session not found", 404);
    const protocol = request.headers.get("sec-websocket-protocol");
    if (protocol && (protocol.includes(",") || !/^[a-f0-9]{40}$/.test(protocol))) return error("invalid client credential", 401);

    const active = this.client();
    if (active && await this.challenge(active)) return this.busyClient(protocol, CLIENT_GRACE_MS / 1000);
    if (active) {
      active.close(4000, "connection lost");
      await this.ctx.storage.put("clientDisconnectedAt", Date.now());
    }

    const storedCredential = await this.ctx.storage.get<string>("clientCredential");
    const disconnectedAt = await this.ctx.storage.get<number>("clientDisconnectedAt") ?? 0;
    const reconnect = storedCredential !== undefined && protocol === storedCredential;
    if (!reconnect && storedCredential !== undefined && Date.now() - disconnectedAt < CLIENT_GRACE_MS) {
      return this.busyClient(protocol, Math.ceil((CLIENT_GRACE_MS - (Date.now() - disconnectedAt)) / 1000));
    }

    const credential = reconnect ? storedCredential : token(40);
    await this.ctx.storage.put("clientCredential", credential);
    await this.ctx.storage.delete("clientDisconnectedAt");
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.serializeAttachment({ role: "client", probedAt: Date.now() } satisfies ClientAttachment);
    this.ctx.acceptWebSocket(server);
    if (!reconnect) server.send(JSON.stringify({ type: "credential", credential }));
    const view = await this.ctx.storage.get<RenderedView>("view") ?? { id: "", html: "<p>Waiting for the agent…</p>", css: "" };
    const pending = await this.pendingActions();
    server.send(JSON.stringify({
      type: "state",
      view: { render_id: view.id, html: view.html, css: view.css },
      pending: Object.entries(pending).map(([id, item]) => ({
        id,
        action_id: item.actionId,
        form_id: item.formId,
        target_id: item.targetId
      })),
      producer_connected: Boolean(this.producer())
    }));
    return new Response(null, {
      status: 101,
      webSocket: client,
      ...(protocol ? { headers: { "Sec-WebSocket-Protocol": protocol } } : {})
    });
  }

  private async browserRequest(request: Request): Promise<Response> {
    if (!(await this.ctx.storage.get<boolean>("opened"))) return error("session not found", 404);
    const path = request.headers.get("x-letmeknow-path")!;
    if (path === "/" && (request.method === "GET" || request.method === "HEAD")) {
      const response = shell();
      return request.method === "HEAD" ? new Response(null, { status: response.status, headers: response.headers }) : response;
    }
    if (path.startsWith("/assets/") && (request.method === "GET" || request.method === "HEAD")) {
      const asset = await this.ctx.storage.get<StoredAsset>(`asset:${path}`);
      return asset ? assetResponse(asset, request.method === "HEAD") : error("asset not found", 404);
    }
    await request.body?.cancel();
    return error("not found", 404);
  }

  async webSocketMessage(socket: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const attachment = socket.deserializeAttachment() as Attachment;
    if (attachment.role === "producer") return this.producerMessage(socket, attachment, message);
    if (attachment.role === "client") return this.clientMessage(socket, message);
  }

  private async producerMessage(socket: WebSocket, attachment: ProducerAttachment, message: string | ArrayBuffer): Promise<void> {
    let packet: Packet | undefined;
    try {
      packet = this.parseMessage(message);
      await this.mutate(() => this.producerCommand(socket, attachment, packet!));
    } catch (cause) {
      const text = cause instanceof Error ? cause.message : "invalid packet";
      try {
        socket.send(JSON.stringify({ type: "error", ...(typeof packet?.id === "string" ? { id: packet.id } : {}), message: text }));
      } catch {}
    }
  }

  private parseMessage(message: string | ArrayBuffer, maxBytes = MAX_BODY_BYTES * 2 + 4096): Packet {
    if (typeof message !== "string") throw new Error("packets must be text");
    if (encoder.encode(message).byteLength > maxBytes) throw new Error("packet is too large");
    let value: unknown;
    try {
      value = JSON.parse(message);
    } catch {
      throw new Error("invalid JSON");
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("packet must be a JSON object");
    return value as Packet;
  }

  private async producerCommand(socket: WebSocket, attachment: ProducerAttachment, packet: Packet): Promise<void> {
    if (typeof packet.type !== "string") throw new Error("type is required");
    if (packet.id !== undefined && typeof packet.id !== "string") throw new Error("id must be a string");
    if (attachment.closing) throw new Error("session is closing");

    if (packet.type === "open") {
      await this.ctx.storage.transaction(async (txn) => {
        if (await txn.get<boolean>("expired") || !(await txn.get<string>("credential"))) throw new Error("session expired");
        await txn.put("opened", true);
      });
      attachment.opened = true;
      socket.serializeAttachment(attachment);
      await this.ctx.storage.deleteAlarm();
      socket.send(JSON.stringify({
        type: "session",
        ...(packet.id !== undefined ? { id: packet.id } : {}),
        url: attachment.url,
        expires_after_disconnect: PRODUCER_GRACE_MS / 1000
      }));
      return;
    }
    if (!attachment.opened) throw new Error("open must be the first command");

    if (packet.type === "render") {
      const view: RenderedView = { id: crypto.randomUUID(), html: await packetHtml(packet), css: packetCss(packet, true)! };
      await this.ctx.storage.put({ view, pendingActions: {} });
      this.sendClient({ type: "render", render_id: view.id, html: view.html, css: view.css });
      this.ack(socket, packet, { render_id: view.id });
      return;
    }
    if (packet.type === "put") {
      const path = this.assetPath(packet);
      const asset = assetData(packet);
      await this.ctx.storage.transaction(async (txn) => {
        const previous = await txn.get<StoredAsset>(`asset:${path}`);
        const count = await txn.get<number>("assetCount") ?? 0;
        const bytes = await txn.get<number>("assetBytes") ?? 0;
        const nextCount = count + (previous ? 0 : 1);
        const nextBytes = bytes - (previous?.bytes ?? 0) + asset.bytes;
        if (nextCount > MAX_ASSETS) throw new Error("too many assets");
        if (nextBytes > MAX_ASSET_BYTES) throw new Error("assets are too large");
        await txn.put(`asset:${path}`, asset);
        await txn.put({ assetCount: nextCount, assetBytes: nextBytes });
      });
      this.ack(socket, packet);
      return;
    }
    if (packet.type === "response") {
      if (typeof packet.request_id !== "string") throw new Error("request_id is required");
      const pending = await this.pendingActions();
      const action = pending[packet.request_id];
      if (!action) throw new Error("interaction is not pending");
      const fragment = await packetHtml(packet);
      const css = packetCss(packet, false);
      const current = await this.ctx.storage.get<RenderedView>("view");
      if (!current) throw new Error("interface is not rendered");
      const targetId = action.targetId;
      const view: RenderedView = {
        id: crypto.randomUUID(),
        html: await replaceTarget(current.html, targetId, fragment),
        css: css ?? current.css
      };
      delete pending[packet.request_id];
      await this.ctx.storage.put({ view, pendingActions: pending });
      this.sendClient({
        type: "update",
        request_id: packet.request_id,
        target_id: targetId,
        html: fragment,
        ...(css !== undefined ? { css } : {}),
        render_id: view.id
      });
      this.ack(socket, packet, { render_id: view.id });
      return;
    }
    if (packet.type === "close") {
      attachment.opened = false;
      attachment.closing = true;
      socket.serializeAttachment(attachment);
      this.ack(socket, packet);
      socket.send(JSON.stringify({ type: "closing" }));
      this.sendClient({ type: "closed", message: "Session closed" });
      await this.ctx.storage.deleteAll();
      this.client()?.close(1000, "session closed");
      socket.close(1000, "session closed");
      return;
    }
    throw new Error("unknown command type");
  }

  private async clientMessage(socket: WebSocket, message: string | ArrayBuffer): Promise<void> {
    let packet: Packet | undefined;
    try {
      packet = this.parseMessage(message, MAX_BODY_BYTES);
      if (packet.type === "alive") {
        if (typeof packet.nonce === "string" && this.probe?.socket === socket && this.probe.nonce === packet.nonce) {
          this.probe.settle(true);
        }
        return;
      }
      await this.mutate(async () => {
        if (packet?.type !== "action") throw new Error("unknown client event");
        const action = actionPacket(packet);
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(action.id as string)) {
          throw new Error("invalid action id");
        }
        const view = await this.ctx.storage.get<RenderedView>("view");
        if (!view || action.render_id !== view.id) throw new Error("interface has changed");
        if (!this.producer()) throw new Error("producer disconnected");
        const pending = await this.pendingActions();
        if (Object.keys(pending).length >= MAX_PENDING_ACTIONS) throw new Error("too many pending interactions");
        if (pending[action.id as string]) throw new Error("interaction is already pending");
        if (Object.values(pending).some((item) => item.renderId === action.render_id
          && (item.formId === action.form_id || item.targetId === action.target_id))) {
          throw new Error("interaction already pending");
        }
        pending[action.id as string] = {
          renderId: action.render_id as string,
          actionId: action.action_id as string,
          formId: action.form_id as string | null,
          targetId: action.target_id as string
        };
        await this.ctx.storage.put("pendingActions", pending);
        this.sendProducer({ type: "action", ...action });
      });
    } catch (cause) {
      const text = cause instanceof Error ? cause.message : "invalid client event";
      try {
        socket.send(JSON.stringify({ type: "action_error", ...(typeof packet?.id === "string" ? { request_id: packet.id } : {}), message: text }));
      } catch {}
    }
  }

  private async pendingActions(): Promise<Record<string, PendingAction>> {
    return await this.ctx.storage.get<Record<string, PendingAction>>("pendingActions") ?? {};
  }

  private assetPath(packet: Packet): string {
    if (typeof packet.path !== "string"
      || !/^\/assets\/[A-Za-z0-9._/-]+$/.test(packet.path)
      || packet.path.includes("//")
      || packet.path.split("/").some((part) => part === "." || part === "..")) {
      throw new Error("asset path must be under /assets/");
    }
    return packet.path;
  }

  private ack(socket: WebSocket, packet: Packet, fields: Packet = {}): void {
    socket.send(JSON.stringify({ type: "ack", ...(packet.id !== undefined ? { id: packet.id } : {}), ...fields }));
  }

  private sendProducer(packet: Packet): void {
    try {
      this.producer()?.send(JSON.stringify(packet));
    } catch {}
  }

  private sendClient(packet: Packet): void {
    try {
      this.client()?.send(JSON.stringify(packet));
    } catch {}
  }

  async webSocketClose(socket: WebSocket, code: number, reason: string): Promise<void> {
    const attachment = socket.deserializeAttachment() as Attachment;
    if (this.probe?.socket === socket) this.probe.settle(false);
    await this.mutate(async () => {
      if (attachment.role === "producer") {
        this.sendClient({ type: "producer", connected: false });
        if (attachment.opened && await this.ctx.storage.get<boolean>("opened")) {
          await this.ctx.storage.setAlarm(Date.now() + PRODUCER_GRACE_MS);
        }
      } else if (attachment.role === "client" && await this.ctx.storage.get<boolean>("opened")) {
        await this.ctx.storage.put("clientDisconnectedAt", Date.now());
      }
    });
    if (code === 1005 || code === 1006 || code === 1015) socket.close();
    else socket.close(code, reason);
  }

  async webSocketError(socket: WebSocket, _error: unknown): Promise<void> {
    await this.webSocketClose(socket, 1011, "WebSocket error");
  }

  async alarm(): Promise<void> {
    await this.mutate(async () => {
      const producer = this.producer();
      if (producer && (producer.deserializeAttachment() as ProducerAttachment).opened) return;
      this.sendClient({ type: "closed", message: "Session expired" });
      this.client()?.close(1000, "session expired");
      producer?.close(1000, "session expired");
      await this.ctx.storage.deleteAll();
    });
  }
}

function home(): Response {
  return new Response(`# LetMeKnow\n\nRun a local Vite preview for an agent-managed folder:\n\n  npx letmeknow-cli ./workspace\n\nThe CLI prints the preview URL and form submissions as JSON lines. The hosted WebSocket protocol is available explicitly with LETMEKNOW_URL=https://letmeknow.dev.\n`, {
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
  });
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
      if (target.path === "/_letmeknow/client") {
        headers.set("x-letmeknow-action", "client");
      } else if (target.path === "/" || target.path.startsWith("/assets/")) {
        headers.set("x-letmeknow-action", "browser");
        headers.set("x-letmeknow-path", target.path);
      } else {
        await request.body?.cancel();
        return error("not found", 404);
      }
      return env.SESSIONS.getByName(target.code).fetch(new Request(request, { headers }));
    }

    if (url.pathname === "/v1/connect") {
      if (isProductionHost(url.hostname) && normalizedHostname(url.hostname) !== "letmeknow.dev") return error("not found", 404);
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return error("websocket upgrade required", 426);
      const requestedCode = url.searchParams.get("code");
      if (requestedCode !== null && !new RegExp(`^[a-f0-9]{${CODE_LENGTH}}$`).test(requestedCode)) return error("invalid session code", 400);
      const reconnect = requestedCode !== null;
      if (url.searchParams.has("credential")) return error("invalid producer credentials", 401);
      const protocol = request.headers.get("sec-websocket-protocol");
      if (protocol && (protocol.includes(",") || protocol.trim() !== protocol)) return error("invalid producer credentials", 401);
      if (reconnect ? !protocol : protocol !== null) return error("invalid producer credentials", 401);
      const credential = reconnect ? protocol : token(CODE_LENGTH * 2);
      if (!reconnect) {
        const ip = request.headers.get("cf-connecting-ip") || "unknown";
        if (!(await env.CREATE_RATE_LIMIT.limit({ key: ip })).success) return error("too many sessions", 429);
      }
      const code = requestedCode || token();
      const producerCredential = credential || token(CODE_LENGTH * 2);
      const headers = new Headers(request.headers);
      headers.set("x-letmeknow-action", "producer");
      headers.set("x-letmeknow-url", sessionUrl(url, code));
      headers.set("x-letmeknow-credential", producerCredential);
      if (reconnect) headers.set("x-letmeknow-reconnect", "true");
      return env.SESSIONS.getByName(code).fetch(new Request(request, { headers }));
    }

    if (url.pathname === "/" && request.method === "GET") return home();
    return error("not found", 404);
  }
};
