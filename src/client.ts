const client = String.raw`(() => {
  const socketPath = "/_letmeknow/client";
  const stateKey = () => "letmeknow-state:" + location.href;
  let socket;
  let connected = false;
  let reconnecting = false;
  let reconnectTimer;
  let terminal = false;
  const statusPage = document.documentElement.hasAttribute("data-letmeknow-status-page");

  function statusTarget(form) {
    return form.querySelector("[data-letmeknow-status]") || document.querySelector("[data-letmeknow-status]");
  }

  function setStatus(form, message) {
    let target = statusTarget(form);
    if (!target) {
      target = document.createElement("output");
      target.setAttribute("role", "status");
      target.setAttribute("data-letmeknow-status", "");
      form.append(target);
    }
    target.textContent = message;
  }

  function saveState() {
    const values = {};
    const seen = new Set();
    for (const control of document.querySelectorAll("input[id], textarea[id], select[id]")) {
      if (seen.has(control.id) || document.querySelectorAll("#" + CSS.escape(control.id)).length !== 1) continue;
      seen.add(control.id);
      if (control instanceof HTMLInputElement && (control.type === "checkbox" || control.type === "radio")) {
        values[control.id] = { checked: control.checked };
      } else if (control instanceof HTMLSelectElement && control.multiple) {
        values[control.id] = { selected: Array.from(control.selectedOptions, (option) => option.value) };
      } else {
        values[control.id] = { value: control.value };
      }
    }
    try {
      sessionStorage.setItem(stateKey(), JSON.stringify({ values, scrollX: scrollX, scrollY: scrollY }));
    } catch {}
  }

  function restoreState() {
    let saved;
    try {
      saved = JSON.parse(sessionStorage.getItem(stateKey()) || "null");
      sessionStorage.removeItem(stateKey());
    } catch {
      return;
    }
    if (!saved) return;
    for (const [id, state] of Object.entries(saved.values || {})) {
      const control = document.getElementById(id);
      if (!control || document.querySelectorAll("#" + CSS.escape(id)).length !== 1) continue;
      if (control instanceof HTMLInputElement && (control.type === "checkbox" || control.type === "radio")) control.checked = Boolean(state.checked);
      else if (control instanceof HTMLSelectElement && control.multiple) {
        const selected = new Set(state.selected || []);
        for (const option of control.options) option.selected = selected.has(option.value);
      } else if (typeof state.value === "string") control.value = state.value;
    }
    if (Number.isFinite(saved.scrollX) && Number.isFinite(saved.scrollY)) scrollTo(saved.scrollX, saved.scrollY);
  }

  function reload() {
    saveState();
    location.reload();
  }

  function connect() {
    if (terminal) return;
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    socket = new WebSocket(protocol + "//" + location.host + socketPath);
    socket.addEventListener("open", () => {
      if (connected || reconnecting) {
        reconnecting = false;
        connected = true;
        reload();
        return;
      }
      connected = true;
    });
    socket.addEventListener("message", (event) => {
      let message;
      try { message = JSON.parse(event.data); } catch { return; }
      if (message.type === "revision") reload();
      else if (message.type === "producer") {
        if (message.connected) {
          document.documentElement.removeAttribute("data-letmeknow-disconnected");
          if (statusPage) reload();
        }
        else {
          document.documentElement.setAttribute("data-letmeknow-disconnected", "");
          setStatus(document.body, "Connection lost. Reconnecting…");
        }
      } else if (message.type === "connected") {
        if (message.producer_connected) {
          document.documentElement.removeAttribute("data-letmeknow-disconnected");
          if (statusPage) reload();
        }
        else {
          document.documentElement.setAttribute("data-letmeknow-disconnected", "");
          setStatus(document.body, "Connection lost. Reconnecting…");
        }
      } else if (message.type === "closed") {
        terminal = true;
        if (reconnectTimer) clearTimeout(reconnectTimer);
        setStatus(document.body, message.message || "Session closed");
      }
    });
    socket.addEventListener("close", () => {
      if (terminal) return;
      if (connected) reconnecting = true;
      connected = false;
      document.documentElement.setAttribute("data-letmeknow-disconnected", "");
      setStatus(document.body, "Connection lost. Reconnecting…");
      reconnectTimer = setTimeout(connect, 1000);
    });
    socket.addEventListener("error", () => {});
  }

  async function submit(form, submitter) {
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }
    const method = (form.method || "get").toUpperCase();
    if (method !== "GET" && method !== "POST") return;
    const action = new URL(form.action || location.href, location.href);
    const data = new FormData(form);
    const values = {};
    for (const [name, value] of data.entries()) {
      if (typeof value !== "string") continue;
      if (name in values) values[name] = Array.isArray(values[name]) ? values[name].concat(value) : [values[name], value];
      else values[name] = value;
    }
    if (method === "GET") {
      for (const [name, value] of data.entries()) if (typeof value === "string") action.searchParams.append(name, value);
    }
    const id = crypto.randomUUID();
    const headers = {
      "X-LetMeKnow-Submission": "1",
      "X-LetMeKnow-ID": id,
      "X-LetMeKnow-Form-ID": encodeURIComponent(form.id || ""),
      "X-LetMeKnow-Action": encodeURIComponent(action.pathname + action.search)
    };
    if (submitter) {
      headers["X-LetMeKnow-Trigger-ID"] = encodeURIComponent(submitter.id || "");
      headers["X-LetMeKnow-Trigger-Name"] = encodeURIComponent(submitter.name || "");
      headers["X-LetMeKnow-Trigger-Value"] = encodeURIComponent(submitter.value || "");
    }
    let body;
    if (method === "POST") {
      body = new URLSearchParams();
      for (const [name, value] of data.entries()) if (typeof value === "string") body.append(name, value);
    }
    const previousBusy = form.getAttribute("aria-busy");
    const previousDisabled = submitter?.disabled;
    form.setAttribute("aria-busy", "true");
    if (submitter) submitter.disabled = true;
    setStatus(form, "Sending…");
    try {
      const response = await fetch(action, { method, headers, body });
      if (response.status !== 202) throw new Error("submission failed");
      setStatus(form, "Sent. Waiting for an update…");
    } catch {
      setStatus(form, "Couldn’t send. Try again.");
    } finally {
      if (previousBusy === null) form.removeAttribute("aria-busy");
      else form.setAttribute("aria-busy", previousBusy);
      if (submitter && previousDisabled !== undefined) submitter.disabled = previousDisabled;
    }
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    event.preventDefault();
    submit(form, event.submitter);
  });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", restoreState, { once: true });
  else restoreState();
  connect();
})();`;

export default client;
