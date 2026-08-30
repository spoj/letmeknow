(() => {
  const socketPath = "/_letmeknow/client";
  const stateKey = () => "letmeknow-state:" + location.href;
  let hadSocketConnection = false;
  let reconnectTimer;
  let terminal = false;
  let reloading = false;
  let producerKnown = false;
  let producerConnected = false;
  const disconnectedPage = document.documentElement.getAttribute("data-letmeknow-status-page") === "disconnected";
  const submitting = new WeakSet();
  const outboxInFlight = new Set();
  const submissionForms = new Map();
  const OUTBOX_RETRY_MS = 1000;
  let outboxDatabasePromise;
  let outboxFlushPromise;
  let outboxRetryTimer;

  function outboxDatabase() {
    outboxDatabasePromise ??= new Promise((resolve, reject) => {
      const request = indexedDB.open("letmeknow-outbox:" + location.origin, 1);
      request.onupgradeneeded = () => request.result.createObjectStore("submissions", { keyPath: "id" });
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("could not open submission outbox"));
    });
    return outboxDatabasePromise;
  }

  function outboxTransaction(mode, operation) {
    return outboxDatabase().then((database) => new Promise((resolve, reject) => {
      const transaction = database.transaction("submissions", mode);
      const store = transaction.objectStore("submissions");
      let result;
      transaction.oncomplete = () => resolve(result);
      transaction.onerror = () => reject(transaction.error || new Error("submission outbox failed"));
      transaction.onabort = () => reject(transaction.error || new Error("submission outbox aborted"));
      result = operation(store);
    }));
  }

  function outboxPut(record) {
    return outboxTransaction("readwrite", (store) => store.put(record));
  }

  function outboxDelete(id) {
    return outboxTransaction("readwrite", (store) => store.delete(id));
  }

  function outboxList() {
    return outboxTransaction("readonly", (store) => {
      const request = store.getAll();
      return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error("could not read submission outbox"));
      });
    });
  }

  function scheduleOutboxFlush(delay = OUTBOX_RETRY_MS) {
    if (outboxRetryTimer) return;
    outboxRetryTimer = setTimeout(() => {
      outboxRetryTimer = undefined;
      void flushOutbox();
    }, delay);
  }

  function setSubmissionStatus(id, message, formId) {
    const form = submissionForms.get(id) || (formId ? document.getElementById(formId) : undefined);
    if (form && (!form.dataset.letmeknowSubmission || form.dataset.letmeknowSubmission === id)) setStatus(form, message);
  }

  async function deliverSubmission(record) {
    if (outboxInFlight.has(record.id)) return;
    outboxInFlight.add(record.id);
    try {
      const response = await fetch(record.url, {
        method: record.method,
        headers: record.headers,
        body: record.body === null ? undefined : record.body.slice(0)
      });
      if (response.status === 202) {
        await outboxDelete(record.id);
        setSubmissionStatus(record.id, "Sent. Waiting for an update…", record.form_id);
        const form = submissionForms.get(record.id);
        if (form?.dataset.letmeknowSubmission === record.id) delete form.dataset.letmeknowSubmission;
        submissionForms.delete(record.id);
        return;
      }
      setSubmissionStatus(record.id, response.status === 413 ? "Attachment is too large." : "Couldn’t send. Try again.", record.form_id);
      if (response.status >= 500) scheduleOutboxFlush();
    } catch {
      setSubmissionStatus(record.id, "Couldn’t send. Try again.", record.form_id);
      scheduleOutboxFlush();
    } finally {
      outboxInFlight.delete(record.id);
    }
  }

  function flushOutbox() {
    if (!producerConnected) return Promise.resolve();
    if (outboxFlushPromise) return outboxFlushPromise;
    outboxFlushPromise = outboxList().then(async (records) => {
      for (const record of records) await deliverSubmission(record);
    }).catch(() => {}).finally(() => {
      outboxFlushPromise = undefined;
    });
    return outboxFlushPromise;
  }

  function statusTarget(form) {
    const local = form.querySelector("[data-letmeknow-status]");
    if (local) return local;
    for (const candidate of document.querySelectorAll("[data-letmeknow-status]")) {
      if (!candidate.closest("form")) return candidate;
    }
    let generated = form.querySelector("output[data-letmeknow-generated-status]");
    if (!generated) {
      generated = document.createElement("output");
      generated.setAttribute("role", "status");
      generated.setAttribute("data-letmeknow-status", "");
      generated.setAttribute("data-letmeknow-generated-status", "");
      form.append(generated);
    }
    return generated;
  }

  function setStatus(form, message) {
    statusTarget(form).textContent = message;
  }

  function setSystemStatus(message) {
    let target;
    for (const candidate of document.querySelectorAll("[data-letmeknow-system-status]")) {
      if (!candidate.closest("form")) {
        target = candidate;
        break;
      }
    }
    if (!target) {
      target = document.createElement("output");
      target.setAttribute("role", "status");
      target.setAttribute("data-letmeknow-system-status", "");
      target.setAttribute("data-letmeknow-generated-status", "");
      document.body.append(target);
    }
    target.textContent = message;
  }

  function clearSystemStatus() {
    for (const target of document.querySelectorAll("[data-letmeknow-system-status][data-letmeknow-generated-status]")) {
      if (!target.closest("form")) target.remove();
    }
  }

  function saveState() {
    const values = {};
    const seen = new Set();
    for (const control of document.querySelectorAll("input[id], textarea[id], select[id]")) {
      if (control instanceof HTMLInputElement && control.type === "file") continue;
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
      sessionStorage.setItem(stateKey(), JSON.stringify({ values, scrollX, scrollY }));
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
      if (!control || (control instanceof HTMLInputElement && control.type === "file") || document.querySelectorAll("#" + CSS.escape(id)).length !== 1) continue;
      if (control instanceof HTMLInputElement && (control.type === "checkbox" || control.type === "radio")) control.checked = Boolean(state.checked);
      else if (control instanceof HTMLSelectElement && control.multiple) {
        const selected = new Set(state.selected || []);
        for (const option of control.options) option.selected = selected.has(option.value);
      } else if (typeof state.value === "string") control.value = state.value;
    }
    if (Number.isFinite(saved.scrollX) && Number.isFinite(saved.scrollY)) {
      requestAnimationFrame(() => scrollTo(saved.scrollX, saved.scrollY));
    }
  }

  function reload() {
    if (terminal || reloading) return;
    reloading = true;
    saveState();
    location.reload();
  }

  function updateProducer(connected) {
    if (connected) {
      document.documentElement.removeAttribute("data-letmeknow-disconnected");
      clearSystemStatus();
    } else {
      document.documentElement.setAttribute("data-letmeknow-disconnected", "");
      setSystemStatus("Connection lost. Reconnecting…");
    }
    if (connected && (disconnectedPage || (producerKnown && !producerConnected))) reload();
    producerKnown = true;
    producerConnected = connected;
    if (connected) void flushOutbox();
  }

  function connect() {
    if (terminal) return;
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(protocol + "//" + location.host + socketPath);
    socket.addEventListener("open", () => {
      const reconnect = hadSocketConnection;
      hadSocketConnection = true;
      if (reconnect) reload();
      clearSystemStatus();
      void flushOutbox();
    });
    socket.addEventListener("message", (event) => {
      let message;
      try { message = JSON.parse(event.data); } catch { return; }
      if (message.type === "revision") reload();
      else if (message.type === "producer") updateProducer(Boolean(message.connected));
      else if (message.type === "connected") updateProducer(Boolean(message.producer_connected));
      else if (message.type === "closed") {
        terminal = true;
        if (reconnectTimer) clearTimeout(reconnectTimer);
        setSystemStatus(message.message || "Session closed");
      }
    });
    socket.addEventListener("close", () => {
      if (terminal || reloading) return;
      document.documentElement.setAttribute("data-letmeknow-disconnected", "");
      setSystemStatus("Connection lost. Reconnecting…");
      reconnectTimer = setTimeout(connect, 1000);
    });
    socket.addEventListener("error", () => {});
  }

  function submissionDetails(form, submitter) {
    const method = (submitter?.formMethod || form.method || "get").toUpperCase();
    const action = new URL(submitter?.formAction || form.action || location.href, location.href);
    return { method, action, noValidate: Boolean(form.noValidate || submitter?.formNoValidate) };
  }

  async function submit(form, submitter, details) {
    if (submitting.has(form)) return;
    if (!details.noValidate && !form.checkValidity()) {
      form.reportValidity();
      return;
    }
    if (details.method !== "GET" && details.method !== "POST") return;
    if (details.action.origin !== location.origin) {
      setStatus(form, "Only same-origin forms can be sent.");
      return;
    }
    const data = new FormData(form, submitter);
    const files = Array.from(data.values()).filter((value) => typeof File !== "undefined" && value instanceof File);
    const hasSelectedFile = files.some((file) => file.name);
    if (details.method === "GET" && hasSelectedFile) {
      setStatus(form, "File uploads are not supported for GET forms.");
      return;
    }
    const id = crypto.randomUUID();
    const previousBusy = form.getAttribute("aria-busy");
    const previousDisabled = submitter ? submitter.disabled : undefined;
    submitting.add(form);
    submissionForms.set(id, form);
    form.dataset.letmeknowSubmission = id;
    form.setAttribute("aria-busy", "true");
    if (submitter) submitter.disabled = true;
    try {
      if (details.method === "GET") {
        details.action.search = "";
        for (const [name, value] of data.entries()) if (typeof value === "string") details.action.searchParams.append(name, value);
      }
      const headers = {
        "X-LetMeKnow-Submission": "1",
        "X-LetMeKnow-ID": id,
        "X-LetMeKnow-Form-ID": encodeURIComponent(form.id || ""),
        "X-LetMeKnow-Action": encodeURIComponent(details.action.pathname + details.action.search)
      };
      if (submitter) {
        headers["X-LetMeKnow-Trigger-ID"] = encodeURIComponent(submitter.id || "");
        headers["X-LetMeKnow-Trigger-Name"] = encodeURIComponent(submitter.name || "");
        headers["X-LetMeKnow-Trigger-Value"] = encodeURIComponent(submitter.value || "");
      }
      let body = null;
      let uploading = false;
      if (details.method === "POST") {
        const submitterEnctype = submitter?.hasAttribute("formenctype")
          ? submitter.formEnctype || submitter.getAttribute("formenctype")
          : undefined;
        const enctype = (submitterEnctype || form.enctype || "application/x-www-form-urlencoded").toLowerCase();
        uploading = hasSelectedFile;
        const source = hasSelectedFile || enctype === "multipart/form-data"
          ? data
          : (() => {
            const values = new URLSearchParams();
            for (const [name, value] of data.entries()) if (typeof value === "string") values.append(name, value);
            return values;
          })();
        const request = new Request(details.action, { method: details.method, body: source });
        body = await request.arrayBuffer();
        headers["Content-Type"] = request.headers.get("content-type") || "application/octet-stream";
      }
      const basedOn = document.documentElement.getAttribute("data-letmeknow-workspace");
      if (basedOn) headers["X-LetMeKnow-Based-On"] = encodeURIComponent(basedOn);
      const record = { id, url: details.action.toString(), method: details.method, headers, body, form_id: form.id || null, ...(basedOn ? { based_on: basedOn } : {}) };
      setStatus(form, uploading ? "Uploading…" : "Sending…");
      await outboxPut(record);
      await flushOutbox();
    } catch {
      setStatus(form, "Couldn’t send. Try again.");
      delete form.dataset.letmeknowSubmission;
      submissionForms.delete(id);
    } finally {
      submitting.delete(form);
      if (previousBusy === null) form.removeAttribute("aria-busy");
      else form.setAttribute("aria-busy", previousBusy);
      if (submitter) submitter.disabled = previousDisabled;
    }
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const details = submissionDetails(form, event.submitter);
    if (details.method === "DIALOG") return;
    event.preventDefault();
    submit(form, event.submitter, details);
  });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", restoreState, { once: true });
  else restoreState();
  connect();
})();
