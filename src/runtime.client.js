(() => {
  const socketPath = "/_letmeknow/client";
  const submissionPath = "/_letmeknow/submit";
  let hadSocketConnection = false;
  let reconnectTimer;
  let reloadScheduled = false;
  let terminal = false;
  let producerKnown = false;
  let producerConnected = false;
  const initialPageEvent = readPageEvent(document);
  const dynamicPage = initialPageEvent !== null;
  let pageEvent = initialPageEvent ?? 0;
  const submissionForms = new Map();
  const OUTBOX_RETRY_MS = 1000;
  let outboxDatabasePromise;
  let outboxFlushPromise;
  let outboxFlushAgain = false;
  let outboxRetryTimer;

  function readPageEvent(documentLike) {
    const value = documentLike.querySelector("script[data-letmeknow-runtime]")?.getAttribute("data-letmeknow-page-event");
    if (value === null || value === undefined || value === "") return null;
    const number = Number(value);
    return Number.isSafeInteger(number) && number >= 0 ? number : null;
  }

  function outboxDatabase() {
    outboxDatabasePromise ??= new Promise((resolve, reject) => {
      const request = indexedDB.open("letmeknow-outbox-v2:" + location.origin, 1);
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

  function outboxClear() {
    return outboxTransaction("readwrite", (store) => store.clear());
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
    if (terminal || outboxRetryTimer) return;
    outboxRetryTimer = setTimeout(() => {
      outboxRetryTimer = undefined;
      void flushOutbox();
    }, delay);
  }

  function formForSubmission(id, formId) {
    return (formId && document.getElementById(formId)) || submissionForms.get(id);
  }

  function setSubmissionStatus(id, message, formId) {
    const form = formForSubmission(id, formId);
    if (form instanceof HTMLFormElement) setStatus(form, message);
  }

  async function deliverSubmission(record) {
    try {
      const response = await fetch(submissionPath, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: record.body
      });
      if (response.status === 202) {
        await outboxDelete(record.id);
        setSubmissionStatus(record.id, "Sent. Waiting for an update…", record.form_id);
        submissionForms.delete(record.id);
        return;
      }
      if (response.status >= 400 && response.status < 500) await outboxDelete(record.id);
      setSubmissionStatus(record.id, response.status === 413 ? "Submission is too large." : "Couldn’t send. Try again.", record.form_id);
      if (response.status >= 500) scheduleOutboxFlush();
    } catch {
      setSubmissionStatus(record.id, "Couldn’t send. Try again.", record.form_id);
      scheduleOutboxFlush();
    }
  }

  function flushOutbox() {
    if (terminal || !producerConnected) return Promise.resolve();
    if (outboxFlushPromise) {
      outboxFlushAgain = true;
      return outboxFlushPromise;
    }
    outboxFlushPromise = outboxList().then(async (records) => {
      for (const record of records) await deliverSubmission(record);
    }).catch(() => {}).finally(() => {
      outboxFlushPromise = undefined;
      if (outboxFlushAgain && !terminal) {
        outboxFlushAgain = false;
        void flushOutbox();
      } else {
        outboxFlushAgain = false;
      }
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

  function scheduleReload() {
    if (terminal || reloadScheduled) return;
    reloadScheduled = true;
    setTimeout(() => {
      if (!terminal) location.reload();
    }, 0);
  }

  function targetIsUnique(id) {
    let count = 0;
    for (const element of document.querySelectorAll("[id]")) if (element.id === id) count += 1;
    return count === 1;
  }

  function protectedTarget(target) {
    if (target === document.documentElement || target === document.head || target === document.body) return true;
    if (target.localName === "script" || target.closest("head")) return true;
    const runtime = document.querySelector("script[data-letmeknow-runtime]");
    return runtime !== null && target.contains(runtime);
  }

  function containsScript(node) {
    if (node.nodeType === Node.ELEMENT_NODE && node.localName === "script") return true;
    if (node.nodeType === Node.ELEMENT_NODE && node.localName === "template" && containsScript(node.content)) return true;
    return Array.from(node.childNodes).some(containsScript);
  }

  function replacementFor(target, html) {
    const range = document.createRange();
    range.selectNode(target);
    const fragment = range.createContextualFragment(html);
    const roots = Array.from(fragment.childNodes).filter(node => node.nodeType === Node.ELEMENT_NODE);
    if (roots.length !== 1 || Array.from(fragment.childNodes).some(node => node.nodeType === Node.TEXT_NODE && node.textContent.trim() !== "")) return null;
    const replacement = roots[0];
    if (replacement.id !== target.id || containsScript(fragment)) return null;
    return replacement;
  }

  function applyUpdate(update) {
    if (typeof update.target !== "string" || update.target === "" || typeof update.html !== "string") return false;
    const target = document.getElementById(update.target);
    if (!target || !targetIsUnique(update.target) || protectedTarget(target)) return false;
    const replacement = replacementFor(target, update.html);
    if (!replacement) return false;
    target.replaceWith(replacement);
    pageEvent = update.event_number;
    document.querySelector("script[data-letmeknow-runtime]")?.setAttribute("data-letmeknow-page-event", String(pageEvent));
    return true;
  }

  function receiveUpdate(update) {
    if (terminal || !dynamicPage || !Number.isSafeInteger(update.event_number) || update.event_number <= pageEvent) return;
    if (!applyUpdate(update)) scheduleReload();
  }

  function updateProducer(connected) {
    if (terminal) return;
    const recovered = connected && producerKnown && !producerConnected;
    producerKnown = true;
    producerConnected = connected;
    if (connected) {
      document.documentElement.removeAttribute("data-letmeknow-disconnected");
      clearSystemStatus();
      if (recovered || document.documentElement.getAttribute("data-letmeknow-status-page") === "disconnected") scheduleReload();
      void flushOutbox();
    } else {
      document.documentElement.setAttribute("data-letmeknow-disconnected", "");
      setSystemStatus("Connection lost. Reconnecting…");
    }
  }

  function connect() {
    if (terminal) return;
    reconnectTimer = undefined;
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(protocol + "//" + location.host + socketPath);
    socket.addEventListener("open", () => {
      if (terminal) return;
      const reconnect = hadSocketConnection;
      hadSocketConnection = true;
      clearSystemStatus();
      if (reconnect) scheduleReload();
      void flushOutbox();
    });
    socket.addEventListener("message", (event) => {
      let message;
      try { message = JSON.parse(event.data); } catch { return; }
      if (message.type === "update_ui") receiveUpdate(message);
      else if (message.type === "producer") updateProducer(Boolean(message.connected));
      else if (message.type === "connected") updateProducer(Boolean(message.producer_connected));
      else if (message.type === "closed") {
        terminal = true;
        producerConnected = false;
        if (reconnectTimer) clearTimeout(reconnectTimer);
        if (outboxRetryTimer) clearTimeout(outboxRetryTimer);
        outboxRetryTimer = undefined;
        outboxFlushAgain = false;
        submissionForms.clear();
        void outboxClear().catch(() => {});
        setSystemStatus(message.message || "Session closed");
      }
    });
    socket.addEventListener("close", () => {
      if (terminal) return;
      document.documentElement.setAttribute("data-letmeknow-disconnected", "");
      setSystemStatus("Connection lost. Reconnecting…");
      reconnectTimer = setTimeout(connect, 1000);
    });
    socket.addEventListener("error", () => {});
  }

  function submissionValues(data) {
    const values = Object.create(null);
    for (const [name, value] of data.entries()) {
      if (typeof value !== "string") continue;
      if (!Object.prototype.hasOwnProperty.call(values, name)) values[name] = value;
      else values[name] = Array.isArray(values[name]) ? [...values[name], value] : [values[name], value];
    }
    return values;
  }

  async function submit(form, submitter) {
    if (terminal) {
      setStatus(form, "Session closed.");
      return;
    }
    if (!form.noValidate && !submitter?.formNoValidate && !form.checkValidity()) {
      form.reportValidity();
      return;
    }
    const actionValue = submitter?.hasAttribute("formaction") ? submitter.formAction : form.action;
    const action = new URL(actionValue || location.href, location.href);
    if (action.origin !== location.origin) {
      setStatus(form, "Only same-origin forms can be sent.");
      return;
    }
    const data = new FormData(form, submitter);
    const selectedFile = Array.from(data.values()).some((value) => typeof File !== "undefined" && value instanceof File && value.name);
    if (selectedFile) {
      setStatus(form, "File uploads are not supported.");
      return;
    }
    const id = crypto.randomUUID();
    const formId = form.id || null;
    const trigger = submitter ? { id: submitter.id || null, name: submitter.name || null, value: submitter.value || null } : null;
    const payload = {
      id,
      page_event: pageEvent,
      form_id: formId,
      action: action.pathname + action.search,
      trigger,
      values: submissionValues(data)
    };
    submissionForms.set(id, form);
    setStatus(form, "Sending…");
    try {
      await outboxPut({ id, form_id: formId, body: JSON.stringify(payload) });
      if (terminal) {
        submissionForms.delete(id);
        await outboxDelete(id);
        return;
      }
      void flushOutbox();
    } catch {
      submissionForms.delete(id);
      setStatus(form, "Couldn’t send. Try again.");
    }
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.method.toLowerCase() === "dialog") return;
    event.preventDefault();
    void submit(form, event.submitter);
  });
  connect();
})();
