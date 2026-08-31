(() => {
  const socketPath = "/_letmeknow/client";
  const submissionPath = "/_letmeknow/submit";
  let hadSocketConnection = false;
  let reconnectTimer;
  let reloadScheduled = false;
  let terminal = false;
  let producerKnown = false;
  let producerConnected = false;
  const history = readHistory(document);
  const dynamicPage = history !== null;
  let pageEvent = 0;
  const submissionForms = new Map();
  const OUTBOX_RETRY_MS = 1000;
  let outboxDatabasePromise;
  let outboxFlushPromise;
  let outboxFlushAgain = false;
  let outboxRetryTimer;

  function readHistory(documentLike) {
    const elements = documentLike.querySelectorAll("script[data-letmeknow-history]");
    const element = elements[elements.length - 1];
    if (!element) return null;
    try {
      const value = JSON.parse(element.textContent || "");
      if (!Array.isArray(value)) throw new Error("history must be an array");
      return value;
    } catch (error) {
      reportScriptFailure(error);
      return [];
    }
  }

  function outboxDatabase() {
    outboxDatabasePromise ??= new Promise((resolve, reject) => {
      const request = indexedDB.open("letmeknow-outbox-v2:" + location.origin, 1);
      request.onupgradeneeded = () => request.result.createObjectStore("submissions", { keyPath: "id" });
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("could not open submission outbox"));
    }).catch(error => {
      outboxDatabasePromise = undefined;
      throw error;
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
        if (terminal) return;
        setSubmissionStatus(record.id, "Sent. Waiting for an update…", record.form_id);
        submissionForms.delete(record.id);
        return;
      }
      if (response.status >= 400 && response.status < 500) await outboxDelete(record.id);
      if (terminal) return;
      setSubmissionStatus(record.id, response.status === 413 ? "Submission is too large." : "Couldn’t send. Try again.", record.form_id);
      if (response.status >= 500) scheduleOutboxFlush();
    } catch {
      if (terminal) return;
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

  function reportScriptFailure(error) {
    console.error("LetMeKnow UI script failed", error);
    setSystemStatus("A page update failed. Waiting for a correction…");
  }

  function setPageEvent(eventNumber) {
    pageEvent = eventNumber;
  }

  function runScript(event) {
    setPageEvent(event.event_number);
    try {
      Function(event.script).call(window);
      clearSystemStatus();
    } catch (error) {
      reportScriptFailure(error);
    }
  }

  function runHistory() {
    for (const event of history) {
      if (!event || typeof event !== "object" || !Number.isSafeInteger(event.event_number) || event.event_number < 0 || typeof event.script !== "string") {
        reportScriptFailure(new Error("invalid page history event"));
        continue;
      }
      runScript(event);
    }
  }

  function receiveUpdate(update) {
    if (terminal || !dynamicPage || !Number.isSafeInteger(update.event_number) || update.event_number <= pageEvent || typeof update.script !== "string") return;
    runScript({ event_number: update.event_number, script: update.script });
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
      if (message.type === "run_ui") receiveUpdate(message);
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
    if (event.defaultPrevented) return;
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.method.toLowerCase() === "dialog") return;
    event.preventDefault();
    void submit(form, event.submitter);
  });
  if (dynamicPage) runHistory();
  connect();
})();
