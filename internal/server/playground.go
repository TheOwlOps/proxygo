package server

import "net/http"

// PlaygroundHandler serves the built-in chat playground: a single
// self-contained HTML page (no build step, no external assets) that
// talks to this server's own /v1 endpoints from the browser. It is
// purely client-side — the handler only returns the page; all model
// loading and chat traffic goes through GET /v1/models and
// POST /v1/chat/completions with the API key the user pastes in.
//
// Parent wiring: mux.Handle("GET /playground", PlaygroundHandler())
func PlaygroundHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(playgroundHTML))
	})
}

const playgroundHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>9Router Playground</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: #f9fafb;
    color: #111827;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 14px;
    line-height: 1.45;
  }
  .topbar {
    background: #ffffff;
    border-bottom: 1px solid #e5e7eb;
  }
  .topbar-inner {
    max-width: 1080px;
    margin: 0 auto;
    padding: 14px 16px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .topbar h1 { font-size: 18px; margin: 0; font-weight: 600; }
  .badge {
    font-size: 11px;
    color: #374151;
    border: 1px solid #e5e7eb;
    border-radius: 999px;
    padding: 1px 8px;
    background: #f9fafb;
  }
  main {
    max-width: 1080px;
    margin: 0 auto;
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .card {
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 16px;
  }
  .card h2 { font-size: 14px; margin: 0 0 12px 0; font-weight: 600; }
  label { display: block; font-size: 12px; font-weight: 600; color: #374151; margin-bottom: 4px; }
  input[type="password"], input[type="number"], select, textarea {
    width: 100%;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    padding: 8px 10px;
    font: inherit;
    background: #ffffff;
    color: #111827;
  }
  textarea { resize: vertical; }
  .row { display: flex; gap: 12px; flex-wrap: wrap; }
  .row > .grow { flex: 1 1 240px; }
  .row > .fixed { flex: 0 0 130px; }
  .btn {
    border: 1px solid #d1d5db;
    background: #ffffff;
    color: #111827;
    border-radius: 6px;
    padding: 8px 14px;
    font: inherit;
    cursor: pointer;
  }
  .btn:hover:not(:disabled) { background: #f3f4f6; }
  .btn:disabled { opacity: 0.5; cursor: default; }
  .btn.primary { background: #111827; border-color: #111827; color: #ffffff; }
  .btn.primary:hover:not(:disabled) { background: #1f2937; }
  .btn.toggle.active { background: #111827; border-color: #111827; color: #ffffff; }
  .key-row { display: flex; gap: 8px; align-items: flex-end; flex-wrap: wrap; }
  .key-row > .grow { flex: 1 1 260px; }
  .note { color: #6b7280; font-size: 12px; margin: 10px 0 0 0; }
  .status { margin-top: 10px; font-size: 13px; min-height: 18px; }
  .status.ok { color: #065f46; }
  .status.error { color: #b91c1c; }
  .mode-toggle { display: flex; gap: 8px; margin-top: 14px; }
  .hidden { display: none !important; }
  .messages {
    display: flex;
    flex-direction: column;
    gap: 10px;
    min-height: 180px;
    max-height: 480px;
    overflow-y: auto;
    padding: 4px 0 12px 0;
  }
  .msg {
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 10px 12px;
    max-width: 92%;
  }
  .msg.user { align-self: flex-end; background: #f9fafb; }
  .msg.assistant { align-self: flex-start; background: #ffffff; }
  .msg.error { border-color: #fca5a5; }
  .msg .role { font-size: 11px; font-weight: 700; color: #6b7280; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 4px; }
  .msg .content { white-space: pre-wrap; word-break: break-word; }
  .msg .stats { font-size: 12px; color: #6b7280; margin-top: 6px; }
  .composer { border-top: 1px solid #e5e7eb; padding-top: 12px; }
  .composer-actions { display: flex; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
  .compare-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }
  @media (max-width: 720px) {
    .compare-grid { grid-template-columns: 1fr; }
    .msg { max-width: 100%; }
  }
  .panel {
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    display: flex;
    flex-direction: column;
    min-height: 220px;
  }
  .panel-head { padding: 10px 12px; border-bottom: 1px solid #e5e7eb; }
  .panel-title { font-size: 12px; font-weight: 700; color: #374151; margin-bottom: 6px; word-break: break-all; }
  .panel-body {
    padding: 10px 12px;
    white-space: pre-wrap;
    word-break: break-word;
    flex: 1;
    overflow-y: auto;
    max-height: 420px;
  }
  .panel-body.error { color: #b91c1c; }
  .panel-stats {
    padding: 8px 12px;
    border-top: 1px solid #e5e7eb;
    font-size: 12px;
    color: #6b7280;
    min-height: 33px;
  }
  .winner {
    margin-top: 12px;
    border: 1px solid #a7f3d0;
    background: #ecfdf5;
    color: #065f46;
    border-radius: 8px;
    padding: 10px 12px;
    font-size: 13px;
  }
</style>
</head>
<body>
<header class="topbar">
  <div class="topbar-inner">
    <h1>9Router Playground</h1>
    <span class="badge">chat tester</span>
  </div>
</header>
<main>
  <section class="card" id="setup-card">
    <h2>Connection</h2>
    <div class="key-row">
      <div class="grow">
        <label for="api-key">API key</label>
        <input type="password" id="api-key" placeholder="sk-..." autocomplete="off" spellcheck="false">
      </div>
      <button id="load-models" class="btn primary" type="button">Load models</button>
    </div>
    <p class="note">Calls go to this server's /v1 endpoints (GET /v1/models and POST /v1/chat/completions), authenticated with the key above as a Bearer token. The key is stored only in your browser (localStorage) and never sent anywhere else.</p>
    <div id="setup-status" class="status"></div>
    <div class="row" style="margin-top:12px;">
      <div class="fixed">
        <label for="temperature">Temperature</label>
        <input type="number" id="temperature" min="0" max="2" step="0.1" value="0.7">
      </div>
      <div class="fixed">
        <label for="max-tokens">Max tokens</label>
        <input type="number" id="max-tokens" min="1" step="1" placeholder="optional">
      </div>
    </div>
    <div class="mode-toggle" role="group" aria-label="Playground mode">
      <button id="mode-single-btn" class="btn toggle active" type="button">Single</button>
      <button id="mode-compare-btn" class="btn toggle" type="button">Compare mode</button>
    </div>
  </section>

  <section class="card" id="single-panel">
    <div class="row" style="margin-bottom:12px;">
      <div class="grow">
        <label for="model">Model</label>
        <select id="model"></select>
      </div>
    </div>
    <div id="messages" class="messages"></div>
    <div class="composer">
      <textarea id="prompt" rows="3" placeholder="Type a message... (Ctrl/Cmd+Enter to send)"></textarea>
      <div class="composer-actions">
        <button id="send" class="btn primary" type="button">Send</button>
        <button id="stop" class="btn" type="button" disabled>Stop</button>
        <button id="clear" class="btn" type="button">Clear chat</button>
      </div>
    </div>
  </section>

  <section class="card hidden" id="compare-panel">
    <div class="compare-grid">
      <div class="panel">
        <div class="panel-head">
          <div class="panel-title" id="panel-a-title">Model A</div>
          <select id="model-a" aria-label="Model A"></select>
        </div>
        <div class="panel-body" id="panel-a-body"></div>
        <div class="panel-stats" id="panel-a-stats">Idle</div>
      </div>
      <div class="panel">
        <div class="panel-head">
          <div class="panel-title" id="panel-b-title">Model B</div>
          <select id="model-b" aria-label="Model B"></select>
        </div>
        <div class="panel-body" id="panel-b-body"></div>
        <div class="panel-stats" id="panel-b-stats">Idle</div>
      </div>
    </div>
    <div id="winner" class="winner hidden"></div>
    <div class="composer">
      <textarea id="compare-prompt" rows="3" placeholder="One prompt, sent to both models... (Ctrl/Cmd+Enter to send)"></textarea>
      <div class="composer-actions">
        <button id="compare-send" class="btn primary" type="button">Send to both</button>
        <button id="compare-stop" class="btn" type="button" disabled>Stop both</button>
      </div>
    </div>
  </section>
</main>
<script>
(function () {
  "use strict";

  var LS_KEY = "9router-playground-api-key";

  function el(id) { return document.getElementById(id); }
  var keyInput = el("api-key");
  var statusEl = el("setup-status");
  var tempInput = el("temperature");
  var maxTokensInput = el("max-tokens");
  var modelSel = el("model");
  var modelASel = el("model-a");
  var modelBSel = el("model-b");
  var messagesEl = el("messages");
  var promptInput = el("prompt");
  var sendBtn = el("send");
  var stopBtn = el("stop");
  var comparePromptInput = el("compare-prompt");
  var compareSendBtn = el("compare-send");
  var compareStopBtn = el("compare-stop");
  var winnerEl = el("winner");

  var history = [];
  var singleAbort = null;
  var compareAborts = [];

  function getKey() { return keyInput.value.trim(); }

  function saveKey() {
    try { localStorage.setItem(LS_KEY, getKey()); } catch (e) { /* storage unavailable */ }
  }

  function setStatus(msg, isError) {
    statusEl.textContent = msg || "";
    statusEl.className = "status" + (msg ? (isError ? " error" : " ok") : "");
  }

  function tempValue() {
    var v = parseFloat(tempInput.value);
    return isNaN(v) ? null : v;
  }

  function maxTokensValue() {
    var v = parseInt(maxTokensInput.value, 10);
    return isNaN(v) || v <= 0 ? null : v;
  }

  function fillSelect(sel, ids) {
    var prev = sel.value;
    sel.innerHTML = "";
    for (var i = 0; i < ids.length; i++) {
      var opt = document.createElement("option");
      opt.value = ids[i];
      opt.textContent = ids[i];
      sel.appendChild(opt);
    }
    if (prev && ids.indexOf(prev) >= 0) sel.value = prev;
  }

  function loadModels() {
    var key = getKey();
    if (!key) {
      setStatus("Enter an API key first, then load models.", true);
      keyInput.focus();
      return;
    }
    saveKey();
    setStatus("Loading models...");
    fetch("/v1/models", { headers: { "Authorization": "Bearer " + key } })
      .then(function (res) {
        if (res.status === 401) {
          throw new Error("Invalid API key (401 Unauthorized). Check the key and try again.");
        }
        if (!res.ok) throw new Error("Loading models failed: HTTP " + res.status);
        return res.json();
      })
      .then(function (data) {
        var list = (data && data.data) || [];
        var ids = [];
        for (var i = 0; i < list.length; i++) {
          if (list[i] && list[i].id) ids.push(list[i].id);
        }
        if (ids.length === 0) {
          setStatus("The server returned no models for this key.", true);
          return;
        }
        fillSelect(modelSel, ids);
        fillSelect(modelASel, ids);
        fillSelect(modelBSel, ids);
        if (ids.length > 1 && modelASel.value === modelBSel.value) {
          modelBSel.value = ids[1];
        }
        setStatus("Loaded " + ids.length + " models.");
      })
      .catch(function (err) {
        setStatus("Could not load models: " + err.message, true);
      });
  }

  function httpErrorMessage(status, text) {
    try {
      var j = JSON.parse(text);
      if (j && j.error && j.error.message) return j.error.message;
      if (j && j.message) return j.message;
    } catch (e) { /* not JSON */ }
    var trimmed = (text || "").trim();
    return "HTTP " + status + (trimmed ? ": " + trimmed.slice(0, 200) : "");
  }

  function statsText(result) {
    var parts = [result.latencyMs + " ms"];
    if (result.usage) {
      var u = result.usage;
      var total = u.total_tokens;
      if (typeof total !== "number") {
        total = (u.prompt_tokens || 0) + (u.completion_tokens || 0);
      }
      parts.push("tokens: " + (u.prompt_tokens || 0) + " in / " +
        (u.completion_tokens || 0) + " out / " + total + " total");
    }
    return parts.join("  ·  ");
  }

  // Streams one chat completion. Calls onToken(text) per chunk and
  // resolves to {usage, latencyMs}. Rejects with an Error on failure.
  function streamChat(opts) {
    var body = {
      model: opts.model,
      messages: opts.messages,
      stream: true,
      stream_options: { include_usage: true }
    };
    if (opts.temperature !== null) body.temperature = opts.temperature;
    if (opts.maxTokens !== null) body.max_tokens = opts.maxTokens;

    var headers = { "Content-Type": "application/json" };
    var key = getKey();
    if (key) headers["Authorization"] = "Bearer " + key;

    var started = performance.now();
    var usage = null;

    return fetch("/v1/chat/completions", {
      method: "POST",
      headers: headers,
      body: JSON.stringify(body),
      signal: opts.signal
    }).then(function (res) {
      if (res.status === 401) {
        return res.text().then(function () {
          throw new Error("Invalid API key (401 Unauthorized). Reload models with a valid key.");
        });
      }
      if (!res.ok) {
        return res.text().then(function (t) {
          throw new Error(httpErrorMessage(res.status, t));
        });
      }
      var ct = res.headers.get("content-type") || "";
      if (ct.indexOf("text/event-stream") < 0 || !res.body || !res.body.getReader) {
        // Non-streaming fallback: whole JSON response at once.
        return res.json().then(function (j) {
          var txt = "";
          if (j.choices && j.choices[0] && j.choices[0].message) {
            txt = j.choices[0].message.content || "";
          }
          if (j.usage) usage = j.usage;
          if (txt) opts.onToken(txt);
          return { usage: usage, latencyMs: Math.round(performance.now() - started) };
        });
      }
      var reader = res.body.getReader();
      var decoder = new TextDecoder();
      var buffer = "";
      var streamError = null;

      function handlePayload(payload) {
        if (payload === "[DONE]") return;
        var chunk;
        try { chunk = JSON.parse(payload); } catch (e) { return; }
        if (chunk.usage) usage = chunk.usage;
        if (chunk.error) {
          streamError = (chunk.error && chunk.error.message) || "stream error";
          return;
        }
        var ch = chunk.choices && chunk.choices[0];
        if (!ch) return;
        var deltaText = "";
        if (ch.delta && typeof ch.delta.content === "string") deltaText = ch.delta.content;
        else if (ch.delta && typeof ch.delta.text === "string") deltaText = ch.delta.text;
        else if (typeof ch.text === "string") deltaText = ch.text;
        if (deltaText) opts.onToken(deltaText);
      }

      function pump() {
        return reader.read().then(function (r) {
          if (r.done) {
            if (buffer.trim()) {
              var rest = buffer.split("\n");
              for (var i = 0; i < rest.length; i++) {
                var line = rest[i].trim();
                if (line.indexOf("data:") === 0) handlePayload(line.slice(5).trim());
              }
            }
            if (streamError) throw new Error(streamError);
            return { usage: usage, latencyMs: Math.round(performance.now() - started) };
          }
          buffer += decoder.decode(r.value, { stream: true });
          var lines = buffer.split("\n");
          buffer = lines.pop();
          for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if (line.indexOf("data:") === 0) handlePayload(line.slice(5).trim());
          }
          return pump();
        });
      }
      return pump();
    });
  }

  // ---- Single mode ----

  function appendMessage(role, text) {
    var wrap = document.createElement("div");
    wrap.className = "msg " + role;
    var roleEl = document.createElement("div");
    roleEl.className = "role";
    roleEl.textContent = role === "user" ? "You" : "Assistant";
    var contentEl = document.createElement("div");
    contentEl.className = "content";
    contentEl.textContent = text;
    var statsEl = document.createElement("div");
    statsEl.className = "stats";
    wrap.appendChild(roleEl);
    wrap.appendChild(contentEl);
    wrap.appendChild(statsEl);
    messagesEl.appendChild(wrap);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    return { wrap: wrap, content: contentEl, stats: statsEl };
  }

  function setSending(on) {
    sendBtn.disabled = on;
    stopBtn.disabled = !on;
  }

  function sendSingle() {
    var model = modelSel.value;
    var text = promptInput.value.trim();
    if (!model) {
      setStatus("Load models and pick a model first.", true);
      return;
    }
    if (!text || singleAbort) return;
    promptInput.value = "";
    history.push({ role: "user", content: text });
    appendMessage("user", text);
    var bubble = appendMessage("assistant", "");
    bubble.stats.textContent = "streaming...";
    singleAbort = new AbortController();
    setSending(true);
    var full = "";
    streamChat({
      model: model,
      messages: history,
      temperature: tempValue(),
      maxTokens: maxTokensValue(),
      signal: singleAbort.signal,
      onToken: function (t) {
        full += t;
        bubble.content.textContent = full;
        messagesEl.scrollTop = messagesEl.scrollHeight;
      }
    }).then(function (res) {
      history.push({ role: "assistant", content: full });
      bubble.stats.textContent = statsText(res);
    }).catch(function (err) {
      if (err && err.name === "AbortError") {
        bubble.stats.textContent = "stopped";
        if (full) history.push({ role: "assistant", content: full });
      } else {
        bubble.wrap.className += " error";
        bubble.content.textContent = (full ? full + "\n" : "") + "Error: " + (err && err.message ? err.message : err);
        bubble.stats.textContent = "";
      }
    }).then(function () {
      singleAbort = null;
      setSending(false);
    });
  }

  // ---- Compare mode ----

  function setCompareSending(on) {
    compareSendBtn.disabled = on;
    compareStopBtn.disabled = !on;
  }

  function runPanel(which, model, ctrl, messages) {
    var bodyEl = el("panel-" + which + "-body");
    var statsEl = el("panel-" + which + "-stats");
    var titleEl = el("panel-" + which + "-title");
    titleEl.textContent = model;
    bodyEl.textContent = "";
    bodyEl.className = "panel-body";
    statsEl.textContent = "streaming...";
    var full = "";
    return streamChat({
      model: model,
      messages: messages,
      temperature: tempValue(),
      maxTokens: maxTokensValue(),
      signal: ctrl.signal,
      onToken: function (t) {
        full += t;
        bodyEl.textContent = full;
        bodyEl.scrollTop = bodyEl.scrollHeight;
      }
    }).then(function (res) {
      var total = null;
      if (res.usage) {
        total = typeof res.usage.total_tokens === "number"
          ? res.usage.total_tokens
          : (res.usage.prompt_tokens || 0) + (res.usage.completion_tokens || 0);
      }
      statsEl.textContent = statsText(res);
      return { ok: true, model: model, latencyMs: res.latencyMs, totalTokens: total };
    }).catch(function (err) {
      if (err && err.name === "AbortError") {
        statsEl.textContent = "stopped";
        return { ok: false, model: model, aborted: true };
      }
      bodyEl.className = "panel-body error";
      bodyEl.textContent = (full ? full + "\n" : "") + "Error: " + (err && err.message ? err.message : err);
      statsEl.textContent = "failed";
      return { ok: false, model: model };
    });
  }

  function showWinner(results) {
    var a = results[0];
    var b = results[1];
    if (!a.ok || !b.ok) {
      winnerEl.classList.add("hidden");
      winnerEl.textContent = "";
      return;
    }
    var hints = [];
    if (a.latencyMs !== b.latencyMs) {
      var faster = a.latencyMs < b.latencyMs ? a : b;
      var slower = a.latencyMs < b.latencyMs ? b : a;
      hints.push("Faster: " + faster.model + " (" + faster.latencyMs + " ms vs " + slower.latencyMs + " ms)");
    } else {
      hints.push("Same latency (" + a.latencyMs + " ms)");
    }
    if (a.totalTokens !== null && b.totalTokens !== null && a.totalTokens !== b.totalTokens) {
      var fewer = a.totalTokens < b.totalTokens ? a : b;
      hints.push("Fewer tokens: " + fewer.model + " (" + fewer.totalTokens + " total)");
    }
    winnerEl.textContent = hints.join("  ·  ");
    winnerEl.classList.remove("hidden");
  }

  function sendCompare() {
    var a = modelASel.value;
    var b = modelBSel.value;
    var text = comparePromptInput.value.trim();
    if (!a || !b) {
      setStatus("Load models and pick both models first.", true);
      return;
    }
    if (!text || compareAborts.length) return;
    comparePromptInput.value = "";
    winnerEl.classList.add("hidden");
    winnerEl.textContent = "";
    compareAborts = [new AbortController(), new AbortController()];
    setCompareSending(true);
    var messages = [{ role: "user", content: text }];
    Promise.all([
      runPanel("a", a, compareAborts[0], messages),
      runPanel("b", b, compareAborts[1], messages)
    ]).then(function (results) {
      compareAborts = [];
      setCompareSending(false);
      showWinner(results);
    });
  }

  // ---- Wiring ----

  function setMode(mode) {
    el("single-panel").classList.toggle("hidden", mode !== "single");
    el("compare-panel").classList.toggle("hidden", mode !== "compare");
    el("mode-single-btn").classList.toggle("active", mode === "single");
    el("mode-compare-btn").classList.toggle("active", mode === "compare");
  }

  el("mode-single-btn").addEventListener("click", function () { setMode("single"); });
  el("mode-compare-btn").addEventListener("click", function () { setMode("compare"); });
  el("load-models").addEventListener("click", loadModels);
  keyInput.addEventListener("change", saveKey);
  sendBtn.addEventListener("click", sendSingle);
  stopBtn.addEventListener("click", function () {
    if (singleAbort) singleAbort.abort();
  });
  el("clear").addEventListener("click", function () {
    history = [];
    messagesEl.innerHTML = "";
  });
  compareSendBtn.addEventListener("click", sendCompare);
  compareStopBtn.addEventListener("click", function () {
    for (var i = 0; i < compareAborts.length; i++) compareAborts[i].abort();
  });

  function ctrlEnter(e, fn) {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      fn();
    }
  }
  promptInput.addEventListener("keydown", function (e) { ctrlEnter(e, sendSingle); });
  comparePromptInput.addEventListener("keydown", function (e) { ctrlEnter(e, sendCompare); });

  // Init: restore the saved key and load models with it if present.
  try {
    var saved = localStorage.getItem(LS_KEY);
    if (saved) {
      keyInput.value = saved;
      loadModels();
    }
  } catch (e) { /* storage unavailable */ }
})();
</script>
</body>
</html>
`
