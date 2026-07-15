"use strict";

const rowsEl = document.getElementById("rows");
const emptyEl = document.getElementById("empty");
const detailEl = document.getElementById("detail");
const statusEl = document.getElementById("status");
const countEl = document.getElementById("count");
const searchEl = document.getElementById("search");
const onlyErrorsEl = document.getElementById("onlyErrors");

const btnCapture = document.getElementById("btnCapture");
const btnClear = document.getElementById("btnClear");
const btnSysProxy = document.getElementById("btnSysProxy");
const btnCertInstall = document.getElementById("btnCertInstall");
const btnTheme = document.getElementById("btnTheme");
const proxyAddrEl = document.getElementById("proxyAddr");
const colFilterEls = [...document.querySelectorAll(".col-filter")];

// id -> summary
const sessions = new Map();
let selectedId = null;
let activeTab = "overview";
let captureEnabled = true;
let sysProxyEnabled = false;
let certTrusted = false;

// Per-column filter predicates (null = no filter). See makeMatcher for syntax.
const columnFilters = { method: null, status: null, host: null, path: null, type: null };
let searchMatcher = null;

// Compiles filter text into a predicate, DevTools-style:
//   /pattern/  → regular expression (case-insensitive)
//   a*b        → wildcard, * matches any run of characters
//   plain text → case-insensitive substring
// Invalid regex falls back to substring so a half-typed pattern never blanks the list.
// anchorWildcards: column filters glob against the whole cell value (so "2*" means
// 2xx, not "contains a 2"); the global search matches against a concatenated
// haystack where full-match anchoring would never succeed, so it stays unanchored.
function makeMatcher(text, anchorWildcards = false) {
  const q = text.trim();
  if (!q) return null;
  if (q.length > 2 && q.startsWith("/") && q.endsWith("/")) {
    try {
      const re = new RegExp(q.slice(1, -1), "i");
      return s => re.test(s);
    } catch { /* fall through to substring */ }
  }
  if (q.includes("*")) {
    const body = q.split("*").map(p => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*");
    const re = new RegExp(anchorWildcards ? `^${body}$` : body, "i");
    return s => re.test(s);
  }
  const needle = q.toLowerCase();
  return s => s.toLowerCase().includes(needle);
}

// ---------- theme ----------
// Initial theme is set by an inline script in index.html (saved choice, else OS
// preference). Clicking the toggle saves an explicit choice; until then the app
// live-follows the OS setting. Storage access is guarded: when the browser blocks
// it (e.g. "block all cookies"), the toggle still works, just without persistence.
function getSavedTheme() {
  try { return localStorage.getItem("theme"); } catch { return null; }
}
function saveTheme(theme) {
  try { localStorage.setItem("theme", theme); } catch { /* not persisted */ }
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const light = theme === "light";
  btnTheme.textContent = light ? "🌙" : "☀️";
  btnTheme.title = light ? "Switch to dark theme" : "Switch to light theme";
}

btnTheme.addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  saveTheme(next);
  applyTheme(next);
});

matchMedia("(prefers-color-scheme: light)").addEventListener("change", e => {
  if (!getSavedTheme()) applyTheme(e.matches ? "light" : "dark");
});

applyTheme(document.documentElement.dataset.theme);

// ---------- helpers ----------
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtSize(n) {
  if (n == null || n < 0) return "";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(2) + " MB";
}
function fmtTime(ms) {
  if (ms == null || ms <= 0) return "";
  return ms < 1000 ? Math.round(ms) + " ms" : (ms / 1000).toFixed(2) + " s";
}
function fmtClock(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const p = (n, w = 2) => String(n).padStart(w, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}
function fmtDateTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  return d.toLocaleString() + "." + String(d.getMilliseconds()).padStart(3, "0");
}
function statusClass(s) {
  if (s.Error) return "st-err";
  if (!s.HasResponse) return "st-pending";
  const c = Math.floor(s.StatusCode / 100);
  return "st-" + c;
}
function statusText(s) {
  if (s.Error) return "ERR";
  if (!s.HasResponse) return "…";
  return s.StatusCode;
}
function shortType(ct) {
  if (!ct) return "";
  return ct.split(";")[0].trim();
}

// ---------- list rendering ----------
function matchesFilter(s) {
  if (onlyErrorsEl.checked && !s.Error && !(s.HasResponse && s.StatusCode >= 400)) return false;

  // Per-column filters
  if (columnFilters.method && !columnFilters.method(String(s.Method ?? ""))) return false;
  if (columnFilters.status && !columnFilters.status(String(statusText(s)))) return false;
  if (columnFilters.host && !columnFilters.host(String(s.Host ?? ""))) return false;
  if (columnFilters.path && !columnFilters.path(String(s.Path ?? ""))) return false;
  if (columnFilters.type && !columnFilters.type(String(shortType(s.ResponseContentType) ?? ""))) return false;

  if (!searchMatcher) return true;
  return searchMatcher(s.Url + " " + s.Host + " " + s.Method + " " + s.StatusCode + " " + (s.ResponseContentType || ""));
}

function rowHtml(s) {
  return `<tr data-id="${s.Id}" class="${s.Id === selectedId ? "selected" : ""}">
    <td class="c-idx">${s.Index}</td>
    <td class="c-clock" title="${esc(fmtDateTime(s.StartedUtc))}">${esc(fmtClock(s.StartedUtc))}</td>
    <td class="c-method"><span class="method m-${esc(s.Method)}">${esc(s.Method)}</span></td>
    <td class="c-status"><span class="${statusClass(s)}">${esc(statusText(s))}</span></td>
    <td class="c-host"><span class="host scheme-${esc(s.Scheme)}">${esc(s.Host)}</span></td>
    <td class="c-path" title="${esc(s.Path)}">${esc(s.Path)}</td>
    <td class="c-type">${esc(shortType(s.ResponseContentType))}</td>
    <td class="c-size">${fmtSize(s.ResponseBodySize)}</td>
    <td class="c-time">${fmtTime(s.DurationMs)}</td>
  </tr>`;
}

function renderList() {
  const items = [...sessions.values()].filter(matchesFilter).sort((a, b) => b.Index - a.Index);
  rowsEl.innerHTML = items.map(rowHtml).join("");
  emptyEl.style.display = sessions.size === 0 ? "flex" : "none";
  countEl.textContent = items.length;
}

function upsert(summary) {
  // When paused, freeze the list: ignore any in-flight broadcasts so the UI
  // visibly stops updating (mirrors Fiddler's pause behaviour).
  if (!captureEnabled) return;
  sessions.set(summary.Id, summary);
  // Targeted DOM update if visible, else full render.
  const existing = rowsEl.querySelector(`tr[data-id="${summary.Id}"]`);
  if (existing && matchesFilter(summary)) {
    existing.outerHTML = rowHtml(summary);
  } else {
    renderList();
  }
  countEl.textContent = [...sessions.values()].filter(matchesFilter).length;
  if (summary.Id === selectedId) loadDetail(selectedId);
}

// ---------- detail rendering ----------
function tryPretty(body, contentType) {
  if (body == null) return null;
  const ct = (contentType || "").toLowerCase();
  const looksJson = ct.includes("json") || /^\s*[\[{]/.test(body);
  if (looksJson) {
    try { return JSON.stringify(JSON.parse(body), null, 2); } catch { /* not json */ }
  }
  return body;
}

function headersTable(headers) {
  if (!headers || headers.length === 0) return `<div class="note">No headers.</div>`;
  return `<table class="headers">${headers.map(h =>
    `<tr><td class="k">${esc(h.Name)}</td><td>${esc(h.Value)}</td></tr>`).join("")}</table>`;
}

function bodyBlock(body, isBinary, contentType, label) {
  if (isBinary) return `<div class="note">${label} body is binary or too large to display (${esc(shortType(contentType)) || "binary"}).</div>`;
  if (body == null || body === "") return `<div class="note">No ${label.toLowerCase()} body.</div>`;
  const pretty = tryPretty(body, contentType);
  return `<div class="copybar"><button class="btn" data-copy="${label}">Copy</button></div><pre class="body" data-bodylabel="${label}">${esc(pretty)}</pre>`;
}

function toCurl(s) {
  let c = `curl -X ${s.Method} '${s.Url}'`;
  for (const h of s.RequestHeaders || []) {
    if (/^(host|content-length|connection|proxy-connection)$/i.test(h.Name)) continue;
    c += ` \\\n  -H '${h.Name}: ${h.Value.replace(/'/g, "'\\''")}'`;
  }
  if (s.RequestBody && !s.RequestBodyIsBinary) {
    c += ` \\\n  --data-raw '${s.RequestBody.replace(/'/g, "'\\''")}'`;
  }
  return c;
}

let currentDetail = null;

function renderDetail(s) {
  currentDetail = s;
  const tabs = ["overview", "request", "response", "raw"];
  const tabLabels = { overview: "Overview", request: "Request", response: "Response", raw: "Raw" };

  let body = "";
  if (activeTab === "overview") {
    body = `
      <div class="section-title">General</div>
      <table class="headers">
        <tr><td class="k">URL</td><td>${esc(s.Url)}</td></tr>
        <tr><td class="k">Method</td><td>${esc(s.Method)}</td></tr>
        <tr><td class="k">Host</td><td>${esc(s.Host)}</td></tr>
        <tr><td class="k">Scheme</td><td>${esc(s.Scheme)}</td></tr>
        <tr><td class="k">Started</td><td>${esc(fmtDateTime(s.StartedUtc)) || "—"}</td></tr>
        <tr><td class="k">Status</td><td>${s.HasResponse ? esc(s.StatusCode + " " + (s.StatusText || "")) : "(pending)"}</td></tr>
        <tr><td class="k">Duration</td><td>${esc(fmtTime(s.DurationMs)) || "—"}</td></tr>
        <tr><td class="k">Req. type</td><td>${esc(s.RequestContentType || "—")}</td></tr>
        <tr><td class="k">Resp. type</td><td>${esc(s.ResponseContentType || "—")}</td></tr>
        <tr><td class="k">Resp. size</td><td>${esc(fmtSize(s.ResponseBodySize)) || "—"}</td></tr>
        ${s.Error ? `<tr><td class="k">Error</td><td><span class="st-err">${esc(s.Error)}</span></td></tr>` : ""}
      </table>`;
  } else if (activeTab === "request") {
    body = `<div class="section-title">Request headers</div>${headersTable(s.RequestHeaders)}
      <div class="section-title" style="margin-top:16px">Request body</div>
      ${bodyBlock(s.RequestBody, s.RequestBodyIsBinary, s.RequestContentType, "Request")}`;
  } else if (activeTab === "response") {
    if (!s.HasResponse) {
      body = `<div class="note">Awaiting response…</div>`;
    } else {
      body = `<div class="section-title">Response headers</div>${headersTable(s.ResponseHeaders)}
        <div class="section-title" style="margin-top:16px">Response body</div>
        ${bodyBlock(s.ResponseBody, s.ResponseBodyIsBinary, s.ResponseContentType, "Response")}`;
    }
  } else if (activeTab === "raw") {
    const reqLine = `${s.Method} ${s.Path} ${s.Scheme.toUpperCase()}`;
    const reqHeaders = (s.RequestHeaders || []).map(h => `${h.Name}: ${h.Value}`).join("\n");
    let raw = `${reqLine}\nHost: ${s.Host}\n${reqHeaders}`;
    if (s.RequestBody && !s.RequestBodyIsBinary) raw += `\n\n${s.RequestBody}`;
    if (s.HasResponse) {
      const respHeaders = (s.ResponseHeaders || []).map(h => `${h.Name}: ${h.Value}`).join("\n");
      raw += `\n\n──────── RESPONSE ────────\nHTTP ${s.StatusCode} ${s.StatusText}\n${respHeaders}`;
      if (s.ResponseBody && !s.ResponseBodyIsBinary) raw += `\n\n${s.ResponseBody}`;
    }
    body = `<div class="copybar"><button class="btn" data-copyraw="1">Copy</button></div><pre class="body" id="rawPre">${esc(raw)}</pre>`;
  }

  detailEl.innerHTML = `
    <div class="detail-head">
      <div class="detail-url"><span class="method m-${esc(s.Method)}">${esc(s.Method)}</span> ${esc(s.Url)}</div>
      <div class="detail-meta">
        <span class="${statusClass(s)}">${s.HasResponse ? esc(s.StatusCode) : "pending"}</span>
        <span>${esc(shortType(s.ResponseContentType) || "")}</span>
        <span>${esc(fmtSize(s.ResponseBodySize))}</span>
        <span>${esc(fmtTime(s.DurationMs))}</span>
      </div>
      <div class="detail-actions">
        <button class="btn" id="btnCurl">📋 Copy as cURL</button>
      </div>
    </div>
    <div class="tabs">
      ${tabs.map(t => `<div class="tab ${t === activeTab ? "active" : ""}" data-tab="${t}">${tabLabels[t]}</div>`).join("")}
    </div>
    <div class="tab-body">${body}</div>`;

  detailEl.querySelectorAll(".tab").forEach(t =>
    t.addEventListener("click", () => { activeTab = t.dataset.tab; renderDetail(currentDetail); }));

  const btnCurl = document.getElementById("btnCurl");
  if (btnCurl) btnCurl.addEventListener("click", () => copy(toCurl(s), btnCurl));

  detailEl.querySelectorAll("[data-copy]").forEach(b =>
    b.addEventListener("click", () => {
      const pre = b.parentElement.nextElementSibling;
      copy(pre.textContent, b);
    }));
  const rawBtn = detailEl.querySelector("[data-copyraw]");
  if (rawBtn) rawBtn.addEventListener("click", () => copy(document.getElementById("rawPre").textContent, rawBtn));
}

function copy(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const old = btn.textContent; btn.textContent = "✓ Copied";
    setTimeout(() => (btn.textContent = old), 1200);
  });
}

async function loadDetail(id) {
  try {
    const r = await fetch(`/api/sessions/${id}`);
    if (!r.ok) return;
    const full = await r.json();
    renderDetail(full);
  } catch { /* ignore */ }
}

// ---------- interactions ----------
rowsEl.addEventListener("click", e => {
  const tr = e.target.closest("tr");
  if (!tr) return;
  selectedId = tr.dataset.id;
  rowsEl.querySelectorAll("tr.selected").forEach(x => x.classList.remove("selected"));
  tr.classList.add("selected");
  activeTab = "overview";
  loadDetail(selectedId);
});

// Single place that turns whatever is in the filter boxes into active matchers —
// used for typing, and for values the browser restores on reload/session-restore.
function refreshFilters() {
  searchMatcher = makeMatcher(searchEl.value);
  for (const inp of colFilterEls) columnFilters[inp.dataset.col] = makeMatcher(inp.value, true);
}

searchEl.addEventListener("input", () => { refreshFilters(); renderList(); });
onlyErrorsEl.addEventListener("change", renderList);

colFilterEls.forEach(inp => {
  inp.title = "text, * wildcard, or /regex/";
  inp.addEventListener("input", () => { refreshFilters(); renderList(); });
  // Don't let clicks on the filter inputs trigger header/sort behaviour.
  inp.addEventListener("click", e => e.stopPropagation());
});
refreshFilters();
// Firefox restores form values after the load event — re-apply them when that happens.
window.addEventListener("pageshow", () => { refreshFilters(); renderList(); });

btnClear.addEventListener("click", async () => {
  await fetch("/api/clear", { method: "POST" });
});

btnCapture.addEventListener("click", async () => {
  const target = !captureEnabled;
  // Optimistic update so the button responds instantly…
  captureEnabled = target;
  updateCaptureBtn();
  try {
    const r = await fetch("/api/capture", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: target })
    });
    // …then reconcile with the server's authoritative value.
    if (r.ok) captureEnabled = (await r.json()).captureEnabled;
  } catch { /* keep optimistic state */ }
  updateCaptureBtn();
});

btnSysProxy.addEventListener("click", async () => {
  const target = !sysProxyEnabled;
  const r = await fetch("/api/system-proxy", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled: target })
  });
  if (r.ok) { sysProxyEnabled = (await r.json()).systemProxyEnabled; updateSysProxyBtn(); }
});

btnCertInstall.addEventListener("click", async () => {
  const r = await fetch("/api/cert/install", { method: "POST" });
  if (r.ok) { certTrusted = (await r.json()).certTrusted; updateCertBtn(); }
});

function updateCaptureBtn() {
  btnCapture.textContent = captureEnabled ? "⏸ Pause" : "▶ Resume";
  btnCapture.classList.toggle("active", !captureEnabled);
}
function updateSysProxyBtn() {
  btnSysProxy.textContent = "🌐 System Proxy: " + (sysProxyEnabled ? "On" : "Off");
  btnSysProxy.classList.toggle("on", sysProxyEnabled);
}
function updateCertBtn() {
  btnCertInstall.textContent = certTrusted ? "🔒 Cert Trusted ✓" : "🔒 Trust Cert";
  btnCertInstall.classList.toggle("on", certTrusted);
}

// ---------- bootstrap ----------
async function loadStatus() {
  try {
    const r = await fetch("/api/status");
    const s = await r.json();
    captureEnabled = s.captureEnabled;
    sysProxyEnabled = s.systemProxyEnabled;
    certTrusted = s.certTrusted;
    updateCaptureBtn(); updateSysProxyBtn(); updateCertBtn();
    statusEl.textContent = `proxy 127.0.0.1:${s.port} • ${s.count}/${s.capacity}`;
    statusEl.className = "status ok";
    proxyAddrEl.textContent = `http://127.0.0.1:${s.port}`;
  } catch {
    statusEl.textContent = "backend unreachable";
    statusEl.className = "status bad";
  }
}

async function loadExisting() {
  try {
    const r = await fetch("/api/sessions");
    const list = await r.json();
    for (const s of list) sessions.set(s.Id, s);
    renderList();
  } catch { /* ignore */ }
}

const connection = new signalR.HubConnectionBuilder()
  .withUrl("/hub")
  .withAutomaticReconnect()
  .build();

connection.on("newSession", upsert);
connection.on("updateSession", upsert);
connection.on("cleared", () => {
  sessions.clear(); selectedId = null;
  renderList();
  detailEl.innerHTML = `<div class="detail-empty">Select a request to inspect it.</div>`;
});

connection.onreconnecting(() => { statusEl.textContent = "reconnecting…"; statusEl.className = "status bad"; });
connection.onreconnected(() => { loadStatus(); loadExisting(); });

// Resilience: if the live connection isn't up, poll the list so the UI still refreshes.
setInterval(() => {
  if (connection.state !== "Connected") loadExisting();
}, 4000);

async function start() {
  await loadStatus();
  await loadExisting();
  try {
    await connection.start();
    statusEl.className = "status ok";
  } catch {
    statusEl.textContent = "live updates unavailable";
    statusEl.className = "status bad";
  }
}
start();
setInterval(loadStatus, 5000);
