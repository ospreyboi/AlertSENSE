"use strict";
// AlertSense dashboard.
// SECURITY: alert fields (URLs, user agents, descriptions) are attacker-controlled.
// Every value is inserted with textContent - never as HTML - so payloads stay harmless text.

const $ = (id) => document.getElementById(id);
const STORE = "alertsense_key";
let KEY = "";
try { KEY = sessionStorage.getItem(STORE) || ""; } catch (_) { /* storage blocked */ }
let selectedId = null;
let timer = null;
let lastAlerts = [];

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}

function safeJson(s, fallback) {
  try { return s ? JSON.parse(s) : fallback; } catch (_) { return fallback; }
}

function fmtTime(s) {
  if (!s) return "-";
  const iso = /Z$|[+-]\d\d:\d\d$/.test(s) ? s : s + "Z";   // stored in UTC
  return new Date(iso).toLocaleString();
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { "X-API-Key": KEY, "Content-Type": "application/json" },
  });
  if (res.status === 401) { showLogin("Invalid or missing API key"); throw new Error("unauthorized"); }
  if (!res.ok) throw new Error(`${res.status}: ${(await res.text()).slice(0, 200)}`);
  return res.json();
}

function showLogin(msg) {
  clearInterval(timer);
  $("app").hidden = true;
  $("login").hidden = false;
  $("login-msg").textContent = msg || "";
}

function showApp() {
  $("login").hidden = true;
  $("app").hidden = false;
  refresh();
  clearInterval(timer);
  timer = setInterval(refresh, 5000);
}

$("keyform").addEventListener("submit", (e) => {
  e.preventDefault();
  KEY = $("key").value.trim();
  try { sessionStorage.setItem(STORE, KEY); } catch (_) { /* ignore */ }
  $("key").value = "";
  showApp();
});

$("logout").addEventListener("click", () => {
  try { sessionStorage.removeItem(STORE); } catch (_) { /* ignore */ }
  KEY = "";
  showLogin("");
});

$("f-status").addEventListener("change", refresh);

async function refresh() {
  try {
    const status = $("f-status").value;
    const q = status ? `&status=${encodeURIComponent(status)}` : "";
    const [stats, alerts, blocks] = await Promise.all([
      api("/stats"), api(`/alerts?sort=risk&limit=100${q}`), api("/blocks"),
    ]);
    lastAlerts = alerts;
    renderStats(stats);
    renderAlerts(alerts);
    renderBlocks(blocks);
    renderTopIps(stats.top_ips);
    const sel = alerts.find((a) => a.id === selectedId);
    if (sel) renderDetail(sel);
    $("updated").textContent = "Updated " + new Date().toLocaleTimeString();
    $("error").textContent = "";
  } catch (err) {
    if (err.message !== "unauthorized") $("error").textContent = "⚠ " + err.message;
  }
}

function renderStats(s) {
  $("k-open").textContent = s.open;
  $("k-critical").textContent = s.by_priority.critical || 0;
  $("k-high").textContent = s.by_priority.high || 0;
  $("k-24h").textContent = s.last_24h;
  $("k-blocks").textContent = s.active_blocks;
  $("mode").textContent = s.auto_block_score ? `AUTO-BLOCK ≥ ${s.auto_block_score}` : "APPROVAL MODE";
  $("mode").className = "pill " + (s.auto_block_score ? "p-high" : "p-low");
}

function actionButton(label, cls, onClick) {
  const b = el("button", label, cls);
  b.type = "button";
  b.addEventListener("click", (e) => { e.stopPropagation(); onClick(); });
  return b;
}

function renderAlerts(alerts) {
  const rows = alerts.map((a) => {
    const tr = el("tr");
    if (a.id === selectedId) tr.className = "selected";
    const prio = el("td");
    prio.append(el("span", a.priority || "pending", "pill p-" + (a.priority || "none")));
    tr.append(
      el("td", a.risk_score == null ? "…" : Math.round(a.risk_score), "num"),
      prio,
      el("td", a.rule_name),
      el("td", a.src_ip || "-", "mono"),
      el("td", a.status),
      el("td", fmtTime(a.timestamp), "muted"),
    );
    const act = el("td", null, "actions");
    if (a.src_ip && a.status !== "blocked") act.append(actionButton("Block", "danger", () => blockAlert(a)));
    if (!["resolved", "false_positive"].includes(a.status)) {
      act.append(actionButton("FP", "", () => setStatus(a.id, "false_positive")));
      act.append(actionButton("Resolve", "", () => setStatus(a.id, "resolved")));
    }
    tr.append(act);
    tr.addEventListener("click", () => { selectedId = a.id; renderDetail(a); renderAlerts(lastAlerts); });
    return tr;
  });
  $("alerts").replaceChildren(...rows);
  $("empty").hidden = alerts.length > 0;
}

function renderDetail(a) {
  const dl = el("dl");
  const add = (k, v) => { if (v !== null && v !== undefined && v !== "") dl.append(el("dt", k), el("dd", v)); };
  add("Alert", `#${a.id} ${a.rule_name}`);
  add("Score", a.risk_score == null ? "pending" : `${Math.round(a.risk_score)} / 100 (${a.priority})`);
  add("Source", a.source);
  add("Source IP", a.src_ip);
  add("URL", a.url);
  add("File hash", a.file_hash);
  add("Description", a.description);
  add("Event time", fmtTime(a.timestamp));
  add("Status", a.status);
  const reasons = el("ul");
  for (const r of safeJson(a.score_reasons, [])) reasons.append(el("li", r));
  const intel = el("pre", JSON.stringify(safeJson(a.intel, {}), null, 2));
  const box = $("detail");
  box.className = "";
  box.replaceChildren(dl, el("h3", "Why this score"), reasons, el("h3", "Threat intel"), intel);
}

function renderBlocks(blocks) {
  const items = blocks.map((b) => {
    const li = el("li");
    li.title = b.reason || "";
    li.append(
      el("span", b.ip, "mono"),
      el("span", `${b.created_by} · until ${fmtTime(b.expires_at)}`, "muted"),
      actionButton("Unblock", "", () => unblock(b.ip)),
    );
    return li;
  });
  $("blocks").replaceChildren(...(items.length ? items : [el("li", "No active blocks", "muted")]));
}

function renderTopIps(list) {
  const items = (list || []).map(([ip, n]) => {
    const li = el("li");
    li.append(el("span", ip, "mono"), el("span", `${n} alerts`, "muted"));
    return li;
  });
  $("topips").replaceChildren(...(items.length ? items : [el("li", "No data yet", "muted")]));
}

async function blockAlert(a) {
  if (!confirm(`Block ${a.src_ip} for 24 hours?\n\nAlert #${a.id}: ${a.rule_name}`)) return;
  try { await api(`/alerts/${a.id}/block?hours=24`, { method: "POST" }); }
  catch (e) { if (e.message !== "unauthorized") alert("Block failed: " + e.message); }
  refresh();
}

async function setStatus(id, status) {
  try { await api(`/alerts/${id}/status`, { method: "PATCH", body: JSON.stringify({ status }) }); }
  catch (e) { if (e.message !== "unauthorized") alert(e.message); }
  refresh();
}

async function unblock(ip) {
  if (!confirm(`Unblock ${ip}?`)) return;
  try { await api(`/blocks/${encodeURIComponent(ip)}`, { method: "DELETE" }); }
  catch (e) { if (e.message !== "unauthorized") alert(e.message); }
  refresh();
}

if (KEY) showApp(); else showLogin("");
