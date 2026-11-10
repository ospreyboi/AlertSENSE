"use strict";
/* AlertSense Security Operations Console.
 * SECURITY: alert fields (URLs, user agents, descriptions, intel) are attacker-controlled.
 * They are written only through textContent / createElement - never parsed as HTML. */
(() => {
  const $ = (id) => document.getElementById(id);
  const SVG_NS = "http://www.w3.org/2000/svg";
  const KEY_STORE = "alertsense_key";
  const THEME_STORE = "alertsense_theme";
  const REFRESH_MS = 5000;
  const OPEN = ["new", "triaged"];

  // ------------------------------------------------------------------ icons (Lucide paths)
  const ICONS = {
    shield: ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"],
    grid: ["M3 3h7v7H3z", "M14 3h7v7h-7z", "M14 14h7v7h-7z", "M3 14h7v7H3z"],
    list: ["M8 6h13", "M8 12h13", "M8 18h13", "M3 6h.01", "M3 12h.01", "M3 18h.01"],
    ban: [{ c: [12, 12, 10] }, "m4.9 4.9 14.2 14.2"],
    alert: ["m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z", "M12 9v4", "M12 17h.01"],
    search: [{ c: [11, 11, 8] }, "m21 21-4.3-4.3"],
    pause: ["M6 4h4v16H6z", "M14 4h4v16h-4z"],
    play: ["m6 3 14 9-14 9V3z"],
    sun: [{ c: [12, 12, 4] }, "M12 2v2", "M12 20v2", "m4.93 4.93 1.41 1.41", "m17.66 17.66 1.41 1.41", "M2 12h2", "M20 12h2", "m6.34 17.66-1.41 1.41", "m19.07 4.93-1.41 1.41"],
    moon: ["M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"],
    logout: ["M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4", "m16 17 5-5-5-5", "M21 12H9"],
    x: ["M18 6 6 18", "m6 6 12 12"],
    flag: ["M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z", "M4 22v-7"],
    check: ["M20 6 9 17l-5-5"],
    checkCircle: [{ c: [12, 12, 10] }, "m9 12 2 2 4-4"],
    unlock: ["M5 11h14v10H5z", "M7 11V7a5 5 0 0 1 9.9-1"],
    refresh: ["M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8", "M3 3v5h5", "M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16", "M16 16h5v5"],
    download: ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "m7 10 5 5 5-5", "M12 15V3"],
    chevLeft: ["m15 18-6-6 6-6"],
    chevRight: ["m9 18 6-6-6-6"],
    arrowUp: ["m5 12 7-7 7 7", "M12 19V5"],
    arrowDown: ["M12 5v14", "m19 12-7 7-7-7"],
    upDown: ["m7 15 5 5 5-5", "m7 9 5-5 5 5"],
    building: ["M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z", "M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2", "M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2", "M10 6h4", "M10 10h4", "M10 14h4", "M10 18h4"],
  };

  const SEVS = ["critical", "high", "medium", "low"];
  const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", pending: "Pending" };
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, pending: 0 };
  const STATUS_LABEL = { new: "New", triaged: "Triaged", blocked: "Blocked", resolved: "Resolved", false_positive: "False positive" };
  const MITRE = {
    "T1190": "Exploit Public-Facing Application",
    "T1189": "Drive-by Compromise",
    "T1083": "File and Directory Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1595": "Active Scanning",
    "T1595.003": "Wordlist Scanning",
    "T1110": "Brute Force",
  };

  const state = {
    key: "", alerts: [], blocks: [], stats: null,
    range: 24, sev: "", status: "open", q: "",
    sort: { key: "risk", dir: "desc" }, page: 0, pageSize: 50, selected: new Set(),
    paused: false, timer: null, online: null, lastOk: null,
    openId: null, tab: "summary", returnFocus: null, lastSr: "",
    auth: { mode: "", csrf: "", user: null, cfg: { oidc: false, provider: null, api_key_login: true } },
  };
  const authed = () => Boolean(state.key || state.auth.user);
  const canRespond = () => state.auth.mode !== "session" || state.auth.user?.role === "responder";
  const AUTH_ERRORS = {
    denied: "Sign-in was cancelled at your organisation's login page.",
    domain: "That account is not from an allowed domain for this console.",
    no_role: "Your account signed in, but it has not been given an AlertSense role. Ask your administrator.",
    login_failed: "Single sign-on failed. Please try again.",
    provider_unreachable: "The identity provider could not be reached. Try again later.",
  };

  // ------------------------------------------------------------------ helpers
  const store = {
    get(k, s) { try { return (s || sessionStorage).getItem(k); } catch (_) { return null; } },
    set(k, v, s) { try { (s || sessionStorage).setItem(k, v); } catch (_) { /* storage unavailable */ } },
    del(k, s) { try { (s || sessionStorage).removeItem(k); } catch (_) { /* storage unavailable */ } },
  };

  function h(tag, props = {}, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = String(v);
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      e.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return e;
  }

  function svg(tag, attrs = {}) {
    const e = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    return e;
  }

  function icon(name, size = 16) {
    const s = svg("svg", { viewBox: "0 0 24 24", width: size, height: size, fill: "none", stroke: "currentColor",
      "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round", class: "icon", "aria-hidden": "true", focusable: "false" });
    for (const p of ICONS[name] || []) {
      s.append(typeof p === "string" ? svg("path", { d: p }) : svg("circle", { cx: p.c[0], cy: p.c[1], r: p.c[2] }));
    }
    return s;
  }

  function hydrateIcons(root = document) {
    root.querySelectorAll("[data-icon]").forEach((el) => el.replaceChildren(icon(el.dataset.icon, Number(el.dataset.size) || 16)));
  }

  function toDate(s) {
    if (!s) return null;
    const d = new Date(/Z$|[+-]\d\d:\d\d$/.test(s) ? s : s + "Z"); // API stores UTC
    return Number.isNaN(d.getTime()) ? null : d;
  }
  function ago(d) {
    if (!d) return "—";
    let s = Math.round((Date.now() - d.getTime()) / 1000);
    const future = s < 0; s = Math.abs(s);
    const t = s < 60 ? `${s}s` : s < 3600 ? `${Math.round(s / 60)}m` : s < 172800 ? `${Math.round(s / 3600)}h` : `${Math.round(s / 86400)}d`;
    if (!future && s < 30) return "just now";
    return future ? `in ${t}` : `${t} ago`;
  }
  const pad2 = (n) => String(n).padStart(2, "0");
  const hhmm = (d) => `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  const stamp = (d) => (d ? `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${hhmm(d)}:${pad2(d.getSeconds())}` : "—");
  const fmt = (n) => Number(n || 0).toLocaleString();
  const safeJson = (s, fb) => { if (s && typeof s === "object") return s; try { return s ? JSON.parse(s) : fb; } catch (_) { return fb; } };
  const eventTime = (a) => toDate(a.timestamp) || toDate(a.created_at);
  const techOf = (a) => ((a.description || "").match(/\bT\d{4}(?:\.\d{3})?\b/) || [null])[0];
  const sevOf = (a) => a.priority || "pending";
  const isOpen = (a) => OPEN.includes(a.status);
  const blockedSet = () => new Set(state.blocks.map((b) => b.ip));
  const rangeLabel = (hrs) => (hrs === 1 ? "last hour" : hrs === 24 ? "last 24h" : "last 7 days");
  const inRange = (a, hrs, offset = 0) => {
    const d = eventTime(a); if (!d) return false;
    const age = Date.now() - d.getTime();
    return age >= offset * 3600e3 && age < (offset + hrs) * 3600e3;
  };

  function sevCell(sev) {
    return h("span", { class: "sev-cell" }, h("span", { class: `sev-sq sev-${sev}`, "aria-hidden": "true" }), SEV_LABEL[sev] || sev);
  }
  function statusCell(st) { return h("span", { class: `status s-${st}` }, STATUS_LABEL[st] || st); }

  // ------------------------------------------------------------------ feedback
  function toast(msg, kind = "ok") {
    const t = h("div", { class: `toast ${kind === "error" ? "is-error" : ""}` }, icon(kind === "error" ? "alert" : "checkCircle", 16), h("span", { text: msg }));
    $("toasts").append(t);
    setTimeout(() => t.remove(), kind === "error" ? 7000 : 4000);
  }

  function confirmDialog({ title, text, ok = "Confirm", danger = true }) {
    const d = $("confirm");
    $("confirm-title").textContent = title;
    $("confirm-text").textContent = text;
    const okBtn = $("confirm-ok");
    okBtn.textContent = ok;
    okBtn.className = `btn ${danger ? "btn-danger" : "btn-primary"}`;
    if (typeof d.showModal !== "function") return Promise.resolve(window.confirm(`${title}\n\n${text}`));
    d.returnValue = "";
    d.showModal();
    return new Promise((resolve) => d.addEventListener("close", () => resolve(d.returnValue === "ok"), { once: true }));
  }

  // ------------------------------------------------------------------ API
  async function api(path, opts = {}) {
    let res;
    try {
      const headers = { "Content-Type": "application/json" };
      if (state.key) headers["X-API-Key"] = state.key;
      if (state.auth.csrf) headers["X-CSRF-Token"] = state.auth.csrf;
      res = await fetch(path, { ...opts, headers, credentials: "same-origin" });
    } catch (_) {
      throw Object.assign(new Error("The AlertSense API is unreachable."), { network: true });
    }
    if (res.status === 401) {
      signOut(state.auth.mode === "session" ? "Your session has expired. Sign in again." : "The API key was rejected. Check ALERTSENSE_API_KEY on the server.", false);
      throw Object.assign(new Error("unauthorized"), { auth: true });
    }
    if (res.status === 403) {
      let detail = "";
      try { detail = (await res.json()).detail; } catch (_) { /* not JSON */ }
      throw new Error(typeof detail === "string" && detail ? `Not permitted: ${detail}.` : "Your role does not permit this action.");
    }
    if (!res.ok) {
      let detail = "";
      try { const j = await res.json(); detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch (_) { /* not JSON */ }
      throw new Error(`Request failed (${res.status})${detail ? ": " + detail : ""}`);
    }
    return res.json();
  }

  // ------------------------------------------------------------------ session
  function showLogin(msg) {
    stopTimer();
    closeFlyout(false);
    $("app").hidden = true;
    $("login").hidden = false;
    $("login-msg").textContent = msg || "";
    (state.auth.cfg.oidc ? $("sso-btn") : $("key")).focus();
  }
  function showApp() {
    $("login").hidden = true;
    $("app").hidden = false;
    const u = state.auth.user;
    $("user").hidden = !u;
    if (u) {
      $("user-name").textContent = u.name || u.email;
      $("user").title = u.email || "";
      $("user-role").textContent = u.role === "responder" ? "Responder" : "Viewer";
    }
    document.body.classList.toggle("is-readonly", !canRespond());
    refresh();
    startTimer();
  }
  async function signOut(msg, callServer = true) {
    const wasSession = state.auth.mode === "session";
    if (wasSession && callServer) {
      try { await fetch("/auth/logout", { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": state.auth.csrf } }); } catch (_) { /* offline */ }
    }
    state.key = "";
    state.auth.mode = ""; state.auth.csrf = ""; state.auth.user = null;
    store.del(KEY_STORE);
    showLogin(msg);
  }

  function applyAuthConfig(cfg) {
    state.auth.cfg = cfg;
    $("sso-btn").hidden = !cfg.oidc;
    $("sso-note").hidden = !cfg.oidc;
    $("sso-label").textContent = cfg.provider ? `Sign in with ${cfg.provider}` : "Sign in with single sign-on";
    $("keyform").hidden = !cfg.api_key_login;
    $("login-or").hidden = !(cfg.oidc && cfg.api_key_login);
    $("login-btn").className = `btn ${cfg.oidc ? "" : "btn-primary "}btn-block`;
  }

  async function boot() {
    let cfg = { oidc: false, provider: null, api_key_login: true };
    try { const r = await fetch("/auth/config", { credentials: "same-origin" }); if (r.ok) cfg = await r.json(); } catch (_) { /* older server */ }
    applyAuthConfig(cfg);

    const params = new URLSearchParams(location.search);
    const err = params.get("auth_error");
    if (err) history.replaceState(null, "", location.pathname + location.hash);

    if (cfg.oidc) {
      try {
        const r = await fetch("/auth/me", { credentials: "same-origin" });
        if (r.ok) {
          const me = await r.json();
          state.auth = { ...state.auth, mode: "session", csrf: me.csrf || "", user: me };
          showApp();
          return;
        }
      } catch (_) { /* fall through to sign-in */ }
    }
    state.key = cfg.api_key_login ? store.get(KEY_STORE) || "" : "";
    if (state.key) { state.auth.mode = "key"; showApp(); }
    else showLogin(err ? (AUTH_ERRORS[err] || AUTH_ERRORS.login_failed) : "");
  }

  // ------------------------------------------------------------------ polling
  function startTimer() {
    stopTimer();
    if (!state.paused && !document.hidden) state.timer = setInterval(refresh, REFRESH_MS);
    setConn();
  }
  function stopTimer() { clearInterval(state.timer); state.timer = null; }

  let inflight = false, again = false;
  async function refresh() {
    if (!authed()) return;
    if (inflight) { again = true; return; }
    inflight = true;
    try {
      const [stats, alerts, blocks] = await Promise.all([api("/stats"), api("/alerts?sort=newest&limit=500"), api("/blocks")]);
      Object.assign(state, { stats, alerts, blocks, online: true, lastOk: new Date() });
      const ids = new Set(alerts.map((a) => a.id));
      for (const id of [...state.selected]) if (!ids.has(id)) state.selected.delete(id);
      $("banner").hidden = true;
      render();
    } catch (e) {
      if (e.auth) return;
      state.online = false;
      setConn();
      $("banner").replaceChildren(icon("alert", 16), h("span", { text: `${e.message} Retrying every ${REFRESH_MS / 1000} seconds.` }));
      $("banner").hidden = false;
    } finally {
      inflight = false;
      if (again) { again = false; refresh(); }
    }
  }

  function setConn() {
    let cls = "conn", text = "Connecting";
    if (state.online === false) { cls += " is-offline"; text = "Disconnected"; }
    else if (state.paused) { cls += " is-paused"; text = "Paused"; }
    else if (state.online) { cls += " is-live"; text = "Live"; }
    $("conn").className = cls;
    $("conn").title = state.online ? `Polling every ${REFRESH_MS / 1000}s` : "";
    $("conn-text").textContent = text;
  }

  // ------------------------------------------------------------------ render
  function render() {
    renderKpis();
    renderChart();
    renderSeverity();
    renderMitre();
    renderSources();
    renderAlerts();
    renderBlocks();
    setConn();
    $("updated").textContent = `Updated ${hhmm(state.lastOk)}:${pad2(state.lastOk.getSeconds())}`;
    if (state.openId != null) {
      const a = state.alerts.find((x) => x.id === state.openId);
      if (a) renderFlyout(a);
    }
  }

  function renderKpis() {
    const s = state.stats, A = state.alerts, R = state.range;
    const open = A.filter(isOpen);
    const critOpen = open.filter((a) => sevOf(a) === "critical").length;
    const highOpen = open.filter((a) => sevOf(a) === "high").length;
    const cur = A.filter((a) => inRange(a, R));
    const prev = A.filter((a) => inRange(a, R, R));
    const scored = cur.filter((a) => a.risk_score != null);
    const mean = scored.length ? Math.round(scored.reduce((t, a) => t + a.risk_score, 0) / scored.length) : null;
    const auto = state.blocks.filter((b) => b.created_by === "auto").length;

    $("k-open").textContent = fmt(s.open);
    $("k-open-note").textContent = `${fmt(s.total)} alerts total`;
    $("k-critical").textContent = fmt(critOpen);
    $("k-critical-note").textContent = `${fmt(s.by_priority.critical || 0)} critical all time`;
    $("k-high").textContent = fmt(highOpen);
    $("k-high-note").textContent = `${fmt(s.by_priority.high || 0)} high all time`;
    $("k-range-label").textContent = `Alerts, ${rangeLabel(R)}`;
    $("k-range").textContent = fmt(cur.length);
    const note = $("k-range-note");
    if (prev.length) {
      const pct = Math.round(((cur.length - prev.length) / prev.length) * 100);
      note.replaceChildren(h("span", { class: pct > 0 ? "up" : pct < 0 ? "down" : "", text: `${pct > 0 ? "+" : ""}${pct}%` }), " vs previous period");
    } else note.textContent = "no prior period data";
    $("k-risk").textContent = mean == null ? "—" : String(mean);
    $("k-risk-note").textContent = scored.length ? `max ${Math.round(Math.max(...scored.map((a) => a.risk_score)))} · ${rangeLabel(R)}` : "no scored alerts";
    $("k-blocks").textContent = fmt(s.active_blocks);
    $("k-blocks-note").textContent = s.active_blocks ? `${auto} automatic · ${state.blocks.length - auto} analyst` : "none active";

    $("nav-open").textContent = s.open ? fmt(s.open) : "";
    $("nav-blocks").textContent = s.active_blocks ? fmt(s.active_blocks) : "";
    $("mode").replaceChildren(
      h("strong", { text: s.auto_block_score ? "Automatic containment" : "Analyst approval" }),
      s.auto_block_score ? `IPs blocked when risk ≥ ${s.auto_block_score}` : "Every block requires confirmation");

    const sr = `${s.open} open alerts: ${critOpen} critical, ${highOpen} high. ${s.active_blocks} addresses blocked.`;
    if (sr !== state.lastSr) { $("sr-status").textContent = sr; state.lastSr = sr; }
  }

  function renderChart() {
    const R = state.range;
    const cfg = R === 1 ? { n: 12, step: 5 * 60e3 } : R === 24 ? { n: 24, step: 3600e3 } : { n: 28, step: 6 * 3600e3 };
    const end = Math.ceil(Date.now() / cfg.step) * cfg.step;
    const start = end - cfg.n * cfg.step;
    const all = new Array(cfg.n).fill(0), hot = new Array(cfg.n).fill(0);
    for (const a of state.alerts) {
      const d = eventTime(a); if (!d) continue;
      const i = Math.floor((d.getTime() - start) / cfg.step);
      if (i < 0 || i >= cfg.n) continue;
      all[i] += 1;
      if (["critical", "high"].includes(sevOf(a))) hot[i] += 1;
    }
    const max = Math.max(4, ...all);
    const yMax = Math.ceil(max / 4) * 4;
    const W = 1000, H = 200;
    const x = (i) => (i / (cfg.n - 1)) * W;
    const y = (v) => H - (v / yMax) * H;
    const path = (arr) => arr.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
    const labelOf = (i) => {
      const d = new Date(start + i * cfg.step);
      return R === 168 ? `${["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][d.getDay()]} ${pad2(d.getHours())}:00` : hhmm(d);
    };

    const total = all.reduce((t, v) => t + v, 0), hotTotal = hot.reduce((t, v) => t + v, 0);
    const peakI = all.indexOf(Math.max(...all));
    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img",
      "aria-label": `Line chart of alerts over the ${rangeLabel(R)}. ${total} alerts, ${hotTotal} critical or high.` });
    for (let k = 0; k <= 4; k++) root.append(svg("line", { class: "gridline", x1: 0, x2: W, y1: (H / 4) * k, y2: (H / 4) * k }));
    root.append(svg("path", { class: "area", d: `${path(all)}L${W},${H}L0,${H}Z` }));
    root.append(svg("path", { class: "line-all", d: path(all) }));
    root.append(svg("path", { class: "line-crit", d: path(hot) }));
    const slot = W / (cfg.n - 1);
    all.forEach((v, i) => {
      const r = svg("rect", { class: "hit", x: Math.max(0, x(i) - slot / 2), y: 0, width: slot, height: H });
      const t = svg("title"); t.textContent = `${labelOf(i)} · ${v} alert${v === 1 ? "" : "s"} · ${hot[i]} critical/high`;
      r.append(t); root.append(r);
    });
    const yl = h("div", { class: "y-labels", "aria-hidden": "true" },
      [0, 1, 2, 3, 4].map((k) => { const s = h("span", { text: (yMax / 4) * (4 - k) }); s.style.top = `${k * 25}%`; return s; }));
    const xIdx = [0, Math.round((cfg.n - 1) / 4), Math.round((cfg.n - 1) / 2), Math.round(((cfg.n - 1) * 3) / 4), cfg.n - 1];
    const xl = h("div", { class: "x-labels", "aria-hidden": "true" }, xIdx.map((i) => h("span", { text: labelOf(i) })));
    $("chart").replaceChildren(yl, root, xl);
    $("chart-summary").textContent = total
      ? `${fmt(total)} alerts in the ${rangeLabel(R)} · ${fmt(hotTotal)} critical or high · peak of ${all[peakI]} at ${labelOf(peakI)}`
      : `No alerts in the ${rangeLabel(R)}.`;
  }

  function renderSeverity() {
    const cur = state.alerts.filter((a) => inRange(a, state.range));
    $("sev-scope").textContent = rangeLabel(state.range);
    const keys = [...SEVS, ...(cur.some((a) => sevOf(a) === "pending") ? ["pending"] : [])];
    const counts = Object.fromEntries(keys.map((k) => [k, cur.filter((a) => sevOf(a) === k)]));
    const total = cur.length;
    const bar = $("sev-bar");
    bar.setAttribute("aria-label", keys.map((k) => `${SEV_LABEL[k]} ${counts[k].length}`).join(", "));
    bar.replaceChildren(...keys.filter((k) => counts[k].length).map((k) => {
      const s = h("span", { class: `sev-${k}`, title: `${SEV_LABEL[k]}: ${counts[k].length}` });
      s.style.width = `${(counts[k].length / total) * 100}%`;
      return s;
    }));
    $("sev-body").replaceChildren(...keys.map((k) => h("tr", {},
      h("td", {}, sevCell(k)),
      h("td", { class: "num", text: fmt(counts[k].length) }),
      h("td", { class: "num text-muted", text: total ? `${((counts[k].length / total) * 100).toFixed(1)}%` : "—" }),
      h("td", { class: "num", text: fmt(counts[k].filter(isOpen).length) }))));
  }

  function renderMitre() {
    $("mitre-scope").textContent = rangeLabel(state.range);
    const m = new Map();
    for (const a of state.alerts) {
      const t = techOf(a);
      if (t && inRange(a, state.range)) m.set(t, (m.get(t) || 0) + 1);
    }
    const rows = [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
    if (!rows.length) { $("mitre-body").replaceChildren(h("tr", {}, h("td", { colspan: 4, class: "empty-row", text: "No mapped techniques in this period." }))); return; }
    const max = rows[0][1];
    $("mitre-body").replaceChildren(...rows.map(([t, n]) => {
      const fill = h("span"); fill.style.width = `${(n / max) * 100}%`;
      return h("tr", {},
        h("td", {}, h("span", { class: "tech", text: t })),
        h("td", { class: "name", title: MITRE[t] || "", text: MITRE[t] || "—" }),
        h("td", { class: "num", text: fmt(n) }),
        h("td", {}, h("div", { class: "minibar", "aria-hidden": "true" }, fill)));
    }));
  }

  function renderSources() {
    $("ip-scope").textContent = rangeLabel(state.range);
    const m = new Map();
    for (const a of state.alerts) {
      if (!a.src_ip || !inRange(a, state.range)) continue;
      const e = m.get(a.src_ip) || { n: 0, max: 0 };
      e.n += 1; e.max = Math.max(e.max, a.risk_score || 0);
      m.set(a.src_ip, e);
    }
    const rows = [...m.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, 6);
    const blocked = blockedSet();
    if (!rows.length) { $("ip-body").replaceChildren(h("tr", {}, h("td", { colspan: 5, class: "empty-row", text: "No source addresses in this period." }))); return; }
    $("ip-body").replaceChildren(...rows.map(([ip, e]) => {
      const isB = blocked.has(ip);
      return h("tr", {},
        h("td", {}, h("span", { class: "ip", text: ip })),
        h("td", { class: "num", text: fmt(e.n) }),
        h("td", { class: "num hide-sm", text: Math.round(e.max) }),
        h("td", {}, isB ? h("span", { class: "state is-blocked" }, icon("ban", 13), "Blocked") : h("span", { class: "state", text: "Allowed" })),
        h("td", { class: "act requires-responder" }, isB
          ? h("button", { type: "button", class: "btn btn-sm", onclick: () => doUnblock(ip) }, "Unblock")
          : h("button", { type: "button", class: "btn btn-sm btn-danger-outline", onclick: () => doBlockIp(ip) }, "Block")));
    }));
  }

  // ------------------------------------------------------------------ alert table
  function filtered() {
    const q = state.q.trim().toLowerCase();
    const rows = state.alerts.filter((a) => {
      if (state.sev && sevOf(a) !== state.sev) return false;
      if (state.status === "open" && !isOpen(a)) return false;
      if (state.status && state.status !== "open" && a.status !== state.status) return false;
      if (q) {
        const t = techOf(a) || "";
        const hay = `${a.rule_name} ${a.src_ip || ""} ${a.url || ""} ${a.description || ""} ${a.source} ${t} ${MITRE[t] || ""} #${a.id} ${a.id}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    const dir = state.sort.dir === "asc" ? 1 : -1;
    const key = {
      risk: (a) => a.risk_score ?? -1,
      severity: (a) => SEV_RANK[sevOf(a)] * 1000 + (a.risk_score ?? 0),
      rule: (a) => a.rule_name.toLowerCase(),
      ip: (a) => (a.src_ip || "").split(".").map((p) => p.padStart(3, "0")).join("."),
      status: (a) => STATUS_LABEL[a.status] || a.status,
      time: (a) => (eventTime(a) || new Date(0)).getTime(),
    }[state.sort.key];
    return rows.sort((a, b) => {
      const ka = key(a), kb = key(b);
      return (ka < kb ? -1 : ka > kb ? 1 : 0) * dir || b.id - a.id;
    });
  }

  function renderSortHeaders() {
    document.querySelectorAll("#alerts-table th.sortable").forEach((th) => {
      const active = th.dataset.sort === state.sort.key;
      if (active) th.setAttribute("aria-sort", state.sort.dir === "asc" ? "ascending" : "descending");
      else th.removeAttribute("aria-sort");
      const btn = th.querySelector("button");
      btn.querySelector(".sort-ind")?.remove();
      const ind = h("span", { class: "sort-ind", "aria-hidden": "true" }, icon(active ? (state.sort.dir === "asc" ? "arrowUp" : "arrowDown") : "upDown", 12));
      btn.append(ind);
    });
  }

  function renderAlerts() {
    const rows = filtered();
    const blocked = blockedSet();
    const pages = Math.max(1, Math.ceil(rows.length / state.pageSize));
    state.page = Math.min(state.page, pages - 1);
    const from = state.page * state.pageSize;
    const view = rows.slice(from, from + state.pageSize);

    $("alert-count").textContent = `(${fmt(rows.length)})`;
    $("page-info").textContent = rows.length ? `${fmt(from + 1)}–${fmt(from + view.length)} of ${fmt(rows.length)}` : "0 of 0";
    $("pg-prev").disabled = state.page === 0;
    $("pg-next").disabled = state.page >= pages - 1;
    $("btn-clear").hidden = !(state.sev || state.q || state.status !== "open");
    renderSortHeaders();

    $("alerts-body").replaceChildren(...view.map((a) => {
      const sev = sevOf(a), t = techOf(a), d = eventTime(a);
      const sel = state.selected.has(a.id);
      const ipBlocked = a.src_ip && blocked.has(a.src_ip);
      const cb = h("input", { type: "checkbox", "aria-label": `Select alert ${a.id}`, checked: sel,
        onclick: (e) => e.stopPropagation(),
        onchange: (e) => { if (e.target.checked) state.selected.add(a.id); else state.selected.delete(a.id); renderAlerts(); } });
      const acts = h("div", { class: "row-actions requires-responder" });
      if (a.src_ip && !ipBlocked) acts.append(rowBtn("ban", `Block ${a.src_ip}`, () => doBlockAlert(a), "is-danger"));
      if (isOpen(a)) {
        acts.append(rowBtn("check", `Resolve alert ${a.id}`, () => doStatus([a], "resolved")));
        acts.append(rowBtn("flag", `Mark alert ${a.id} as false positive`, () => doStatus([a], "false_positive")));
      }
      const tr = h("tr", {
        class: `${sel ? "is-selected" : ""} ${a.id === state.openId ? "is-open" : ""}`, tabindex: 0,
        "aria-label": `Alert ${a.id}, ${a.rule_name}, ${SEV_LABEL[sev]} severity, risk ${a.risk_score ?? "pending"}. Press Enter to open.`,
        onclick: () => openFlyout(a.id, tr),
        onkeydown: (e) => { if ((e.key === "Enter" || e.key === " ") && e.target === tr) { e.preventDefault(); openFlyout(a.id, tr); } },
      },
        h("td", { class: "c-check requires-responder" }, cb),
        h("td", {}, sevCell(sev)),
        h("td", { class: "num" }, h("span", { class: `risk r-${sev}`, text: a.risk_score == null ? "…" : Math.round(a.risk_score) })),
        h("td", {}, h("div", { class: "alert-cell" }, h("span", { class: "alert-id", text: `#${a.id}` }), h("span", { class: "rule", title: a.rule_name, text: a.rule_name }))),
        h("td", { class: "hide-sm" }, t ? h("span", { class: "tech", title: MITRE[t] || "", text: t }) : h("span", { class: "text-dim", text: "—" })),
        h("td", {}, a.src_ip ? h("span", { class: "ip", text: a.src_ip }) : h("span", { class: "text-dim", text: "—" }), ipBlocked ? h("span", { class: "sr-only", text: " (blocked)" }) : null),
        h("td", { class: "hide-sm" }, statusCell(a.status)),
        h("td", { class: "text-muted", title: stamp(d), text: ago(d) }),
        h("td", { class: "c-act" }, acts));
      return tr;
    }));

    const pageIds = view.map((a) => a.id);
    const nSel = pageIds.filter((id) => state.selected.has(id)).length;
    const all = $("sel-all");
    all.checked = pageIds.length > 0 && nSel === pageIds.length;
    all.indeterminate = nSel > 0 && nSel < pageIds.length;
    all.disabled = pageIds.length === 0;

    $("bulkbar").hidden = state.selected.size === 0 || !canRespond();
    $("bulk-count").textContent = `${state.selected.size} selected`;

    const empty = $("alerts-empty");
    if (!rows.length) {
      const has = state.alerts.length > 0;
      empty.replaceChildren(
        h("strong", { text: has ? "No alerts match the current filters" : "No alerts received" }),
        h("span", { text: has ? "Change the severity, status or search filters." : "Alerts appear here when a sensor reports a detection." }),
        has ? h("button", { type: "button", class: "btn btn-sm", onclick: clearFilters, text: "Clear filters" }) : null);
      empty.hidden = false;
    } else empty.hidden = true;
  }

  function rowBtn(name, label, fn, extra = "") {
    return h("button", { type: "button", class: `btn ${extra}`, "aria-label": label, title: label, onclick: (e) => { e.stopPropagation(); fn(); } }, icon(name, 15));
  }

  function renderBlocks() {
    $("block-count").textContent = `(${fmt(state.blocks.length)})`;
    $("blocks-body").replaceChildren(...state.blocks.map((b) => {
      const exp = toDate(b.expires_at), add = toDate(b.created_at);
      return h("tr", { class: "static" },
        h("td", {}, h("span", { class: "ip", text: b.ip })),
        h("td", {}, h("span", { class: "origin", text: b.created_by === "auto" ? "Automatic" : "Analyst" })),
        h("td", { class: "hide-sm" }, h("span", { class: "text-muted", title: b.reason || "", text: b.reason || "—" })),
        h("td", { class: "hide-sm text-muted", title: stamp(add), text: ago(add) }),
        h("td", { title: stamp(exp), text: exp ? ago(exp) : "Never" }),
        h("td", { class: "c-act requires-responder" }, h("button", { type: "button", class: "btn btn-sm", onclick: () => doUnblock(b.ip) }, "Unblock")));
    }));
    const empty = $("blocks-empty");
    empty.replaceChildren(h("strong", { text: "No active blocks" }), h("span", { text: "Addresses blocked automatically or by an analyst are listed here until they expire." }));
    empty.hidden = state.blocks.length > 0;
  }

  // ------------------------------------------------------------------ flyout
  function openFlyout(id, from) {
    if (!state.alerts.find((x) => x.id === id)) return;
    if (state.openId !== id) state.tab = "summary";
    state.openId = id;
    state.returnFocus = from || document.activeElement;
    renderFlyout(state.alerts.find((x) => x.id === id));
    $("scrim").hidden = false;
    $("flyout").hidden = false;
    $("fly-close").focus();
    renderAlerts();
  }

  function closeFlyout(restore = true) {
    if ($("flyout").hidden) return;
    $("flyout").hidden = true;
    $("scrim").hidden = true;
    state.openId = null;
    if (state.alerts.length) renderAlerts();
    if (restore && state.returnFocus && document.contains(state.returnFocus)) state.returnFocus.focus();
  }

  function setTab(tab, focus = false) {
    state.tab = tab;
    document.querySelectorAll(".tabs [role=tab]").forEach((b) => {
      const on = b.dataset.tab === tab;
      b.setAttribute("aria-selected", String(on));
      b.tabIndex = on ? 0 : -1;
      if (on) { $("pane").setAttribute("aria-labelledby", b.id); if (focus) b.focus(); }
    });
    const a = state.alerts.find((x) => x.id === state.openId);
    if (a) renderPane(a);
  }

  function renderFlyout(a) {
    const sev = sevOf(a), d = eventTime(a);
    $("fly-eyebrow").textContent = `ALERT #${a.id}`;
    $("fly-title").textContent = a.rule_name;
    $("fly-meta").replaceChildren(
      h("span", {}, sevCell(sev)),
      h("span", {}, statusCell(a.status)),
      h("span", { title: stamp(d), text: `Seen ${ago(d)}` }),
      h("span", { text: a.source }));
    setTab(state.tab);

    const blocked = a.src_ip && blockedSet().has(a.src_ip);
    const foot = [];
    if (a.src_ip && !blocked) {
      const sel = h("select", { "aria-label": "Block duration" },
        h("option", { value: "1", text: "1 hour" }), h("option", { value: "24", text: "24 hours", selected: true }), h("option", { value: "168", text: "7 days" }));
      foot.push(h("button", { type: "button", class: "btn btn-danger", onclick: () => doBlockAlert(a, Number(sel.value)) }, icon("ban", 15), "Block source"), sel);
    } else if (blocked) {
      foot.push(h("button", { type: "button", class: "btn", onclick: () => doUnblock(a.src_ip) }, icon("unlock", 15), "Unblock source"));
    }
    foot.push(h("span", { class: "spacer" }));
    if (isOpen(a)) {
      foot.push(h("button", { type: "button", class: "btn", onclick: () => doStatus([a], "false_positive") }, "False positive"));
      foot.push(h("button", { type: "button", class: "btn btn-primary", onclick: () => doStatus([a], "resolved") }, "Resolve"));
    } else {
      foot.push(h("button", { type: "button", class: "btn", onclick: () => doStatus([a], "triaged") }, "Reopen"));
    }
    foot.push(h("button", { type: "button", class: "btn btn-icon", "aria-label": "Re-run enrichment and scoring", title: "Re-run enrichment and scoring", onclick: () => doRetriage(a) }, icon("refresh", 15)));
    $("fly-foot").replaceChildren(...foot);
  }

  function props(pairs) {
    return h("dl", { class: "props" }, pairs.filter(Boolean).map(([k, v]) => [h("dt", { text: k }), h("dd", {}, v ?? "—")]));
  }

  function renderPane(a) {
    const sev = sevOf(a), t = techOf(a), d = eventTime(a);
    const intel = safeJson(a.intel, {});
    const reasons = safeJson(a.score_reasons, []);
    const out = [];

    if (state.tab === "summary") {
      const fill = h("span", { class: `sev-${sev}` }); fill.style.width = `${a.risk_score ?? 0}%`;
      out.push(h("div", { class: "scorebox" },
        h("div", {}, h("div", { class: "text-muted small", text: "Risk score" }),
          h("div", { class: "big" }, a.risk_score == null ? "…" : String(Math.round(a.risk_score)), h("small", { text: "/100" }))),
        h("div", { class: "meter" }, h("div", { class: "meter-track", "aria-hidden": "true" }, fill),
          h("div", { class: "meter-scale", "aria-hidden": "true" }, ["0", "40", "70", "90", "100"].map((s) => h("span", { text: s }))))));
      out.push(h("h3", { text: "Details" }), props([
        ["Detection rule", a.rule_name],
        ["Severity", sevCell(sev)],
        ["Status", statusCell(a.status)],
        ["Source IP", a.src_ip ? h("span", { class: "ip", text: a.src_ip }) : "—"],
        ["MITRE ATT&CK", t ? h("span", {}, h("span", { class: "tech", text: t }), ` ${MITRE[t] || ""}`) : "Not mapped"],
        ["Sensor", a.source],
        ["Event time", stamp(d)],
        ["Received", stamp(toDate(a.created_at))],
      ]));
      out.push(h("h3", { text: "Score contributions" }));
      if (reasons.length) {
        const rows = reasons.map((r) => {
          const m = String(r).match(/^([+-]\d+)\s+(.*)$/);
          return h("tr", {}, h("td", { class: `pts ${m && Number(m[1]) < 0 ? "neg" : ""}`, text: m ? m[1] : "" }), h("td", { text: m ? m[2] : r }));
        });
        out.push(h("table", { class: "contrib" }, h("tbody", {}, rows)));
      } else out.push(h("p", { class: "note", text: "Scoring has not completed for this alert." }));
    }

    if (state.tab === "evidence") {
      out.push(h("h3", { text: "Request" }), a.url ? h("pre", { class: "code", text: a.url }) : h("p", { class: "note", text: "No request captured." }));
      out.push(h("h3", { text: "Sensor detail" }), a.description ? h("pre", { class: "code", text: a.description }) : h("p", { class: "note", text: "None." }));
      if (a.file_hash) out.push(h("h3", { text: "File hash" }), h("pre", { class: "code", text: a.file_hash }));
    }

    if (state.tab === "intel") {
      out.push(h("h3", { text: "AbuseIPDB · source IP" }), intelProps(intel.ip, (x) => [
        ["Abuse confidence", `${x.abuse_score ?? 0}%`], ["Reports (90 days)", fmt(x.reports)],
        ["Country", x.country || "—"], ["ISP", x.isp || "—"], ["Tor exit node", x.is_tor ? "Yes" : "No"]]));
      if (a.file_hash || intel.hash) out.push(h("h3", { text: "VirusTotal · file hash" }), intelProps(intel.hash, (x) => [
        ["Known sample", x.known ? "Yes" : "No"], ["Detections", x.engines ? `${x.malicious} of ${x.engines} engines` : fmt(x.malicious)], ["Name", x.name || "—"]]));
    }

    if (state.tab === "raw") {
      const raw = { ...a, intel, score_reasons: reasons };
      out.push(h("pre", { class: "code", text: JSON.stringify(raw, null, 2) }));
    }
    $("pane").replaceChildren(...out);
  }

  function intelProps(data, rows) {
    if (!data) return h("p", { class: "note", text: "No lookup was performed." });
    if (data.skipped) return h("p", { class: "note", text: `Lookup skipped: ${data.skipped}` });
    if (data.error) return h("p", { class: "note", text: `Lookup failed: ${data.error}` });
    return props(rows(data));
  }

  // ------------------------------------------------------------------ actions
  async function act(fn, okMsg) {
    try { await fn(); toast(okMsg); } catch (e) { if (!e.auth) toast(e.message, "error"); }
    await refresh();
  }
  const hrsText = (n) => (n === 168 ? "7 days" : n === 1 ? "1 hour" : `${n} hours`);

  async function doBlockAlert(a, hours = 24) {
    const ok = await confirmDialog({ title: `Block ${a.src_ip}?`, ok: "Block address",
      text: `All requests from ${a.src_ip} will be denied at the Nginx edge for ${hrsText(hours)}. Linked to alert #${a.id} (${a.rule_name}).` });
    if (ok) await act(() => api(`/alerts/${a.id}/block?hours=${hours}`, { method: "POST" }), `${a.src_ip} blocked for ${hrsText(hours)}.`);
  }
  async function doBlockIp(ip) {
    const ok = await confirmDialog({ title: `Block ${ip}?`, ok: "Block address", text: `All requests from ${ip} will be denied at the Nginx edge for 24 hours.` });
    if (ok) await act(() => api("/blocks", { method: "POST", body: JSON.stringify({ ip, reason: "analyst: top source address", hours: 24 }) }), `${ip} blocked for 24 hours.`);
  }
  async function doUnblock(ip) {
    const ok = await confirmDialog({ title: `Unblock ${ip}?`, ok: "Unblock", danger: false, text: `Requests from ${ip} will be allowed again after the next enforcer sync (about 5 seconds).` });
    if (ok) await act(() => api(`/blocks/${encodeURIComponent(ip)}`, { method: "DELETE" }), `${ip} unblocked.`);
  }
  async function doStatus(list, status) {
    const label = STATUS_LABEL[status].toLowerCase();
    if (list.length > 1) {
      const ok = await confirmDialog({ title: `Mark ${list.length} alerts as ${label}?`, ok: "Update alerts", danger: false, text: "The status of every selected alert will be changed." });
      if (!ok) return;
    }
    await act(async () => {
      await Promise.all(list.map((a) => api(`/alerts/${a.id}/status`, { method: "PATCH", body: JSON.stringify({ status }) })));
      list.forEach((a) => state.selected.delete(a.id));
    }, list.length > 1 ? `${list.length} alerts marked as ${label}.` : `Alert #${list[0].id} marked as ${label}.`);
  }
  async function doBulkBlock() {
    const blocked = blockedSet();
    const byIp = new Map();
    for (const a of selectedAlerts()) if (a.src_ip && !blocked.has(a.src_ip) && !byIp.has(a.src_ip)) byIp.set(a.src_ip, a);
    if (!byIp.size) { toast("The selected alerts have no unblocked source addresses.", "error"); return; }
    const ips = [...byIp.keys()];
    const ok = await confirmDialog({ title: `Block ${ips.length} address${ips.length === 1 ? "" : "es"}?`, ok: "Block addresses",
      text: `${ips.join(", ")} will be denied at the Nginx edge for 24 hours.` });
    if (!ok) return;
    await act(async () => {
      await Promise.all([...byIp.values()].map((a) => api(`/alerts/${a.id}/block?hours=24`, { method: "POST" })));
      state.selected.clear();
    }, `${ips.length} address${ips.length === 1 ? "" : "es"} blocked for 24 hours.`);
  }
  async function doRetriage(a) {
    await act(() => api(`/alerts/${a.id}/retriage`, { method: "POST" }), `Alert #${a.id} re-scored.`);
  }
  const selectedAlerts = () => state.alerts.filter((a) => state.selected.has(a.id));

  function exportCsv() {
    const rows = filtered();
    const cell = (v) => {
      let s = v == null ? "" : String(v);
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // neutralise spreadsheet formula injection
      return `"${s.replace(/"/g, '""')}"`;
    };
    const head = ["id", "severity", "risk_score", "rule", "mitre", "src_ip", "status", "event_time_utc", "url", "source"];
    const lines = [head.join(",")].concat(rows.map((a) => [a.id, sevOf(a), a.risk_score, a.rule_name, techOf(a), a.src_ip, a.status,
      (eventTime(a) || null)?.toISOString(), a.url, a.source].map(cell).join(",")));
    const blob = new Blob([lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = h("a", { href: url, download: `alertsense-alerts-${new Date().toISOString().slice(0, 10)}.csv` });
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`Exported ${rows.length} alert${rows.length === 1 ? "" : "s"} to CSV.`);
  }

  // ------------------------------------------------------------------ UI wiring
  function clearFilters() {
    Object.assign(state, { sev: "", status: "open", q: "", page: 0 });
    $("q").value = ""; $("f-sev").value = ""; $("f-status").value = "open";
    renderAlerts();
  }

  function applyTheme(t) {
    document.documentElement.dataset.theme = t;
    const next = t === "dark" ? "light" : "dark";
    $("btn-theme").setAttribute("aria-label", `Switch to ${next} theme`);
    $("btn-theme").title = `Switch to ${next} theme`;
    $("btn-theme").replaceChildren(icon(t === "dark" ? "sun" : "moon", 16));
  }

  function setPaused(p) {
    state.paused = p;
    const b = $("btn-pause");
    b.setAttribute("aria-pressed", String(p));
    b.replaceChildren(icon(p ? "play" : "pause", 16), h("span", { class: "label", text: p ? "Resume" : "Pause" }));
    if (p) stopTimer(); else { refresh(); startTimer(); }
    setConn();
  }

  function initNav() {
    if (!("IntersectionObserver" in window)) return;
    const links = [...document.querySelectorAll(".rail-link")];
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) links.forEach((l) => l.classList.toggle("is-active", l.dataset.nav === e.target.id));
    }, { rootMargin: "-35% 0px -60% 0px" });
    ["overview", "alerts", "blocklist"].forEach((id) => io.observe($(id)));
  }

  function init() {
    hydrateIcons();
    const saved = store.get(THEME_STORE, localStorage);
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(saved || (prefersDark ? "dark" : "light"));

    $("keyform").addEventListener("submit", async (e) => {
      e.preventDefault();
      const k = $("key").value.trim();
      if (!k) { $("login-msg").textContent = "Enter the API key."; $("key").focus(); return; }
      const btn = $("login-btn");
      btn.disabled = true; btn.textContent = "Signing in…";
      state.key = k;
      try {
        await api("/stats");
        store.set(KEY_STORE, k);
        state.auth.mode = "key";
        $("key").value = ""; $("login-msg").textContent = "";
        showApp();
      } catch (err) {
        if (!err.auth) $("login-msg").textContent = err.message;
      } finally { btn.disabled = false; btn.textContent = "Sign in"; }
    });

    $("btn-logout").addEventListener("click", () => signOut(""));
    $("btn-pause").addEventListener("click", () => setPaused(!state.paused));
    $("btn-theme").addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      store.set(THEME_STORE, next, localStorage);
      applyTheme(next);
    });
    $("btn-refresh").addEventListener("click", async () => { await refresh(); if (state.online) toast("Data refreshed."); });
    $("btn-export").addEventListener("click", exportCsv);

    $("range").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-range]"); if (!b) return;
      state.range = Number(b.dataset.range);
      $("range").querySelectorAll("button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
      if (state.stats) { renderKpis(); renderChart(); renderSeverity(); renderMitre(); renderSources(); }
    });

    $("f-sev").addEventListener("change", (e) => { state.sev = e.target.value; state.page = 0; renderAlerts(); });
    $("f-status").addEventListener("change", (e) => { state.status = e.target.value; state.page = 0; renderAlerts(); });
    $("btn-clear").addEventListener("click", clearFilters);
    let deb;
    $("q").addEventListener("input", (e) => { clearTimeout(deb); deb = setTimeout(() => { state.q = e.target.value; state.page = 0; renderAlerts(); }, 150); });

    document.querySelectorAll("#alerts-table th.sortable button").forEach((b) => b.addEventListener("click", () => {
      const key = b.parentElement.dataset.sort;
      state.sort = state.sort.key === key ? { key, dir: state.sort.dir === "asc" ? "desc" : "asc" } : { key, dir: ["rule", "ip", "status"].includes(key) ? "asc" : "desc" };
      state.page = 0;
      renderAlerts();
    }));
    $("page-size").addEventListener("change", (e) => { state.pageSize = Number(e.target.value); state.page = 0; renderAlerts(); });
    $("pg-prev").addEventListener("click", () => { state.page -= 1; renderAlerts(); });
    $("pg-next").addEventListener("click", () => { state.page += 1; renderAlerts(); });

    $("sel-all").addEventListener("change", (e) => {
      const rows = filtered().slice(state.page * state.pageSize, (state.page + 1) * state.pageSize);
      rows.forEach((a) => (e.target.checked ? state.selected.add(a.id) : state.selected.delete(a.id)));
      renderAlerts();
    });
    $("bulk-resolve").addEventListener("click", () => doStatus(selectedAlerts().filter(isOpen), "resolved"));
    $("bulk-fp").addEventListener("click", () => doStatus(selectedAlerts().filter(isOpen), "false_positive"));
    $("bulk-block").addEventListener("click", doBulkBlock);
    $("bulk-clear").addEventListener("click", () => { state.selected.clear(); renderAlerts(); });

    const tabs = [...document.querySelectorAll(".tabs [role=tab]")];
    tabs.forEach((b, i) => {
      b.addEventListener("click", () => setTab(b.dataset.tab));
      b.addEventListener("keydown", (e) => {
        const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
        if (d) { e.preventDefault(); setTab(tabs[(i + d + tabs.length) % tabs.length].dataset.tab, true); }
      });
    });
    $("fly-close").addEventListener("click", () => closeFlyout());
    $("scrim").addEventListener("click", () => closeFlyout());
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !$("flyout").hidden && !$("confirm").open) closeFlyout();
      if (e.key === "/" && !["INPUT", "SELECT", "TEXTAREA"].includes(document.activeElement.tagName) && !$("app").hidden) { e.preventDefault(); $("q").focus(); }
    });
    document.addEventListener("visibilitychange", () => {
      if (!authed()) return;
      if (document.hidden) stopTimer(); else if (!state.paused) { refresh(); startTimer(); }
    });

    initNav();
    boot();
  }

  init();
})();
