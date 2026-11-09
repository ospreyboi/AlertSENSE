#!/usr/bin/env bash
# AlertSense enterprise console (v3) installer - run from the AlertSENSE repo root:
#   bash install_dashboard_v3.sh
set -euo pipefail
[ -f app/main.py ] || { echo "Run this from the AlertSENSE repo root (the folder that contains app/)."; exit 1; }
STAMP=$(date +%Y%m%d-%H%M%S)
if [ -f app/static/index.html ]; then
  mkdir -p "backups/dashboard-$STAMP" && cp app/static/*.* "backups/dashboard-$STAMP/" 2>/dev/null || true
  echo "Backed up current dashboard to backups/dashboard-$STAMP"
fi
mkdir -p app/static/fonts tests
rm -f app/static/fonts/fira-*.woff2 tests/test_dashboard_v2.py
cat > app/static/index.html <<'__ALERTSENSE_EOF__'
<!doctype html>
<html lang="en" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>AlertSense · Security Operations</title>
  <link rel="stylesheet" href="/static/dashboard.css">
</head>
<body>
  <a class="skip-link" href="#main">Skip to main content</a>

  <!-- =============================================================== sign in -->
  <div id="login" class="login" hidden>
    <form id="keyform" class="login-box" novalidate>
      <div class="login-brand"><span class="logo" data-icon="shield" data-size="18"></span>AlertSense</div>
      <h1>Sign in</h1>
      <p class="text-muted">Security Operations Console</p>
      <div class="field">
        <label for="key">API key</label>
        <input id="key" name="key" type="password" autocomplete="off" spellcheck="false" required aria-describedby="key-help login-msg">
        <p id="key-help" class="help">The value of <code>ALERTSENSE_API_KEY</code> on the server. Stored for this browser tab only.</p>
        <p id="login-msg" class="field-error" role="alert"></p>
      </div>
      <button id="login-btn" class="btn btn-primary btn-block" type="submit">Sign in</button>
    </form>
  </div>

  <!-- =============================================================== app -->
  <div id="app" class="app" hidden>
    <header class="masthead">
      <div class="masthead-left">
        <a class="product" href="#overview"><span class="logo" data-icon="shield" data-size="16"></span><span>AlertSense</span></a>
        <span class="divider" aria-hidden="true"></span>
        <span class="workspace" title="Monitored workspace"><span class="text-dim">Workspace</span> lab-nginx</span>
      </div>
      <div class="masthead-right">
        <span id="conn" class="conn"><span class="dot" aria-hidden="true"></span><span id="conn-text">Connecting</span></span>
        <button id="btn-pause" class="mh-btn" type="button" aria-pressed="false"><span data-icon="pause"></span><span class="label">Pause</span></button>
        <button id="btn-theme" class="mh-btn mh-icon" type="button" aria-label="Switch to dark theme" title="Switch theme"><span data-icon="moon"></span></button>
        <button id="btn-logout" class="mh-btn" type="button"><span data-icon="logout"></span><span class="label">Sign out</span></button>
      </div>
    </header>

    <div class="body">
      <nav class="rail" aria-label="Primary">
        <p class="rail-heading">Security operations</p>
        <a class="rail-link is-active" href="#overview" data-nav="overview"><span data-icon="grid"></span>Overview</a>
        <a class="rail-link" href="#alerts" data-nav="alerts"><span data-icon="list"></span>Alerts<span class="rail-count" id="nav-open"></span></a>
        <a class="rail-link" href="#blocklist" data-nav="blocklist"><span data-icon="ban"></span>Blocklist<span class="rail-count" id="nav-blocks"></span></a>
        <div class="rail-foot">
          <p class="rail-heading">Response policy</p>
          <div id="mode" class="policy"></div>
        </div>
      </nav>

      <main id="main" tabindex="-1">
        <p id="sr-status" class="sr-only" role="status" aria-atomic="true"></p>
        <div id="banner" class="banner" role="alert" hidden></div>

        <div class="page-head">
          <div>
            <p class="crumbs">AlertSense <span aria-hidden="true">/</span> Security operations</p>
            <h1>Security overview</h1>
          </div>
          <div class="page-tools">
            <span id="updated" class="text-muted small">Waiting for data</span>
            <div class="seg" role="group" aria-label="Time range" id="range">
              <button type="button" data-range="1" aria-pressed="false">1h</button>
              <button type="button" data-range="24" aria-pressed="true">24h</button>
              <button type="button" data-range="168" aria-pressed="false">7d</button>
            </div>
          </div>
        </div>

        <!-- --------------------------------------------------------- overview -->
        <section id="overview" aria-labelledby="h-overview" class="stack">
          <h2 id="h-overview" class="sr-only">Overview</h2>
          <dl class="kpi-strip">
            <div class="kpi"><dt>Open alerts</dt><dd id="k-open">–</dd><p class="kpi-note" id="k-open-note">&nbsp;</p></div>
            <div class="kpi"><dt><span class="sev-sq sev-critical" aria-hidden="true"></span>Critical open</dt><dd id="k-critical">–</dd><p class="kpi-note" id="k-critical-note">&nbsp;</p></div>
            <div class="kpi"><dt><span class="sev-sq sev-high" aria-hidden="true"></span>High open</dt><dd id="k-high">–</dd><p class="kpi-note" id="k-high-note">&nbsp;</p></div>
            <div class="kpi"><dt id="k-range-label">Alerts, last 24h</dt><dd id="k-range">–</dd><p class="kpi-note" id="k-range-note">&nbsp;</p></div>
            <div class="kpi"><dt>Mean risk score</dt><dd id="k-risk">–</dd><p class="kpi-note" id="k-risk-note">&nbsp;</p></div>
            <div class="kpi"><dt>Active blocks</dt><dd id="k-blocks">–</dd><p class="kpi-note" id="k-blocks-note">&nbsp;</p></div>
          </dl>

          <div class="grid">
            <article class="panel col-8">
              <header class="panel-head">
                <h3 id="h-trend">Alert trend</h3>
                <ul class="legend" aria-label="Series">
                  <li><span class="lg lg-all" aria-hidden="true"></span>All alerts</li>
                  <li><span class="lg lg-crit" aria-hidden="true"></span>Critical + high</li>
                </ul>
              </header>
              <div id="chart" class="chart" aria-describedby="chart-summary"></div>
              <p id="chart-summary" class="panel-foot text-muted small"></p>
            </article>
            <article class="panel col-4">
              <header class="panel-head"><h3>Severity distribution</h3><span class="text-muted small" id="sev-scope"></span></header>
              <div class="panel-pad">
                <div id="sev-bar" class="sev-bar" role="img"></div>
                <table class="mini">
                  <thead><tr><th scope="col">Severity</th><th scope="col" class="num">Alerts</th><th scope="col" class="num">Share</th><th scope="col" class="num">Open</th></tr></thead>
                  <tbody id="sev-body"></tbody>
                </table>
              </div>
            </article>

            <article class="panel col-6">
              <header class="panel-head"><h3>MITRE ATT&amp;CK techniques</h3><span class="text-muted small" id="mitre-scope"></span></header>
              <table class="mini mini-flush">
                <thead><tr><th scope="col">Technique</th><th scope="col">Name</th><th scope="col" class="num">Alerts</th><th scope="col" class="w-bar"><span class="sr-only">Relative volume</span></th></tr></thead>
                <tbody id="mitre-body"></tbody>
              </table>
            </article>
            <article class="panel col-6">
              <header class="panel-head"><h3>Top source addresses</h3><span class="text-muted small" id="ip-scope"></span></header>
              <table class="mini mini-flush">
                <thead><tr><th scope="col">Source IP</th><th scope="col" class="num">Alerts</th><th scope="col" class="num hide-sm">Max risk</th><th scope="col">State</th><th scope="col" class="act"><span class="sr-only">Action</span></th></tr></thead>
                <tbody id="ip-body"></tbody>
              </table>
            </article>
          </div>
        </section>

        <!-- --------------------------------------------------------- alerts -->
        <section id="alerts" class="panel" aria-labelledby="h-alerts">
          <header class="panel-head">
            <h2 id="h-alerts">Alerts <span class="count" id="alert-count"></span></h2>
            <div class="head-actions">
              <button id="btn-export" class="btn btn-sm" type="button"><span data-icon="download"></span>Export CSV</button>
              <button id="btn-refresh" class="btn btn-sm" type="button"><span data-icon="refresh"></span>Refresh</button>
            </div>
          </header>
          <div class="toolbar">
            <div class="search">
              <span data-icon="search" aria-hidden="true"></span>
              <label class="sr-only" for="q">Search alerts</label>
              <input id="q" type="search" placeholder="Search by rule, IP, URL, technique or ID" autocomplete="off">
              <kbd aria-hidden="true">/</kbd>
            </div>
            <label class="select-label">Severity
              <select id="f-sev">
                <option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
              </select>
            </label>
            <label class="select-label">Status
              <select id="f-status">
                <option value="open">Open</option><option value="">All</option><option value="new">New</option><option value="triaged">Triaged</option>
                <option value="blocked">Blocked</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option>
              </select>
            </label>
            <button id="btn-clear" class="btn btn-link btn-sm" type="button" hidden>Clear filters</button>
          </div>
          <div id="bulkbar" class="bulkbar" hidden>
            <span id="bulk-count" class="bulk-count"></span>
            <button type="button" class="btn btn-sm" id="bulk-resolve"><span data-icon="check"></span>Resolve</button>
            <button type="button" class="btn btn-sm" id="bulk-fp"><span data-icon="flag"></span>False positive</button>
            <button type="button" class="btn btn-sm btn-danger-outline" id="bulk-block"><span data-icon="ban"></span>Block source IPs</button>
            <button type="button" class="btn btn-link btn-sm" id="bulk-clear">Clear selection</button>
          </div>
          <div class="table-wrap">
            <table class="grid-table" id="alerts-table">
              <thead>
                <tr>
                  <th scope="col" class="c-check"><input type="checkbox" id="sel-all" aria-label="Select all alerts on this page"></th>
                  <th scope="col" data-sort="severity" class="sortable"><button type="button">Severity</button></th>
                  <th scope="col" data-sort="risk" class="sortable num"><button type="button">Risk</button></th>
                  <th scope="col" data-sort="rule" class="sortable"><button type="button">Alert</button></th>
                  <th scope="col" class="hide-sm">Technique</th>
                  <th scope="col" data-sort="ip" class="sortable"><button type="button">Source IP</button></th>
                  <th scope="col" data-sort="status" class="sortable hide-sm"><button type="button">Status</button></th>
                  <th scope="col" data-sort="time" class="sortable"><button type="button">Last seen</button></th>
                  <th scope="col" class="c-act"><span class="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody id="alerts-body"></tbody>
            </table>
            <div id="alerts-empty" class="empty" hidden></div>
          </div>
          <footer class="pager">
            <label class="select-label">Rows per page
              <select id="page-size"><option>25</option><option selected>50</option><option>100</option></select>
            </label>
            <span id="page-info" class="text-muted"></span>
            <div class="pager-btns">
              <button type="button" class="btn btn-sm btn-icon" id="pg-prev" aria-label="Previous page"><span data-icon="chevLeft"></span></button>
              <button type="button" class="btn btn-sm btn-icon" id="pg-next" aria-label="Next page"><span data-icon="chevRight"></span></button>
            </div>
          </footer>
        </section>

        <!-- --------------------------------------------------------- blocklist -->
        <section id="blocklist" class="panel" aria-labelledby="h-blocks">
          <header class="panel-head">
            <h2 id="h-blocks">Blocklist <span class="count" id="block-count"></span></h2>
            <span class="text-muted small">Enforced at the Nginx edge · enforcer sync every 5 s</span>
          </header>
          <div class="table-wrap">
            <table class="grid-table">
              <thead>
                <tr>
                  <th scope="col">IP address</th><th scope="col">Origin</th><th scope="col" class="hide-sm">Reason</th>
                  <th scope="col" class="hide-sm">Added</th><th scope="col">Expires</th><th scope="col" class="c-act"><span class="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody id="blocks-body"></tbody>
            </table>
            <div id="blocks-empty" class="empty" hidden></div>
          </div>
        </section>

        <footer class="page-foot text-muted small">AlertSense · alert triage and automated response</footer>
      </main>
    </div>
  </div>

  <!-- =============================================================== flyout -->
  <div id="scrim" class="scrim" hidden></div>
  <aside id="flyout" class="flyout" role="dialog" aria-modal="false" aria-labelledby="fly-title" hidden>
    <header class="fly-head">
      <div class="fly-titles">
        <p class="fly-eyebrow" id="fly-eyebrow"></p>
        <h2 id="fly-title"></h2>
        <div class="fly-meta" id="fly-meta"></div>
      </div>
      <button id="fly-close" class="btn btn-icon btn-ghost" type="button" aria-label="Close alert details"><span data-icon="x"></span></button>
    </header>
    <div class="tabs" role="tablist" aria-label="Alert details">
      <button type="button" role="tab" id="tab-summary" aria-controls="pane" aria-selected="true" data-tab="summary">Summary</button>
      <button type="button" role="tab" id="tab-evidence" aria-controls="pane" aria-selected="false" data-tab="evidence" tabindex="-1">Evidence</button>
      <button type="button" role="tab" id="tab-intel" aria-controls="pane" aria-selected="false" data-tab="intel" tabindex="-1">Threat intel</button>
      <button type="button" role="tab" id="tab-raw" aria-controls="pane" aria-selected="false" data-tab="raw" tabindex="-1">Raw</button>
    </div>
    <div class="fly-body" id="pane" role="tabpanel" tabindex="0"></div>
    <footer class="fly-foot" id="fly-foot"></footer>
  </aside>

  <dialog id="confirm" class="modal" aria-labelledby="confirm-title" aria-describedby="confirm-text">
    <form method="dialog">
      <h2 id="confirm-title"></h2>
      <p id="confirm-text"></p>
      <div class="modal-actions">
        <button class="btn" value="cancel">Cancel</button>
        <button class="btn btn-danger" value="ok" id="confirm-ok">Confirm</button>
      </div>
    </form>
  </dialog>

  <div id="toasts" class="toasts" role="status" aria-live="polite"></div>
  <script src="/static/dashboard.js"></script>
</body>
</html>
__ALERTSENSE_EOF__
echo 'wrote app/static/index.html'
cat > app/static/dashboard.css <<'__ALERTSENSE_EOF__'
/* AlertSense console — "Data-Dense Dashboard" + Swiss minimalism (UI UX Pro Max).
   Tokens: 8px grid gap, 12px card padding, 36px table rows, 48px masthead, 224px rail. */

@font-face { font-family: "IBM Plex Sans"; font-weight: 400; font-display: swap; src: url("/static/fonts/ibm-plex-sans-latin-400-normal.woff2") format("woff2"); }
@font-face { font-family: "IBM Plex Sans"; font-weight: 500; font-display: swap; src: url("/static/fonts/ibm-plex-sans-latin-500-normal.woff2") format("woff2"); }
@font-face { font-family: "IBM Plex Sans"; font-weight: 600; font-display: swap; src: url("/static/fonts/ibm-plex-sans-latin-600-normal.woff2") format("woff2"); }
@font-face { font-family: "IBM Plex Mono"; font-weight: 400; font-display: swap; src: url("/static/fonts/ibm-plex-mono-latin-400-normal.woff2") format("woff2"); }
@font-face { font-family: "IBM Plex Mono"; font-weight: 500; font-display: swap; src: url("/static/fonts/ibm-plex-mono-latin-500-normal.woff2") format("woff2"); }
@font-face { font-family: "IBM Plex Mono"; font-weight: 600; font-display: swap; src: url("/static/fonts/ibm-plex-mono-latin-600-normal.woff2") format("woff2"); }

/* ------------------------------------------------------------------ tokens */
:root {
  --font: "IBM Plex Sans", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;

  --space-1: 4px; --space-2: 8px; --space-3: 12px; --space-4: 16px; --space-5: 24px; --space-6: 32px;
  --radius: 4px; --radius-sm: 3px;
  --row-h: 36px; --mast-h: 48px; --rail-w: 224px;
  --t-fast: 120ms; --t: 180ms;
}

:root[data-theme="light"] {
  --page: #f2f4f7;
  --surface: #ffffff;
  --surface-2: #f7f8fa;
  --surface-hover: #f0f3f8;
  --surface-sel: #e8eefb;
  --border: #dde1e6;
  --border-strong: #c1c7cd;
  --text: #161b22;
  --text-2: #4a5361;
  --text-dim: #6b7380;
  --primary: #1e40af;
  --primary-hover: #1e3a8a;
  --on-primary: #ffffff;
  --link: #1e40af;
  --ring: #1e40af;
  --mast: #10161f;
  --mast-text: #e6e9ee;
  --mast-dim: #9aa3b0;
  --mast-hover: #1f2732;
  --rail: #ffffff;

  --crit: #da1e28;  --crit-text: #a2191f; --crit-bg: #fff1f1;
  --high: #eb6200;  --high-text: #a33f00; --high-bg: #fff2e8;
  --med:  #d2a106;  --med-text:  #7a5c00; --med-bg:  #fdf6dd;
  --low:  #24a148;  --low-text:  #0e6027; --low-bg:  #defbe6;
  --pend: #8d96a3;
  --ok:   #198038;
  --danger: #da1e28; --danger-hover: #b81921;

  --chart-all: #1e40af; --chart-all-fill: rgba(30, 64, 175, .12); --chart-crit: #da1e28; --grid: #e6e9ed;
  --shadow-pop: 0 8px 24px rgba(16, 22, 31, .16), 0 1px 3px rgba(16, 22, 31, .12);
  color-scheme: light;
}

:root[data-theme="dark"] {
  --page: #0d1117;
  --surface: #151a22;
  --surface-2: #1a2029;
  --surface-hover: #1e2530;
  --surface-sel: #1d2a45;
  --border: #2a313c;
  --border-strong: #3a4350;
  --text: #e6e9ee;
  --text-2: #b0b8c4;
  --text-dim: #8b94a1;
  --primary: #2f5fd0;
  --primary-hover: #3b6ce0;
  --on-primary: #ffffff;
  --link: #8cb0ff;
  --ring: #8cb0ff;
  --mast: #0a0d12;
  --mast-text: #e6e9ee;
  --mast-dim: #8b94a1;
  --mast-hover: #1a2029;
  --rail: #11161d;

  --crit: #fa4d56;  --crit-text: #ff8389; --crit-bg: rgba(250, 77, 86, .12);
  --high: #ff832b;  --high-text: #ffa86b; --high-bg: rgba(255, 131, 43, .12);
  --med:  #f1c21b;  --med-text:  #f1c21b; --med-bg:  rgba(241, 194, 27, .10);
  --low:  #42be65;  --low-text:  #6fdc8c; --low-bg:  rgba(66, 190, 101, .12);
  --pend: #8b94a1;
  --ok:   #42be65;
  --danger: #da1e28; --danger-hover: #f0323c;

  --chart-all: #8cb0ff; --chart-all-fill: rgba(140, 176, 255, .14); --chart-crit: #fa4d56; --grid: #232a34;
  --shadow-pop: 0 12px 32px rgba(0, 0, 0, .5), 0 1px 3px rgba(0, 0, 0, .4);
  color-scheme: dark;
}

/* ------------------------------------------------------------------ base */
*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; background: var(--page); color: var(--text);
  font: 400 14px/1.45 var(--font); font-feature-settings: "tnum" 1;
  -webkit-font-smoothing: antialiased;
}
h1, h2, h3 { margin: 0; font-weight: 600; letter-spacing: 0; }
p { margin: 0; }
code, kbd, pre, .mono { font-family: var(--mono); }
code { font-size: 12px; background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 0 4px; }
a { color: var(--link); }
button, input, select { font: inherit; color: inherit; }
button { cursor: pointer; }
[hidden] { display: none !important; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
.text-muted { color: var(--text-2); }
.text-dim { color: var(--text-dim); }
.small { font-size: 12px; }
:focus-visible { outline: 2px solid var(--ring); outline-offset: 1px; }
.skip-link { position: absolute; left: 8px; top: -40px; z-index: 100; background: var(--primary); color: var(--on-primary); padding: 6px 10px; border-radius: var(--radius); }
.skip-link:focus { top: 8px; }
.icon { flex: none; display: block; }
[data-icon] { display: inline-flex; }

/* ------------------------------------------------------------------ controls */
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  height: 32px; padding: 0 12px; border: 1px solid var(--border-strong); border-radius: var(--radius-sm);
  background: var(--surface); color: var(--text); font-weight: 500; font-size: 13px; white-space: nowrap;
  transition: background var(--t-fast), border-color var(--t-fast), color var(--t-fast);
}
.btn:hover { background: var(--surface-hover); }
.btn:disabled { opacity: .5; cursor: not-allowed; }
.btn-sm { height: 28px; padding: 0 10px; font-size: 12.5px; }
.btn-icon { width: 32px; padding: 0; }
.btn-sm.btn-icon { width: 28px; }
.btn-primary { background: var(--primary); border-color: var(--primary); color: var(--on-primary); }
.btn-primary:hover { background: var(--primary-hover); border-color: var(--primary-hover); }
.btn-danger { background: var(--danger); border-color: var(--danger); color: #fff; }
.btn-danger:hover { background: var(--danger-hover); border-color: var(--danger-hover); }
.btn-danger-outline { color: var(--crit-text); }
.btn-danger-outline:hover { background: var(--crit-bg); border-color: var(--crit); }
.btn-ghost { background: transparent; border-color: transparent; color: var(--text-2); }
.btn-ghost:hover { background: var(--surface-hover); color: var(--text); }
.btn-link { border-color: transparent; background: transparent; color: var(--link); padding: 0 4px; }
.btn-link:hover { background: transparent; text-decoration: underline; }
.btn-block { width: 100%; height: 36px; }

input[type="search"], input[type="password"], select {
  height: 32px; border: 1px solid var(--border-strong); border-radius: var(--radius-sm);
  background: var(--surface); padding: 0 10px; font-size: 13px;
}
select { padding-right: 28px; cursor: pointer; }
input:hover, select:hover { border-color: var(--text-dim); }
input[type="checkbox"] { width: 16px; height: 16px; margin: 0; accent-color: var(--primary); cursor: pointer; vertical-align: middle; }
.select-label { display: inline-flex; align-items: center; gap: 8px; font-size: 12.5px; color: var(--text-2); }
.select-label select { color: var(--text); }

/* ------------------------------------------------------------------ sign in */
.login { min-height: 100vh; display: grid; place-items: center; padding: 16px; background: var(--page); }
.login-box { width: 100%; max-width: 380px; background: var(--surface); border: 1px solid var(--border); border-top: 3px solid var(--primary); border-radius: var(--radius); padding: 28px; }
.login-brand { display: flex; align-items: center; gap: 8px; font-weight: 600; margin-bottom: 24px; }
.login-box h1 { font-size: 20px; }
.login-box > .text-muted { margin: 2px 0 20px; }
.field label { display: block; font-size: 12.5px; font-weight: 500; margin-bottom: 6px; }
.field input { width: 100%; height: 36px; }
.help { font-size: 12px; color: var(--text-2); margin-top: 6px; }
.field-error { min-height: 18px; font-size: 12.5px; color: var(--crit-text); margin: 6px 0 12px; }
.logo { width: 24px; height: 24px; border-radius: 3px; background: var(--primary); color: #fff; align-items: center; justify-content: center; }

/* ------------------------------------------------------------------ masthead */
.masthead {
  position: sticky; top: 0; z-index: 30; height: var(--mast-h);
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding: 0 12px 0 16px; background: var(--mast); color: var(--mast-text); border-bottom: 1px solid #000;
}
.masthead-left, .masthead-right { display: flex; align-items: center; gap: 8px; min-width: 0; }
.product { display: flex; align-items: center; gap: 8px; color: inherit; text-decoration: none; font-weight: 600; font-size: 14px; }
.divider { width: 1px; height: 20px; background: #2b3441; margin: 0 6px; }
.workspace { font-size: 13px; white-space: nowrap; }
.workspace .text-dim { color: var(--mast-dim); margin-right: 4px; }
.mh-btn {
  display: inline-flex; align-items: center; gap: 6px; height: 32px; padding: 0 10px;
  background: transparent; border: 0; border-radius: var(--radius-sm); color: var(--mast-text); font-size: 13px;
  transition: background var(--t-fast);
}
.mh-btn:hover { background: var(--mast-hover); }
.mh-icon { width: 32px; padding: 0; justify-content: center; }
.mh-btn:focus-visible { outline-color: #8cb0ff; }
.conn { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--mast-dim); padding: 0 8px; white-space: nowrap; }
.conn .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--mast-dim); }
.conn.is-live .dot { background: #42be65; }
.conn.is-live { color: var(--mast-text); }
.conn.is-paused .dot { background: #f1c21b; }
.conn.is-offline .dot { background: #fa4d56; }
.conn.is-offline { color: #ffb3b8; }

/* ------------------------------------------------------------------ layout */
.body { display: grid; grid-template-columns: var(--rail-w) minmax(0, 1fr); min-height: calc(100vh - var(--mast-h)); }
.rail {
  position: sticky; top: var(--mast-h); height: calc(100vh - var(--mast-h));
  display: flex; flex-direction: column; gap: 2px; padding: 16px 8px;
  background: var(--rail); border-right: 1px solid var(--border);
}
.rail-heading { font-size: 11.5px; font-weight: 600; color: var(--text-dim); padding: 0 10px 6px; letter-spacing: .02em; }
.rail-link {
  display: flex; align-items: center; gap: 10px; height: 36px; padding: 0 10px;
  border-radius: var(--radius-sm); color: var(--text-2); text-decoration: none; font-weight: 500; font-size: 13.5px;
  border-left: 3px solid transparent; transition: background var(--t-fast), color var(--t-fast);
}
.rail-link:hover { background: var(--surface-hover); color: var(--text); }
.rail-link.is-active { background: var(--surface-sel); color: var(--text); border-left-color: var(--primary); border-radius: 0 var(--radius-sm) var(--radius-sm) 0; }
.rail-count { margin-left: auto; font-size: 12px; color: var(--text-2); font-weight: 500; }
.rail-foot { margin-top: auto; padding-top: 12px; border-top: 1px solid var(--border); }
.policy { padding: 0 10px; font-size: 12.5px; color: var(--text-2); }
.policy strong { display: block; color: var(--text); font-weight: 600; font-size: 13px; }

main { padding: 16px 20px 32px; min-width: 0; outline: none; }
.stack { display: flex; flex-direction: column; gap: 8px; margin-bottom: 8px; }
.page-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
.page-head h1 { font-size: 20px; line-height: 1.3; }
.crumbs { font-size: 12px; color: var(--text-dim); margin-bottom: 2px; }
.crumbs span { margin: 0 4px; }
.page-tools { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }

.seg { display: inline-flex; border: 1px solid var(--border-strong); border-radius: var(--radius-sm); overflow: hidden; background: var(--surface); }
.seg button { height: 30px; min-width: 44px; padding: 0 10px; background: transparent; border: 0; border-left: 1px solid var(--border-strong); font-size: 12.5px; font-weight: 500; color: var(--text-2); }
.seg button:first-child { border-left: 0; }
.seg button:hover { background: var(--surface-hover); color: var(--text); }
.seg button[aria-pressed="true"] { background: var(--primary); color: var(--on-primary); }

.banner { display: flex; align-items: center; gap: 8px; padding: 8px 12px; margin-bottom: 12px; background: var(--crit-bg); border: 1px solid var(--crit); border-left-width: 3px; border-radius: var(--radius-sm); color: var(--text); font-size: 13px; }

/* ------------------------------------------------------------------ KPI strip */
.kpi-strip { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); margin: 0; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); }
.kpi { padding: 12px 16px; border-left: 1px solid var(--border); min-width: 0; }
.kpi:first-child { border-left: 0; }
.kpi dt { display: flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--text-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.kpi dd { margin: 4px 0 2px; font-size: 26px; line-height: 1.15; font-weight: 500; font-variant-numeric: tabular-nums; }
.kpi-note { font-size: 12px; color: var(--text-dim); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.kpi-note .up { color: var(--crit-text); }
.kpi-note .down { color: var(--ok); }
.sev-sq { width: 8px; height: 8px; border-radius: 1px; flex: none; display: inline-block; }
.sev-critical { background: var(--crit); }
.sev-high { background: var(--high); }
.sev-medium { background: var(--med); }
.sev-low { background: var(--low); }
.sev-pending { background: var(--pend); }

/* ------------------------------------------------------------------ panels */
.grid { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 8px; }
.col-4 { grid-column: span 4; } .col-6 { grid-column: span 6; } .col-8 { grid-column: span 8; }
.panel { position: relative; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); min-width: 0; display: flex; flex-direction: column; }
section.panel { margin-top: 8px; }
.panel-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; min-height: 44px; padding: 8px 12px; border-bottom: 1px solid var(--border); flex-wrap: wrap; }
.panel-head h2, .panel-head h3 { font-size: 14px; }
.panel-head .count { font-weight: 400; color: var(--text-2); margin-left: 4px; }
.panel-pad { padding: 12px; }
.panel-foot { padding: 8px 12px; border-top: 1px solid var(--border); margin-top: auto; }
.head-actions { display: flex; gap: 8px; }

/* legend + chart */
.legend { display: flex; gap: 16px; list-style: none; margin: 0; padding: 0; font-size: 12px; color: var(--text-2); }
.legend li { display: flex; align-items: center; gap: 6px; }
.lg { width: 16px; height: 0; border-top: 2px solid; display: inline-block; }
.lg-all { border-color: var(--chart-all); }
.lg-crit { border-color: var(--chart-crit); border-top-style: dashed; }
.chart { position: relative; padding: 12px 12px 4px 44px; }
.chart svg { display: block; width: 100%; height: 200px; overflow: visible; }
.chart .gridline { stroke: var(--grid); stroke-width: 1; shape-rendering: crispEdges; }
.chart .area { fill: var(--chart-all-fill); }
.chart .line-all { fill: none; stroke: var(--chart-all); stroke-width: 2; vector-effect: non-scaling-stroke; stroke-linejoin: round; }
.chart .line-crit { fill: none; stroke: var(--chart-crit); stroke-width: 1.75; stroke-dasharray: 5 3; vector-effect: non-scaling-stroke; stroke-linejoin: round; }
.chart .hit { fill: transparent; }
.chart .hit:hover { fill: var(--surface-hover); fill-opacity: .6; }
.chart .y-labels { position: absolute; left: 0; top: 12px; width: 40px; height: 200px; font-size: 11px; color: var(--text-dim); }
.chart .y-labels span { position: absolute; right: 6px; transform: translateY(-50%); font-family: var(--mono); }
.chart .x-labels { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-dim); padding-top: 6px; font-family: var(--mono); }

/* severity distribution */
.sev-bar { display: flex; height: 10px; border-radius: 2px; overflow: hidden; background: var(--surface-2); margin-bottom: 12px; gap: 1px; }
.sev-bar span { display: block; height: 100%; }

/* compact tables */
.mini { width: 100%; border-collapse: collapse; font-size: 13px; }
.mini th { text-align: left; font-size: 12px; font-weight: 500; color: var(--text-2); padding: 6px 8px; border-bottom: 1px solid var(--border); white-space: nowrap; }
.mini td { padding: 0 8px; height: 34px; border-bottom: 1px solid var(--border); white-space: nowrap; }
.mini tbody tr:last-child td { border-bottom: 0; }
.mini-flush th:first-child, .mini-flush td:first-child { padding-left: 12px; }
.mini-flush th:last-child, .mini-flush td:last-child { padding-right: 12px; }
.mini .num, .grid-table .num { text-align: right; font-variant-numeric: tabular-nums; }
.mini .act { text-align: right; width: 1%; }
.mini .w-bar { width: 28%; }
.mini .name { color: var(--text-2); overflow: hidden; text-overflow: ellipsis; max-width: 0; width: 45%; }
.mini td.empty-row { color: var(--text-2); height: 56px; text-align: center; white-space: normal; }
.minibar { height: 6px; background: var(--surface-2); border-radius: 1px; overflow: hidden; }
.minibar > span { display: block; height: 100%; background: var(--primary); }
.sev-cell { display: inline-flex; align-items: center; gap: 8px; }

.tech { font-family: var(--mono); font-size: 12px; color: var(--text); }
.ip { font-family: var(--mono); font-size: 12.5px; white-space: nowrap; }
.state { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--text-2); white-space: nowrap; }
.state .icon { color: currentColor; }
.state.is-blocked { color: var(--crit-text); font-weight: 500; }

/* ------------------------------------------------------------------ alert table */
.toolbar { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding: 8px 12px; border-bottom: 1px solid var(--border); background: var(--surface-2); }
.search { position: relative; display: flex; align-items: center; flex: 1 1 280px; max-width: 420px; }
.search > [data-icon] { position: absolute; left: 9px; color: var(--text-dim); pointer-events: none; }
.search input { width: 100%; padding-left: 32px; padding-right: 30px; }
.search kbd { position: absolute; right: 8px; font-size: 11px; color: var(--text-dim); border: 1px solid var(--border-strong); border-radius: 3px; padding: 0 5px; line-height: 16px; }

.bulkbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding: 6px 12px; background: var(--surface-sel); border-bottom: 1px solid var(--border); }
.bulk-count { font-weight: 600; font-size: 13px; margin-right: 8px; }

.table-wrap { overflow-x: auto; position: relative; }
.grid-table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 13px; }
.grid-table th {
  position: sticky; top: 0; z-index: 1; background: var(--surface); text-align: left; white-space: nowrap;
  font-size: 12px; font-weight: 600; color: var(--text-2); height: 36px; padding: 0 12px; border-bottom: 1px solid var(--border-strong);
}
.grid-table th.sortable { padding: 0; }
.grid-table th.sortable button {
  display: inline-flex; align-items: center; gap: 4px; width: 100%; height: 36px; padding: 0 12px;
  background: none; border: 0; font: inherit; color: inherit; text-align: left;
}
.grid-table th.num.sortable button { justify-content: flex-end; }
.grid-table th.sortable button:hover { color: var(--text); background: var(--surface-hover); }
.grid-table th[aria-sort] button { color: var(--text); }
.sort-ind { width: 12px; color: var(--text-dim); }
.grid-table td { height: var(--row-h); padding: 0 12px; border-bottom: 1px solid var(--border); white-space: nowrap; vertical-align: middle; }
.grid-table tbody tr { cursor: pointer; transition: background var(--t-fast); }
.grid-table tbody tr:hover { background: var(--surface-hover); }
.grid-table tbody tr.is-selected { background: var(--surface-sel); }
.grid-table tbody tr.is-open { box-shadow: inset 3px 0 0 var(--primary); }
.grid-table .c-check { width: 40px; padding: 0 0 0 12px; }
.grid-table .c-act { width: 1%; text-align: right; padding-right: 8px; }
.risk { display: inline-block; min-width: 34px; text-align: right; font-weight: 600; font-variant-numeric: tabular-nums; }
.risk.r-critical { color: var(--crit-text); } .risk.r-high { color: var(--high-text); }
.risk.r-medium { color: var(--med-text); } .risk.r-low { color: var(--low-text); } .risk.r-pending { color: var(--text-dim); }
.rule { font-weight: 500; color: var(--text); max-width: 340px; overflow: hidden; text-overflow: ellipsis; display: block; }
.alert-id { color: var(--text-dim); font-family: var(--mono); font-size: 12px; margin-right: 8px; }
.alert-cell { display: flex; align-items: baseline; min-width: 0; }
.row-actions { display: inline-flex; gap: 2px; opacity: .85; }
tr:hover .row-actions, tr:focus-within .row-actions { opacity: 1; }
.row-actions .btn { width: 28px; height: 28px; padding: 0; border-color: transparent; background: transparent; color: var(--text-2); }
.row-actions .btn:hover { background: var(--surface); border-color: var(--border-strong); color: var(--text); }
.row-actions .btn.is-danger:hover { color: var(--crit-text); border-color: var(--crit); }
.status { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--text-2); }
.status::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; opacity: .9; }
.status.s-new { color: var(--link); } .status.s-triaged { color: var(--text); }
.status.s-blocked { color: var(--crit-text); } .status.s-resolved { color: var(--ok); } .status.s-false_positive { color: var(--text-dim); }
.origin { font-size: 12.5px; color: var(--text-2); }

.empty { padding: 40px 16px; text-align: center; color: var(--text-2); display: flex; flex-direction: column; align-items: center; gap: 6px; }
.empty strong { color: var(--text); font-weight: 600; }
.pager { display: flex; align-items: center; gap: 16px; justify-content: flex-end; flex-wrap: wrap; padding: 8px 12px; border-top: 1px solid var(--border); font-size: 12.5px; }
.pager-btns { display: flex; gap: 4px; }
.page-foot { text-align: center; padding: 24px 0 0; }

/* ------------------------------------------------------------------ flyout */
.scrim { position: fixed; inset: 0; z-index: 40; background: rgba(10, 13, 18, .35); }
.flyout {
  position: fixed; top: 0; right: 0; bottom: 0; z-index: 50; width: min(560px, 100vw);
  display: flex; flex-direction: column; background: var(--surface); border-left: 1px solid var(--border-strong); box-shadow: var(--shadow-pop);
  animation: fly-in var(--t) ease-out;
}
@keyframes fly-in { from { transform: translateX(16px); opacity: 0; } to { transform: none; opacity: 1; } }
.fly-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; padding: 16px 16px 12px 20px; }
.fly-titles { min-width: 0; }
.fly-eyebrow { font-size: 12px; color: var(--text-dim); font-family: var(--mono); }
.fly-head h2 { font-size: 17px; line-height: 1.35; margin: 2px 0 8px; }
.fly-meta { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 12.5px; color: var(--text-2); }
.fly-meta > span { display: inline-flex; align-items: center; gap: 6px; }
.tabs { display: flex; gap: 4px; padding: 0 20px; border-bottom: 1px solid var(--border); }
.tabs button { height: 36px; padding: 0 8px; background: none; border: 0; border-bottom: 2px solid transparent; margin-bottom: -1px; color: var(--text-2); font-weight: 500; font-size: 13px; }
.tabs button:hover { color: var(--text); }
.tabs button[aria-selected="true"] { color: var(--text); border-bottom-color: var(--primary); }
.fly-body { flex: 1; overflow-y: auto; padding: 16px 20px 24px; outline: none; }
.fly-body h3 { font-size: 12.5px; font-weight: 600; color: var(--text-2); margin: 20px 0 8px; }
.fly-body h3:first-child { margin-top: 0; }
.fly-foot { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding: 12px 20px; border-top: 1px solid var(--border); background: var(--surface-2); }
.fly-foot .spacer { flex: 1; }
.fly-foot select { height: 32px; }

.props { display: grid; grid-template-columns: 140px minmax(0, 1fr); margin: 0; border: 1px solid var(--border); border-radius: var(--radius-sm); }
.props dt, .props dd { margin: 0; padding: 7px 10px; border-bottom: 1px solid var(--border); font-size: 13px; }
.props dt { color: var(--text-2); background: var(--surface-2); }
.props dd { overflow-wrap: anywhere; }
.props dt:nth-last-of-type(1), .props dd:last-child { border-bottom: 0; }
.scorebox { display: flex; align-items: center; gap: 16px; padding: 12px; border: 1px solid var(--border); border-radius: var(--radius-sm); margin-bottom: 16px; }
.scorebox .big { font-size: 30px; font-weight: 500; line-height: 1; font-variant-numeric: tabular-nums; }
.scorebox .big small { font-size: 13px; color: var(--text-dim); margin-left: 2px; }
.scorebox .meter { flex: 1; }
.meter-track { height: 6px; background: var(--surface-2); border-radius: 1px; overflow: hidden; border: 1px solid var(--border); }
.meter-track > span { display: block; height: 100%; }
.meter-scale { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-dim); margin-top: 4px; font-family: var(--mono); }
.contrib { width: 100%; border-collapse: collapse; font-size: 13px; }
.contrib td { padding: 6px 0; border-bottom: 1px solid var(--border); }
.contrib td.pts { width: 56px; font-family: var(--mono); font-weight: 600; text-align: right; padding-right: 12px; color: var(--crit-text); }
.contrib td.pts.neg { color: var(--ok); }
.contrib tfoot td { border-bottom: 0; font-weight: 600; }
.code { margin: 0; padding: 10px 12px; background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius-sm); font: 12.5px/1.55 var(--mono); white-space: pre-wrap; overflow-wrap: anywhere; max-height: 360px; overflow: auto; }
.note { font-size: 13px; color: var(--text-2); padding: 10px 12px; background: var(--surface-2); border: 1px dashed var(--border-strong); border-radius: var(--radius-sm); }

/* ------------------------------------------------------------------ modal + toasts */
.modal { width: min(440px, calc(100vw - 32px)); padding: 0; border: 1px solid var(--border-strong); border-radius: var(--radius); background: var(--surface); color: var(--text); box-shadow: var(--shadow-pop); }
.modal::backdrop { background: rgba(10, 13, 18, .45); }
.modal form { padding: 20px; }
.modal h2 { font-size: 16px; margin-bottom: 8px; }
.modal p { color: var(--text-2); font-size: 13.5px; }
.modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 20px; }
.toasts { position: fixed; right: 16px; top: calc(var(--mast-h) + 12px); z-index: 60; display: flex; flex-direction: column; gap: 8px; max-width: min(400px, calc(100vw - 32px)); }
.toast { display: flex; align-items: flex-start; gap: 10px; padding: 10px 12px; background: var(--surface); border: 1px solid var(--border-strong); border-left: 3px solid var(--ok); border-radius: var(--radius-sm); box-shadow: var(--shadow-pop); font-size: 13px; animation: fly-in var(--t) ease-out; }
.toast .icon { color: var(--ok); margin-top: 1px; }
.toast.is-error { border-left-color: var(--crit); }
.toast.is-error .icon { color: var(--crit); }

/* ------------------------------------------------------------------ responsive */
@media (max-width: 1280px) {
  .kpi-strip { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .kpi:nth-child(4) { border-left: 0; }
  .kpi:nth-child(n+4) { border-top: 1px solid var(--border); }
}
@media (max-width: 1100px) {
  .col-8, .col-4, .col-6 { grid-column: span 12; }
}
@media (max-width: 960px) {
  .body { grid-template-columns: minmax(0, 1fr); }
  .rail { position: sticky; top: var(--mast-h); z-index: 20; height: auto; flex-direction: row; align-items: center; gap: 4px; padding: 0 12px; overflow-x: auto; border-right: 0; border-bottom: 1px solid var(--border); }
  .rail-heading, .rail-foot { display: none; }
  .rail-link { height: 44px; border-left: 0; border-bottom: 2px solid transparent; border-radius: 0; white-space: nowrap; }
  .rail-link.is-active { background: transparent; border-bottom-color: var(--primary); border-radius: 0; }
  .workspace, .divider { display: none; }
}
@media (max-width: 720px) {
  main { padding: 12px 12px 24px; }
  .kpi-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .kpi:nth-child(n) { border-left: 1px solid var(--border); border-top: 1px solid var(--border); }
  .kpi:nth-child(odd) { border-left: 0; }
  .kpi:nth-child(-n+2) { border-top: 0; }
  .kpi dd { font-size: 22px; }
  .hide-sm { display: none; }
  .mh-btn .label { display: none; }
  .mh-btn { width: 40px; justify-content: center; padding: 0; height: 40px; }
  .conn #conn-text { display: none; }
  .btn, .btn-sm { height: 40px; }
  .btn-sm.btn-icon, .btn-icon { width: 40px; }
  .row-actions .btn { width: 40px; height: 40px; }
  .seg button { height: 40px; }
  input[type="search"], select { height: 40px; }
  .search { max-width: none; flex-basis: 100%; }
  .search kbd { display: none; }
  .page-tools { width: 100%; justify-content: space-between; }
  .props { grid-template-columns: 110px minmax(0, 1fr); }
  .legend { gap: 10px; }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; }
}
.grid-table tbody tr.static { cursor: default; }
__ALERTSENSE_EOF__
echo 'wrote app/static/dashboard.css'
cat > app/static/dashboard.js <<'__ALERTSENSE_EOF__'
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
      res = await fetch(path, { ...opts, headers: { "X-API-Key": state.key, "Content-Type": "application/json" } });
    } catch (_) {
      throw Object.assign(new Error("The AlertSense API is unreachable."), { network: true });
    }
    if (res.status === 401) {
      signOut("The API key was rejected. Check ALERTSENSE_API_KEY on the server.");
      throw Object.assign(new Error("unauthorized"), { auth: true });
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
    $("key").focus();
  }
  function showApp() {
    $("login").hidden = true;
    $("app").hidden = false;
    refresh();
    startTimer();
  }
  function signOut(msg) {
    state.key = "";
    store.del(KEY_STORE);
    showLogin(msg);
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
    if (!state.key) return;
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
        h("td", { class: "act" }, isB
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
      const acts = h("div", { class: "row-actions" });
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
        h("td", { class: "c-check" }, cb),
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

    $("bulkbar").hidden = state.selected.size === 0;
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
        h("td", { class: "c-act" }, h("button", { type: "button", class: "btn btn-sm", onclick: () => doUnblock(b.ip) }, "Unblock")));
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
      if (!state.key) return;
      if (document.hidden) stopTimer(); else if (!state.paused) { refresh(); startTimer(); }
    });

    initNav();
    state.key = store.get(KEY_STORE) || "";
    if (state.key) showApp(); else showLogin("");
  }

  init();
})();
__ALERTSENSE_EOF__
echo 'wrote app/static/dashboard.js'

# IBM Plex fonts, self-hosted so the strict Content-Security-Policy keeps working.
TMPF=$(mktemp -d)
if command -v npm >/dev/null && (cd "$TMPF" && npm pack --silent @fontsource/ibm-plex-sans@5 @fontsource/ibm-plex-mono@5 >/dev/null 2>&1); then
  for pkg in ibm-plex-sans ibm-plex-mono; do
    tar xzf "$TMPF"/fontsource-$pkg-*.tgz -C "$TMPF"
    for w in 400 500 600; do cp "$TMPF/package/files/$pkg-latin-$w-normal.woff2" app/static/fonts/; done
    rm -rf "$TMPF/package"
  done
  echo "Installed IBM Plex Sans + IBM Plex Mono"
else
  echo "Could not download fonts - the console falls back to system fonts."
fi
rm -rf "$TMPF"

grep -q '^backups/' .gitignore 2>/dev/null || echo 'backups/' >> .gitignore

cat > tests/test_dashboard_static.py <<'__ALERTSENSE_EOF__'
"""Static checks that keep the console compatible with the strict CSP and safe from stored XSS."""
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "app" / "static"


def test_no_inline_script_style_or_handlers():
    html = (STATIC / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "inline <script> is blocked by the CSP"
    assert "<style" not in html and " style=" not in html, "inline styles are blocked by the CSP"
    assert not re.search(r"\son[a-z]+=", html), "inline event handlers are blocked by the CSP"


def test_no_external_resources():
    for f in ("index.html", "dashboard.css", "dashboard.js"):
        text = (STATIC / f).read_text().replace("http://www.w3.org/2000/svg", "")
        assert "https://" not in text and "http://" not in text, f"{f} loads an external resource"


def test_js_never_parses_html():
    js = (STATIC / "dashboard.js").read_text()
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert bad not in js, bad


def test_csv_export_blocks_formula_injection():
    js = (STATIC / "dashboard.js").read_text()
    assert "formula injection" in js
__ALERTSENSE_EOF__
echo "wrote tests/test_dashboard_static.py"

echo
echo "Done. Next:"
echo "  python -m pytest -q"
echo "  bash scripts/stop_all.sh && bash scripts/run_all.sh"
echo "  open the forwarded port-8000 URL and hard-refresh (Cmd+Shift+R)"
