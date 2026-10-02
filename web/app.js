"use strict";
/* Stratum web UI. No build step: plain JS, template strings, one delegated click handler. */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const PALETTE = ["var(--c1)", "var(--c2)", "var(--c3)", "var(--c4)", "var(--c5)", "var(--c6)", "var(--c7)", "var(--c8)"];

function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(n >= 100 ? 0 : 1)) + " " + u[i];
}
const now = () => Date.now() / 1000;
const optOf = (o, k) => { try { return JSON.parse(o || "{}")[k]; } catch { return ""; } };
const fmtNum = (n) => (Number(n) || 0).toLocaleString();
const fmtShort = (n) => { n = Number(n) || 0; return n >= 1e9 ? (n / 1e9).toFixed(2) + "B" : n >= 1e6 ? (n / 1e6).toFixed(2) + "M" : n >= 1e4 ? (n / 1e3).toFixed(1) + "K" : fmtNum(n); };
const fmtDate = (u) => u ? new Date(u * 1000).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "";
const fmtDay = (u) => u ? new Date(u * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "";
function ago(u) {
  if (!u) return "never";
  const s = Math.max(0, Date.now() / 1000 - u);
  if (s < 60) return Math.floor(s) + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}

const ICONS = {
  dash: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
  db: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
  copy: '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M4 16V5a2 2 0 0 1 2-2h11"/>',
  alert: '<path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>',
  activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  server: '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>',
  tag: '<path d="M20.6 13.4 13.4 20.6a2 2 0 0 1-2.8 0L3 13V3h10l7.6 7.6a2 2 0 0 1 0 2.8z"/><circle cx="7.5" cy="7.5" r="1.5"/>',
  flow: '<rect x="3" y="3" width="6" height="6" rx="1"/><rect x="15" y="15" width="6" height="6" rx="1"/><path d="M9 6h4a2 2 0 0 1 2 2v7"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
  flame: '<path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.4-.5-2-1-3-1.1-2.1-.2-4 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.2.4-2.3 1-3.2.3 1.6 1.2 2.7 2.5 2.7z"/>',
  snow: '<path d="M12 2v20M4.9 4.9l14.2 14.2M2 12h20M4.9 19.1 19.1 4.9"/>',
  branch: '<circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><path d="M6 9v3a6 6 0 0 0 6 6h3"/>',
  trend: '<path d="m22 7-8.5 8.5-5-5L2 17"/><path d="M16 7h6v6"/>',
  files: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
  folder: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  play: '<path d="m6 3 14 9-14 9z"/>',
  flask: '<path d="M9 3h6M10 3v6L4 20a1 1 0 0 0 .9 1.5h14.2A1 1 0 0 0 20 20L14 9V3"/>',
  trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>',
  edit: '<path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
  history: '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l4 2"/>',
  back: '<path d="m15 18-6-6 6-6"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.8 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  stop: '<rect x="5" y="5" width="14" height="14" rx="2"/>',
};
const icon = (n, s = 16, extra = "") => `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ${extra}>${ICONS[n] || ""}</svg>`;

// ---------- state & api ----------
const S = {
  scope: (() => { try { return JSON.parse(localStorage.getItem("scope")) || { device: 0, share: 0 }; } catch { return { device: 0, share: 0 }; } })(),
  tree: [],
  version: "",
};
function saveScope() { try { localStorage.setItem("scope", JSON.stringify(S.scope)); } catch {} }
function scopeQS(extra = {}) {
  const p = new URLSearchParams();
  if (S.scope.device) p.set("device", S.scope.device);
  if (S.scope.share) p.set("share", S.scope.share);
  for (const [k, v] of Object.entries(extra)) if (v !== "" && v != null && v !== 0) p.set(k, v);
  return p.toString();
}
async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: {} };
  if (opts.body !== undefined) { init.body = JSON.stringify(opts.body); init.headers["Content-Type"] = "application/json"; }
  const r = await fetch(path, init);
  if (r.status === 401 && !path.startsWith("/api/login")) { renderLogin(); throw new Error("sign in required"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}
function toast(msg, err) {
  const t = document.createElement("div");
  t.className = "toast" + (err ? " err" : "");
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), err ? 6000 : 3000);
}
// A newer search cancels the one still running; that cancellation is expected, not an error.
window.addEventListener("unhandledrejection", (e) => { if (e.reason && e.reason.name === "AbortError") e.preventDefault(); });
const tryApi = async (fn) => { try { return await fn(); } catch (e) { if (e.message !== "sign in required") toast(e.message, true); } };

// ---------- modal ----------
function modal(html, onMount) {
  const bg = document.createElement("div");
  bg.className = "modal-bg";
  bg.innerHTML = `<div class="modal">${html}</div>`;
  bg.addEventListener("mousedown", (e) => { if (e.target === bg) bg.remove(); });
  document.body.appendChild(bg);
  const m = bg.firstElementChild;
  m.close = () => bg.remove();
  onMount && onMount(m);
  return m;
}
function confirmTyped(title, body, word, danger = true) {
  return new Promise((res) => {
    modal(`<h3>${esc(title)}</h3><p>${body}</p>
      <div class="field"><label>Type <code>${esc(word)}</code> to confirm</label><input class="in" id="ct"></div>
      <div class="row end"><button class="btn" id="cn">Cancel</button><button class="btn ${danger ? "danger" : "primary"}" id="ok" disabled>Confirm</button></div>`, (m) => {
      const inp = $("#ct", m), ok = $("#ok", m);
      inp.focus();
      inp.oninput = () => (ok.disabled = inp.value !== word);
      $("#cn", m).onclick = () => { m.close(); res(null); };
      ok.onclick = () => { m.close(); res(inp.value); };
    });
  });
}

// ---------- shell ----------
const NAV = [
  ["dashboard", "Overview", "dash"], ["sources", "Sources", "db"], ["index", "Scans", "history"], ["search", "Search", "search"],
  ["insights", "Insights", "bulb"], ["risk", "Risk", "shield"], ["reports", "Reports", "files"], ["automations", "Automations", "flow"], ["settings", "Settings", "gear"],
];
ICONS.bulb = '<path d="M9 18h6M10 22h4M12 2a7 7 0 0 0-4 12.7V17h8v-2.3A7 7 0 0 0 12 2z"/>';
ICONS.spark = '<path d="M12 3l1.9 5.8L20 11l-6.1 2.2L12 19l-1.9-5.8L4 11l6.1-2.2z"/>';
ICONS.cloud = '<path d="M17.5 19H9a7 7 0 1 1 6.7-9h1.8a4.5 4.5 0 1 1 0 9z"/>';
const REPORTS = [
  ["search", "Search", "Find files by name, type, age, owner, path or tag across every source, then export.", "search", "#eef0ff", "var(--c1)"],
  ["automations", "Automations", "Copy, move, delete, rename or tag files at scale. Dry-run first, every item audited.", "flow", "#e6f7f1", "var(--ok)"],
  ["tags", "Tag rules", "Tag files by rule. Automatic, reversible, re-applied after every scan. Feeds Automations.", "tag", "#fff4e0", "var(--warn)"],
  ["duplicates", "Duplicates", "Reclaimable space: duplicate files ranked by wasted bytes, with every copy's location.", "copy", "#e7f5fd", "var(--c3)"],
  ["issues", "Path problems", "Folders the scan could not read, links and stubs not followed, long and illegal Windows paths.", "alert", "#fff4e0", "var(--warn)"],
  ["owners", "Owners", "Capacity rolled up by folder owner, next to how active each account is in the audit stream.", "users", "#f3ecff", "var(--c2)"],
  ["audit", "File activity", "Create, modify, delete, rename and read events per device, aggregated into 60-second windows.", "activity", "#fdecee", "var(--bad)"],
  ["iops", "Disk activity", "Per-disk, per-node and per-share IOPS against each series' own baseline: anomalies, level shifts, and the most contended files.", "activity", "#fdecee", "var(--bad)"],
  ["ads", "Hidden data streams", "NTFS alternate data streams by class, device and owner: internet-origin, cloud-sync, and unknown or hidden payloads.", "shield", "#fdecee", "var(--bad)"],
  ["inventory", "Hardware", "Hardware and capacity of every registered device: model, serial, OS version, node count.", "server", "#eef1f5", "var(--muted)"],
];

function shell() {
  $("#root").innerHTML = `
  <header class="top">
    <div class="top-in">
      <a class="brand" href="#/dashboard">
        <svg width="34" height="34" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#c2410c"/><path d="M7 10.5h13M10 16h15M7 21.5h11" stroke="#fff" stroke-width="3.2" stroke-linecap="round"/></svg>
        <div><b>Stratum</b><small>Know your storage · v<span id="ver"></span></small></div>
      </a>
      <nav class="main">${NAV.map(([k, l, i]) => `<a href="#/${k}" data-nav="${k}">${icon(i, 15)} ${l}</a>`).join("")}</nav>
      <div class="top-right"><a id="running" href="#/index"></a><span class="small muted" id="whoami"></span><button class="btn sm primary" data-act="wizard">${icon("plus", 13)} Add source</button><button class="btn sm" data-act="theme" title="Toggle theme">◐</button><button class="btn sm" data-act="logout" title="Sign out">${icon("logout", 14)}</button></div>
    </div>
    <div class="scopebar"><span class="lbl">SCOPE</span>
      <select id="scDev"></select><span class="faint">›</span><select id="scShare"></select>
      <span id="scopeNote" class="faint"></span>
    </div>
  </header>
  <main id="view"></main>`;
  $("#ver").textContent = S.version;
  if (S.me) $("#whoami").textContent = S.me.username + " · " + S.me.role;
  $("#scDev").onchange = (e) => { S.scope = { device: +e.target.value, share: 0 }; saveScope(); fillScope(); route(); };
  $("#scShare").onchange = (e) => {
    const sid = +e.target.value;
    const d = S.tree.find((x) => x.shares.some((s) => s.id === sid));
    S.scope = sid && d ? { device: d.id, share: sid } : { device: S.scope.device, share: 0 };
    saveScope(); fillScope(); route();
  };
}

async function loadScope() {
  S.tree = await api("/api/scope");
  if (S.scope.device && !S.tree.find((d) => d.id === S.scope.device)) S.scope = { device: 0, share: 0 };
  fillScope();
}
function fillScope() {
  const dev = $("#scDev"), sh = $("#scShare");
  if (!dev) return;
  dev.innerHTML = `<option value="0">All devices</option>` + S.tree.map((d) => `<option value="${d.id}" ${d.id === S.scope.device ? "selected" : ""}>${esc(d.name)}</option>`).join("");
  const opt = (s) => `<option value="${s.id}" ${s.id === S.scope.share ? "selected" : ""}>${esc(s.name)}${s.published ? "" : " (not indexed yet)"}</option>`;
  const devs = S.scope.device ? S.tree.filter((x) => x.id === S.scope.device) : S.tree;
  sh.disabled = false;
  sh.innerHTML = `<option value="0">All shares</option>` + devs.map((d) => devs.length > 1 ? `<optgroup label="${esc(d.name)}">${d.shares.map(opt).join("")}</optgroup>` : d.shares.map(opt).join("")).join("");
}
function scopeLabel() {
  const d = S.tree.find((x) => x.id === S.scope.device);
  if (!d) return "All storage sources";
  const s = d.shares.find((x) => x.id === S.scope.share);
  return esc(d.name) + (s ? " › " + esc(s.name) : "");
}
const showing = () => `<div class="showing">SHOWING <span class="chip">${icon("db", 13)} ${scopeLabel()}</span></div>`;

function hero({ eyebrow = "", title, sub, iconName, actions = "", kpis = "", back = true, extra = "" }) {
  return `<section class="hero">
    <div class="hero-actions">${actions}</div>
    ${back ? `<a class="back" href="#/dashboard">${icon("back", 13)} Back to Overview</a>` : ""}
    ${eyebrow ? `<div class="eyebrow">${eyebrow}</div>` : ""}
    <h1>${iconName ? icon(iconName, 24) : ""}${esc(title)}</h1>
    <p>${sub}</p>${extra}
    ${kpis ? `<div class="kpis">${kpis}</div>` : ""}
  </section>`;
}
const kpi = (k, v, s = "", ic = "", attrs = "") => `<div class="kpi" ${attrs}><div class="k">${ic ? icon(ic, 14) : ""}${k}</div><div class="v">${v}</div>${s ? `<div class="s">${s}</div>` : ""}</div>`;

// ---------- router ----------
const PAGES = {};
let routeSeq = 0;
async function route() {
  const [, name = "dashboard", ...rest] = location.hash.split("/");
  const page = PAGES[name] || PAGES.dashboard;
  $$("nav.main a").forEach((a) => a.classList.toggle("on", a.dataset.nav === name || (name !== "dashboard" && a.dataset.nav === "reports" && !NAV.find((n) => n[0] === name))));
  const seq = ++routeSeq;
  const view = $("#view");
  if (!view) return; // login screen is showing
  view.innerHTML = `<div class="progress" style="margin:30px 0"><div></div></div>`;
  try { await page(view, rest, () => seq === routeSeq); } catch (e) { if (e.message !== "sign in required") view.innerHTML = `<div class="panel empty"><b>Something went wrong</b>${esc(e.message)}</div>`; }
}
window.addEventListener("hashchange", route);

// ---------- dashboard ----------
PAGES.dashboard = async (view) => {
  const qs = scopeQS();
  const sum = await api("/api/summary?" + qs);
  let published = S.tree.some((d) => d.shares.some((s) => s.published));
  if (!published) { await loadScope(); published = S.tree.some((d) => d.shares.some((s) => s.published)); } // a first scan may have finished since sign-in
  if (!published) {
    const hasDev = S.tree.length > 0, hasShare = S.tree.some((d) => d.shares.length);
    const step = (n, done, title, body, btn) => `<div class="step ${done ? "done" : ""}"><div class="num">${done ? "✓" : n}</div><div style="flex:1"><b>${title}</b><div class="small muted">${body}</div></div>${done ? "" : btn}</div>`;
    view.innerHTML = hero({ title: "Welcome to Stratum", back: false, sub: "Three steps to your first storage report. Nothing is copied: Stratum reads file names, sizes, dates and owners, never file contents." }) +
      `<div class="panel"><h2>${icon("spark", 16)} Getting started</h2><div class="sub">Each step takes a minute. Scans run in the background; watch them on the Scans page.</div>
      ${step(1, hasDev, "Connect a storage system", "A Windows file server (this machine or a remote one) or a PowerScale cluster. If the storage sits in another network, install a collector there first.", `<button class="btn primary" data-act="wizard">${icon("plus", 14)} Add source</button>`)}
      ${step(2, hasShare, "Pick the shares to index", "Discover the shares the system publishes and tick the ones you care about.", `<a class="btn" href="#/sources">Open Sources</a>`)}
      ${step(3, false, "Let the first scan finish", "Progress, speed and the folder being read are live on the Scans page. Reports fill in the moment a share is published.", `<a class="btn" href="#/index">Watch progress</a>`)}
      </div>`;
    return;
  }
  view.innerHTML = hero({
    title: "Overview", back: false,
    sub: "What your storage holds, how old it is, who owns it and how fast it grows, across every connected source.",
    extra: `<form class="ask" id="askf"><span>${icon("spark", 18)}</span><input class="in" id="askq" placeholder="Ask your data: videos over 1 GB not touched in 2 years in Finance" autocomplete="off"><button class="btn primary">Ask</button></form>
      <div class="meta">${icon("history", 13)} Index as of ${sum.oldest ? `<b>${fmtDate(sum.oldest)}</b> (oldest share) · newest ${fmtDate(sum.newest)}` : "no published scans yet"} ${sum.running ? `· <span class="pulse"><i></i>${sum.running} scan${sum.running > 1 ? "s" : ""} running</span>` : ""}</div>`,
    actions: `<a class="btn" href="/api/export/dashboard.xlsx?${scopeQS()}">${icon("download", 14)} Excel report</a> <a class="btn" href="#/index">${icon("refresh", 14)} Scans</a>`,
    kpis: kpi("Total data", fmtBytes(sum.bytes), "", "db") + kpi("Files", fmtNum(sum.files), "", "files") + kpi("Folders", fmtNum(sum.folders), "", "folder") + kpi("Sources", `${sum.devices}<span style="font-size:14px;opacity:.7"> devices · ${sum.shares} shares</span>`, "", "server"),
  }) + `
  <div class="panel"><h2>${icon("dash", 16)} Reports</h2><div class="sub">Every report, one click away.</div>
    <div class="grid3 cards">${REPORTS.map(([k, t, d, i, bg, fg]) => `<a class="card" href="#/${k}"><div class="ic" style="background:color-mix(in srgb, ${fg} 14%, transparent);color:${fg}">${icon(i, 20)}</div><div><b>${t}</b><span>${d}</span></div></a>`).join("")}</div>
  </div>
  ${showing()}
  <div class="panel" id="ins"></div>
  <div class="panel" id="hc"></div>
  <div class="panel" id="tf"></div>
  <div class="panel" id="gr"></div>
  <div class="grid2"><div class="panel" id="ft"></div><div class="panel" id="ow"></div></div>`;
  bindAsk($("#askf"));
  insightStrip($("#ins"));
  hotCold($("#hc"), 12);
  topFolders($("#tf"), 1);
  growthChart($("#gr"));
  fileTypes($("#ft"));
  ownersMini($("#ow"));
};

const BAND_COLORS = ["#ef4444", "#f97316", "#facc15", "#2dd4bf", "#38bdf8", "#3b82f6"];
async function hotCold(el, months) {
  const d = await api("/api/hotcold?" + scopeQS({ months }));
  const tot = d.hot_bytes + d.cold_bytes || 1;
  const pct = (x) => Math.round((x / tot) * 1000) / 10;
  const stack = (arr) => { const t = arr.reduce((a, b) => a + b.bytes, 0) || 1; return `<div class="stack">${arr.map((b, i) => `<div title="${b.key}: ${fmtBytes(b.bytes)}" style="flex:${b.bytes / t};background:${BAND_COLORS[i]}"></div>`).join("")}</div>`; };
  const cutDays = Math.round(months * 30.44);
  el.innerHTML = `<div class="panel-head"><div><h2>${icon("flame", 16, 'style="color:var(--hot)"')} Data age</h2><div class="sub">How much data changed within the window (active) and how much has sat untouched for longer (idle).</div></div>
    <div class="seg">${[1, 3, 6, 12, 24].map((m) => `<button class="${m === months ? "on" : ""}" data-m="${m}">${m}mo</button>`).join("")}</div></div>
    <div class="tempcard hot">${icon("flame", 26, 'style="color:var(--hot)"')}<div><b>${fmtBytes(d.hot_bytes)} active (${pct(d.hot_bytes)}% of data by size)</b><div class="small muted">${fmtNum(d.hot_files)} files modified within the last ${months} months: the working set.</div></div>
      <a class="btn sm" href="#/search/newer_days=${cutDays}">Show active files →</a><div class="big">${pct(d.hot_bytes)}%</div></div>
    <div class="tempcard cold">${icon("snow", 26, 'style="color:var(--cold)"')}<div><b>${fmtBytes(d.cold_bytes)} idle (${pct(d.cold_bytes)}% of data by size)</b><div class="small muted">${fmtNum(d.cold_files)} files not modified in over ${months} months: candidates for a cheaper tier or an archive.</div></div>
      <a class="btn sm" href="#/search/older_days=${cutDays}">Show idle files →</a><div class="big">${pct(d.cold_bytes)}%</div></div>
    <div class="grid2" style="margin-top:14px"><div><div class="small muted" style="margin-bottom:6px">By last access</div>${stack(d.by_access)}</div><div><div class="small muted" style="margin-bottom:6px">By last modified</div>${stack(d.by_modified)}</div></div>
    <div class="legend">${d.by_modified.map((b, i) => `<span><i style="background:${BAND_COLORS[i]}"></i>${b.key}</span>`).join("")}</div>
    <div class="small faint" style="margin-top:8px">Access times depend on the storage keeping them: Windows disables last-access updates on many volumes and PowerScale updates atime only when atime tracking is enabled, so "by last modified" is the reliable view.</div>`;
  $$(".seg button", el).forEach((b) => (b.onclick = () => hotCold(el, +b.dataset.m)));
}

async function topFolders(el, depth) {
  const rows = await api("/api/topfolders?" + scopeQS({ depth, limit: 10 }));
  const max = rows[0]?.bytes || 1;
  el.innerHTML = `<div class="panel-head"><div><h2>${icon("branch", 16, 'style="color:var(--c7)"')} Largest folders</h2><div class="sub">The ten biggest folders at the level you pick. Hover one to see where it sits.</div></div>
    <div class="row"><span class="small muted">Folder tree depth</span><div class="seg">${[1, 2, 3, 4, 5, 6].map((n) => `<button class="${n === depth ? "on" : ""}" data-d="${n}">${n}</button>`).join("")}</div></div></div>
    <div class="grid2"><div>${rows.length ? rows.map((r, i) => `<div class="hbar" data-i="${i}"><span class="faint">${i + 1}</span><span class="nm" title="${esc(r.path)}">${esc(r.path.split("/").pop() || r.share)}</span>
      <div class="track"><div class="fill" style="width:${(r.bytes / max) * 100}%;background:${PALETTE[i % 8]}"></div></div><span class="num" style="text-align:right">${fmtBytes(r.bytes)}</span><span class="files faint small" style="text-align:right">${fmtNum(r.files)}</span></div>`).join("") : `<div class="empty">No folders at depth ${depth}.</div>`}</div>
    <div class="unroll" id="unroll"><div class="empty">${icon("branch", 22)}<br>Hover a folder to unroll its path</div></div></div>`;
  $$(".seg button", el).forEach((b) => (b.onclick = () => topFolders(el, +b.dataset.d)));
  $$(".hbar", el).forEach((h) => (h.onmouseenter = () => {
    const r = rows[+h.dataset.i];
    const parts = r.path.split("/").filter(Boolean);
    $("#unroll", el).innerHTML = `<div class="small muted">${esc(r.device)} › ${esc(r.share)}</div>` +
      parts.map((p, i) => `<div class="seg-path" style="margin-left:${i * 14}px">${esc(p)}</div>`).join("") +
      `<div class="small" style="margin-top:10px">${fmtBytes(r.bytes)} · ${fmtNum(r.files)} files · owner <b>${esc(r.owner || "unknown")}</b></div>
       <div class="row" style="margin-top:8px"><a class="btn sm" href="#/search/share=${r.share_id}&path=${encodeURIComponent(r.path)}">Browse files</a>
       <button class="btn sm ghost-danger" data-act="exclude-path" data-id="${r.share_id}" data-path="${esc(r.path)}">${icon("x", 12)} Exclude from scans</button></div>`;
  }));
}

async function growthChart(el) {
  const d = await api("/api/growth?" + scopeQS({ months: 24 }));
  const all = [...d.series.map((p) => ({ ...p, proj: false })), ...d.projection.map((p) => ({ ...p, proj: true }))];
  const W = 1000, H = 280, L = 60, B = 30, T = 10, R = 10;
  const maxV = Math.max(1, ...all.map((p) => p.bytes)) * 1.1;
  const x = (i) => L + (i * (W - L - R)) / (all.length - 1);
  const y = (v) => T + (H - T - B) * (1 - v / maxV);
  const actual = d.series.map((p, i) => `${x(i)},${y(p.bytes)}`).join(" ");
  const li = d.series.length - 1;
  const proj = [`${x(li)},${y(d.series[li].bytes)}`, ...d.projection.map((p, j) => `${x(li + 1 + j)},${y(p.bytes)}`)].join(" ");
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => maxV * f);
  const mlabel = (m) => { const [yy, mm] = m.split("-"); return new Date(+yy, +mm - 1, 1).toLocaleDateString(undefined, { month: "short", year: "2-digit" }); };
  el.innerHTML = `<div class="panel-head"><div><h2>${icon("trend", 16, 'style="color:var(--c2)"')} Growth</h2><div class="sub">Cumulative data by creation month, with a 6-month straight-line projection from the last 6 months.</div></div>
    <div class="small muted">Projected growth <b>${fmtBytes(d.monthly_growth)}/month</b></div></div>
    <svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto">
      <defs><linearGradient id="gfill" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#8b5cf6" stop-opacity=".35"/><stop offset="1" stop-color="#8b5cf6" stop-opacity="0"/></linearGradient></defs>
      ${ticks.map((t) => `<line x1="${L}" x2="${W - R}" y1="${y(t)}" y2="${y(t)}" stroke="var(--line)" stroke-dasharray="3 4"/><text x="${L - 8}" y="${y(t) + 4}" text-anchor="end">${fmtBytes(t)}</text>`).join("")}
      ${all.map((p, i) => (i % 3 === 0 || i === all.length - 1) ? `<text x="${x(i)}" y="${H - 8}" text-anchor="middle">${mlabel(p.month)}</text>` : "").join("")}
      <polygon points="${x(0)},${y(0)} ${actual} ${x(li)},${y(0)}" fill="url(#gfill)"/>
      <polyline points="${actual}" fill="none" stroke="#7c3aed" stroke-width="2.5"/>
      <polyline points="${proj}" fill="none" stroke="#7c3aed" stroke-width="2" stroke-dasharray="6 5"/>
      ${d.series.map((p, i) => `<circle cx="${x(i)}" cy="${y(p.bytes)}" r="3" fill="#7c3aed"><title>${mlabel(p.month)}: ${fmtBytes(p.bytes)}</title></circle>`).join("")}
      ${d.projection.map((p, j) => `<circle cx="${x(li + 1 + j)}" cy="${y(p.bytes)}" r="3" fill="var(--panel)" stroke="#7c3aed"><title>Projected ${mlabel(p.month)}: ${fmtBytes(p.bytes)}</title></circle>`).join("")}
    </svg>
    <div class="legend" style="justify-content:center"><span><i style="background:#7c3aed"></i>Indexed</span><span><i style="background:transparent;border:2px dashed #7c3aed"></i>Projected</span></div>
    <div class="small faint" style="margin-top:6px">Creation time resets when files are copied or migrated, so a migration shows up as a single spike. Scan history (${d.history?.length || 0} days recorded) tracks what the index actually held over time.</div>`;
}

async function fileTypes(el) {
  const rows = await api("/api/filetypes?" + scopeQS({ limit: 15 }));
  const max = rows[0]?.bytes || 1;
  el.innerHTML = `<h2>${icon("files", 16, 'style="color:var(--c3)"')} By File Type</h2><div class="sub">Top extensions by total size.</div>
    ${rows.map((r, i) => `<div class="hbar" style="grid-template-columns:70px 1fr 80px 80px"><span class="nm mono">${esc(r.ext || "(none)")}</span>
      <div class="track"><div class="fill" style="width:${(r.bytes / max) * 100}%;background:${PALETTE[i % 8]}"></div></div><span style="text-align:right">${fmtBytes(r.bytes)}</span><span class="files faint small" style="text-align:right">${fmtShort(r.files)}</span></div>`).join("") || `<div class="empty">Nothing indexed yet.</div>`}`;
}

async function ownersMini(el) {
  const rows = await api("/api/owners?" + scopeQS({ limit: 10 }));
  const max = rows[0]?.bytes || 1;
  el.innerHTML = `<div class="panel-head"><div><h2>${icon("users", 16, 'style="color:var(--c2)"')} Biggest owners</h2><div class="sub">Capacity by folder owner.</div></div><a class="btn sm" href="#/owners">All owners →</a></div>
    ${rows.map((r, i) => `<div class="hbar" style="grid-template-columns:minmax(120px,200px) 1fr 80px"><span class="nm" title="${esc(r.owner)}">${esc(r.owner)}</span>
      <div class="track"><div class="fill" style="width:${(r.bytes / max) * 100}%;background:${PALETTE[(i + 1) % 8]}"></div></div><span style="text-align:right">${fmtBytes(r.bytes)}</span></div>`).join("") || `<div class="empty">Nothing indexed yet.</div>`}`;
}

// ---------- sources ----------
let pollTimer = null;
PAGES.sources = async (view, _, alive) => {
  const [devs, scans, cols] = await Promise.all([api("/api/devices"), api("/api/scans?limit=25"), api("/api/collectors").catch(() => [])]);
  view.innerHTML = hero({
    title: "Sources", iconName: "db",
    sub: "Register Windows file servers and PowerScale clusters, pick the shares to index, and schedule metadata scans. A scan that fails or is interrupted never replaces the last good index.",
    actions: `<button class="btn primary" data-act="wizard">${icon("plus", 14)} Add source</button> <button class="btn" data-act="add-device">Manual device</button>`,
  }) + `<div id="active"></div>
  ${devs.length ? devs.map(deviceCard).join("") : `<div class="panel empty"><b>No devices yet</b>Start with this machine (local drives and shares), a remote Windows file server, or a PowerScale cluster.<br><br><button class="btn primary" data-act="wizard">Add source</button></div>`}
  <div class="panel"><div class="panel-head"><div><h2>${icon("cloud", 16)} Collectors</h2><div class="sub">On-site agents for storage this server cannot reach. They connect out over HTTPS.</div></div><button class="btn sm" data-act="add-collector">${icon("plus", 12)} New collector</button></div>
  <table class="t"><thead><tr><th>Name</th><th>Status</th><th>Host</th><th>Version</th><th class="num">Devices</th><th></th></tr></thead><tbody>
  ${cols.map((c) => `<tr><td><b>${esc(c.name)}</b></td><td>${c.online ? '<span class="pill ok">ONLINE</span>' : `<span class="pill ${c.last_seen ? "bad" : "mute"}">${c.last_seen ? "OFFLINE" : "NEVER CONNECTED"}</span>`} <span class="small faint">${c.last_seen ? ago(c.last_seen) : ""}</span></td><td class="small">${esc(c.hostname)}</td><td class="small">${esc(c.version)}</td><td class="num">${c.devices}</td>
    <td class="num">${c.online && !c.devices ? `<button class="btn sm primary" data-act="collector-drives" data-id="${c.id}" data-name="${esc(c.hostname || c.name)}">${icon("plus", 12)} Add this machine's drives</button> ` : ""}<button class="btn sm" data-act="rotate-collector" data-id="${c.id}" data-name="${esc(c.name)}">New token</button> <button class="btn sm ghost-danger" data-act="del-collector" data-id="${c.id}">${icon("trash", 12)}</button></td></tr>`).join("") || `<tr><td colspan="6" class="empty small">None. Only needed when the storage is in another network than this server.</td></tr>`}
  </tbody></table></div>
  <div class="panel"><h2>${icon("history", 16)} Scan history</h2><div class="sub">Most recent metadata walks.</div>
  <table class="t"><thead><tr><th>#</th><th>Device</th><th>Share</th><th>Started</th><th>Duration</th><th>Status</th><th class="num">Files</th><th class="num">Size</th><th class="num">Errors</th><th>Message</th></tr></thead><tbody>
  ${scans.history.map((s) => `<tr><td class="faint">${s.id}</td><td>${esc(s.device)}</td><td>${esc(s.share)}</td><td>${fmtDate(s.started)}</td><td>${s.finished ? Math.max(1, s.finished - s.started) + "s" : ""}</td>
    <td>${statusPill(s.status)}</td><td class="num">${fmtNum(s.files)}</td><td class="num">${fmtBytes(s.bytes)}</td><td class="num">${s.errors || ""}</td><td class="small muted ellip" style="max-width:340px" title="${esc(s.message)}">${esc(s.message)}</td></tr>`).join("") || `<tr><td colspan="10" class="empty">No scans yet.</td></tr>`}
  </tbody></table></div>`;
  S.devs = devs;
  S.cols = cols;
  const idle = cols.filter((c) => c.online && !c.devices);
  if (idle.length) {
    view.querySelector(".hero").insertAdjacentHTML("afterend", idle.map((c) => `<div class="note info" style="display:flex;align-items:center;gap:12px;justify-content:space-between">
      <span>${icon("cloud", 14)} Collector <b>${esc(c.name)}</b> on <b>${esc(c.hostname)}</b> is online but has no devices yet. Add its drives to start scanning that machine.</span>
      <button class="btn sm primary" data-act="collector-drives" data-id="${c.id}" data-name="${esc(c.hostname || c.name)}">${icon("plus", 12)} Add this machine's drives</button></div>`).join(""));
  }
  const renderActive = (act) => {
    const el = $("#active");
    if (!el) return;
    el.innerHTML = act.length ? `<div class="panel"><h2><span class="pulse"><i></i></span> Scans in progress</h2><div class="sub">Counts update live. Cancelling keeps the previous index published.</div>
      ${act.map((p) => `<div style="margin:10px 0"><div class="row" style="justify-content:space-between"><b>${esc(p.device)} › ${esc(p.share)}</b>
      <span class="small muted">${p.publishing ? '<span class="pill info">BUILDING REPORTS</span> walk finished, indexing ' : ""}${fmtNum(p.files)} files · ${fmtNum(p.dirs)} folders · ${fmtBytes(p.bytes)} · ${p.errors} errors · ${ago(p.started)} <button class="btn sm ghost-danger" data-act="cancel-scan" data-id="${p.scan_id}">${icon("stop", 12)} Cancel</button></span></div>
      <div class="progress" style="margin-top:6px"><div></div></div></div>`).join("")}</div>` : "";
  };
  renderActive(scans.active);
  clearInterval(pollTimer);
  let hadActive = scans.active.length > 0;
  pollTimer = setInterval(async () => {
    if (!alive() || !location.hash.startsWith("#/sources")) return clearInterval(pollTimer);
    const s = await api("/api/scans?limit=1").catch(() => null);
    if (!s) return;
    renderActive(s.active);
    if (hadActive && !s.active.length) { clearInterval(pollTimer); loadScope(); route(); }
    hadActive = s.active.length > 0;
  }, 2000);
};
function statusPill(s) {
  const m = { done: "ok", running: "info", failed: "bad" };
  return `<span class="pill ${m[s] || "mute"}">${esc(s === "failed" ? "not published" : s || "never scanned")}</span>`;
}
function deviceCard(d) {
  const kind = { powerscale: "POWERSCALE", s3: "S3 / OBJECTSCALE", windows: "FILE SERVER" }[d.kind] || d.kind.toUpperCase();
  return `<div class="panel" style="padding:0;overflow:hidden"><div class="device-card" style="border:0;margin:0">
    <div class="dh">${icon("server", 18)}<b style="font-size:15px">${esc(d.name)}</b><span class="pill info">${kind}</span>
      <span class="small muted">${esc(d.host || (d.collector_id ? "the collector's machine" : "the Stratum server itself"))}${d.username ? " · " + esc(d.username) : ""}</span>
      ${d.collector_id ? `<span class="pill ${now() - d.collector_seen < 30 ? "ok" : "bad"}">${icon("cloud", 11)} via ${esc(d.collector)}</span>` : ""}
      <span style="flex:1"></span>
      ${d.kind === "windows" ? `<button class="btn sm" data-act="enable-audit" data-id="${d.id}" title="Turn file auditing on or off for these shares">${icon("activity", 13)} Auditing</button>` : ""}
      <button class="btn sm" data-act="discover" data-id="${d.id}">${icon("search", 13)} Discover shares</button>
      <button class="btn sm" data-act="add-share" data-id="${d.id}">${icon("plus", 13)} Add path</button>
      <button class="btn sm" data-act="edit-device" data-id="${d.id}">${icon("edit", 13)}</button>
      <button class="btn sm ghost-danger" data-act="del-device" data-id="${d.id}" data-name="${esc(d.name)}">${icon("trash", 13)}</button>
    </div>
    ${d.shares.length ? `<table class="t"><thead><tr><th>Share</th><th>Path</th><th>Schedule</th>${d.kind === "windows" ? '<th title="Scan NTFS alternate data streams (one extra call per file)">ADS</th>' : ""}${d.kind !== "s3" ? '<th title="Read folder permissions during the scan (one call per folder)">Perms</th>' : ""}<th>Last scan</th><th>Status</th><th class="num">Files</th><th class="num">Size</th><th></th></tr></thead><tbody>
    ${d.shares.map((s) => `<tr><td><b>${esc(s.name)}</b></td><td class="path">${esc(s.path)}</td>
      <td><select class="in" style="width:auto;padding:3px 6px" data-sched="${s.id}" data-name="${esc(s.name)}">${[[0, "Manual"], [6, "Every 6h"], [12, "Every 12h"], [24, "Daily"], [168, "Weekly"]].map(([v, l]) => `<option value="${v}" ${v === s.schedule_hours ? "selected" : ""}>${l}</option>`).join("")}</select></td>
      ${d.kind === "windows" ? `<td><input type="checkbox" data-ads="${s.id}" data-name="${esc(s.name)}" data-sched2="${s.schedule_hours}" ${(s.options || "").includes('"ads":true') ? "checked" : ""} title="Scan alternate data streams"></td>` : ""}
      ${d.kind !== "s3" ? `<td><input type="checkbox" data-perms="${s.id}" data-name="${esc(s.name)}" data-sched2="${s.schedule_hours}" ${(s.options || "").includes('"perms":false') ? "" : "checked"} title="Read folder permissions (Permissions report)"></td>` : ""}
      <td>${s.last_scan_at ? ago(s.last_scan_at) : "never"}</td><td title="${esc(s.message)}">${statusPill(s.status)}</td>
      <td class="num">${fmtNum(s.files)}</td><td class="num">${fmtBytes(s.bytes)}</td>
      <td class="num"><button class="btn sm" data-act="exclude" data-id="${s.id}" title="Folders and files to leave out">${icon("x", 12)} Exclude${(optOf(s.options, "exclude") || []).length ? " (" + optOf(s.options, "exclude").length + ")" : ""}</button>
      <button class="btn sm primary" data-act="scan" data-id="${s.id}">${icon("play", 12)} Scan</button>
      <button class="btn sm ghost-danger" data-act="del-share" data-id="${s.id}" data-name="${esc(s.name)}">${icon("trash", 12)}</button></td></tr>`).join("")}
    </tbody></table>` : `<div class="empty small">No shares selected. Use <b>Discover shares</b> or <b>Add path</b>.</div>`}
  </div></div>`;
}
function deviceForm(d = {}) {
  modal(`<h3>${d.id ? "Edit device" : "Add device"}</h3>
    <div class="field"><label>Type</label><div class="seg" id="kind"><button data-k="windows" class="${d.kind !== "powerscale" ? "on" : ""}">Windows file server</button><button data-k="powerscale" class="${d.kind === "powerscale" ? "on" : ""}">Dell PowerScale</button><button data-k="s3" class="${d.kind === "s3" ? "on" : ""}">S3 / ObjectScale</button></div></div>
    <div class="fgrid">
      <div class="field"><label>Display name</label><input class="in" id="f_name" value="${esc(d.name || "")}" placeholder="fs01 or ps-prod"></div>
      <div class="field"><label id="hostLbl">Server</label><input class="in" id="f_host" value="${esc(d.host || "")}"><span class="hint" id="hostHint"></span></div>
      <div class="field"><label>Username</label><input class="in" id="f_user" value="${esc(d.username || "")}" autocomplete="off"><span class="hint" id="userHint"></span></div>
      <div class="field"><label>Password</label><input class="in" id="f_pass" type="password" autocomplete="new-password" placeholder="${d.has_secret ? "unchanged" : ""}"></div>
      <div class="field" style="grid-column:1/-1"><label>Reached through</label><select class="in" id="f_col"><option value="0">This server</option>${(S.cols || []).map((c) => `<option value="${c.id}" ${c.id === d.collector_id ? "selected" : ""}>Collector: ${esc(c.name)}</option>`).join("")}</select></div>
      <div class="field s3o"><label>Region</label><input class="in" id="f_region" value="${esc(optOf(d.options, "region") || "us-east-1")}"></div>
      <div class="field s3o"><label>Addressing</label><label class="small"><input type="checkbox" id="f_vhost" ${(d.options || "").includes('"path_style":false') ? "checked" : ""}> Virtual-hosted buckets (AWS); off = path-style (ObjectScale, MinIO)</label></div>
      <div class="field ps"><label>API port</label><input class="in" id="f_port" type="number" value="${d.port || 8080}"></div>
      <div class="field ps"><label>TLS</label><label class="small"><input type="checkbox" id="f_ins" ${d.insecure ? "checked" : ""}> Accept self-signed certificate</label></div>
    </div>
    <div class="note info small" id="req"></div>
    <div class="row end"><button class="btn" data-close>Cancel</button><button class="btn primary" id="save">Save</button></div>`, (m) => {
    let kind = d.kind || "windows";
    const sync = () => {
      $$("#kind button", m).forEach((b) => b.classList.toggle("on", b.dataset.k === kind));
      $$(".ps", m).forEach((e) => (e.style.display = kind === "powerscale" || (kind === "s3" && e.querySelector("#f_ins")) ? "" : "none"));
      $$(".s3o", m).forEach((e) => (e.style.display = kind === "s3" ? "" : "none"));
      if (kind === "s3") {
        $("#hostLbl", m).textContent = "Endpoint URL";
        $("#hostHint", m).textContent = "e.g. https://objectscale.corp:9021 or https://s3.eu-west-1.amazonaws.com";
        $("#userHint", m).textContent = "Access key ID. The password field takes the secret key.";
        $("#req", m).innerHTML = "Read-only needs <code>s3:ListAllMyBuckets</code>, <code>s3:ListBucket</code> and <code>s3:GetObject</code> (viewer). Buckets are discovered as shares; prefixes appear as folders. Duplicates use the object ETag.";
      } else if (kind === "powerscale") {
        $("#hostLbl", m).textContent = "Cluster address (SmartConnect or node IP)";
        $("#hostHint", m).textContent = "PAPI and RAN on port 8080 over HTTPS.";
        $("#userHint", m).textContent = "Local or AD account with the RBAC privileges listed below.";
        $("#req", m).innerHTML = "Read-only role needs: <code>ISI_PRIV_LOGIN_PAPI</code>, <code>ISI_PRIV_NS_TRAVERSE</code>, <code>ISI_PRIV_NS_IFS_ACCESS</code> (read), <code>ISI_PRIV_SMB</code> (read, for share discovery), <code>ISI_PRIV_STATISTICS</code> and <code>ISI_PRIV_CLUSTER</code> (read, for inventory). RAN must be enabled (HTTP service). Automations additionally need write on the namespace. Audit: forward protocol audit to this server's syslog port.";
      } else {
        $("#hostLbl", m).textContent = "Server (blank = this machine)";
        $("#hostHint", m).textContent = "Hostname of a remote Windows file server, or leave blank for local drives.";
        $("#userHint", m).textContent = "Optional DOMAIN\\user. Blank = the account this service runs as.";
        $("#req", m).innerHTML = "The account needs read and list on every folder (Backup Operators or an explicit read ACE). Owners are read from folder security descriptors. For audit activity on this machine, enable <b>Audit File System</b> and add a SACL to the audited folders; events are read from the Security log.";
      }
    };
    $$("#kind button", m).forEach((b) => (b.onclick = () => { kind = b.dataset.k; sync(); }));
    sync();
    $("[data-close]", m).onclick = m.close;
    $("#save", m).onclick = () => tryApi(async () => {
      await api("/api/devices" + (d.id ? "/" + d.id : ""), { method: d.id ? "PUT" : "POST", body: {
        name: $("#f_name", m).value, kind, host: $("#f_host", m).value, username: $("#f_user", m).value, password: $("#f_pass", m).value,
        port: +$("#f_port", m).value || 0, insecure: $("#f_ins", m).checked, collector_id: +$("#f_col", m).value,
        options: kind === "s3" ? JSON.stringify({ region: $("#f_region", m).value || "us-east-1", path_style: !$("#f_vhost", m).checked }) : "" } });
      m.close(); toast("Device saved"); await loadScope(); route();
    });
  });
}
function shareForm(devId, pre = {}) {
  modal(`<h3>Add path to index</h3>
    <div class="field"><label>Name</label><input class="in" id="s_name" value="${esc(pre.name || "")}" placeholder="Finance"></div>
    <div class="field"><label>Path</label><input class="in mono" id="s_path" value="${esc(pre.path || "")}" placeholder="D:\\Shares\\Finance, \\\\fs01\\finance or /ifs/data/finance"></div>
    <div class="field"><label>Schedule</label><select class="in" id="s_sched"><option value="0">Manual</option><option value="12">Every 12h</option><option value="24" selected>Daily</option><option value="168">Weekly</option></select></div>
    <div class="row end"><button class="btn" data-close>Cancel</button><button class="btn primary" id="save">Add and scan now</button></div>`, (m) => {
    $("[data-close]", m).onclick = m.close;
    $("#save", m).onclick = () => tryApi(async () => {
      const r = await api("/api/shares", { method: "POST", body: { device_id: devId, name: $("#s_name", m).value, path: $("#s_path", m).value, schedule_hours: +$("#s_sched", m).value } });
      await api(`/api/shares/${r.id}/scan`, { method: "POST" });
      m.close(); toast("Scan started"); await loadScope(); route();
    });
  });
}
async function discoverDialog(devId) {
  const m = modal(`<h3>Discover shares</h3><div class="progress"><div></div></div>`);
  try {
    const list = await api(`/api/devices/${devId}/discover`, { method: "POST" });
    const dev = S.devs.find((d) => d.id === devId);
    const have = new Set(dev.shares.map((s) => s.path.toLowerCase()));
    m.innerHTML = `<h3>Discover shares</h3><div class="sub muted small" style="margin-bottom:10px">Pick the shares to index. Scope selection keeps scans fast: index only what you need.</div>
      <table class="t"><thead><tr><th></th><th>Share</th><th>Path</th><th>Zone / note</th></tr></thead><tbody>
      ${list.map((s, i) => `<tr><td><input type="checkbox" data-i="${i}" ${have.has(s.path.toLowerCase()) ? "disabled checked" : ""}></td><td><b>${esc(s.name)}</b></td><td class="path">${esc(s.path)}</td><td class="small muted">${esc(s.zone || s.comment || "")}</td></tr>`).join("") || `<tr><td colspan="4" class="empty">No shares found.</td></tr>`}
      </tbody></table>
      <div class="row" style="margin-top:12px"><span class="small muted">Schedule</span><select class="in" style="width:auto" id="d_sched"><option value="0">Manual</option><option value="24" selected>Daily</option><option value="168">Weekly</option></select>
      <span style="flex:1"></span><button class="btn" data-close>Cancel</button><button class="btn primary" id="add">Add selected and scan</button></div>`;
    $("[data-close]", m).onclick = m.close;
    $("#add", m).onclick = () => tryApi(async () => {
      const picked = $$("input[data-i]:checked:not(:disabled)", m).map((c) => list[+c.dataset.i]);
      for (const s of picked) {
        const r = await api("/api/shares", { method: "POST", body: { device_id: devId, name: s.name, path: s.path, schedule_hours: +$("#d_sched", m).value } });
        await api(`/api/shares/${r.id}/scan`, { method: "POST" }).catch(() => {});
      }
      m.close(); toast(`${picked.length} share(s) added`); await loadScope(); route();
    });
  } catch (e) {
    m.innerHTML = `<h3>Discover shares</h3><div class="note">${esc(e.message)}</div><div class="row end"><button class="btn" data-close>Close</button></div>`;
    $("[data-close]", m).onclick = m.close;
  }
}

// ---------- search ----------
function parseHashParams(rest) { return new URLSearchParams((rest || []).join("/")); }
PAGES.search = async (view, rest) => {
  const init = parseHashParams(rest);
  const F = { q: init.get("q") || "", ext: init.get("ext") || "", path: init.get("path") || "", owner: init.get("owner") || "", tag: init.get("tag") || "",
    older_days: init.get("older_days") || "", newer_days: init.get("newer_days") || "", not_accessed_days: init.get("not_accessed_days") || "", min_size: init.get("min_size") || "", sort: init.get("sort") || "name",
    share: init.get("share") || "" };
  // Conditions without a dedicated input (from Ask or links) ride along until cleared.
  const extra = {};
  for (const k of ["max_size", "path_contains"]) if (init.get(k)) extra[k] = init.get(k);
  if (F.not_accessed_days) extra.not_accessed_days = F.not_accessed_days;
  const chips = S.askChips; S.askChips = null;
  if (F.share) { const sid = +F.share; const d = S.tree.find((x) => x.shares.some((s) => s.id === sid)); if (d) { S.scope = { device: d.id, share: sid }; saveScope(); fillScope(); } }
  const tags = await api("/api/tags").catch(() => []);
  view.innerHTML = hero({
    title: "Search", iconName: "search",
    sub: "Find files by name across every source. Searches run live against the index; pick a device and share in the scope bar for the fastest results.",
    actions: `<button class="btn" data-act="search-csv">${icon("download", 14)} CSV</button> <button class="btn" data-act="search-xlsx">${icon("download", 14)} Excel</button>`,
    extra: `<div style="margin-top:16px"><input class="in" id="q" placeholder="Search by name (substring), e.g. q3-budget, passwords, .xlsx" value="${esc(F.q)}"></div>
    <div class="row" style="margin-top:10px">
      <select class="in" style="width:auto" id="age"><option value="">Any date</option>
        <option value="n30">Modified in last 30 days</option><option value="n365">Modified in last year</option>
        <option value="o365">Not modified in 1 year+</option><option value="o730">Not modified in 2 years+</option><option value="o1825">Not modified in 5 years+</option>
        <option value="a365">Not accessed in 1 year+</option></select>
      <input class="in" style="width:170px" id="ext" placeholder="Types: pdf,docx" value="${esc(F.ext)}">
      <input class="in" style="width:220px" id="path" placeholder="Path prefix: /Projects" value="${esc(F.path)}">
      <input class="in" style="width:160px" id="owner" placeholder="Owner" value="${esc(F.owner)}">
      <select class="in" style="width:auto" id="tag"><option value="">Any tag</option>${tags.map((t) => `<option ${t.tag === F.tag ? "selected" : ""}>${esc(t.tag)}</option>`).join("")}</select>
      <select class="in" style="width:auto" id="minsize"><option value="">Any size</option><option value="1048576">≥ 1 MB</option><option value="104857600">≥ 100 MB</option><option value="1073741824">≥ 1 GB</option><option value="10737418240">≥ 10 GB</option></select>
      <select class="in" style="width:auto" id="sort"><option value="name">Sort: name</option><option value="size">Sort: largest</option><option value="mtime">Sort: newest</option><option value="path">Sort: path</option></select>
    </div>`,
  }) + (chips ? `<div class="note info small">${icon("spark", 13)} Understood as: ${chips.map((c) => `<span class="pill info">${esc(c)}</span>`).join(" ")}</div>` : "") +
    (Object.keys(extra).length ? `<div class="row small muted" style="margin-bottom:10px">Also filtering: ${Object.entries(extra).map(([k, v]) => `<span class="chip">${esc(k.replace("_", " "))}: ${esc(k.includes("size") ? fmtBytes(v) : v)}</span>`).join(" ")} <button class="btn sm" id="clrx">Clear</button></div>` : "") +
    showing() + `<div class="panel" id="res"></div>`;
  $("#clrx") && ($("#clrx").onclick = () => { for (const k in extra) delete extra[k]; $("#clrx").parentElement.remove(); run(false); });
  $("#sort").value = F.sort;
  if (F.min_size) { const ms = $("#minsize"); if (![...ms.options].some((o) => o.value === F.min_size)) ms.insertAdjacentHTML("beforeend", `<option value="${esc(F.min_size)}">≥ ${fmtBytes(F.min_size)}</option>`); ms.value = F.min_size; }
  const ageSel = $("#age");
  if (F.older_days) ageSel.insertAdjacentHTML("beforeend", `<option value="o${F.older_days}" selected>Not modified in ${F.older_days} days+</option>`);
  if (F.newer_days) ageSel.insertAdjacentHTML("beforeend", `<option value="n${F.newer_days}" selected>Modified in last ${F.newer_days} days</option>`);
  let offset = 0, loading = false, done = false, timer;
  const params = () => {
    const a = ageSel.value, p = { ...extra, q: $("#q").value.trim(), ext: $("#ext").value.trim(), path: $("#path").value.trim(), owner: $("#owner").value.trim(), tag: $("#tag").value, min_size: $("#minsize").value, sort: $("#sort").value };
    if (a[0] === "n") p.newer_days = a.slice(1); else if (a[0] === "o") p.older_days = a.slice(1); else if (a[0] === "a") p.not_accessed_days = a.slice(1);
    return p;
  };
  S.lastSearch = params;
  let ctl = null;
  const run = async (append) => {
    if (append && (loading || done)) return;
    const res0 = $("#res");
    const p = params();
    const hasFilter = Object.entries(p).some(([k, v]) => k !== "sort" && v !== "" && v != null);
    if (!append && !hasFilter) {
      ctl && ctl.abort();
      loading = false; done = true;
      res0.innerHTML = `<div class="empty"><b>Type part of a file name, or pick a filter</b>For example <code>budget</code>, <code>.pst</code>, or "Not modified in 2 years+". Tip: choose a device and share in the scope bar to search only there.</div>`;
      return;
    }
    if (!append) {
      ctl && ctl.abort(); // a newer search replaces the one still running
      offset = 0;
      res0.innerHTML = `<div class="empty"><div class="progress" style="max-width:320px;margin:0 auto 10px"><div></div></div>Searching ${scopeLabel()}…</div>`;
    }
    ctl = new AbortController();
    loading = true;
    let r;
    try {
      const resp = await fetch("/api/search?" + scopeQS({ ...p, offset, limit: 1000 }), { signal: ctl.signal });
      r = await resp.json();
      if (!resp.ok) throw new Error(r.error || resp.statusText);
    } catch (e) {
      loading = false;
      if (e.name === "AbortError") return;
      res0.innerHTML = `<div class="note">Search failed: ${esc(e.message)}</div>`;
      return;
    }
    loading = false;
    const res = $("#res");
    if (!res) return;
    const rowsHtml = r.rows.map((f) => `<tr><td>${icon("files", 15, 'style="color:var(--faint)"')}</td><td><div><b>${esc(f.name)}</b>${f.stub ? ' <span class="pill mute">stub</span>' : ""}</div><div class="path">${esc(f.device)} / ${esc(f.share)} / ${esc(f.path)}</div></td>
      <td class="small">${esc(f.owner)}</td><td class="small muted">${esc(f.ext)}</td><td class="small">${fmtDate(f.mtime)}</td><td class="num mono">${fmtBytes(f.size)}</td>
      <td class="num"><button class="btn sm" data-act="view-file" data-share="${f.share_id}" data-path="${esc(f.path)}" data-size="${f.size}">View</button></td></tr>`).join("");
    if (!append) {
      res.innerHTML = `<div class="panel-head"><div><h2>${icon("files", 16)} Results <span class="faint small" style="font-weight:400">${fmtNum(r.total)} total matches</span></h2>
        <div class="sub">Files matching <b>${fmtNum(r.total)}</b> · total size <b style="color:var(--accent)">${fmtBytes(r.bytes)}</b> · query time <b>${r.ms} ms</b>. The owner column is the owner of the folder each file sits in.</div></div></div>
        <table class="t"><thead><tr><th></th><th>Name / location</th><th>Folder owner</th><th>Type</th><th>Modified</th><th class="num">Size</th><th></th></tr></thead><tbody id="rows">${rowsHtml || `<tr><td colspan="6" class="empty">No matches.</td></tr>`}</tbody></table><div id="more" class="small faint" style="text-align:center;padding:10px"></div>`;
    } else $("#rows").insertAdjacentHTML("beforeend", rowsHtml);
    offset += r.rows.length;
    done = offset >= r.total;
    $("#more").textContent = done ? (r.total ? `All ${fmtNum(r.total)} loaded` : "") : `Showing ${fmtNum(offset)} of ${fmtNum(r.total)}. Scroll for more.`;
  };
  const deb = () => { clearTimeout(timer); timer = setTimeout(() => run(false), 250); };
  $$("#q,#ext,#path,#owner").forEach((i) => (i.oninput = deb));
  $$("#age,#tag,#minsize,#sort").forEach((i) => (i.onchange = () => run(false)));
  window.onscroll = () => { if (location.hash.startsWith("#/search") && innerHeight + scrollY > document.body.offsetHeight - 400) run(true); };
  run(false);
};

// ---------- reports hub ----------
PAGES.reports = async (view) => {
  view.innerHTML = hero({ title: "Reports", iconName: "files", sub: "Focused deep-dives into the index." }) +
    `<div class="grid3 cards">${REPORTS.map(([k, t, d, i, bg, fg]) => `<a class="card" href="#/${k}"><div class="ic" style="background:color-mix(in srgb, ${fg} 14%, transparent);color:${fg}">${icon(i, 20)}</div><div><b>${t}</b><span>${d}</span></div></a>`).join("")}</div>`;
};

// ---------- duplicates ----------
PAGES.duplicates = async (view) => {
  let top = 50;
  const load = async () => {
    const d = await api("/api/duplicates?" + scopeQS({ top }));
    view.innerHTML = hero({
      title: "Duplicates", iconName: "copy",
      sub: "Candidate duplicates by metadata: how much space you could reclaim, and where the copies are.",
      actions: `<select class="in" id="top" style="width:auto">${[25, 50, 100, 250].map((n) => `<option ${n === top ? "selected" : ""} value="${n}">Top ${n}</option>`).join("")}</select>`,
      kpis: kpi("Reclaimable space", fmtBytes(d.reclaimable), "if duplicate files are de-duplicated", "refresh") + kpi("Duplicate sets", fmtNum(d.sets), "groups of 2+ candidate duplicates", "copy") + kpi("Largest single set", fmtBytes(d.largest), "biggest reclaimable win", "db"),
    }) + `<div class="note">These are <b>candidate</b> duplicates from metadata only; no file content is read. Sets match on name + size + modified time within each share. Reclaimable space is logical (size × (copies − 1)); hard-linked or dedup-backed copies may free less.</div>` + showing() +
      `<div class="panel"><h2>${icon("files", 16)} Duplicate file sets, ranked by reclaimable space</h2><div class="sub">Click a set to see the full path of each copy.</div>
      ${d.rows.map((r, i) => `<div class="dup"><div class="hbar" style="grid-template-columns:28px minmax(160px,260px) 90px 1fr 90px 18px;cursor:pointer" data-i="${i}"><span class="faint">${i + 1}</span><span class="nm mono">${esc(r.name)}</span><span class="small muted">${r.copies} copies</span>
        <div class="track"><div class="fill" style="width:${(r.reclaim / (d.rows[0].reclaim || 1)) * 100}%;background:var(--c1)"></div></div><b style="text-align:right">${fmtBytes(r.reclaim)}</b><span class="faint">›</span></div><div class="copies" style="display:none;padding:0 0 10px 40px"></div></div>`).join("") || `<div class="empty">No duplicate sets in this scope.</div>`}</div>`;
    $("#top").onchange = (e) => { top = +e.target.value; load(); };
    $$(".dup .hbar", view).forEach((h) => (h.onclick = async () => {
      const box = h.nextElementSibling;
      if (box.style.display === "block") { box.style.display = "none"; return; }
      const r = d.rows[+h.dataset.i];
      const list = await api(`/api/duplicates/set?share=${r.share_id}&name=${encodeURIComponent(r.name)}&size=${r.size}&mtime=${r.mtime}&etag=${encodeURIComponent(r.etag || "")}`);
      box.innerHTML = `<div class="small muted" style="margin-bottom:4px">${esc(r.device)} › ${esc(r.share)} · ${fmtBytes(r.size)} each · modified ${fmtDate(r.mtime)}</div>` + list.map((c) => `<div class="path">${esc(c.path)} <span class="faint">· ${esc(c.owner)}</span></div>`).join("");
      box.style.display = "block";
    }));
  };
  await load();
};

// ---------- path & scan issues ----------
const ISSUE_LABEL = { error: "Scan error", interrupted: "Interrupted", link: "Link / stub", long_path: "Long path (Windows)", long_name: "Long name", illegal: "Illegal name", reserved: "Reserved name", not_published: "Index not published" };
const ISSUE_PILL = { error: "bad", interrupted: "warn", link: "mute", long_path: "info", long_name: "info", illegal: "warn", reserved: "warn", not_published: "bad" };
PAGES.issues = async (view) => {
  const st = { family: "", q: "", state: "", sort: "len", min_len: "" };
  const load = async () => {
    const d = await api("/api/issues?" + scopeQS({ family: st.family, q: st.q, state: st.state, sort: st.sort, min_len: st.min_len, limit: 500 }));
    const c = d.counts, total = Object.values(c).reduce((a, b) => a + b, 0);
    const fam = [["", "All", total], ["errors", "Scan errors", c.errors || 0], ["interrupted", "Interrupted", c.interrupted || 0], ["links", "Links & stubs", c.links || 0], ["long", "Long paths", c.long || 0], ["illegal", "Illegal / reserved", c.illegal || 0], ["unpublished", "Index not published", c.unpublished || 0]];
    view.innerHTML = hero({
      title: "Path problems", iconName: "alert",
      sub: "Every finding the metadata scan recorded against a path: what could not be read, the links and stubs it did not follow, names that will break Windows clients, and shares whose fresh index was not published.",
      actions: `<button class="btn" data-act="issues-csv">${icon("download", 14)} Export CSV</button>`,
      extra: `<div class="row" style="margin-top:14px"><div class="seg">${fam.map(([k, l, n]) => `<button class="${st.family === k ? "on" : ""}" data-fam="${k}">${l}<span class="n">${fmtNum(n)}</span></button>`).join("")}</div></div>
        <div class="row" style="margin-top:10px"><input class="in" id="iq" style="width:260px" placeholder="Filter by path" value="${esc(st.q)}">
        <select class="in" id="ist" style="width:auto"><option value="">Any triage</option><option value="open" ${st.state === "open" ? "selected" : ""}>Open</option><option value="acknowledged" ${st.state === "acknowledged" ? "selected" : ""}>Acknowledged</option><option value="ignored" ${st.state === "ignored" ? "selected" : ""}>Ignored</option></select>
        <select class="in" id="isort" style="width:auto"><option value="len">Sort: longest path</option><option value="newest" ${st.sort === "newest" ? "selected" : ""}>Sort: newest</option></select>
        <input class="in" id="iml" type="number" style="width:120px" placeholder="Min length" value="${esc(st.min_len)}"></div>`,
      kpis: kpi("Total findings", fmtNum(total), "sum of the tiles below", "alert") + kpi("Errors", fmtNum(c.errors || 0), "could not be read, needs action", "alert") + kpi("Interrupted", fmtNum(c.interrupted || 0), "connection dropped, retryable", "refresh") +
        kpi("Links & stubs", fmtNum(c.links || 0), "not followed by design, informational", "link") + kpi("Index not published", fmtNum(c.unpublished || 0), "share kept its previous index", "shield") +
        kpi("Long path", fmtNum(c.long || 0), "name or path over length", "files") + kpi("Illegal / reserved", fmtNum(c.illegal || 0), "bad chars, trailing dot, reserved", "x") +
        kpi("Devices affected", fmtNum(d.devices), "distinct devices", "server") + kpi("Shares", fmtNum(d.shares), "distinct scopes", "db"),
    }) + `<div class="note"><b>Path hygiene</b> entries are indexed, but their name or path will break Windows clients, backup agents or a migration. They are advisory: fix them at your own pace and tag them Acknowledged or Ignored to track triage.</div>` + showing() +
      `<div class="panel"><div class="panel-head"><div><h2>${icon("alert", 16, 'style="color:var(--warn)"')} Findings</h2><div class="sub">Showing ${fmtNum(d.rows.length)} of ${fmtNum(d.matched)} matching issues.</div></div>
      <div class="row"><button class="btn sm" data-tri="acknowledged">Acknowledge selected</button><button class="btn sm" data-tri="ignored">Ignore selected</button><button class="btn sm" data-tri="">Reopen selected</button></div></div>
      <table class="t"><thead><tr><th><input type="checkbox" id="all"></th><th>Platform</th><th>Device</th><th>Share</th><th>Path</th><th>Issue</th><th class="num">Len</th><th>Scan</th><th>Detected</th><th>Triage</th></tr></thead><tbody>
      ${d.rows.map((r, i) => `<tr title="${esc(r.detail)}"><td><input type="checkbox" data-i="${i}"></td><td><span class="pill mute">${r.platform === "powerscale" ? "SMB · OneFS" : "SMB · Windows"}</span></td><td>${esc(r.device)}</td><td>${esc(r.share)}</td>
        <td class="path ellip" style="max-width:520px">${esc(r.path)}<div class="small faint">${esc(r.detail)}</div></td><td><span class="pill ${ISSUE_PILL[r.kind] || "mute"}">${ISSUE_LABEL[r.kind] || r.kind}</span></td>
        <td class="num">${r.len || ""}</td><td class="faint">#${r.scan_id}</td><td class="small">${fmtDate(r.detected)}</td><td>${r.state ? `<span class="pill ${r.state === "ignored" ? "mute" : "ok"}">${r.state}</span>` : ""}</td></tr>`).join("") || `<tr><td colspan="10" class="empty">No issues in this scope.</td></tr>`}
      </tbody></table></div>`;
    $$("[data-fam]").forEach((b) => (b.onclick = () => { st.family = b.dataset.fam; load(); }));
    let t;
    $("#iq").oninput = (e) => { st.q = e.target.value; clearTimeout(t); t = setTimeout(load, 300); };
    $("#iml").onchange = (e) => { st.min_len = e.target.value; load(); };
    $("#ist").onchange = (e) => { st.state = e.target.value; load(); };
    $("#isort").onchange = (e) => { st.sort = e.target.value; load(); };
    $("#all").onchange = (e) => $$("input[data-i]").forEach((c) => (c.checked = e.target.checked));
    $$("[data-tri]").forEach((b) => (b.onclick = () => tryApi(async () => {
      const sel = $$("input[data-i]:checked").map((c) => d.rows[+c.dataset.i]).map((r) => ({ share_id: r.share_id, path: r.path, kind: r.kind, state: b.dataset.tri }));
      if (!sel.length) return toast("Select rows first", true);
      await api("/api/issues/triage", { method: "POST", body: sel });
      load();
    })));
  };
  await load();
};

// ---------- owners ----------
PAGES.owners = async (view, rest) => {
  const tab = (rest && rest[0]) || "accounts";
  const [rows, org] = await Promise.all([api("/api/owners?" + scopeQS({ limit: 300 })), api("/api/owners/org?" + scopeQS())]);
  const tot = rows.reduce((a, r) => a + r.bytes, 0) || 1;
  const tabs = `<div class="seg" style="margin-top:14px">${[["accounts", "Accounts"], ["departments", "Departments"], ["ou", "OU tree"]].map(([k, l]) => `<button class="${tab === k ? "on" : ""}" onclick="location.hash='#/owners/${k}'">${l}</button>`).join("")}</div>`;
  let body = "";
  if (tab === "accounts") {
    body = `<table class="t"><thead><tr><th>#</th><th>Owner</th><th>Share of data</th><th class="num">Size</th><th class="num">Files</th><th class="num">Folders</th><th class="num">Ops (30d)</th><th></th></tr></thead><tbody>
    ${rows.map((r, i) => `<tr><td class="faint">${i + 1}</td><td><b>${esc(r.owner)}</b></td><td style="width:30%"><div class="hbar" style="grid-template-columns:1fr 50px;padding:0"><div class="track"><div class="fill" style="width:${(r.bytes / tot) * 100}%;background:var(--c2)"></div></div><span class="small muted">${((r.bytes / tot) * 100).toFixed(1)}%</span></div></td>
      <td class="num">${fmtBytes(r.bytes)}</td><td class="num">${fmtNum(r.files)}</td><td class="num">${fmtNum(r.folders)}</td><td class="num">${r.activity_30d ? fmtNum(r.activity_30d) : '<span class="faint">none</span>'}</td>
      <td><a class="btn sm" href="#/search/owner=${encodeURIComponent(r.owner)}">Files</a></td></tr>`).join("") || `<tr><td colspan="8" class="empty">Nothing indexed yet.</td></tr>`}</tbody></table>`;
  } else if (!org.configured) {
    body = `<div class="empty"><b>Connect Active Directory first</b>Departments and the OU tree come from an LDAP lookup of each folder owner. Set it up under <a href="#/settings">Settings → Directory</a>; it can run through a collector inside your domain network.</div>`;
  } else if (tab === "departments") {
    const max = org.departments[0]?.bytes || 1;
    body = `<table class="t"><thead><tr><th>Department</th><th>Share of data</th><th class="num">Size</th><th class="num">Files</th><th class="num">Accounts</th><th class="num">Ops (30d)</th></tr></thead><tbody>
      ${org.departments.map((d) => `<tr><td><b>${esc(d.name)}</b></td><td style="width:30%"><div class="track" style="height:8px;background:var(--line-2);border-radius:9px"><div class="fill" style="height:8px;border-radius:9px;width:${(d.bytes / max) * 100}%;background:var(--c1)"></div></div></td>
        <td class="num">${fmtBytes(d.bytes)}</td><td class="num">${fmtNum(d.files)}</td><td class="num">${fmtNum(d.owners)}</td><td class="num">${d.activity_30d ? fmtNum(d.activity_30d) : '<span class="faint">none</span>'}</td></tr>`).join("")}</tbody></table>`;
  } else {
    const node = (n, depth) => `<div class="ounode" style="padding-left:${depth * 18}px"><span>${n.children?.length ? "▸" : "·"} <b>${esc(n.name)}</b></span><span class="small muted">${fmtBytes(n.bytes)} · ${fmtNum(n.owners)} accounts${n.activity_30d ? " · " + fmtNum(n.activity_30d) + " ops" : ""}</span></div>` +
      (depth < 6 ? (n.children || []).map((c) => node(c, depth + 1)).join("") : "");
    body = (org.tree.children || []).map((c) => node(c, 0)).join("") || `<div class="empty">No owners resolved yet. Run a directory sync in Settings.</div>`;
  }
  view.innerHTML = hero({ title: "Owners", iconName: "users", sub: "Capacity by folder owner, and rolled up by department and Active Directory OU, next to how active each account is in the audit stream.",
    kpis: org.configured ? kpi("Owned by disabled accounts", fmtBytes(org.disabled_bytes), "accounts switched off in AD", "users") + kpi("Not in directory", fmtBytes(org.unresolved_bytes), "deleted accounts or local users", "alert") + kpi("System accounts", fmtBytes(org.system_bytes), "BUILTIN, SYSTEM, TrustedInstaller", "server") : "",
    extra: tabs }) + showing() + `<div class="panel">${body}</div>`;
};

// ---------- audit ----------
const OP_COLORS = { create: "var(--ok)", modify: "#3b82f6", delete: "var(--bad)", rename: "var(--c5)", read: "#94a3b8", other: "#cbd5e1" };
PAGES.audit = async (view, _, alive) => {
  const draw = async () => {
    const [s, ev] = await Promise.all([api("/api/audit/summary"), api("/api/audit/events?" + new URLSearchParams({ limit: 100, ...(S.scope.device ? { device: S.scope.device } : {}) }))]);
    if (!alive()) return;
    const card = (d) => {
      const tot = Object.values(d.ops).reduce((a, b) => a + b, 0) || 1;
      const stale = d.last_event && Date.now() / 1000 - d.last_event > 900;
      return `<div class="device-card"><div class="dh">${icon("server", 16)}<b>${esc(d.name)}</b><span class="pill info">${(d.kind || "unknown").toUpperCase()}</span><span style="flex:1"></span>
        <span class="pill ${!d.last_event ? "mute" : stale ? "warn" : "ok"}">${!d.last_event ? "NO EVENTS" : stale ? "IDLE" : "LIVE"}</span><span class="small muted">last event ${ago(d.last_event)}</span></div>
        <div class="statgrid"><div><b>${fmtShort(d.events)}</b><span class="small muted">operations</span></div><div><b>${fmtShort(d.rows)}</b><span class="small muted">stored rows</span></div><div><b>${ago(d.last_event)}</b><span class="small muted">last event</span></div></div>
        <div style="padding:12px 16px"><div class="stack" style="height:10px">${Object.keys(OP_COLORS).map((k) => `<div style="flex:${(d.ops[k] || 0) / tot};background:${OP_COLORS[k]}"></div>`).join("")}</div>
        <div class="legend">${Object.keys(OP_COLORS).map((k) => `<span><i style="background:${OP_COLORS[k]}"></i>${k[0].toUpperCase() + k.slice(1)} <b>${fmtShort(d.ops[k] || 0)}</b></span>`).join("")}</div></div></div>`;
    };
    const wa = s.windows_audit;
    view.innerHTML = hero({ title: "File activity", iconName: "activity", sub: "Audit records stored per device. Counts are real operations: repeating I/O is aggregated into 60-second windows at ingest, with bytes summed.",
      extra: `<div class="meta"><span class="pulse"><i></i>Auto-refreshing every 15s</span> · ${s.dropped_lines ? fmtNum(s.dropped_lines) + " unparsed syslog lines" : "no unparsed lines"} · Windows Security log: ${wa.enabled ? `<b>collecting</b> (${fmtNum(wa.events)} events)` : esc(wa.error || "no local Windows device registered")}</div>` }) +
      `<div class="grid2">${s.devices.map(card).join("") || `<div class="panel empty">No devices.</div>`}</div>
      <div class="panel"><h2>${icon("activity", 16)} Recent operations</h2><div class="sub">Newest first${S.scope.device ? ", scoped to the selected device" : ""}.</div>
      <table class="t"><thead><tr><th>Window</th><th>User</th><th>Op</th><th>Path</th><th>Protocol</th><th>Client</th><th class="num">Count</th><th class="num">Bytes</th></tr></thead><tbody>
      ${ev.map((e) => `<tr><td class="small">${fmtDate(e.ts)}</td><td>${esc(e.user)}</td><td><span class="pill" style="background:${OP_COLORS[e.op]}22;color:${OP_COLORS[e.op]}">${e.op}</span></td><td class="path ellip">${esc(e.path)}</td><td class="small muted">${esc(e.proto)}</td><td class="small muted">${esc(e.client)}</td><td class="num">${e.count}</td><td class="num">${e.bytes ? fmtBytes(e.bytes) : ""}</td></tr>`).join("") || `<tr><td colspan="8" class="empty">No audit events yet. See Settings for how to connect PowerScale protocol audit and the Windows Security log.</td></tr>`}
      </tbody></table></div>`;
  };
  await draw();
  const t = setInterval(() => { if (!alive() || !location.hash.startsWith("#/audit")) return clearInterval(t); draw().catch(() => {}); }, 15000);
};

// ---------- inventory ----------
PAGES.inventory = async (view) => {
  const rows = await api("/api/inventory");
  view.innerHTML = hero({ title: "Hardware", iconName: "server", sub: "Hardware and capacity of every registered device, collected daily and on every scan." }) +
    `<div class="panel"><table class="t"><thead><tr><th>Device</th><th>Type</th><th>Model</th><th>OS</th><th>Serial / GUID</th><th class="num">Nodes</th><th class="num">Raw capacity</th><th class="num">Used</th><th>Collected</th><th></th></tr></thead><tbody>
    ${rows.map((d) => { const v = d.inventory || {}; return `<tr><td><b>${esc(d.name)}</b><div class="small faint">${esc(d.host || v.hostname || "")}</div></td><td><span class="pill info">${d.kind.toUpperCase()}</span></td>
      <td>${esc(v.model || "")}</td><td class="small">${esc(v.os || "")}</td><td class="mono small">${esc(v.guid || (v.nodes || []).map((n) => n.serial).filter(Boolean).join(", ") || "")}</td>
      <td class="num">${v.node_count || (d.kind === "windows" ? 1 : "")}</td><td class="num">${v.raw_bytes ? fmtBytes(v.raw_bytes) : ""}</td><td class="num">${v.used_bytes ? fmtBytes(v.used_bytes) : ""}</td>
      <td class="small">${d.collected ? ago(d.collected) : "never"}${v.error ? `<div class="small" style="color:var(--bad)">${esc(v.error)}</div>` : ""}</td><td><button class="btn sm" data-act="inv" data-id="${d.id}">${icon("refresh", 12)}</button></td></tr>`; }).join("") || `<tr><td colspan="10" class="empty">No devices.</td></tr>`}
    </tbody></table></div>`;
};

// ---------- filter editor (shared by tags and automations) ----------
function filterFields(f = {}, prefix = "ff") {
  const shares = S.tree.flatMap((d) => d.shares.map((s) => ({ ...s, dev: d.name })));
  return `<div class="fgrid">
    <div class="field"><label>Name contains</label><input class="in" id="${prefix}_q" value="${esc(f.q || "")}"></div>
    <div class="field"><label>File types</label><input class="in" id="${prefix}_ext" value="${esc((f.ext || []).join(","))}" placeholder="pdf,docx,tmp"></div>
    <div class="field"><label>Path starts with</label><input class="in mono" id="${prefix}_path" value="${esc(f.path_prefix || "")}" placeholder="/Projects/Archive"></div>
    <div class="field"><label>Path contains</label><input class="in mono" id="${prefix}_pc" value="${esc(f.path_contains || "")}"></div>
    <div class="field"><label>Not modified for (days)</label><input class="in" type="number" id="${prefix}_old" value="${f.older_than_days || ""}"></div>
    <div class="field"><label>Not accessed for (days)</label><input class="in" type="number" id="${prefix}_na" value="${f.not_accessed_days || ""}"></div>
    <div class="field"><label>Min size (MB)</label><input class="in" type="number" id="${prefix}_min" value="${f.min_size ? f.min_size / 1048576 : ""}"></div>
    <div class="field"><label>Folder owner contains</label><input class="in" id="${prefix}_own" value="${esc(f.owner || "")}"></div>
    <div class="field" style="grid-column:1/-1"><label>Share</label><select class="in" id="${prefix}_share"><option value="0">All shares</option>${shares.map((s) => `<option value="${s.id}" ${s.id === f.share_id ? "selected" : ""}>${esc(s.dev)} › ${esc(s.name)}</option>`).join("")}</select></div>
  </div>`;
}
function readFilter(m, prefix = "ff") {
  const v = (id) => $(`#${prefix}_${id}`, m).value.trim();
  const f = {};
  if (v("q")) f.q = v("q");
  if (v("ext")) f.ext = v("ext").split(",").map((s) => s.trim()).filter(Boolean);
  if (v("path")) f.path_prefix = v("path");
  if (v("pc")) f.path_contains = v("pc");
  if (+v("old")) f.older_than_days = +v("old");
  if (+v("na")) f.not_accessed_days = +v("na");
  if (+v("min")) f.min_size = Math.round(+v("min") * 1048576);
  if (v("own")) f.owner = v("own");
  if (+v("share")) f.share_id = +v("share");
  return f;
}
function describeFilter(f) {
  const p = [];
  if (f.tag) p.push(`tag “${f.tag}”`);
  if (f.q) p.push(`name contains “${f.q}”`);
  if (f.ext?.length) p.push(`type ${f.ext.join("/")}`);
  if (f.path_prefix) p.push(`under ${f.path_prefix}`);
  if (f.path_contains) p.push(`path contains ${f.path_contains}`);
  if (f.older_than_days) p.push(`not modified ${f.older_than_days}d`);
  if (f.not_accessed_days) p.push(`not accessed ${f.not_accessed_days}d`);
  if (f.min_size) p.push(`≥ ${fmtBytes(f.min_size)}`);
  if (f.owner) p.push(`owner ~ ${f.owner}`);
  if (f.share_id) { const s = S.tree.flatMap((d) => d.shares).find((x) => x.id === f.share_id); p.push(`share ${s ? s.name : f.share_id}`); }
  return p.join(" · ") || "everything";
}

// ---------- auto tag ----------
PAGES.tags = async (view) => {
  const [rules, tags] = await Promise.all([api("/api/tagrules"), api("/api/tags")]);
  view.innerHTML = hero({ title: "Tag rules", iconName: "tag", sub: "Tag files by rule. Tags are re-applied after every scan, removed with their rule, and feed Search and Automations.",
    actions: `<button class="btn primary" data-act="new-rule">${icon("plus", 14)} New rule</button>`,
    kpis: kpi("Rules", rules.length, "", "tag") + kpi("Distinct tags", tags.length, "", "tag") + kpi("Tagged files", fmtNum(tags.reduce((a, t) => a + t.files, 0)), "", "files") }) +
    `<div class="panel"><h2>${icon("tag", 16)} Rules</h2><div class="sub">Each rule selects files from the published index and stamps them with a tag.</div>
    <table class="t"><thead><tr><th>Rule</th><th>Tag</th><th>Matches</th><th class="num">Tagged</th><th>Status</th><th></th></tr></thead><tbody>
    ${rules.map((r) => `<tr><td><b>${esc(r.name)}</b></td><td><span class="pill info">${esc(r.tag)}</span></td><td class="small muted">${esc(describeFilter(r.match))}</td><td class="num">${fmtNum(r.tagged)}</td>
      <td>${r.enabled ? '<span class="pill ok">ENABLED</span>' : '<span class="pill mute">DISABLED</span>'}</td>
      <td class="num"><a class="btn sm" href="#/search/tag=${encodeURIComponent(r.tag)}">Files</a> <button class="btn sm" data-act="apply-rule" data-id="${r.id}">${icon("refresh", 12)} Re-apply</button> <button class="btn sm" data-act="edit-rule" data-id="${r.id}">${icon("edit", 12)}</button> <button class="btn sm ghost-danger" data-act="del-rule" data-id="${r.id}">${icon("trash", 12)}</button></td></tr>`).join("") || `<tr><td colspan="6" class="empty">No rules yet. Example: tag <b>stale-media</b> for mp4/mov not modified for 730 days.</td></tr>`}
    </tbody></table></div>`;
  S.rules = rules;
};
function ruleForm(r = { enabled: true, match: {} }) {
  modal(`<h3>${r.id ? "Edit" : "New"} tag rule</h3>
    <div class="fgrid"><div class="field"><label>Rule name</label><input class="in" id="r_name" value="${esc(r.name || "")}"></div><div class="field"><label>Tag</label><input class="in" id="r_tag" value="${esc(r.tag || "")}" placeholder="stale-media"></div></div>
    ${filterFields(r.match, "rf")}
    <label class="small"><input type="checkbox" id="r_en" ${r.enabled ? "checked" : ""}> Enabled</label>
    <div class="row" style="margin-top:14px"><button class="btn" id="prev">Preview matches</button><span id="pv" class="small muted"></span><span style="flex:1"></span><button class="btn" data-close>Cancel</button><button class="btn primary" id="save">Save and apply</button></div>`, (m) => {
    $("[data-close]", m).onclick = m.close;
    $("#prev", m).onclick = () => tryApi(async () => { const p = await api("/api/tagrules/preview", { method: "POST", body: readFilter(m, "rf") }); $("#pv", m).textContent = `${fmtNum(p.files)} files · ${fmtBytes(p.bytes)}`; });
    $("#save", m).onclick = () => tryApi(async () => {
      await api("/api/tagrules" + (r.id ? "/" + r.id : ""), { method: r.id ? "PUT" : "POST", body: { name: $("#r_name", m).value, tag: $("#r_tag", m).value, enabled: $("#r_en", m).checked, match: readFilter(m, "rf") } });
      m.close(); toast("Rule saved and applied"); route();
    });
  });
}

// ---------- automations ----------
PAGES.automations = async (view) => {
  const { automations } = await api("/api/automations");
  S.autos = automations;
  const stPill = (s) => !s ? "" : `<span class="pill ${s.startsWith("completed") && !s.includes("errors") ? "ok" : s === "running" ? "info" : s === "failed" ? "bad" : "warn"}">${esc(s[0].toUpperCase() + s.slice(1))}</span>`;
  view.innerHTML = hero({ title: "Automations", iconName: "flow", sub: "Named workflows that run an ordered action pipeline over a search or a tag. Dry-run first, always audited.",
    actions: `<button class="btn primary" data-act="new-auto">${icon("plus", 14)} New automation</button>` }) +
    `<div class="note">These actions <b>change customer data</b>. A dry-run computes every intended change and makes none. A real run with a destructive action (delete, move, rename) requires typing the automation's name. Copy never overwrites an existing file. Runs continue on the server; you can leave this page and come back.</div>
    <div class="panel"><h2>${icon("flow", 16)} Automations</h2><div class="sub">${automations.length} automation${automations.length === 1 ? "" : "s"}.</div>
    ${automations.map((a) => `<div class="pipeline" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;background:var(--panel)"><div style="flex:1;min-width:260px">
      <div class="row"><b style="font-size:15px">${esc(a.name)}</b>${a.enabled ? '<span class="pill ok">ENABLED</span>' : '<span class="pill mute">DISABLED</span>'}${stPill(a.last_status)}</div>
      ${a.description ? `<div class="small muted">${esc(a.description)}</div>` : ""}
      <div class="small faint" style="margin-top:3px">${a.actions.map((x) => x.type).join(" → ")} · ${a.schedule ? "Runs every day at " + esc(a.schedule) : "Manual only"} · Input: ${esc(a.input_kind)} (${esc(describeFilter(a.input))})${a.last_run_at ? " · last run " + ago(a.last_run_at) : ""}</div></div>
      <button class="btn sm" data-act="auto-hist" data-id="${a.id}">${icon("history", 13)} History</button>
      <button class="btn sm primary" data-act="auto-dry" data-id="${a.id}">${icon("flask", 13)} Dry-run</button>
      <button class="btn sm danger" data-act="auto-run" data-id="${a.id}">${icon("play", 13)} Run</button>
      <button class="btn sm" data-act="auto-edit" data-id="${a.id}">${icon("edit", 13)}</button>
      <button class="btn sm ghost-danger" data-act="auto-del" data-id="${a.id}">${icon("trash", 13)}</button></div>`).join("") || `<div class="empty"><b>No automations yet</b>Example: move PDFs not modified for 3 years under /Finance to an archive share, then tag them.</div>`}</div>`;
};
function autoForm(a = { enabled: true, input_kind: "search", input: {}, actions: [{ type: "copy" }], schedule: "" }) {
  modal(`<h3>${a.id ? "Edit" : "New"} automation</h3>
    <div class="fgrid"><div class="field"><label>Name</label><input class="in" id="a_name" value="${esc(a.name || "")}"></div><div class="field"><label>Description</label><input class="in" id="a_desc" value="${esc(a.description || "")}"></div></div>
    <div class="field"><label>Input</label><div class="seg" id="a_kind"><button data-k="search">Search</button><button data-k="tag">Tag</button></div></div>
    <div id="a_in_search">${filterFields(a.input_kind === "search" ? a.input : {}, "af")}</div>
    <div id="a_in_tag" class="field"><label>Tag</label><input class="in" id="a_tag" value="${esc(a.input.tag || "")}"></div>
    <div class="field"><label>Action pipeline (runs in order per item)</label><div id="a_acts"></div><button class="btn sm" id="a_add">${icon("plus", 12)} Add action</button></div>
    <div class="fgrid"><div class="field"><label>Schedule</label><input class="in" id="a_sched" placeholder="Manual (blank) or HH:MM daily" value="${esc(a.schedule || "")}"></div>
    <div class="field"><label>&nbsp;</label><label class="small"><input type="checkbox" id="a_en" ${a.enabled ? "checked" : ""}> Enabled</label></div></div>
    <div class="row"><button class="btn" id="a_prev">Preview input</button><span id="a_pv" class="small muted"></span><span style="flex:1"></span><button class="btn" data-close>Cancel</button><button class="btn primary" id="a_save">Save</button></div>`, (m) => {
    let kind = a.input_kind || "search";
    const acts = a.actions.map((x) => ({ ...x }));
    const syncKind = () => { $$("#a_kind button", m).forEach((b) => b.classList.toggle("on", b.dataset.k === kind)); $("#a_in_search", m).style.display = kind === "search" ? "" : "none"; $("#a_in_tag", m).style.display = kind === "tag" ? "" : "none"; };
    const drawActs = () => {
      $("#a_acts", m).innerHTML = acts.map((x, i) => `<div class="pipeline row"><b class="faint">${i + 1}</b>
        <select class="in" style="width:auto" data-ai="${i}" data-f="type">${["copy", "move", "delete", "rename", "tag", "untag"].map((t) => `<option ${t === x.type ? "selected" : ""}>${t}</option>`).join("")}</select>
        ${x.type === "copy" || x.type === "move" ? `<input class="in mono" style="flex:1" data-ai="${i}" data-f="target" value="${esc(x.target || "")}" placeholder="Target root on the same device, e.g. E:\\Archive or /ifs/archive">` : ""}
        ${x.type === "rename" ? `<input class="in mono" style="flex:1" data-ai="${i}" data-f="template" value="${esc(x.template || "")}" placeholder="{stem}_archived_{date}{ext}">` : ""}
        ${x.type === "tag" || x.type === "untag" ? `<input class="in" style="flex:1" data-ai="${i}" data-f="tag" value="${esc(x.tag || "")}" placeholder="tag name">` : ""}
        ${x.type === "delete" ? `<span class="small" style="flex:1;color:var(--bad)">Permanently removes each file. No recycle bin on network shares.</span>` : ""}
        <button class="btn sm ghost-danger" data-rm="${i}">${icon("x", 12)}</button></div>`).join("");
      $$("[data-ai]", m).forEach((e) => (e.onchange = e.oninput = () => { acts[+e.dataset.ai][e.dataset.f] = e.value; if (e.dataset.f === "type") drawActs(); }));
      $$("[data-rm]", m).forEach((b) => (b.onclick = () => { acts.splice(+b.dataset.rm, 1); drawActs(); }));
    };
    $$("#a_kind button", m).forEach((b) => (b.onclick = () => { kind = b.dataset.k; syncKind(); }));
    $("#a_add", m).onclick = () => { acts.push({ type: "tag" }); drawActs(); };
    syncKind(); drawActs();
    $("[data-close]", m).onclick = m.close;
    const input = () => kind === "tag" ? { tag: $("#a_tag", m).value.trim() } : readFilter(m, "af");
    $("#a_prev", m).onclick = () => tryApi(async () => { const p = await api("/api/tagrules/preview", { method: "POST", body: input() }); $("#a_pv", m).textContent = `${fmtNum(p.files)} files · ${fmtBytes(p.bytes)}`; });
    $("#a_save", m).onclick = () => tryApi(async () => {
      const body = { name: $("#a_name", m).value.trim(), description: $("#a_desc", m).value, enabled: $("#a_en", m).checked, input_kind: kind, input: input(), actions: acts, schedule: $("#a_sched", m).value.trim() };
      const destructive = acts.some((x) => ["move", "delete", "rename"].includes(x.type));
      if (body.schedule && destructive) {
        const c = await confirmTyped("Schedule a destructive automation", `A schedule runs <b>for real</b> every day at ${esc(body.schedule)} with no dry-run.`, body.name);
        if (c === null) return;
        body.confirm = c;
      }
      await api("/api/automations" + (a.id ? "/" + a.id : ""), { method: a.id ? "PUT" : "POST", body });
      m.close(); toast("Automation saved"); route();
    });
  });
}
async function autoHistory(id) {
  const a = S.autos.find((x) => x.id === id);
  const runs = await api(`/api/automations/${id}/runs`);
  const m = modal(`<h3>${esc(a.name)} · run history</h3>
    <table class="t"><thead><tr><th>#</th><th>Mode</th><th>Started</th><th>Status</th><th class="num">Items</th><th class="num">OK</th><th class="num">Failed</th><th></th></tr></thead><tbody>
    ${runs.map((r) => `<tr><td class="faint">${r.id}</td><td>${r.dry_run ? '<span class="pill info">DRY-RUN</span>' : '<span class="pill bad">REAL</span>'}</td><td class="small">${fmtDate(r.started)}</td><td>${esc(r.status)}${r.message ? `<div class="small faint">${esc(r.message)}</div>` : ""}</td>
      <td class="num">${fmtNum(r.items)}</td><td class="num">${fmtNum(r.ok)}</td><td class="num">${fmtNum(r.failed)}</td><td class="num"><button class="btn sm" data-led="${r.id}">Ledger</button> <a class="btn sm" href="/api/runs/${r.id}/ledger.csv">CSV</a></td></tr>`).join("") || `<tr><td colspan="8" class="empty">Never run.</td></tr>`}
    </tbody></table><div id="led" style="margin-top:12px"></div><div class="row end" style="margin-top:12px"><button class="btn" data-close>Close</button></div>`);
  $("[data-close]", m).onclick = m.close;
  $$("[data-led]", m).forEach((b) => (b.onclick = async () => {
    const rows = await api(`/api/runs/${b.dataset.led}/ledger?limit=300`);
    $("#led", m).innerHTML = `<b class="small">Per-item ledger (first 300)</b><table class="t"><thead><tr><th>Share</th><th>Path</th><th>Action</th><th>Target</th><th>Result</th></tr></thead><tbody>
      ${rows.map((l) => `<tr><td class="small">${esc(l.share)}</td><td class="path">${esc(l.path)}</td><td>${esc(l.action)}</td><td class="path">${esc(l.target)}</td><td><span class="pill ${l.result === "ok" ? "ok" : l.result === "dry-run" ? "info" : "bad"}">${esc(l.result)}</span>${l.detail ? `<div class="small faint">${esc(l.detail)}</div>` : ""}</td></tr>`).join("")}</tbody></table>`;
  }));
}

// ---------- settings ----------
PAGES.settings = async (view) => {
  const s = await api("/api/settings");
  if (S.me && S.me.role === "admin") setTimeout(() => usersPanel(), 0);
  setTimeout(async () => {
    const [dc, vl, cols] = await Promise.all([api("/api/directory/config"), api("/api/viewlog"), api("/api/collectors").catch(() => [])]);
    const c = dc.config || {};
    const box = $("#dirbox"); if (!box) return;
    box.innerHTML = `<div class="fgrid">
      <div class="field"><label>LDAP URL</label><input class="in" id="ld_url" value="${esc(c.url || "")}" placeholder="ldaps://dc01.corp.local:636"></div>
      <div class="field"><label>Base DN</label><input class="in" id="ld_base" value="${esc(c.base_dn || "")}" placeholder="DC=corp,DC=local"></div>
      <div class="field"><label>Bind account</label><input class="in" id="ld_user" value="${esc(c.bind_user || "")}" placeholder="CORP\\svc-stratum or svc@corp.local"></div>
      <div class="field"><label>Password</label><input class="in" id="ld_pass" type="password" placeholder="${dc.has_password ? "unchanged" : ""}" autocomplete="new-password"></div>
      <div class="field"><label>Run from</label><select class="in" id="ld_col"><option value="0">This server</option>${cols.map((x) => `<option value="${x.id}" ${x.id === c.collector_id ? "selected" : ""}>Collector: ${esc(x.name)}</option>`).join("")}</select></div>
      <div class="field"><label>TLS</label><label class="small"><input type="checkbox" id="ld_ins" ${c.insecure ? "checked" : ""}> Accept self-signed certificate</label></div></div>
      <div class="row"><button class="btn primary" data-act="dir-save">Save</button><button class="btn" data-act="dir-sync">Sync owners now</button>
      <span class="small muted">${dc.owners ? `${fmtNum(dc.resolved)} of ${fmtNum(dc.owners)} owners resolved${dc.last_sync ? " · last sync " + ago(+dc.last_sync) : ""}` : "Not synced yet."}</span></div>`;
    $("#viewlog").innerHTML = vl.length ? `<table class="t"><thead><tr><th>When</th><th>Share</th><th>Path</th><th class="num">Size</th><th>From</th></tr></thead><tbody>${vl.slice(0, 20).map((v) => `<tr><td class="small">${fmtDate(v.ts)}</td><td>${esc(v.share)}</td><td class="path">${esc(v.path)}</td><td class="num">${fmtBytes(v.bytes)}</td><td class="small muted">${esc(v.client)}</td></tr>`).join("")}</tbody></table>` : "No files opened yet.";
  }, 0);
  const host = location.hostname;
  view.innerHTML = hero({ title: "Settings", iconName: "gear", sub: "Account, audit collection and API access." }) + `
  <div class="grid2">
  <div class="panel"><h2>Your password</h2><div class="sub">Sessions last 12 hours of inactivity.</div>
    <div class="field"><label>Current password</label><input class="in" type="password" id="p_cur"></div>
    <div class="field"><label>New password (10+ characters)</label><input class="in" type="password" id="p_new"></div>
    <button class="btn primary" data-act="chpw">Change password</button></div>
  <div class="panel"><h2>Audit ingest API</h2><div class="sub">Push events from other collectors as a JSON array to <code>POST /api/audit/ingest</code> with header <code>X-Ingest-Token</code>.</div>
    <p class="small">Token: ${s.ingest_token_set ? "<b>set</b>" : "not set"} <button class="btn sm" data-act="token">${s.ingest_token_set ? "Rotate" : "Generate"} token</button> <span id="tok" class="mono"></span></p>
    <pre class="code">[{"ts": 1790000000, "device_id": 1, "user": "CORP\\\\jdoe", "op": "delete",
  "path": "/ifs/data/finance/q3.xlsx", "proto": "SMB2", "client": "10.0.4.12"}]</pre></div>
  </div>
  <div class="panel" id="dirpanel"><h2>${icon("users", 16)} Directory (Active Directory)</h2><div class="sub">Looks up folder owners for department, OU and disabled status. Use a read-only account; LDAPS recommended. Run it through a collector if the domain controllers are only reachable on-site.</div><div id="dirbox" class="small muted">Loading…</div></div>
  <div class="panel"><h2>${icon("files", 16)} File viewer log</h2><div class="sub">Every file opened in the viewer.</div><div id="viewlog" class="small muted">Loading…</div></div>
  <div class="panel"><h2>${icon("bulb", 16)} Storage costs</h2><div class="sub">Used by Insights to turn capacity into money. Per TB per month.</div>
    <div class="row"><div class="field"><label>Primary tier $/TB/month</label><input class="in" id="cost_p" type="number" step="0.5" value="${s.cost_primary}" style="width:160px"></div>
    <div class="field"><label>Archive tier $/TB/month</label><input class="in" id="cost_a" type="number" step="0.5" value="${s.cost_archive}" style="width:160px"></div>
    <button class="btn primary" data-act="savecosts">Save</button></div></div>
  <div class="panel"><h2>${icon("activity", 16)} Connecting audit sources</h2>
    <p><b>PowerScale (OneFS 9.x):</b> enable protocol auditing on the access zone and forward it to this server over syslog. Events arriving from an address that resolves to a registered cluster are attributed to it.</p>
    <pre class="code">isi audit settings global modify --protocol-auditing-enabled=true --audited-zones=System
isi audit settings modify --zone=System --audit-success=create,delete,rename,set_security,write,read
isi audit settings global modify --protocol-syslog-forwarding-enabled=true --protocol-syslog-servers=${esc(host)}:5514</pre>
    <p class="small muted">Exact flag names vary between OneFS releases; check <code>isi audit settings global modify --help</code> on your cluster. Reads are high volume: start with create/delete/rename/write.</p>
    <p><b>Windows file server (this machine):</b> ${s.windows_audit.enabled ? `<span class="pill ok">COLLECTING</span> ${fmtNum(s.windows_audit.events)} events, last record ${s.windows_audit.last_record_id}` : `<span class="pill warn">NOT COLLECTING</span> ${esc(s.windows_audit.error || "")}`}</p>
    <pre class="code">auditpol /set /subcategory:"File System" /success:enable
# then on each audited folder: Properties > Security > Advanced > Auditing > Add
#   Principal: Everyone   Type: Success   Applies to: This folder, subfolders and files
#   Permissions: Create files / write data, Delete, Delete subfolders and files</pre>
  </div>`;
};

// ---------- ask ----------
function bindAsk(form) {
  if (!form) return;
  form.onsubmit = (e) => { e.preventDefault(); tryApi(() => runAsk($("input", form).value)); };
}
async function runAsk(q) {
  if (!q.trim()) return;
  const r = await api("/api/ask", { method: "POST", body: { q } });
  if (r.route) { location.hash = r.route; return; }
  const f = r.filter, p = new URLSearchParams();
  if (f.q) p.set("q", f.q);
  if (f.ext?.length) p.set("ext", f.ext.join(","));
  if (f.path_prefix) p.set("path", f.path_prefix);
  if (f.path_contains) p.set("path_contains", f.path_contains);
  if (f.owner) p.set("owner", f.owner);
  if (f.tag) p.set("tag", f.tag);
  if (f.older_than_days) p.set("older_days", f.older_than_days);
  if (f.newer_than_days) p.set("newer_days", f.newer_than_days);
  if (f.not_accessed_days) p.set("not_accessed_days", f.not_accessed_days);
  if (f.min_size) p.set("min_size", f.min_size);
  if (f.max_size) p.set("max_size", f.max_size);
  if (f.share_id) p.set("share", f.share_id);
  if (r.sort) p.set("sort", r.sort);
  S.askChips = r.understood;
  const target = "#/search/" + p.toString();
  if (location.hash === target) route(); else location.hash = target;
}

// ---------- insights ----------
const SEV = { crit: ["bad", "Act now"], warn: ["warn", "Worth a look"], info: ["info", "Opportunity"], good: ["ok", "Good"] };
const insightCard = (i) => `<div class="insight ${i.severity}"><div class="row" style="justify-content:space-between;align-items:flex-start;flex-wrap:nowrap">
  <div><span class="pill ${SEV[i.severity]?.[0] || "info"}">${SEV[i.severity]?.[1] || ""}</span><div class="ititle">${esc(i.title)}</div><div class="small muted">${esc(i.detail)}</div></div>
  ${i.savings_month ? `<div class="save"><b>$${fmtNum(Math.round(i.savings_month))}</b><span>per month</span></div>` : ""}</div>
  ${i.href ? `<a class="btn sm" style="margin-top:10px" href="${esc(i.href)}">${esc(i.action || "Open")} →</a>` : ""}</div>`;
async function insightStrip(el) {
  const d = await api("/api/insights?" + scopeQS());
  if (!d.insights.length) { el.remove(); return; }
  el.innerHTML = `<div class="panel-head"><div><h2>${icon("bulb", 16, 'style="color:var(--warn)"')} Top insights</h2><div class="sub">What the index says you should look at first${d.savings_month ? `, with about <b>$${fmtNum(Math.round(d.savings_month))}/month</b> in potential savings` : ""}.</div></div><a class="btn sm" href="#/insights">All ${d.insights.length} insights →</a></div>
    <div class="grid3">${d.insights.slice(0, 3).map(insightCard).join("")}</div>`;
}
PAGES.insights = async (view) => {
  const [d, ch] = await Promise.all([api("/api/insights?" + scopeQS()), api("/api/changes?" + scopeQS())]);
  const crit = d.insights.filter((i) => i.severity === "crit" || i.severity === "warn").length;
  view.innerHTML = hero({ title: "Insights", iconName: "bulb",
    sub: `Recommendations computed from the index: where money is going, what nobody owns, what is growing. Savings use $${d.cost_primary}/TB/month primary and $${d.cost_archive}/TB/month archive (change in Settings).`,
    kpis: kpi("Potential savings", "$" + fmtNum(Math.round(d.savings_month)), "per month, if acted on", "bulb") + kpi("Insights", d.insights.length, "", "spark") + kpi("Need attention", crit, "warnings and critical", "alert") +
      kpi("Since last scan", ch.available ? (ch.summary.delta >= 0 ? "+" : "−") + fmtBytes(Math.abs(ch.summary.delta)) : "n/a", ch.available ? `${ch.summary.shares_compared} share(s) compared` : "needs two scans of a share", "trend") }) + showing() +
    `<div class="grid2">${d.insights.map((i) => `<div>${insightCard(i)}</div>`).join("") || `<div class="panel empty"><b>Nothing stands out</b>Insights appear once shares are indexed.</div>`}</div>
    <div class="panel" style="margin-top:20px"><h2>${icon("trend", 16, 'style="color:var(--c2)"')} What changed since the previous scan</h2>
    ${ch.available ? `<div class="sub">Comparing ${fmtDate(ch.summary.from)} with ${fmtDate(ch.summary.to)}. Folder totals at depth 1 to 3.</div>
      <div class="grid2"><div><b class="small">Growing</b>${changeRows(ch.summary.leaders, "var(--hot)")}</div><div><b class="small">Shrinking</b>${changeRows(ch.summary.shrinkers, "var(--cold)")}</div></div>`
      : `<div class="empty small">Needs at least two published scans of a share. Rescan any share and come back.</div>`}</div>`;
};
function changeRows(list, color) {
  if (!list?.length) return `<div class="empty small">None.</div>`;
  const max = Math.max(...list.map((c) => Math.abs(c.delta))) || 1;
  return list.map((c) => `<div class="hbar" style="grid-template-columns:minmax(140px,1fr) 1fr 90px"><span class="nm" title="${esc(c.share + " " + c.path)}"><span class="faint small">${esc(c.share)}</span> ${esc(c.path)}</span>
    <div class="track"><div class="fill" style="width:${(Math.abs(c.delta) / max) * 100}%;background:${color}"></div></div><b style="text-align:right">${c.delta >= 0 ? "+" : "−"}${fmtBytes(Math.abs(c.delta))}</b></div>`).join("");
}

// ---------- risk ----------
PAGES.risk = async (view) => {
  const d = await api("/api/risk?" + scopeQS());
  setTimeout(async () => {
    const el = $("#ads-mini"); if (!el) return;
    const x = await api("/api/ads?" + scopeQS()).catch(() => null); if (!x) return;
    el.innerHTML = x.shares_enabled ? (x.by_class.length ? x.by_class.map((c) => `<span class="pill ${c.key === "hidden-payload" ? "bad" : c.key === "internet-origin" ? "warn" : "mute"}">${esc(c.key)} · ${fmtNum(c.streams)}</span>`).join(" ") : "No alternate data streams found.")
      : "ADS scanning is off. Tick <b>ADS</b> next to a Windows share on the Sources page and rescan it.";
  }, 0);
  const rw = d.ransomware;
  const lvl = d.score >= 60 ? ["bad", "High"] : d.score >= 25 ? ["warn", "Elevated"] : ["ok", "Low"];
  view.innerHTML = hero({ title: "Risk", iconName: "shield",
    sub: "Signals the metadata can reveal without reading a single file: ransomware leftovers, secrets and personal data stored by name, and accounts that suddenly change far more files than usual.",
    kpis: kpi("Risk score", `${d.score}<span style="font-size:14px;opacity:.75"> / 100 · ${lvl[1]}</span>`, "metadata signals only", "shield") +
      kpi("Encrypted-looking files", fmtNum(rw.encrypted_files), rw.encrypted_files ? `${fmtNum(rw.folders)} folders · last ${fmtDate(rw.last)}` : "known ransomware extensions", "alert") +
      kpi("Ransom notes", fmtNum(rw.notes), rw.notes ? `in ${fmtNum(rw.note_folders)} folders` : "by known note file names", "files") +
      kpi("Mass-change bursts", fmtNum(d.bursts.length), "last 7 days of audit", "activity") }) + showing() +
    (rw.encrypted_files || rw.notes ? `<div class="note" style="border-color:var(--bad);background:var(--bad-soft)"><b>Ransomware traces found.</b> Files with extensions used by known ransomware families${rw.notes ? " and ransom-note file names" : ""} exist in the index. They may be old test data or a past incident; check the folders below against your incident history before anything else.</div>` : "") +
    `<div class="grid2"><div class="panel"><h2>${icon("alert", 16, 'style="color:var(--bad)"')} Ransomware traces</h2><div class="sub">Folders holding the most files with ransomware extensions.</div>
      ${rw.top_folders.length ? `<table class="t"><thead><tr><th>Device / share</th><th>Folder</th><th class="num">Files</th><th>Newest</th></tr></thead><tbody>${rw.top_folders.map((f) => `<tr><td class="small">${esc(f.device)} › ${esc(f.share)}</td><td class="path">${esc(f.dir)}</td><td class="num">${fmtNum(f.files)}</td><td class="small">${fmtDate(f.last)}</td></tr>`).join("")}</tbody></table><a class="btn sm" style="margin-top:8px" href="#/search/${rw.search}">Search these files</a>` : `<div class="empty small">${icon("shield", 20)}<br>No files with known ransomware extensions.</div>`}
      ${rw.note_samples.length ? `<div style="margin-top:12px"><b class="small">Ransom-note names</b>${rw.note_samples.map((s) => `<div class="path">${esc(s.share)} ${esc(s.path)}</div>`).join("")}</div>` : ""}</div>
    <div class="panel"><h2>${icon("activity", 16, 'style="color:var(--c5)"')} Mass-change bursts</h2><div class="sub">10-minute windows where one account created, changed, renamed or deleted at least 300 files and 10× its normal rate, or touched ransomware extensions.</div>
      ${d.bursts.length ? `<table class="t"><thead><tr><th>When</th><th>User</th><th>Device</th><th class="num">Changes</th><th class="num">Normal</th><th>Mix</th></tr></thead><tbody>${d.bursts.map((b) => `<tr><td class="small">${fmtDate(b.window)}</td><td><b>${esc(b.user)}</b></td><td class="small">${esc(b.device)}</td><td class="num">${fmtNum(b.changes)}</td><td class="num faint">${fmtNum(Math.round(b.norm))}</td><td class="small">${Object.entries(b.ops).map(([k, v]) => `${k} ${fmtShort(v)}`).join(" · ")}${b.ransom_ext_hits ? ` <span class="pill bad">${b.ransom_ext_hits} ransomware ext</span>` : ""}</td></tr>`).join("")}</tbody></table>` : `<div class="empty small">${icon("activity", 20)}<br>No unusual bursts in the last 7 days${""}. Needs audit events (File activity page).</div>`}</div></div>
    <div class="panel"><div class="panel-head"><div><h2>${icon("shield", 16)} Alternate data streams</h2><div class="sub">Hidden NTFS streams found on shares with ADS scanning switched on.</div></div><a class="btn sm" href="#/ads">Open ADS report →</a></div><div id="ads-mini" class="small muted">Loading…</div></div>
    <div class="panel"><h2>${icon("files", 16, 'style="color:var(--c2)"')} Sensitive data by name</h2><div class="sub">Files whose type or name suggests secrets, personal data or whole copies of systems. Based on names only; review who can read these folders.</div>
      <div class="grid3">${d.sensitive.map((c) => `<div class="insight ${c.files ? (c.key === "credentials" || c.key === "keys" ? "crit" : "warn") : "good"}">
        <div class="row" style="justify-content:space-between"><b>${esc(c.label)}</b><span class="pill ${c.files ? "warn" : "ok"}">${c.files ? fmtNum(c.files) + " files" : "none"}</span></div>
        <div class="small muted" style="margin:4px 0 8px">${esc(c.why)}</div>
        ${c.samples.map((s) => `<div class="path ellip" title="${esc(s.share + " " + s.path)}">${esc(s.path)} <span class="faint">· ${esc(s.owner)}</span></div>`).join("")}
        ${c.files && c.search ? `<a class="btn sm" style="margin-top:8px" href="#/search/${c.search}">All ${fmtNum(c.files)} (${fmtBytes(c.bytes)})</a>` : ""}</div>`).join("")}</div></div>`;
};

// ---------- index (scan progress) ----------
let indexTimer = null;
PAGES.index = async (view, _, alive) => {
  view.innerHTML = hero({ title: "Scans", iconName: "history",
    sub: "Every metadata scan: what is running now, how fast, which folder it is reading, and how earlier scans ended. A scan only replaces a share's index when it finishes cleanly.",
    actions: `<button class="btn primary" data-act="wizard">${icon("plus", 14)} Add source</button>` }) +
    `<div id="ix-live"></div><div id="ix-jobs"></div><div id="ix-upd"></div><div id="ix-coll"></div><div id="ix-hist"></div>`;
  const draw = async () => {
    const [s, cols, upd, jb] = await Promise.all([api("/api/scans?limit=40"), api("/api/collectors").catch(() => []), api("/api/liveindex").catch(() => []), api("/api/jobs").catch(() => [])]);
    if (!alive()) return;
    const live = $("#ix-live");
    if (!live) return;
    live.innerHTML = `<div class="panel"><h2>${s.active.length ? `<span class="pulse"><i></i></span>` : icon("history", 16)} Running now</h2><div class="sub">Refreshes every 2 seconds. Percent is estimated from the previous scan of the same share.</div>
      ${s.active.length ? s.active.map((p) => {
        const secs = Math.max(1, Date.now() / 1000 - p.started);
        const rate = p.files / secs;
        const pct = p.prev_files ? Math.min(99, Math.round((p.files / p.prev_files) * 100)) : null;
        const eta = pct && rate > 0 ? Math.max(0, (p.prev_files - p.files) / rate) : null;
        const waiting = p.remote && !p.claimed;
        return `<div class="job"><div class="row" style="justify-content:space-between"><div><b>${esc(p.device)} › ${esc(p.share)}</b> ${p.remote ? `<span class="pill mute">${icon("cloud", 11)} via ${esc(p.collector || "collector")}</span>` : ""} ${p.cancel_requested ? '<span class="pill warn">cancelling</span>' : ""}</div>
          <button class="btn sm ghost-danger" data-act="cancel-scan" data-id="${p.scan_id}">${icon("stop", 12)} Cancel</button></div>
          ${waiting ? `<div class="small" style="margin:8px 0;color:var(--warn)">Waiting for the collector to pick this up. Check that it is online below.</div><div class="progress"><div></div></div>` :
          `<div class="bigbar"><div style="width:${pct ?? 100}%" class="${pct == null ? "indet" : ""}"></div></div>
          <div class="jobstats"><div><b>${pct != null ? pct + "%" : fmtShort(p.files)}</b><span>${pct != null ? "estimated" : "files so far"}</span></div><div><b>${fmtShort(p.files)}</b><span>files</span></div><div><b>${fmtShort(p.dirs)}</b><span>folders</span></div><div><b>${fmtBytes(p.bytes)}</b><span>indexed</span></div>
          <div><b>${fmtShort(Math.round(rate))}/s</b><span>files per second</span></div><div><b>${fmtDur(secs)}</b><span>elapsed${eta != null ? " · ~" + fmtDur(eta) + " left" : ""}</span></div><div><b style="color:${p.errors ? "var(--warn)" : "inherit"}">${fmtNum(p.errors)}</b><span>unreadable folders</span></div></div>
          <div class="small muted mono ellip" style="max-width:100%">${p.attempt > 1 ? '<span class="pill warn">resumed</span> ' : ""}${p.publishing ? "Walk finished: indexing and building reports. On slow disks this can take a while for large shares." : "Reading: " + esc(p.current || "/")}</div>`}</div>`;
      }).join("") : `<div class="empty small">No scan running. Start one from <a href="#/sources">Sources</a> or add a new source.</div>`}</div>`;
    const JOBNAME = { enable_audit: "Turning on file auditing", disable_audit: "Turning off file auditing" };
    $("#ix-jobs").innerHTML = jb.length ? `<div class="panel"><h2><span class="pulse"><i></i></span> Running jobs</h2><div class="sub">Work the collectors are doing besides scans. Turning auditing on or off makes Windows rewrite the security settings of every file below a folder; the estimate comes from that drive's indexed file count.</div>
      ${jb.map((j) => `<div class="job"><div class="row" style="justify-content:space-between"><div><b>${esc(JOBNAME[j.kind] || j.kind)}</b> <span class="pill mute">${icon("cloud", 11)} ${esc(j.where)}</span></div>
        <span class="small muted">step ${j.step} of ${j.steps} · started ${ago(j.started)}</span></div>
        <div class="bigbar"><div style="width:${j.pct >= 0 ? j.pct : 100}%" class="${j.pct >= 0 ? "" : "indet"}"></div></div>
        <div class="jobstats"><div><b>${j.pct >= 0 ? Math.round(j.pct) + "%" : "working"}</b><span>${j.pct >= 0 ? "of this drive (estimate)" : "no file count to estimate from"}</span></div>
          <div><b class="mono">${esc(j.path)}</b><span>${esc(j.share ? j.device + " › " + j.share : "current folder")}</span></div>
          <div><b>${fmtShort(j.ops)}</b><span>disk operations</span></div><div><b>${j.items ? fmtShort(j.items) : "?"}</b><span>files and folders</span></div>
          <div><b>${fmtDur(now() - j.step_started)}</b><span>on this step${j.remain_sec >= 0 ? " · ~" + fmtDur(j.remain_sec) + " left" : ""}</span></div></div></div>`).join("")}</div>` : "";
    $("#ix-upd").innerHTML = `<div class="panel"><h2>${icon("activity", 16)} Live index updates</h2><div class="sub">Between full scans, audit events (create, change, delete, rename) are re-read one path at a time and patched into the index every 3 minutes.</div>
      ${upd.length ? `<table class="t"><thead><tr><th>When</th><th>Share</th><th class="num">Events</th><th class="num">Updated</th><th class="num">Removed</th><th>Note</th></tr></thead><tbody>${upd.slice(0, 10).map((u) => `<tr><td class="small">${fmtDate(u.ts)}</td><td>${esc(u.share)}</td><td class="num">${fmtNum(u.events)}</td><td class="num">${fmtNum(u.upserted)}</td><td class="num">${fmtNum(u.removed)}</td><td class="small muted">${esc(u.message)}</td></tr>`).join("")}</tbody></table>`
        : `<div class="empty small">No audit-driven updates yet. They start once a share is indexed and audit events arrive for it (File activity page).</div>`}</div>`;
    $("#ix-coll").innerHTML = cols.length ? `<div class="panel"><h2>${icon("cloud", 16)} Collectors</h2><div class="sub">On-site agents that scan storage this server cannot reach directly.</div>
      <table class="t"><thead><tr><th>Name</th><th>Status</th><th>Host</th><th>Version</th><th class="num">Devices</th><th>Windows audit</th></tr></thead><tbody>
      ${cols.map((c) => `<tr><td><b>${esc(c.name)}</b></td><td>${c.online ? '<span class="pill ok">ONLINE</span>' : `<span class="pill ${c.last_seen ? "bad" : "mute"}">${c.last_seen ? "OFFLINE" : "NEVER CONNECTED"}</span>`} <span class="small faint">${c.last_seen ? ago(c.last_seen) : ""}</span></td>
        <td class="small">${esc(c.hostname || "")}</td><td class="small">${esc(c.version || "")}</td><td class="num">${c.devices}</td><td class="small">${c.info?.windows_audit ? (c.info.windows_audit.enabled ? `<span class="pill ok">collecting</span> ${fmtNum(c.info.windows_audit.events)}` : `<span class="muted">${esc(c.info.windows_audit.error || "")}</span>`) : ""}</td></tr>`).join("")}</tbody></table></div>` : "";
    $("#ix-hist").innerHTML = `<div class="panel"><h2>${icon("history", 16)} History</h2><div class="sub">Last 40 scans. "Not published" means the share kept its previous index; the reason is on the right.</div>
      <table class="t"><thead><tr><th>#</th><th>Device</th><th>Share</th><th>Started</th><th>Took</th><th>Status</th><th class="num">Files</th><th class="num">Size</th><th class="num">Errors</th><th>Reason</th></tr></thead><tbody>
      ${s.history.map((x) => `<tr><td class="faint">${x.id}</td><td>${esc(x.device)}</td><td>${esc(x.share)}</td><td class="small">${fmtDate(x.started)}</td><td class="small">${x.finished ? fmtDur(x.finished - x.started) : ""}</td>
        <td>${statusPill(x.status)}</td><td class="num">${fmtNum(x.files)}</td><td class="num">${fmtBytes(x.bytes)}</td><td class="num">${x.errors || ""}</td><td class="small muted ellip" style="max-width:320px" title="${esc(x.message)}">${esc(x.message)}</td></tr>`).join("") || `<tr><td colspan="10" class="empty">No scans yet.</td></tr>`}</tbody></table></div>`;
  };
  await draw();
  clearInterval(indexTimer);
  indexTimer = setInterval(() => { if (!alive() || !location.hash.startsWith("#/index")) return clearInterval(indexTimer); draw().catch(() => {}); }, 2000);
};
function fmtDur(s) {
  s = Math.round(s);
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m " + (s % 60) + "s";
  return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
}

// ---------- add-source wizard ----------
async function wizard() {
  const cols = await api("/api/collectors").catch(() => []);
  const st = { where: 0, kind: "windows", dev: null, shares: [] };
  const m = modal(`<div id="wz"></div>`);
  const box = () => $("#wz", m);
  const steps = ["Where", "Connect", "Pick shares", "Scan"];
  const head = (n) => `<div class="wsteps">${steps.map((s, i) => `<span class="${i === n ? "on" : i < n ? "done" : ""}">${i < n ? "✓" : i + 1}. ${s}</span>`).join("")}</div>`;
  const step1 = () => {
    box().innerHTML = head(0) + `<h3>Where does the storage live?</h3>
      <label class="choice"><input type="radio" name="w" value="0" ${st.where === 0 ? "checked" : ""}><div><b>Reachable from this server</b><span>This machine's own drives, or storage on the same network as the Stratum server.</span></div></label>
      ${cols.map((c) => `<label class="choice"><input type="radio" name="w" value="${c.id}" ${st.where === c.id ? "checked" : ""}><div><b>Through collector "${esc(c.name)}"</b> ${c.online ? '<span class="pill ok">online</span>' : '<span class="pill bad">offline</span>'}<span>${esc(c.hostname || "not connected yet")}. Use for storage in that site's network.</span></div></label>`).join("")}
      <label class="choice"><input type="radio" name="w" value="new"><div><b>In another network: set up a collector</b><span>Install a small agent next to the storage. It connects out to this server over HTTPS; nothing needs to be opened inbound.</span></div></label>
      <div class="row end" style="margin-top:14px"><button class="btn" data-x>Cancel</button><button class="btn primary" id="nx">Next</button></div>`;
    $("[data-x]", m).onclick = m.close;
    $("#nx", m).onclick = () => {
      const v = $("input[name=w]:checked", m)?.value;
      if (v === "new") { m.close(); collectorDialog(); return; }
      st.where = +v || 0; step2();
    };
  };
  const step2 = () => {
    box().innerHTML = head(1) + `<h3>Connect</h3>
      <div class="seg" id="wk" style="margin-bottom:12px"><button data-k="windows">Windows / file server</button><button data-k="powerscale">Dell PowerScale</button><button data-k="s3">S3 / ObjectScale</button></div>
      <div class="fgrid"><div class="field"><label>Display name</label><input class="in" id="w_name" placeholder="fs01"></div>
      <div class="field"><label id="w_hl"></label><input class="in" id="w_host"></div>
      <div class="field"><label>Username</label><input class="in" id="w_user" autocomplete="off"></div>
      <div class="field"><label>Password</label><input class="in" type="password" id="w_pass" autocomplete="new-password"></div>
      <div class="field s3o"><label>Region</label><input class="in" id="w_region" value="us-east-1"></div>
      <div class="field ps"><label>API port</label><input class="in" id="w_port" type="number" value="8080"></div>
      <div class="field ps"><label>TLS</label><label class="small"><input type="checkbox" id="w_ins" checked> Accept self-signed certificate</label></div></div>
      <div class="small muted" id="w_hint"></div><div id="w_err" class="small" style="color:var(--bad);margin-top:8px"></div>
      <div class="row end" style="margin-top:14px"><button class="btn" id="bk">Back</button><button class="btn primary" id="nx">Connect and discover shares</button></div>`;
    const sync = () => {
      $$("#wk button", m).forEach((b) => b.classList.toggle("on", b.dataset.k === st.kind));
      $$(".ps", m).forEach((e) => (e.style.display = st.kind === "powerscale" || (st.kind === "s3" && e.querySelector("#w_ins")) ? "" : "none"));
      $$(".s3o", m).forEach((e) => (e.style.display = st.kind === "s3" ? "" : "none"));
      $("#w_hl", m).textContent = st.kind === "powerscale" ? "Cluster address" : st.kind === "s3" ? "Endpoint URL" : `Server (blank = ${st.where ? "the collector's own machine" : "this machine"})`;
      $("#w_hint", m).textContent = st.kind === "powerscale" ? "Uses the OneFS API on port 8080 with a read-only role (see Settings for the privilege list)."
        : st.kind === "s3" ? "Username = access key, password = secret key. Buckets are discovered as shares."
        : st.where ? "Blank server = the machine the collector runs on. For another Windows server use its name and DOMAIN\\user with read access."
        : "Blank server = the machine Stratum runs on: its drives on Windows, its mounted filesystems on Linux. Other Windows machines need a collector, or a UNC server name and an account if Stratum itself runs on Windows.";
    };
    $$("#wk button", m).forEach((b) => (b.onclick = () => { st.kind = b.dataset.k; sync(); }));
    sync();
    $("#bk", m).onclick = step1;
    $("#nx", m).onclick = async () => {
      const btn = $("#nx", m); btn.disabled = true; btn.textContent = "Connecting…"; $("#w_err", m).textContent = "";
      try {
        const body = { name: $("#w_name", m).value || $("#w_host", m).value || "this machine", kind: st.kind, host: $("#w_host", m).value, username: $("#w_user", m).value,
          password: $("#w_pass", m).value, port: +$("#w_port", m).value || 0, insecure: $("#w_ins", m).checked, collector_id: st.where,
          options: st.kind === "s3" ? JSON.stringify({ region: $("#w_region", m).value || "us-east-1", path_style: true }) : "" };
        const r = st.dev ? { id: st.dev } : await api("/api/devices", { method: "POST", body });
        st.dev = r.id;
        st.shares = await api(`/api/devices/${r.id}/discover`, { method: "POST" });
        step3();
      } catch (e) { $("#w_err", m).textContent = e.message + (st.dev ? " (the device was saved; fix it under Sources or try again)" : ""); btn.disabled = false; btn.textContent = "Retry"; }
    };
  };
  const step3 = () => {
    box().innerHTML = head(2) + `<h3>Pick the shares to index</h3><div class="small muted" style="margin-bottom:8px">${st.shares.length} found. You can add a custom path too.</div>
      <div style="max-height:320px;overflow:auto">${st.shares.map((s, i) => `<label class="choice slim"><input type="checkbox" data-i="${i}"><div><b>${esc(s.name)}</b><span class="mono">${esc(s.path)}${s.zone ? " · zone " + esc(s.zone) : ""}${s.comment ? " · " + esc(s.comment) : ""}</span></div></label>`).join("")}</div>
      <div class="field" style="margin-top:10px"><label>Custom path (optional)</label><input class="in mono" id="w_custom" placeholder="D:\\Shares\\Projects or /ifs/data/projects"></div>
      <div class="field"><label>Rescan</label><select class="in" id="w_sched"><option value="0">Manually</option><option value="24" selected>Daily</option><option value="168">Weekly</option></select></div>
      <div class="row end"><button class="btn" data-x>Close</button><button class="btn primary" id="nx">Start scanning</button></div>`;
    $("[data-x]", m).onclick = () => { m.close(); loadScope(); route(); };
    $("#nx", m).onclick = () => tryApi(async () => {
      const picks = $$("input[data-i]:checked", m).map((c) => st.shares[+c.dataset.i]);
      const custom = $("#w_custom", m).value.trim();
      if (custom) picks.push({ name: custom.split(/[\\/]/).filter(Boolean).pop() || custom, path: custom });
      if (!picks.length) return toast("Tick at least one share", true);
      for (const s of picks) {
        const r = await api("/api/shares", { method: "POST", body: { device_id: st.dev, name: s.name, path: s.path, schedule_hours: +$("#w_sched", m).value } });
        await api(`/api/shares/${r.id}/scan`, { method: "POST" }).catch(() => {});
      }
      box().innerHTML = head(3) + `<h3>Scanning ${picks.length} share${picks.length > 1 ? "s" : ""}</h3><p class="muted">Scans run in the background. The Index page shows live progress; reports fill in as each share finishes.</p>
        <div class="row end"><button class="btn" data-x>Stay here</button><button class="btn primary" id="go">Watch progress</button></div>`;
      $("[data-x]", m).onclick = () => { m.close(); loadScope(); route(); };
      $("#go", m).onclick = async () => { m.close(); await loadScope(); location.hash = "#/index"; };
    });
  };
  step1();
}

// ---------- collectors ----------
async function collectorDialog() {
  modal(`<h3>Set up a collector</h3><p class="small muted">A collector is this same program running next to the storage. It connects <b>out</b> to this server over HTTPS, scans shares there, and forwards Windows and PowerScale audit events.</p>
    <div class="field"><label>Name</label><input class="in" id="c_name" placeholder="HQ datacenter"></div>
    <div class="row end"><button class="btn" data-x>Cancel</button><button class="btn primary" id="mk">Create</button></div><div id="c_out"></div>`, (m) => {
    $("[data-x]", m).onclick = m.close;
    $("#mk", m).onclick = () => tryApi(async () => {
      const r = await api("/api/collectors", { method: "POST", body: { name: $("#c_name", m).value } });
      const url = location.origin;
      $("#mk", m).remove();
      $("#c_out", m).innerHTML = installerPanel(r.id, r.token, $("#c_name", m).value);
      bindInstaller(m, r.id, r.token);
      $("[data-x2]", m).onclick = () => { m.close(); route(); };
    });
  });
}

// Pre-configured installer: the server URL and this collector's token are baked into the
// download, so the user only double-clicks it and approves the admin prompt.
function installerPanel(id, token, name) {
  const url = location.origin;
  return `<div class="note info small" style="margin-top:12px"><b>Download the installer now.</b> It contains this collector's token, which is shown only once. Treat the file like a password; if it leaks, use <b>New token</b> on the Sources page.</div>
    <div class="row" style="margin:12px 0"><button class="btn primary" data-inst="windows">${icon("download", 14)} Download Windows installer</button><button class="btn" data-inst="linux">${icon("download", 14)} Linux</button></div>
    <p class="small"><b>Windows:</b> double-click the downloaded file on a machine that can reach the storage and approve the administrator prompt. It installs itself as the <b>StratumCollector</b> service in <code>C:\\Program Files\\Stratum</code>; nothing to type. If SmartScreen appears, choose <b>More info → Run anyway</b>.</p>
    <p class="small"><b>Linux:</b> <code>chmod +x</code> the file and run it; it connects straight away.</p>
    <details class="small"><summary>Command-line alternative</summary><pre class="code">stratum.exe collector -install -server ${esc(url)} -token ${esc(token)}</pre></details>
    <p class="small">It shows as <b>online</b> under Collectors within a few seconds. Then use <b>Add source</b> and pick "${esc(name || "this collector")}".</p>
    <div class="row end"><button class="btn primary" data-x2>Done</button></div>`;
}
function bindInstaller(m, id, token) {
  $$("[data-inst]", m).forEach((b) => (b.onclick = () => tryApi(async () => {
    b.disabled = true; const label = b.innerHTML; b.textContent = "Preparing…";
    try {
      const r = await fetch(`/api/collectors/${id}/installer`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token, os: b.dataset.inst, server: location.origin }) });
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
      const name = (r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/)?.[1] || "stratum-collector.exe";
      const a = document.createElement("a");
      a.href = URL.createObjectURL(await r.blob()); a.download = name; document.body.appendChild(a); a.click();
      setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 2000);
      toast("Downloaded " + name);
    } finally { b.disabled = false; b.innerHTML = label; }
  })));
}

// ---------- ADS report ----------
const ADS_CLS = { "internet-origin": "warn", "cloud-sync": "info", "mac-client": "mute", "app-metadata": "mute", "hidden-payload": "bad", unknown: "warn" };
PAGES.ads = async (view) => {
  const d = await api("/api/ads?" + scopeQS());
  const tot = d.by_class.reduce((a, c) => a + c.streams, 0);
  const grpTable = (rows, label) => `<table class="t"><thead><tr><th>${label}</th><th class="num">Streams</th><th class="num">Files</th><th class="num">Size</th></tr></thead><tbody>${rows.map((g) => `<tr><td>${label === "Class" ? `<span class="pill ${ADS_CLS[g.key] || "mute"}">${esc(g.key)}</span>` : esc(g.key || "(unknown)")}</td><td class="num">${fmtNum(g.streams)}</td><td class="num">${fmtNum(g.files)}</td><td class="num">${fmtBytes(g.bytes)}</td></tr>`).join("") || '<tr><td colspan="4" class="empty small">None.</td></tr>'}</tbody></table>`;
  view.innerHTML = hero({ title: "Hidden data streams", iconName: "shield",
    sub: "NTFS alternate data streams are data attached to a file that Explorer, dir and most backup reports never show. Malware hides payloads in them; downloads carry a Zone.Identifier; sync clients leave their own.",
    kpis: kpi("Streams found", fmtNum(tot), "", "shield") + kpi("Hidden payloads", fmtNum(d.by_class.find((c) => c.key === "hidden-payload")?.streams || 0), "unknown streams over 64 KB", "alert") +
      kpi("Internet-origin files", fmtNum(d.by_class.find((c) => c.key === "internet-origin")?.files || 0), "downloaded or from email", "cloud") + kpi("Shares scanned for ADS", fmtNum(d.shares_enabled), "tick ADS on the Sources page", "db") }) + showing() +
    (d.shares_enabled ? "" : `<div class="note">No share has ADS scanning on. Tick <b>ADS</b> next to a Windows share on the <a href="#/sources">Sources</a> page and rescan it. It adds one call per file, so scans get slower.</div>`) +
    `<div class="grid2"><div class="panel"><h2>By class</h2>${grpTable(d.by_class, "Class")}</div><div class="panel"><h2>By device</h2>${grpTable(d.by_device, "Device")}</div>
    <div class="panel"><h2>By owner</h2>${grpTable(d.by_owner, "Owner")}</div><div class="panel"><h2>By stream name</h2>${grpTable(d.by_stream, "Stream")}</div></div>
    <div class="panel"><h2>${icon("alert", 16, 'style="color:var(--bad)"')} Largest unknown and hidden streams</h2><table class="t"><thead><tr><th>Device / share</th><th>File</th><th>Stream</th><th>Class</th><th>Owner</th><th class="num">Size</th></tr></thead><tbody>
    ${d.hidden.map((x) => `<tr><td class="small">${esc(x.device)} › ${esc(x.share)}</td><td class="path">${esc(x.path)}</td><td class="mono small">${esc(x.stream)}</td><td><span class="pill ${ADS_CLS[x.class]}">${esc(x.class)}</span></td><td class="small">${esc(x.owner)}</td><td class="num">${fmtBytes(x.size)}</td></tr>`).join("") || '<tr><td colspan="6" class="empty small">None.</td></tr>'}</tbody></table></div>`;
};

// ---------- IOPS diagnostics ----------
function sparkline(points, anomalies, shift) {
  if (!points.length) return "";
  const W = 420, H = 64, xs = points.map((p) => p[0]), ys = points.map((p) => p[1]);
  const x0 = Math.min(...xs), x1 = Math.max(...xs) || x0 + 1, y1 = Math.max(...ys, 1);
  const X = (t) => ((t - x0) / (x1 - x0 || 1)) * W, Y = (v) => H - 4 - (v / y1) * (H - 10);
  const an = new Set(anomalies || []);
  return `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:64px"><polyline fill="none" stroke="var(--c3)" stroke-width="1.5" points="${points.map((p) => X(p[0]) + "," + Y(p[1])).join(" ")}"/>
    ${points.filter((p) => an.has(p[0])).map((p) => `<circle cx="${X(p[0])}" cy="${Y(p[1])}" r="3" fill="var(--bad)"><title>${fmtDate(p[0])}: ${Math.round(p[1])}</title></circle>`).join("")}
    ${shift ? `<line x1="${X(shift.at)}" x2="${X(shift.at)}" y1="0" y2="${H}" stroke="var(--warn)" stroke-dasharray="3 3"/>` : ""}</svg>`;
}
PAGES.iops = async (view, rest) => {
  const dev = +(rest && rest[0]) || 0;
  const d = await api("/api/iops" + (dev ? "?device=" + dev : ""));
  const anomalies = d.series.reduce((a, s) => a + s.anomalies.length, 0), shifts = d.series.filter((s) => s.shift).length;
  view.innerHTML = hero({ title: "Disk activity", iconName: "activity",
    sub: "I/O per disk, volume, share and node, sampled every minute and compared with each series' own history: robust hourly baseline, anomalies (red dots) and level shifts (dashed line). Contended files and busy clients come from the audit stream.",
    extra: `<div class="row" style="margin-top:12px"><select class="in" style="width:auto" id="iodev">${d.devices.map((x) => `<option value="${x[0]}" ${x[0] === d.device ? "selected" : ""}>${esc(x[1])} (${esc(x[2])})${x[3] ? "" : " · no samples"}</option>`).join("")}</select></div>`,
    kpis: kpi("Series", d.series.length, "", "activity") + kpi("Anomalies (24h)", anomalies, "points far above baseline", "alert") + kpi("Level shifts", shifts, "sustained change in the last 6h", "trend") }) +
    (d.series.length ? "" : `<div class="note">No samples for this device yet. Samples start one minute after a device is added: Windows (this machine or through a collector on that machine), Linux servers, and PowerScale clusters (statistics API).</div>`) +
    `<div class="grid2">${d.series.map((s) => `<div class="panel"><div class="row" style="justify-content:space-between"><div><span class="pill mute">${esc(s.scope)}</span> <b>${esc(s.key)}</b> <span class="small muted">${esc(s.metric)}</span></div>
      <div class="small">now <b>${Math.round(s.current)}</b> · normal ${Math.round(s.baseline)} · peak ${Math.round(s.peak)}</div></div>
      ${sparkline(s.points, s.anomalies, s.shift)}
      ${s.shift ? `<div class="small" style="color:var(--warn)">Level shift at ${fmtDate(s.shift.at)}: ${Math.round(s.shift.before)} → ${Math.round(s.shift.after)}</div>` : ""}
      ${s.anomalies.length ? `<div class="small" style="color:var(--bad)">${s.anomalies.length} anomalous minutes in 24h</div>` : ""}</div>`).join("")}</div>
    <div class="grid2"><div class="panel"><h2>Most contended files (last hour)</h2><table class="t"><thead><tr><th>Path</th><th class="num">Ops</th><th class="num">Users</th></tr></thead><tbody>${d.files.map((f) => `<tr><td class="path">${esc(f[0])}</td><td class="num">${fmtNum(f[1])}</td><td class="num">${f[2]}</td></tr>`).join("") || '<tr><td colspan="3" class="empty small">Needs audit events for this device.</td></tr>'}</tbody></table></div>
    <div class="panel"><h2>Busiest clients (last hour)</h2><table class="t"><thead><tr><th>Client</th><th class="num">Ops</th><th class="num">Paths</th></tr></thead><tbody>${d.clients.map((c) => `<tr><td>${esc(c[0])}</td><td class="num">${fmtNum(c[1])}</td><td class="num">${fmtNum(c[2])}</td></tr>`).join("") || '<tr><td colspan="3" class="empty small">Needs audit events for this device.</td></tr>'}</tbody></table></div></div>`;
  $("#iodev") && ($("#iodev").onchange = (e) => (location.hash = "#/iops/" + e.target.value));
};

// ---------- file viewer ----------
const VIEW_IMG = ["jpg", "jpeg", "png", "gif", "bmp", "webp", "ico", "avif"], VIEW_VID = ["mp4", "webm", "mov", "m4v", "ogv"], VIEW_AUD = ["mp3", "wav", "ogg", "m4a", "aac", "flac"];
const VIEW_TXT = ["txt", "log", "csv", "tsv", "md", "json", "xml", "yaml", "yml", "ini", "conf", "cfg", "ps1", "bat", "cmd", "sh", "py", "go", "js", "ts", "java", "cs", "c", "h", "cpp", "sql", "html", "htm", "css", "svg", "properties", "reg", "inf"];
function loadScript(src) { return new Promise((res, rej) => { if ([...document.scripts].some((s) => s.src === src)) return res(); const s = document.createElement("script"); s.src = src; s.onload = res; s.onerror = rej; document.head.appendChild(s); }); }
// viewFetch reads (part of) a file with a time limit and a readable error. Files on a
// collector come across the internet from another machine, so this can be slow; it
// must never be silent.
async function viewFetch(url, opts = {}, ms = 150000) {
  const ac = new AbortController(), t = setTimeout(() => ac.abort(), ms);
  try {
    const r = await fetch(url, { ...opts, signal: ac.signal });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `The server answered ${r.status} ${r.statusText}`);
    return r;
  } catch (e) {
    if (e.name === "AbortError") throw new Error("The file took too long to arrive from its storage. Try again, or use Download.");
    if (e instanceof TypeError) throw new Error("The connection dropped while reading the file. Try again.");
    throw e;
  } finally { clearTimeout(t); }
}
// looksBinary: a NUL byte in the first 8 KB means it is not text, whatever its name says.
function looksBinary(bytes) { const n = Math.min(bytes.length, 8192); for (let i = 0; i < n; i++) if (bytes[i] === 0) return true; return false; }
// rtfToText renders an RTF file's readable text: paragraphs, tabs, \'hh bytes in the
// document's code page, and \uN characters. Formatting, fonts and pictures are dropped.
const RTF_CP = { 874: "windows-874", 932: "shift_jis", 936: "gbk", 949: "euc-kr", 950: "big5", 1250: "windows-1250", 1251: "windows-1251", 1252: "windows-1252", 1253: "windows-1253", 1254: "windows-1254", 1255: "windows-1255", 1256: "windows-1256", 1257: "windows-1257", 1258: "windows-1258" };
function rtfToText(src) {
  const cp = /\\ansicpg(\d+)/.exec(src.slice(0, 4096)), fc = /\\fcharset(\d+)/.exec(src.slice(0, 20000));
  const bycs = { 128: 932, 129: 949, 134: 936, 136: 950, 161: 1253, 162: 1254, 177: 1255, 178: 1256, 186: 1257, 204: 1251, 222: 874, 238: 1250 };
  const mk = (code) => { try { return new TextDecoder(RTF_CP[code] || "windows-1252"); } catch { return new TextDecoder("windows-1252"); } };
  const base = mk(cp && +cp[1] !== 1252 ? +cp[1] : bycs[fc && +fc[1]] || 1252);
  // Each font carries its own character set: a Korean document still sets its
  // (c) and (R) signs in a Western font, and decoding those bytes as Korean gives junk.
  const fonts = {};
  for (const f of src.slice(0, 200000).matchAll(/\\f(\d+)[^;{}]*?\\fcharset(\d+)/g)) fonts[f[1]] = f[2] === "0" ? mk(1252) : bycs[+f[2]] ? mk(bycs[+f[2]]) : base;
  let dec = base; const decStack = [];
  const skip = new Set(["fonttbl", "colortbl", "stylesheet", "info", "pict", "object", "header", "footer", "headerl", "headerr", "footerl", "footerr", "listtable", "listoverridetable", "rsidtbl", "generator", "themedata", "colorschememapping", "datastore", "latentstyles", "xmlnstbl", "mmathPr", "filetbl", "revtbl"]);
  let out = "", bytes = [], i = 0, depth = 0, skipAt = -1, uc = 1, drop = 0;
  const flush = () => { if (bytes.length) { out += dec.decode(new Uint8Array(bytes)); bytes = []; } };
  const emit = (s) => { if (skipAt < 0) { flush(); out += s; } };
  while (i < src.length) {
    const c = src[i];
    if (c === "{") { decStack.push(dec); depth++; i++; if (src.startsWith("\\*", i) && skipAt < 0) skipAt = depth; continue; }
    if (c === "}") { if (depth === skipAt) skipAt = -1; depth--; i++; flush(); dec = decStack.pop() || base; continue; }
    if (c === "\\") {
      const m = /^\\([a-zA-Z]+)(-?\d+)? ?|^\\'([0-9a-fA-F]{2})|^\\(.)/s.exec(src.slice(i, i + 40));
      if (!m) { i++; continue; }
      i += m[0].length;
      if (m[3] !== undefined) { if (drop > 0) { drop--; continue; } if (skipAt < 0) bytes.push(parseInt(m[3], 16)); continue; }
      if (m[4] !== undefined) { if (m[4] === "\n" || m[4] === "\r") emit("\n"); else if ("\\{}".includes(m[4])) emit(m[4]); else if (m[4] === "~") emit(" "); continue; }
      const w = m[1], n = m[2] !== undefined ? +m[2] : null;
      if (skip.has(w) && skipAt < 0) { skipAt = depth; continue; }
      if (w === "par" || w === "line" || w === "sect" || w === "page") emit("\n");
      else if (w === "tab" || w === "cell") emit("\t");
      else if (w === "row") emit("\n");
      else if (w === "uc") uc = n ?? 1;
      else if (w === "f" && n !== null && skipAt < 0) { flush(); dec = fonts[n] || base; }
      else if (w === "u" && n !== null) { emit(String.fromCharCode(n < 0 ? n + 65536 : n)); drop = uc; }
      else if (w === "emdash") emit("—"); else if (w === "endash") emit("–"); else if (w === "bullet") emit("•");
      else if (w === "lquote") emit("‘"); else if (w === "rquote") emit("’"); else if (w === "ldblquote") emit("“"); else if (w === "rdblquote") emit("”");
      continue;
    }
    if (c === "\r" || c === "\n") { i++; continue; }
    if (drop > 0) { drop--; i++; continue; }
    emit(c); i++;
  }
  flush();
  return out.replace(/\n{3,}/g, "\n\n").trim();
}
// downloadFile saves a file without leaving the page: a failed download used to replace
// the whole app with the browser's error page. Very large files go straight to the
// browser's download manager instead of through memory.
async function downloadFile(url, name, size, status) {
  if (size > 1024 * 1024 * 1024) {
    const a = document.createElement("a"); a.href = url + "&download=1"; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    status.textContent = "Handed to your browser's downloads.";
    return;
  }
  status.textContent = "Downloading…";
  const r = await viewFetch(url + "&download=1", {}, 30 * 60 * 1000);
  const total = +r.headers.get("Content-Length") || size, reader = r.body.getReader(), parts = [];
  let got = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value); got += value.length;
    status.textContent = `Downloading… ${Math.min(100, Math.round((got / total) * 100))}%`;
  }
  if (got < total) throw new Error(`The download stopped at ${fmtBytes(got)} of ${fmtBytes(total)}. Try again.`);
  const href = URL.createObjectURL(new Blob(parts));
  const a = document.createElement("a"); a.href = href; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 60000);
  status.textContent = "Downloaded.";
}
async function viewFile(shareId, p, size) {
  const name = p.split("/").pop(), ext = (name.includes(".") ? name.split(".").pop() : "").toLowerCase();
  const url = `/api/view?share=${shareId}&path=${encodeURIComponent(p)}`;
  const m = modal(`<div class="row" style="justify-content:space-between;margin-bottom:10px"><div><b>${esc(name)}</b><div class="path">${esc(p)} · ${fmtBytes(size)}</div></div>
    <div class="row"><span class="small muted" data-dls></span><button class="btn sm" data-dl>${icon("download", 12)} Download</button><button class="btn sm" data-x>Close</button></div></div><div id="vbody" class="viewer"><div class="progress"><div></div></div></div>`);
  m.style.width = "min(1100px, 100%)";
  $("[data-x]", m).onclick = m.close;
  const dl = $("[data-dl]", m), dls = $("[data-dls]", m);
  dl.onclick = async () => {
    dl.disabled = true;
    try { await downloadFile(url, name, size, dls); } catch (e) { dls.textContent = e.message; } finally { dl.disabled = false; }
  };
  const body = $("#vbody", m);
  const showText = (t, note) => { body.innerHTML = `<pre class="code" style="max-height:72vh;white-space:pre-wrap"></pre>${note ? `<div class="small muted">${note}</div>` : ""}`; $("pre", body).textContent = t; };
  const noPreview = (why) => { body.innerHTML = `<div class="empty"><b>${why}</b>Use Download to open it locally.</div>`; };
  try {
    if (VIEW_IMG.includes(ext)) body.innerHTML = `<img src="${url}" style="max-width:100%;max-height:75vh">`;
    else if (VIEW_VID.includes(ext)) body.innerHTML = `<video src="${url}" controls style="max-width:100%;max-height:75vh"></video>`;
    else if (VIEW_AUD.includes(ext)) body.innerHTML = `<audio src="${url}" controls style="width:100%"></audio>`;
    else if (ext === "pdf") {
      // Check it really is a PDF first: macOS "._name" files (AppleDouble metadata left
      // by Mac zips, often in __MACOSX) borrow the real file's name but hold no document.
      const head = new Uint8Array(await (await fetch(url, { headers: { Range: "bytes=0-7" } })).arrayBuffer());
      const isPdf = String.fromCharCode(...head.slice(0, 5)) === "%PDF-";
      const appleDouble = head[0] === 0x00 && head[1] === 0x05 && head[2] === 0x16 && head[3] === 0x07;
      if (isPdf) body.innerHTML = `<iframe src="${url}" style="width:100%;height:75vh;border:0"></iframe>`;
      else if (appleDouble || name.startsWith("._")) {
        const real = p.replace("/__MACOSX/", "/").replace(/\/\._([^/]+)$/, "/$1");
        body.innerHTML = `<div class="empty"><b>This is a macOS metadata file, not the PDF</b>When a Mac zips files it adds a small "._" companion (often in a __MACOSX folder) holding Finder details; it borrows the real file's name but contains no document.
          <br><br><button class="btn primary" id="vreal">Open ${esc(real.split("/").pop())}</button>
          <div class="small muted" style="margin-top:10px">To hide these everywhere: Sources → Exclude → "macOS leftovers".</div></div>`;
        $("#vreal", body).onclick = () => { m.close(); viewFile(shareId, real, 0); };
      } else noPreview("This file is named .pdf but is not a PDF document");
    }
    else if (ext === "rtf") {
      if (size > 50 * 1024 * 1024) return noPreview("This RTF file is too large to preview");
      const buf = new Uint8Array(await (await viewFetch(url)).arrayBuffer());
      const text = rtfToText(new TextDecoder("latin1").decode(buf));
      text ? showText(text, "Text only: formatting and pictures are not shown.") : noPreview("This RTF file has no readable text");
    } else if (ext === "docx") {
      if (size > 50 * 1024 * 1024) return noPreview("This document is too large to preview");
      await loadScript("https://cdnjs.cloudflare.com/ajax/libs/mammoth/1.8.0/mammoth.browser.min.js");
      const buf = await (await viewFetch(url)).arrayBuffer();
      const out = await window.mammoth.convertToHtml({ arrayBuffer: buf });
      const doc = new DOMParser().parseFromString(out.value, "text/html");
      doc.querySelectorAll("script,iframe,object,embed,link,style").forEach((e) => e.remove());
      doc.querySelectorAll("*").forEach((e) => [...e.attributes].forEach((a) => { if (/^on/i.test(a.name) || /javascript:/i.test(a.value)) e.removeAttribute(a.name); }));
      body.innerHTML = `<div class="docview">${doc.body.innerHTML}</div>`;
    } else if (["xlsx", "xls", "xlsm", "ods"].includes(ext)) {
      await loadScript("https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js");
      if (size > 50 * 1024 * 1024) return noPreview("This spreadsheet is too large to preview");
      const wb = window.XLSX.read(await (await viewFetch(url)).arrayBuffer(), { type: "array" });
      const first = wb.SheetNames[0];
      const rows = window.XLSX.utils.sheet_to_json(wb.Sheets[first], { header: 1, defval: "" }).slice(0, 500);
      body.innerHTML = `<div class="small muted">Sheet ${esc(first)}${wb.SheetNames.length > 1 ? " (of " + wb.SheetNames.length + ")" : ""}, first 500 rows</div><div style="overflow:auto;max-height:70vh"><table class="t">${rows.map((r) => `<tr>${r.slice(0, 40).map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("")}</table></div>`;
    } else if (["doc", "ppt", "pptx", "odt", "odp", "msg", "exe", "dll", "zip", "7z", "rar", "iso", "bin", "cab", "msi", "jar"].includes(ext)) noPreview(`No in-app preview for .${esc(ext)} files`);
    else if (VIEW_TXT.includes(ext) || size < 1024 * 1024) {
      // Named like text, or small and unknown: read the start and only show it if it
      // really is text. A binary file shown as text is just noise.
      const bytes = new Uint8Array(await (await viewFetch(url, { headers: { Range: "bytes=0-2097151" } })).arrayBuffer());
      if (looksBinary(bytes)) return noPreview(`This .${esc(ext || "?")} file is not text`);
      showText(new TextDecoder().decode(bytes), size > 2097152 ? "Showing the first 2 MB." : "");
    } else noPreview(`No in-app preview for .${esc(ext || "?")} files`);
  } catch (e) { body.innerHTML = `<div class="note">${esc(e.message)}</div>`; }
}

// ---------- exclusions ----------
async function shareByID(id) {
  const devs = S.devs || (S.devs = await api("/api/devices"));
  for (const d of devs) for (const x of d.shares) if (x.id === id) return x;
  S.devs = await api("/api/devices");
  for (const d of S.devs) for (const x of d.shares) if (x.id === id) return x;
}
async function excludeDialog(id) {
  const sh = await shareByID(id);
  const presets = await api("/api/exclude/presets");
  const cur = optOf(sh.options, "exclude") || [];
  const labels = { mac: "macOS leftovers (__MACOSX, ._ files)", linux: "Linux containers and system caches", system: "Recycle bin and system files", dev: "Code folders (node_modules, .git)", temp: "Temp and Office lock files", snapshot: "Snapshot folders" };
  modal(`<h3>Exclude from ${esc(sh.name)}</h3>
    <p class="small muted">One rule per line. <code>/Some/Folder</code> = that folder and everything in it. <code>*.iso</code> = wildcard on names. <code>node_modules</code> = any folder or file with that name. Not case-sensitive.
    Saving removes matching files from the current index right away and skips them in every future scan.</p>
    <div class="row" style="margin-bottom:8px">${Object.keys(presets).map((k) => `<button class="btn sm" data-preset="${k}">+ ${labels[k] || k}</button>`).join("")}</div>
    <textarea class="in mono" id="ex_rules" rows="10" placeholder="/$RECYCLE.BIN&#10;/Archive/Old&#10;node_modules&#10;*.iso">${esc(cur.join("\n"))}</textarea>
    <div class="row end" style="margin-top:12px"><button class="btn" data-x>Cancel</button><button class="btn primary" id="ex_save">Save and apply</button></div>`, (m) => {
    $("[data-x]", m).onclick = m.close;
    $$("[data-preset]", m).forEach((b) => (b.onclick = () => {
      const ta = $("#ex_rules", m), have = new Set(ta.value.split("\n").map((x) => x.trim().toLowerCase()).filter(Boolean));
      const add = presets[b.dataset.preset].filter((x) => !have.has(x.toLowerCase()));
      ta.value = (ta.value.trim() ? ta.value.trim() + "\n" : "") + add.join("\n");
    }));
    $("#ex_save", m).onclick = () => tryApi(async () => {
      const rules = $("#ex_rules", m).value.split("\n").map((x) => x.trim()).filter(Boolean);
      const r = await api(`/api/shares/${id}/exclude`, { method: "PUT", body: { exclude: rules } });
      m.close(); S.devs = null;
      toast(`${rules.length} rule(s) saved${r.removed ? ", " + fmtNum(r.removed) + " files removed from the index" : ""}`);
      route();
    });
  });
}

// ---------- users ----------
const ROLE_HELP = { viewer: "reports and search, no file contents", editor: "+ sources, scans, tags, automations, open files", admin: "+ users, settings, collectors, auditing" };
async function usersPanel() {
  const host = $("main .hero");
  if (!host || $("#userspanel")) return;
  host.insertAdjacentHTML("afterend", `<div class="panel" id="userspanel"></div>`);
  const draw = async () => {
    const users = await api("/api/users");
    $("#userspanel").innerHTML = `<div class="panel-head"><div><h2>${icon("users", 16)} Users</h2><div class="sub">${Object.entries(ROLE_HELP).map(([r, h]) => `<b>${r}</b>: ${h}`).join(" · ")}</div></div>
      <button class="btn sm primary" id="u_add">${icon("plus", 12)} Add user</button></div>
      <table class="t"><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th></th></tr></thead><tbody>
      ${users.map((u) => `<tr><td><b>${esc(u.username)}</b>${S.me && u.id === S.me.id ? ' <span class="pill info">you</span>' : ""}</td>
        <td><select class="in" style="width:auto;padding:3px 6px" data-urole="${u.id}">${["viewer", "editor", "admin"].map((r) => `<option ${r === u.role ? "selected" : ""}>${r}</option>`).join("")}</select></td>
        <td>${u.disabled ? '<span class="pill bad">disabled</span>' : u.must_change ? '<span class="pill warn">must change password</span>' : '<span class="pill ok">active</span>'}</td>
        <td class="small">${u.last_login ? ago(u.last_login) : "never"}</td>
        <td class="num"><button class="btn sm" data-ureset="${u.id}" data-uname="${esc(u.username)}">Reset password</button>
          <button class="btn sm" data-udis="${u.id}" data-val="${u.disabled ? 0 : 1}">${u.disabled ? "Enable" : "Disable"}</button>
          <button class="btn sm ghost-danger" data-udel="${u.id}" data-uname="${esc(u.username)}">${icon("trash", 12)}</button></td></tr>`).join("")}</tbody></table>`;
    const p = $("#userspanel");
    $("#u_add", p).onclick = () => modal(`<h3>Add user</h3>
      <div class="fgrid"><div class="field"><label>Username</label><input class="in" id="nu_name" autocomplete="off"></div>
      <div class="field"><label>Role</label><select class="in" id="nu_role"><option>viewer</option><option>editor</option><option>admin</option></select></div></div>
      <div class="field"><label>Temporary password (10+ characters)</label><input class="in" id="nu_pw" autocomplete="new-password"><span class="hint">They must change it at their first sign-in. Share it with them privately.</span></div>
      <div class="row end"><button class="btn" data-x>Cancel</button><button class="btn primary" id="nu_ok">Create</button></div>`, (m) => {
      $("[data-x]", m).onclick = m.close;
      $("#nu_pw", m).value = Array.from(crypto.getRandomValues(new Uint8Array(9)), (b) => "abcdefghjkmnpqrstuvwxyz23456789"[b % 31]).join("") + "-" + (100 + (crypto.getRandomValues(new Uint8Array(1))[0] % 900));
      $("#nu_ok", m).onclick = () => tryApi(async () => {
        await api("/api/users", { method: "POST", body: { username: $("#nu_name", m).value, role: $("#nu_role", m).value, password: $("#nu_pw", m).value } });
        m.close(); toast("User created"); draw();
      });
    });
    $$("[data-urole]", p).forEach((sel) => (sel.onchange = () => tryApi(async () => { await api("/api/users/" + sel.dataset.urole, { method: "PUT", body: { role: sel.value } }); toast("Role updated"); draw(); }).catch(draw)));
    $$("[data-udis]", p).forEach((b) => (b.onclick = () => tryApi(async () => { await api("/api/users/" + b.dataset.udis, { method: "PUT", body: { disabled: b.dataset.val === "1" } }); draw(); })));
    $$("[data-udel]", p).forEach((b) => (b.onclick = () => tryApi(async () => { if (!confirm("Delete user " + b.dataset.uname + "?")) return; await api("/api/users/" + b.dataset.udel, { method: "DELETE" }); draw(); })));
    $$("[data-ureset]", p).forEach((b) => (b.onclick = () => {
      const pw = prompt("Temporary password for " + b.dataset.uname + " (10+ characters). They must change it at the next sign-in:");
      if (pw) tryApi(async () => { await api("/api/users/" + b.dataset.ureset, { method: "PUT", body: { password: pw } }); toast("Password reset; " + b.dataset.uname + " was signed out"); draw(); });
    }));
  };
  draw();
}

// ---------- file auditing ----------
async function auditDialog(devId) {
  const devs = await api("/api/devices");
  S.devs = devs;
  const d = devs.find((x) => x.id === devId);
  if (!d) return;
  const isSys = (p) => /^[cC]:\\?$/.test(p.trim());
  const audited = (sh) => (sh.options || "").includes('"audited":true');
  const m = modal(`<h3>File auditing on ${esc(d.name)}</h3>
    <p class="small muted">Turns on the Windows <b>File System</b> audit policy and adds one audit rule (write, delete and permission changes, by anyone) to each folder you tick. Existing audit rules are kept. Disabling removes exactly that rule, and turns the policy back off only if Stratum was the one that turned it on.
    Events are read from the Security log by the ${d.collector_id ? "collector service" : "server"} and appear on the File activity page within about 30 seconds; the index then updates itself from them.</p>
    <table class="t"><thead><tr><th></th><th>Share</th><th>Path</th><th>Now</th></tr></thead><tbody>
    ${d.shares.map((sh) => `<tr><td><input type="checkbox" data-sh="${sh.id}" ${isSys(sh.path) || sh.path.startsWith("\\\\") ? "disabled" : audited(sh) ? "checked" : ""}></td><td><b>${esc(sh.name)}</b></td><td class="path">${esc(sh.path)}</td>
      <td>${isSys(sh.path) ? '<span class="pill warn">system drive: audit sub-folders instead</span>' : sh.path.startsWith("\\\\") ? '<span class="pill mute">remote share: enable on that server</span>' : audited(sh) ? '<span class="pill ok">audited</span>' : '<span class="pill mute">off</span>'}</td></tr>`).join("") || '<tr><td colspan="4" class="empty small">No shares on this device yet.</td></tr>'}
    </tbody></table>
    <p class="small muted" style="margin-top:8px">Adding the rule to a big drive makes Windows update the security settings of every file below it; this can take a few minutes. On busy drives the Security log fills faster: raise its size (Event Viewer → Windows Logs → Security → Properties) if you audit several drives.</p>
    <div id="au_out"></div>
    <div class="row end" style="margin-top:12px"><button class="btn" data-x>Close</button><button class="btn ghost-danger" id="au_off">Disable for ticked</button><button class="btn primary" id="au_on">Enable for ticked</button></div>`);
  $("[data-x]", m).onclick = m.close;
  const run = (enable) => tryApi(async () => {
    const ids = $$("input[data-sh]:checked", m).map((c) => +c.dataset.sh);
    if (!ids.length) return toast("Tick at least one share", true);
    const btn = enable ? $("#au_on", m) : $("#au_off", m);
    btn.disabled = true; btn.textContent = enable ? "Enabling…" : "Disabling…";
    try {
      const r = await api(`/api/devices/${devId}/enable-audit`, { method: "POST", body: { enable, share_ids: ids } });
      $("#au_out", m).innerHTML = `<table class="t" style="margin-top:10px">${Object.entries(r).map(([k, v]) => `<tr><td class="path">${esc(k)}</td><td>${esc(v)}</td></tr>`).join("")}</table>`;
      toast(enable ? "Auditing updated" : "Auditing removed");
    } finally { btn.disabled = false; btn.textContent = enable ? "Enable for ticked" : "Disable for ticked"; }
  });
  $("#au_on", m).onclick = () => run(true);
  $("#au_off", m).onclick = () => run(false);
}

// ---------- global actions ----------
document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-act]");
  if (!b) return;
  const id = +b.dataset.id;
  const act = b.dataset.act;
  const acts = {
    theme: () => { const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"); const nx = cur === "dark" ? "light" : "dark"; document.documentElement.dataset.theme = nx; try { localStorage.setItem("theme", nx); } catch {} },
    logout: async () => { await api("/api/logout", { method: "POST" }); renderLogin(); },
    wizard: () => wizard(),
    exclude: () => excludeDialog(id),
    "collector-drives": async () => {
      // A Windows device with a blank server = the machine the collector runs on.
      const r = await api("/api/devices", { method: "POST", body: { name: b.dataset.name, kind: "windows", host: "", collector_id: id } });
      S.devs = await api("/api/devices");
      await loadScope();
      discoverDialog(r.id);
    },
    "exclude-path": async () => {
      const sh = await shareByID(id); const p = b.dataset.path;
      if (!confirm(`Exclude ${p} from ${sh.name}?\n\nIts files leave the index now and future scans skip it. You can undo this under Sources → Exclude.`)) return;
      const rules = [...(optOf(sh.options, "exclude") || []), p];
      const r = await api(`/api/shares/${id}/exclude`, { method: "PUT", body: { exclude: rules } });
      S.devs = null; toast(`Excluded. ${fmtNum(r.removed)} files removed from the index.`); route();
    },
    "view-file": () => viewFile(+b.dataset.share, b.dataset.path, +b.dataset.size),
    "search-xlsx": () => { location.href = "/api/search.xlsx?" + scopeQS(S.lastSearch ? S.lastSearch() : {}); },
    "dir-save": async () => { await api("/api/directory/config", { method: "PUT", body: { url: $("#ld_url").value.trim(), base_dn: $("#ld_base").value.trim(), bind_user: $("#ld_user").value.trim(), password: $("#ld_pass").value, insecure: $("#ld_ins").checked, collector_id: +$("#ld_col").value } }); toast("Directory settings saved"); },
    "dir-sync": async () => { toast("Looking up owners…"); const r = await api("/api/directory/sync", { method: "POST" }); toast(`${r.resolved} owners looked up`); route(); },
    "add-collector": () => collectorDialog(),
    "rotate-collector": async () => {
      if (await confirmTyped("New collector token", "The old token stops working immediately. Download the new installer and run it on the collector machine; it upgrades the service in place.", b.dataset.name, false) === null) return;
      const r = await api(`/api/collectors/${id}/token`, { method: "POST" });
      modal(`<h3>New token for ${esc(b.dataset.name)}</h3><div id="c_out"></div>`, (m) => {
        $("#c_out", m).innerHTML = installerPanel(id, r.token, b.dataset.name);
        bindInstaller(m, id, r.token);
        $("[data-x2]", m).onclick = () => { m.close(); route(); };
      });
    },
    "del-collector": async () => { if (confirm("Remove this collector?")) { await api("/api/collectors/" + id, { method: "DELETE" }); route(); } },
    "enable-audit": () => auditDialog(id),
    savecosts: async () => { await api("/api/settings/costs", { method: "PUT", body: { primary: +$("#cost_p").value, archive: +$("#cost_a").value } }); toast("Costs saved"); },
    "add-device": () => deviceForm(),
    "edit-device": () => deviceForm(S.devs.find((d) => d.id === id)),
    "del-device": async () => { if (await confirmTyped("Remove device", "Removes the device, its shares and their index. Nothing on the storage is touched.", b.dataset.name) !== null) { await api("/api/devices/" + id, { method: "DELETE" }); await loadScope(); route(); } },
    discover: () => discoverDialog(id),
    "add-share": () => shareForm(id),
    "del-share": async () => { if (await confirmTyped("Remove share", "Drops this share's index, tags and triage. Nothing on the storage is touched.", b.dataset.name) !== null) { await api("/api/shares/" + id, { method: "DELETE" }); await loadScope(); route(); } },
    scan: async () => { await api(`/api/shares/${id}/scan`, { method: "POST" }); toast("Scan started"); route(); },
    "cancel-scan": async () => { await api(`/api/scans/${id}/cancel`, { method: "POST" }); toast("Cancelling"); },
    "search-csv": () => { location.href = "/api/search.csv?" + scopeQS(S.lastSearch ? S.lastSearch() : {}); },
    "issues-csv": () => { location.href = "/api/issues.csv?" + scopeQS(); },
    inv: async () => { await api(`/api/devices/${id}/inventory`, { method: "POST" }); route(); },
    "new-rule": () => ruleForm(),
    "edit-rule": () => ruleForm(S.rules.find((r) => r.id === id)),
    "del-rule": async () => { if (confirm("Delete this rule and remove its tags?")) { await api("/api/tagrules/" + id, { method: "DELETE" }); route(); } },
    "apply-rule": async () => { await api(`/api/tagrules/${id}/apply`, { method: "POST" }); toast("Rule re-applied"); route(); },
    "new-auto": () => autoForm(),
    "auto-edit": () => autoForm(S.autos.find((a) => a.id === id)),
    "auto-del": async () => { if (confirm("Delete this automation? Its run ledger is kept.")) { await api("/api/automations/" + id, { method: "DELETE" }); route(); } },
    "auto-hist": () => autoHistory(id),
    "auto-dry": async () => { await api(`/api/automations/${id}/run`, { method: "POST", body: { dry: true } }); toast("Dry-run started. Open History for the ledger."); setTimeout(route, 1200); },
    "auto-run": async () => {
      const a = S.autos.find((x) => x.id === id);
      const destructive = a.actions.some((x) => ["move", "delete", "rename"].includes(x.type));
      let confirmWord = "";
      if (destructive) {
        const c = await confirmTyped("Run for real", `<b>${esc(a.actions.map((x) => x.type).join(" → "))}</b> on every file matching ${esc(describeFilter(a.input))}. This changes data on the storage. Did you check the dry-run ledger?`, a.name);
        if (c === null) return;
        confirmWord = c;
      } else if (!confirm(`Run "${a.name}" for real?`)) return;
      await api(`/api/automations/${id}/run`, { method: "POST", body: { dry: false, confirm: confirmWord } });
      toast("Run started"); setTimeout(route, 1200);
    },
    chpw: async () => { await api("/api/password", { method: "POST", body: { current: $("#p_cur").value, new: $("#p_new").value } }); toast("Password changed"); $("#p_cur").value = $("#p_new").value = ""; },
    token: async () => { const r = await api("/api/settings/ingest-token", { method: "POST" }); $("#tok").textContent = r.token + "  (copy it now, it is not shown again)"; },
  };
  if (acts[act]) { e.preventDefault(); await tryApi(acts[act]); }
});

// schedule dropdowns on the sources page
document.addEventListener("change", (e) => {
  const ad = e.target.closest("[data-ads]");
  if (ad) return tryApi(async () => { await api("/api/shares/" + ad.dataset.ads, { method: "PUT", body: { name: ad.dataset.name, path: "-", schedule_hours: +ad.dataset.sched2, options: JSON.stringify({ ads: ad.checked }) } }); toast(ad.checked ? "ADS scanning on: applies from the next scan" : "ADS scanning off"); });
  const pm = e.target.closest("[data-perms]");
  if (pm) return tryApi(async () => { await api("/api/shares/" + pm.dataset.perms, { method: "PUT", body: { name: pm.dataset.name, path: "-", schedule_hours: +pm.dataset.sched2, options: JSON.stringify({ perms: pm.checked }) } }); toast(pm.checked ? "Folder permissions on: read from the next scan" : "Folder permissions off from the next scan"); });
  const s = e.target.closest("[data-sched]");
  if (s) tryApi(async () => { await api("/api/shares/" + s.dataset.sched, { method: "PUT", body: { name: s.dataset.name, path: "-", schedule_hours: +s.value } }); toast("Schedule saved"); });
});

// ---------- login & boot ----------
function renderLogin() {
  clearInterval(pollTimer);
  $("#root").innerHTML = `<div class="login"><form class="box" id="lf">
    <div class="row" style="margin-bottom:16px"><svg width="36" height="36" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#c2410c"/><path d="M7 10.5h13M10 16h15M7 21.5h11" stroke="#fff" stroke-width="3.2" stroke-linecap="round"/></svg><div><b style="font-size:17px">Stratum</b><div class="small muted">Sign in</div></div></div>
    <div class="field"><label>Username</label><input class="in" id="un" value="admin" autocomplete="username"></div>
    <div class="field"><label>Password</label><div style="position:relative"><input class="in" type="password" id="pw" autofocus autocomplete="current-password" style="padding-right:56px">
      <button type="button" id="pwshow" class="btn sm" style="position:absolute;right:4px;top:50%;transform:translateY(-50%)">Show</button></div></div>
    <div id="lerr" class="small" style="color:var(--bad);min-height:18px"></div>
    <button class="btn primary" style="width:100%;justify-content:center;padding:9px">Sign in</button>
    <div id="lhint" class="small faint" style="margin-top:12px"></div>
    <details class="small faint" style="margin-top:8px"><summary style="cursor:pointer">Forgot your password?</summary>
      <div style="margin-top:6px">Another admin can set a temporary one under Settings, Users. If you are the only admin, run <code>stratum -data &lt;data folder&gt; -reset-password &lt;temporary&gt;</code> on the server; you choose a new password when you sign in.</div></details></form></div>`;
  $("#pwshow").onclick = () => { const p = $("#pw"); const show = p.type === "password"; p.type = show ? "text" : "password"; $("#pwshow").textContent = show ? "Hide" : "Show"; };
  api("/api/me").then((me) => { if (me.default_password) $("#lhint").innerHTML = "New install: sign in as <code>admin</code> / <code>admin</code>; you will be asked to choose a new password."; }).catch(() => {});
  $("#lf").onsubmit = async (e) => {
    e.preventDefault();
    try { await api("/api/login", { method: "POST", body: { username: $("#un").value, password: $("#pw").value } }); boot(); }
    catch (err) { $("#lerr").textContent = err.message; }
  };
}
function renderMustChange(me) {
  $("#root").innerHTML = `<div class="login"><form class="box" id="cf">
    <b style="font-size:17px">Choose a new password</b>
    <div class="small muted" style="margin:4px 0 14px">Signed in as <b>${esc(me.user.username)}</b>. ${me.user.username === "admin" ? "The default password must be replaced before Stratum can be used." : "An admin set a temporary password for you."}</div>
    <div class="field"><label>Current password</label><input class="in" type="password" id="c_cur" autocomplete="current-password"></div>
    <div class="field"><label>New password (10+ characters)</label><input class="in" type="password" id="c_new" autocomplete="new-password"></div>
    <div class="field"><label>Repeat new password</label><input class="in" type="password" id="c_new2" autocomplete="new-password"></div>
    <div id="cerr" class="small" style="color:var(--bad);min-height:18px"></div>
    <button class="btn primary" style="width:100%;justify-content:center;padding:9px">Save and continue</button>
    <div class="small" style="margin-top:10px"><a href="#" id="c_out">Sign out</a></div></form></div>`;
  $("#c_out").onclick = async (e) => { e.preventDefault(); await api("/api/logout", { method: "POST" }); renderLogin(); };
  $("#cf").onsubmit = async (e) => {
    e.preventDefault();
    if ($("#c_new").value !== $("#c_new2").value) { $("#cerr").textContent = "The new passwords do not match"; return; }
    try { await api("/api/password", { method: "POST", body: { current: $("#c_cur").value, new: $("#c_new").value } }); boot(); }
    catch (err) { $("#cerr").textContent = err.message; }
  };
}
async function boot() {
  try { const t = localStorage.getItem("theme"); if (t) document.documentElement.dataset.theme = t; } catch {}
  const me = await fetch("/api/me").then((r) => r.json());
  S.version = me.version;
  if (!me.authed) return renderLogin();
  S.me = me.user;
  if (me.user && me.user.must_change) return renderMustChange(me);
  shell();
  await loadScope();
  route();
  setInterval(async () => {
    const el = $("#running");
    if (!el) return;
    const s = await fetch("/api/scans?limit=1").then((r) => r.ok ? r.json() : null).catch(() => null);
    const n = s ? s.active.length : 0;
    if (n !== S.lastActive) { S.lastActive = n; loadScope().catch(() => {}); } // a scan started or finished: refresh the scope lists
    if (!s || !s.active.length) { el.innerHTML = ""; return; }
    const f = s.active.reduce((a, p) => a + p.files, 0);
    el.innerHTML = `<span class="chip pulse" title="Open the Index page"><i></i>${s.active.length} scan${s.active.length > 1 ? "s" : ""} · ${fmtShort(f)} files</span>`;
  }, 3000);
}
boot();
