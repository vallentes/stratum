"use strict";
// Tripwire (ransomware early warning), Permissions explorer, Migration planner.
// Loaded after app.js and uses its helpers ($, api, hero, kpi, icon, esc, toast, modal…).

ICONS.check = '<path d="M20 6 9 17l-5-5"/>';
ICONS.siren = '<path d="M7 18v-6a5 5 0 0 1 10 0v6"/><path d="M5 21h14v-3H5z"/><path d="M12 2v2M4.2 5.2l1.4 1.4M19.8 5.2l-1.4 1.4M2 12h2M20 12h2"/>';
ICONS.lock = '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>';
ICONS.truck = '<path d="M3 6h11v10H3zM14 9h4l3 3v4h-7"/><circle cx="7" cy="18" r="2"/><circle cx="17" cy="18" r="2"/>';
NAV.splice(6, 0, ["tripwire", "Tripwire", "siren"]);
REPORTS.splice(2, 0,
  ["tripwire", "Tripwire", "Ransomware early warning: decoy files, mass changes and ransomware file endings, with alerts and optional account blocking.", "siren", "#fdecee", "var(--bad)"],
  ["permissions", "Permissions", "Who can open what: folders open to everyone, deleted accounts still holding access, broken inheritance.", "lock", "#f3ecff", "var(--c2)"],
  ["migrations", "Migration", "Plan a move to new storage from the index, see what will fail first, then copy in waves with every file verified.", "truck", "#e6f7f1", "var(--ok)"]);
const isAdmin = () => S.me && S.me.role === "admin";
const canEdit = () => S.me && (S.me.role === "admin" || S.me.role === "editor");

// ---------- Tripwire ----------
const TW_RULE = { decoy: "Decoy file touched", ransom_note: "Ransom note written", ransom_ext: "Ransomware file endings", burst: "Mass change by one account", test: "Test" };
PAGES.tripwire = async (view, rest, alive) => {
  const d = await api("/api/tripwire");
  const c = d.config;
  const armed = d.shares.filter((s) => s.decoys > 0).length;
  view.innerHTML = hero({ title: "Tripwire", iconName: "siren",
    sub: "Ransomware early warning on top of the audit stream: decoy files nobody should ever touch, one account changing far more files than normal, and files with known ransomware endings. Alerts go to email, Teams, Slack or a webhook; blocking the account is one click, or automatic when you switch it on.",
    kpis: kpi("Open alerts", fmtNum(d.open), d.open ? "need a look" : "all quiet", "alert") + kpi("Alerts (24h)", fmtNum(d.last24), "", "siren") +
      kpi("Accounts blocked", fmtNum(d.blocked), "", "lock") + kpi("Audit events (24h)", fmtShort(d.events24), d.events24 ? "watched in real time" : "no audit source yet", "activity") +
      kpi("Shares with decoys", `${armed} <span style="font-size:14px;opacity:.7">of ${d.shares.length}</span>`, "", "shield") }) +
    (c.enabled ? "" : `<div class="note"><b>The tripwire is switched off.</b> Nothing is checked until you switch it on under Settings below.</div>`) +
    (d.events24 ? "" : `<div class="note info">No audit events arrived in the last 24 hours. The tripwire watches what the audit stream reports: switch on file auditing for a Windows device (Sources → Auditing) or forward PowerScale protocol audit to this server.</div>`) +
    `<div class="panel"><div class="panel-head"><div><h2>${icon("alert", 16)} Alerts</h2><div class="sub">Newest first. One alert per account and rule; repeats inside the cool-down add to its count instead of notifying again.</div></div></div>
      <div id="tw-alerts">${twAlertsTable(d.alerts)}</div></div>
    <div class="panel"><h2>${icon("shield", 16)} Decoy files</h2><div class="sub">Two small hidden files in the share root and in its ten biggest top-level folders, named to sort first and last where ransomware starts. Nobody has a reason to open them, so any change, rename or delete is an alert. They are left out of every report.</div>
      <table class="t"><thead><tr><th>Device</th><th>Share</th><th>Audit</th><th class="num">Decoys</th><th></th></tr></thead><tbody>
      ${d.shares.map((s) => `<tr><td>${esc(s.device)}</td><td><b>${esc(s.name)}</b> <span class="path">${esc(s.path)}</span></td>
        <td>${s.audited ? '<span class="pill ok">ON</span>' : '<span class="pill warn" title="Turn on auditing for this share under Sources → Auditing">OFF</span>'}</td>
        <td class="num">${s.decoys || "–"}</td>
        <td class="num">${s.eligible ? `<span class="small faint">${esc(s.eligible)}</span>` : !isAdmin() ? "" : s.decoys ? `<button class="btn sm" data-act="tw-decoys-off" data-id="${s.id}" data-name="${esc(s.name)}">Remove decoys</button>` : `<button class="btn sm primary" data-act="tw-decoys-on" data-id="${s.id}" data-name="${esc(s.name)}" data-audited="${s.audited ? 1 : 0}">Plant decoys</button>`}</td></tr>`).join("") || '<tr><td colspan="5" class="empty small">Add a source first.</td></tr>'}
      </tbody></table></div>
    ${isAdmin() ? twSettings(c) : ""}`;
  if (isAdmin()) bindTwSettings(view);
  const t = setInterval(async () => {
    if (!alive() || !location.hash.startsWith("#/tripwire")) return clearInterval(t);
    try { const x = await api("/api/tripwire"); $("#tw-alerts") && ($("#tw-alerts").innerHTML = twAlertsTable(x.alerts)); } catch {}
  }, 10000);
};

function twAlertsTable(list) {
  if (!list.length) return `<div class="empty">${icon("shield", 22)}<b>No alerts</b>Nothing suspicious so far. Use "Send test" in the settings to check that notifications arrive.</div>`;
  return `<table class="t"><thead><tr><th>When</th><th>What</th><th>Account</th><th>Where</th><th class="num">Count</th><th>Status</th><th></th></tr></thead><tbody>
    ${list.map((a) => `<tr>
      <td class="small">${fmtDate(a.ts)}${a.last_ts > a.ts + 60 ? `<div class="faint">last ${ago(a.last_ts)}</div>` : ""}</td>
      <td><span class="pill ${a.severity === "critical" ? "bad" : "warn"}">${esc(TW_RULE[a.rule] || a.rule)}</span><div class="small muted" style="margin-top:4px;max-width:420px">${esc(a.detail)}</div>
        ${(a.sample || []).length ? `<details class="small"><summary class="faint" style="cursor:pointer">files</summary>${a.sample.map((p) => `<div class="path">${esc(p)}</div>`).join("")}</details>` : ""}
        ${a.notified ? `<div class="small faint">${esc(a.notified)}</div>` : ""}</td>
      <td><b>${esc(a.user || "(unknown)")}</b>${a.client ? `<div class="small faint">${esc(a.client)}</div>` : ""}</td>
      <td class="small">${esc(a.device)}${a.share ? " › " + esc(a.share) : ""}</td>
      <td class="num">${fmtNum(a.count)}</td>
      <td>${a.blocked ? '<span class="pill bad">BLOCKED</span>' : ""} <span class="pill ${a.status === "open" ? "warn" : "mute"}">${esc(a.status.toUpperCase())}</span>
        ${a.block_note && !a.block_note.startsWith("{") ? `<div class="small faint">${esc(a.block_note)}</div>` : ""}</td>
      <td class="num" style="white-space:nowrap">${isAdmin() ? `${a.status === "open" ? `<button class="btn sm" data-act="tw-ack" data-id="${a.id}">Acknowledge</button>` : a.status === "acknowledged" ? `<button class="btn sm" data-act="tw-resolve" data-id="${a.id}">Resolve</button>` : ""}
        ${a.user ? a.blocked ? `<button class="btn sm" data-act="tw-unblock" data-id="${a.id}" data-name="${esc(a.user)}">Unblock</button>` : `<button class="btn sm ghost-danger" data-act="tw-block" data-id="${a.id}" data-name="${esc(a.user)}">${icon("lock", 12)} Block</button>` : ""}` : ""}</td></tr>`).join("")}</tbody></table>`;
}

function twSettings(c) {
  const sec = (k, label, ph) => `<div class="field"><label>${label}</label><input class="in" type="password" autocomplete="off" id="tw_${k}" placeholder="${c[k + "_set"] ? "saved (type to replace)" : ph}">
    ${c[k + "_set"] ? `<label class="small" style="font-weight:400"><input type="checkbox" id="tw_${k}_clear"> remove</label>` : ""}</div>`;
  return `<div class="panel"><h2>${icon("gear", 16)} Settings</h2><div class="sub">Thresholds, notifications and the automatic response. Addresses and passwords are encrypted at rest and never shown again.</div>
    <div class="grid2"><div>
      <label class="row" style="margin-bottom:12px"><input type="checkbox" id="tw_enabled" ${c.enabled ? "checked" : ""}> <b>Tripwire on</b></label>
      <div class="grid2" style="gap:12px">
        <div class="field"><label>Mass change: files per minute by one account</label><input class="in" type="number" min="0" id="tw_burst" value="${c.burst_per_min}"><span class="hint">0 switches the rule off. Big copy jobs by service accounts can pass this: add them to the never-block list.</span></div>
        <div class="field"><label>Ransomware endings: files per minute</label><input class="in" type="number" min="0" id="tw_ext" value="${c.ext_per_min}"><span class="hint">Files named like *.lockbit or *.locked written by one account.</span></div>
        <div class="field"><label>Cool-down (minutes)</label><input class="in" type="number" min="1" id="tw_cool" value="${c.cooldown_min}"><span class="hint">Repeats inside it add to the open alert without notifying again.</span></div>
        <div class="field"><label>Link in messages</label><input class="in" id="tw_link" value="${esc(c.link_url)}" placeholder="https://stratum.example.com:8470"></div>
      </div>
      <div class="note" style="margin-top:6px"><label class="row"><input type="checkbox" id="tw_auto" ${c.auto_block ? "checked" : ""}> <b>Block the account automatically</b></label>
        <div class="small" style="margin-top:6px">On a Windows file server this denies the account on every share and closes its open files and sessions; on PowerScale it adds a deny entry to every SMB share. It runs on that server through its collector. Unblock from the alert. Off by default: try it on a test share first.</div></div>
      <div class="field"><label>Never block these accounts (comma separated)</label><input class="in" id="tw_never" value="${esc((c.never_block || []).join(", "))}" placeholder="Administrator, CORP\\backup-svc"><span class="hint">System and machine accounts are never blocked anyway.</span></div>
    </div><div>
      ${sec("teams_url", "Microsoft Teams workflow URL", "https://….logic.azure.com/… (Workflows: post to a channel when a webhook request is received)")}
      ${sec("slack_url", "Slack incoming webhook", "https://hooks.slack.com/services/…")}
      ${sec("webhook_url", "Generic webhook (JSON)", "https://siem.example.com/hooks/stratum")}
      <div class="grid2" style="gap:12px">
        <div class="field"><label>SMTP server</label><input class="in" id="tw_smtp_host" value="${esc(c.smtp_host)}" placeholder="smtp.office365.com"></div>
        <div class="field"><label>Port and security</label><div class="row" style="flex-wrap:nowrap"><input class="in" style="width:90px" type="number" id="tw_smtp_port" value="${c.smtp_port || 587}">
          <select class="in" id="tw_smtp_tls">${["starttls", "tls", "none"].map((x) => `<option ${c.smtp_tls === x ? "selected" : ""}>${x}</option>`).join("")}</select></div></div>
        <div class="field"><label>SMTP user</label><input class="in" id="tw_smtp_user" value="${esc(c.smtp_user)}" autocomplete="off"></div>
        ${sec("smtp_pass", "SMTP password", "")}
        <div class="field"><label>From</label><input class="in" id="tw_mail_from" value="${esc(c.mail_from)}" placeholder="stratum@example.com"></div>
        <div class="field"><label>To (comma separated)</label><input class="in" id="tw_mail_to" value="${esc(c.mail_to)}" placeholder="soc@example.com"></div>
      </div>
    </div></div>
    <div class="row end"><span id="tw_res" class="small muted"></span><button class="btn" id="tw_test">${icon("siren", 13)} Send test</button><button class="btn primary" id="tw_save">Save settings</button></div></div>`;
}

function bindTwSettings(view) {
  const read = () => {
    const v = (id) => $("#tw_" + id).value.trim();
    const body = { enabled: $("#tw_enabled").checked, burst_per_min: +v("burst"), ext_per_min: +v("ext"), cooldown_min: +v("cool"), link_url: v("link"),
      auto_block: $("#tw_auto").checked, never_block: v("never").split(",").map((s) => s.trim()).filter(Boolean),
      smtp_host: v("smtp_host"), smtp_port: +v("smtp_port"), smtp_tls: $("#tw_smtp_tls").value, smtp_user: v("smtp_user"), mail_from: v("mail_from"), mail_to: v("mail_to") };
    for (const k of ["teams_url", "slack_url", "webhook_url", "smtp_pass"]) {
      body[k] = $("#tw_" + k).value.trim();
      if ($("#tw_" + k + "_clear") && $("#tw_" + k + "_clear").checked) { body[k] = ""; body[k + "_clear"] = true; }
    }
    return body;
  };
  $("#tw_save", view).onclick = () => tryApi(async () => {
    const b = read();
    if (b.auto_block && !(await confirmTyped("Automatic blocking", "When an alert fires, Stratum will deny that account on the file server's shares without asking. Make sure service accounts that copy many files are on the never-block list.", "block", true) !== null)) return;
    await api("/api/tripwire/config", { method: "PUT", body: b }); toast("Tripwire settings saved"); route();
  });
  $("#tw_test", view).onclick = () => tryApi(async () => {
    await api("/api/tripwire/config", { method: "PUT", body: read() });
    $("#tw_res").textContent = "Sending…";
    const r = await api("/api/tripwire/test", { method: "POST" });
    $("#tw_res").textContent = r.results.join(" · ");
  });
}

// ---------- Permissions ----------
const RIGHTS_ORDER = ["full", "modify", "write", "read", "list", "special"];
const aceChip = (e) => `<span class="pill ${e.d ? "bad" : e.o ? "warn" : "mute"}" title="${esc((e.d ? "deny " : "allow ") + e.r + (e.i ? " (inherited)" : "") + (e.s ? " · " + e.s : ""))}" style="margin:1px">${e.d ? "DENY " : ""}${esc(e.t)} · ${esc(e.r)}${e.i ? "" : " ●"}</span>`;
PAGES.permissions = async (view, rest) => {
  const kind = (rest && rest[0]) || "open";
  const [d, list] = await Promise.all([api("/api/perms/summary?" + scopeQS()), api("/api/perms/folders?" + scopeQS({ kind }))]);
  const disabledN = Object.keys(d.disabled || {}).length;
  const tabs = [["open", "Open to everyone", d.open], ["orphan", "Deleted accounts", d.orphan], ["disabled", "Disabled accounts", disabledN], ["protected", "Inheritance off", d.protected], ["deny", "Deny entries", d.deny], ["all", "All", d.folders]];
  view.innerHTML = hero({ title: "Permissions", iconName: "lock",
    sub: "Who can open what. Each folder's access list is read during the scan; only folders whose access differs from their parent are listed, because everything below them has the same access. ● marks an entry set on that folder itself rather than inherited.",
    actions: `<a class="btn" href="/api/perms/export.csv?${scopeQS({ kind })}">${icon("download", 14)} CSV</a>`,
    kpis: kpi("Open to everyone", fmtNum(d.open), d.open_bytes ? `${fmtBytes(d.open_bytes)} in ${fmtShort(d.open_files)} files exposed` : "folders", "users") +
      kpi("Deleted accounts", fmtNum(d.orphan), "folders still granting them access", "alert") +
      kpi("Inheritance off", fmtNum(d.protected), "folders that stop parent access", "lock") +
      kpi("Unique permissions", fmtNum(d.folders), `${fmtNum(d.trustees)} accounts and groups`, "shield") }) +
    (d.shares_without ? `<div class="note info">${d.shares_without} share${d.shares_without > 1 ? "s were" : " was"} indexed before permissions were collected (or ${d.shares_without > 1 ? "have" : "has"} it switched off). Rescan ${d.shares_without > 1 ? "them" : "it"} from Sources to include ${d.shares_without > 1 ? "them" : "it"}.</div>` : "") +
    (disabledN ? "" : `<div class="note info">Disabled accounts appear here once Active Directory is connected (Settings → Directory) and synced.</div>`) +
    showing() +
    `<div class="panel"><h2>${icon("search", 16)} What can this account reach?</h2><div class="sub">Folders whose entries name the account or one of its groups, plus folders open to everybody. Group membership is not read from the directory, so type the groups you care about too.</div>
      <form class="row" id="who" style="flex-wrap:nowrap"><input class="in" id="who_n" placeholder="CORP\\ana.pop" style="max-width:280px"><input class="in" id="who_g" placeholder="Groups, comma separated: CORP\\Finance, CORP\\VPN Users">
        <label class="small row" style="white-space:nowrap"><input type="checkbox" id="who_o" checked> include Everyone-style groups</label><button class="btn primary">Check</button></form><div id="who_out"></div></div>
    <div class="panel"><div class="panel-head"><div class="seg" id="pm_tabs">${tabs.map(([k, l, n]) => `<button data-k="${k}" class="${k === kind ? "on" : ""}">${l}<span class="n">${fmtShort(n)}</span></button>`).join("")}</div>
      <input class="in" id="pm_q" placeholder="Filter by path, account or owner" style="max-width:300px"></div>
      <div id="pm_list" style="margin-top:12px">${permTable(list)}</div></div>`;
  $$("#pm_tabs button", view).forEach((b) => (b.onclick = () => (location.hash = "#/permissions/" + b.dataset.k)));
  let qt;
  $("#pm_q", view).oninput = (e) => { clearTimeout(qt); qt = setTimeout(async () => { $("#pm_list").innerHTML = permTable(await api("/api/perms/folders?" + scopeQS({ kind, q: e.target.value.trim() }))); }, 300); };
  $("#who", view).onsubmit = (e) => { e.preventDefault(); tryApi(async () => {
    const r = await api("/api/perms/who?" + scopeQS({ name: $("#who_n").value.trim(), groups: $("#who_g").value.trim(), open: $("#who_o").checked ? "1" : "0" }));
    $("#who_out").innerHTML = r.rows.length ? `<table class="t" style="margin-top:10px"><thead><tr><th>Folder</th><th>Access</th><th>Through</th><th class="num">Files below</th><th class="num">Size below</th></tr></thead><tbody>
      ${r.rows.map((x) => `<tr><td><span class="small faint">${esc(x.device)} › ${esc(x.share)}</span><div class="path">${esc(x.path)}</div></td>
        <td>${x.denied && !x.rights ? '<span class="pill bad">DENIED</span>' : `<span class="pill ${x.rights === "full" || x.rights === "modify" ? "warn" : "info"}">${esc(x.rights)}</span>${x.denied ? ' <span class="pill bad">also denied</span>' : ""}`}</td>
        <td class="small">${esc(x.via)}</td><td class="num">${fmtNum(x.files)}</td><td class="num">${fmtBytes(x.bytes)}</td></tr>`).join("")}</tbody></table>`
      : `<div class="empty small">No folder with its own permissions names ${esc(r.name)}${$("#who_o").checked ? " and none is open to everybody" : ""}.</div>`;
  }); };
};

function permTable(list) {
  if (!list.length) return `<div class="empty">${icon("lock", 22)}<b>Nothing here</b>No folder in this scope matches.</div>`;
  return `<table class="t"><thead><tr><th>Folder</th><th>Access entries</th><th>Owner</th><th class="num">Files below</th><th class="num">Size below</th></tr></thead><tbody>
    ${list.map((f) => `<tr><td style="max-width:360px"><span class="small faint">${esc(f.device)} › ${esc(f.share)}</span><div class="path">${esc(f.path)}</div>
      <div>${f.open ? '<span class="pill warn">open to everyone</span> ' : ""}${f.protected ? '<span class="pill info">inheritance off</span> ' : ""}${f.orphan ? '<span class="pill warn">deleted account</span> ' : ""}${(f.disabled || []).map((u) => `<span class="pill warn">disabled: ${esc(u)}</span>`).join(" ")}</div></td>
      <td>${[...f.aces].sort((x, y) => (y.d - x.d) || RIGHTS_ORDER.indexOf(x.r) - RIGHTS_ORDER.indexOf(y.r)).map(aceChip).join(" ")}</td>
      <td class="small">${esc(f.owner)}</td><td class="num">${fmtNum(f.files)}</td><td class="num">${fmtBytes(f.bytes)}</td></tr>`).join("")}</tbody></table>`;
}

// ---------- Migration ----------
const MIG_SEV = { blocker: "bad", warning: "warn", info: "info" };
PAGES.migrations = async (view, rest, alive) => {
  if (rest && rest[0]) return migrationDetail(view, +rest[0], alive);
  const list = await api("/api/migrations");
  view.innerHTML = hero({ title: "Migration", iconName: "truck",
    sub: "Plan a move to new storage from the index: how much, how long, and everything that will fail at the target before you copy a byte. Then copy in waves of top-level folders. Every file is verified after copying, the source is never changed, and nothing at the target is overwritten unless you say so.",
    actions: canEdit() ? `<button class="btn primary" data-act="mig-new">${icon("plus", 14)} New migration</button>` : "" }) +
    `<div class="panel"><h2>${icon("truck", 16)} Migrations</h2>
    ${list.length ? `<table class="t"><thead><tr><th>Name</th><th>From</th><th>To</th><th class="num">Files</th><th class="num">Size</th><th>Checks</th><th>Progress</th></tr></thead><tbody>
      ${list.map((m) => { const p = m.plan || {}; const done = m.waves.filter((w) => w.status.startsWith("done") && !w.dry).length;
        return `<tr style="cursor:pointer" onclick="location.hash='#/migrations/${m.id}'"><td><b>${esc(m.name)}</b><div class="small faint">${fmtDay(m.created)}</div></td><td class="small">${esc(m.source)}</td><td class="small">${esc(m.target)}</td>
        <td class="num">${fmtNum(p.files)}</td><td class="num">${fmtBytes(p.bytes)}</td>
        <td>${p.blockers ? `<span class="pill bad">${p.blockers} blocking</span>` : '<span class="pill ok">ready</span>'}</td>
        <td class="small">${done} of ${m.waves.length} waves copied</td></tr>`; }).join("")}</tbody></table>`
      : `<div class="empty">${icon("truck", 22)}<b>No migrations yet</b>Pick an indexed share and a target folder, PowerScale path or S3 bucket. The plan is ready in seconds.</div>`}</div>`;
};

async function migrationForm() {
  if (!S.devs) S.devs = await api("/api/devices");
  const shares = S.tree.flatMap((d) => d.shares.filter((s) => s.published).map((s) => ({ id: s.id, label: `${d.name} › ${s.name}` })));
  if (!shares.length) return toast("Index a share first: the plan comes from the index.", true);
  modal(`<h3>New migration</h3>
    <div class="field"><label>Name</label><input class="in" id="mg_name" placeholder="FS01 to new file server"></div>
    <div class="field"><label>Copy this share</label><select class="in" id="mg_src">${shares.map((s) => `<option value="${s.id}">${esc(s.label)}</option>`).join("")}</select></div>
    <div class="grid2" style="gap:12px"><div class="field"><label>To this device</label><select class="in" id="mg_dev">${S.devs.map((d) => `<option value="${d.id}" data-kind="${d.kind}">${esc(d.name)} (${esc(d.kind)})</option>`).join("")}</select></div>
      <div class="field"><label>Target folder</label><input class="in" id="mg_root" placeholder="E:\\Migrated\\FS01"><span class="hint" id="mg_hint"></span></div></div>
    <div class="grid2" style="gap:12px">
      <div class="field"><label>When a different file is already at the target</label><select class="in" id="mg_conf"><option value="skip">Leave it and report it (safest)</option><option value="newer">Replace it if the source is newer</option><option value="overwrite">Always replace it</option></select></div>
      <div class="field"><label>Verify every copied file by</label><select class="in" id="mg_ver"><option value="checksum">Reading it back and comparing checksums</option><option value="size">Comparing sizes (faster)</option></select></div>
      <div class="field"><label>Wave size (GB)</label><input class="in" type="number" id="mg_wave" value="500"></div>
      <div class="field"><label>Expected speed for the estimate (MB/s)</label><input class="in" type="number" id="mg_mbps" value="100"></div></div>
    <div class="row end"><button class="btn" id="mg_x">Cancel</button><button class="btn primary" id="mg_ok">Build plan</button></div>`, (m) => {
    const hint = () => { const k = $("#mg_dev", m).selectedOptions[0]?.dataset.kind; $("#mg_hint", m).textContent = k === "s3" ? "bucket or bucket/prefix" : k === "powerscale" ? "a path under /ifs" : "a local folder, a Linux path or \\\\server\\share\\folder"; $("#mg_root", m).placeholder = k === "s3" ? "archive/fs01" : k === "powerscale" ? "/ifs/data/fs01" : "E:\\Migrated\\FS01"; };
    $("#mg_dev", m).onchange = hint; hint();
    $("#mg_x", m).onclick = () => m.close();
    $("#mg_ok", m).onclick = () => tryApi(async () => {
      $("#mg_ok", m).disabled = true; $("#mg_ok", m).textContent = "Building the plan…";
      try {
        const r = await api("/api/migrations", { method: "POST", body: { name: $("#mg_name", m).value.trim(), source_share: +$("#mg_src", m).value, target_device: +$("#mg_dev", m).value, target_root: $("#mg_root", m).value.trim(),
          options: { conflict: $("#mg_conf", m).value, verify: $("#mg_ver", m).value, wave_gb: +$("#mg_wave", m).value, mbps: +$("#mg_mbps", m).value } } });
        if (r.plan_error) toast(r.plan_error, true);
        m.close(); location.hash = "#/migrations/" + r.id;
      } finally { $("#mg_ok", m) && ($("#mg_ok", m).disabled = false, $("#mg_ok", m).textContent = "Build plan"); }
    });
  });
}

async function migrationDetail(view, id, alive) {
  const draw = async () => {
    const m = await api("/api/migrations/" + id);
    const p = m.plan;
    const running = m.waves.some((w) => w.status === "running" || w.status === "cancelling");
    const copiedBytes = m.waves.filter((w) => !w.dry).reduce((s, w) => s + w.bytes_done, 0);
    view.innerHTML = hero({ title: m.name, iconName: "truck", eyebrow: "MIGRATION",
      sub: `${esc(m.source)} → ${esc(m.target)}. Conflicts: ${{ skip: "left alone and reported", newer: "replaced when the source is newer", overwrite: "always replaced" }[m.options.conflict]}. Verification: ${m.options.verify === "checksum" ? "checksum of every file read back from the target" : "file size"}.`,
      actions: `<a class="btn" href="#/migrations">${icon("back", 13)} All migrations</a>${canEdit() ? ` <button class="btn" data-act="mig-plan" data-id="${id}">${icon("refresh", 14)} Rebuild plan</button> <button class="btn ghost-danger" data-act="mig-del" data-id="${id}" data-name="${esc(m.name)}">${icon("trash", 14)}</button>` : ""}`,
      kpis: p ? kpi("To copy", fmtBytes(p.bytes), `${fmtNum(p.files)} files`, "files") + kpi("Estimate", fmtDur(p.est_seconds), `at ${m.options.mbps} MB/s, ${m.options.files_per_s} files/s`, "history") +
        kpi("Free at target", p.free >= 0 ? fmtBytes(p.free) : "unknown", esc(p.free_note || ""), "db") + kpi("Copied so far", fmtBytes(copiedBytes), p.bytes ? Math.round((copiedBytes / p.bytes) * 100) + "% of the share" : "", "check") +
        kpi("Runs on", esc(p.runner || "nowhere"), p.blockers ? `<span style="color:var(--bad)">${p.blockers} blocking problem${p.blockers > 1 ? "s" : ""}</span>` : "no blocking problems", "server") : "" }) +
      (p ? "" : `<div class="note">No plan yet. Use Rebuild plan.</div>`) +
      (p && p.checks.length ? `<div class="panel"><h2>${icon("alert", 16)} Before you copy</h2><div class="sub">Found in the index (from ${fmtDate(p.scan_at)}), checked against what the target accepts. Blocking problems stop real runs until they are fixed at the source and the plan is rebuilt; a dry run still works.</div>
        ${p.checks.map((c) => `<div class="insight ${c.severity === "blocker" ? "crit" : c.severity === "warning" ? "warn" : ""}" style="margin-bottom:10px"><div class="row" style="justify-content:space-between"><b>${esc(c.title)}</b><span class="pill ${MIG_SEV[c.severity]}">${c.severity.toUpperCase()}</span></div>
          <div class="small muted" style="margin:4px 0">${esc(c.detail)}</div>
          ${c.sample.length ? `<details class="small"><summary class="faint" style="cursor:pointer">${c.files > c.sample.length ? `first ${c.sample.length} of ${fmtNum(c.files)}` : "show"}</summary>${c.sample.map((x) => `<div class="path">${esc(x)}</div>`).join("")}</details>` : ""}</div>`).join("")}</div>`
        : p ? `<div class="note info">${icon("check", 13)} No problems found: every name fits the target and there is room for the data.</div>` : "") +
      `<div class="panel"><h2>${icon("flow", 16)} Waves</h2><div class="sub">Top-level folders in name order, packed up to ${m.options.wave_gb} GB per wave. Run a wave again at any time: files already at the target are skipped, so a re-run only copies what changed or failed. Dry runs check the target without writing.</div>
        <table class="t"><thead><tr><th>#</th><th>Folders</th><th class="num">Files</th><th class="num">Size</th><th style="width:30%">Progress</th><th></th></tr></thead><tbody>
        ${m.waves.map((w) => { const pct = w.files ? Math.round((w.done / w.files) * 100) : 0; const live = w.status === "running" || w.status === "cancelling";
          return `<tr><td class="faint">${w.idx}</td><td><b>${esc(w.label)}</b></td><td class="num">${fmtNum(w.files)}</td><td class="num">${fmtBytes(w.bytes)}</td>
          <td>${w.status === "pending" ? '<span class="pill mute">NOT STARTED</span>' : `<div class="row" style="justify-content:space-between;flex-wrap:nowrap"><span class="pill ${live ? "info" : w.status === "done" ? "ok" : w.status === "cancelled" ? "mute" : "warn"}">${w.dry ? "DRY RUN " : ""}${esc(w.status.toUpperCase())}</span><span class="small faint">${pct}%</span></div>
            <div class="bigbar" style="margin:6px 0"><div style="width:${pct}%"></div></div>
            <div class="small muted">${fmtNum(w.copied)} ${w.dry ? "to copy" : "copied"} · ${fmtNum(w.skipped)} already there · ${w.conflicts ? `<b style="color:var(--warn)">${fmtNum(w.conflicts)} conflicts</b> · ` : ""}${w.failed ? `<b style="color:var(--bad)">${fmtNum(w.failed)} failed</b> · ` : ""}${fmtBytes(w.bytes_done)}</div>
            ${w.message ? `<div class="small faint">${esc(w.message)}</div>` : ""}`}</td>
          <td class="num" style="white-space:nowrap">${!canEdit() ? "" : live ? `<button class="btn sm ghost-danger" data-act="mig-wave" data-x="cancel" data-id="${id}" data-w="${w.id}">${icon("stop", 12)} Stop</button>`
            : `<button class="btn sm" data-act="mig-wave" data-x="dry-run" data-id="${id}" data-w="${w.id}" ${running ? "disabled" : ""}>Dry run</button> <button class="btn sm primary" data-act="mig-wave" data-x="run" data-id="${id}" data-w="${w.id}" ${running || (p && p.blockers) ? "disabled" : ""}>${w.status === "pending" || w.dry ? "Copy" : "Copy again"}</button>`}
            ${w.status !== "pending" ? ` <button class="btn sm" data-act="mig-ledger" data-id="${id}" data-w="${w.id}">Files</button>` : ""}</td></tr>`; }).join("")}</tbody></table></div>`;
    return running;
  };
  let running = await draw();
  const t = setInterval(async () => {
    if (!alive() || location.hash !== "#/migrations/" + id) return clearInterval(t);
    if (running || document.querySelector("[data-act=mig-wave][data-x=cancel]")) try { running = await draw(); } catch {}
  }, 2000);
}

async function migrationLedger(id, wid) {
  const show = async (m, result) => {
    const rows = await api(`/api/migrations/${id}/waves/${wid}/ledger?result=${result}&limit=500`);
    $("#lg_out", m).innerHTML = rows.length ? `<table class="t"><thead><tr><th>File</th><th>Result</th><th class="num">Size</th><th>Detail</th></tr></thead><tbody>
      ${rows.map((r) => `<tr><td class="path">${esc(r.path)}</td><td><span class="pill ${r.result === "failed" ? "bad" : r.result === "conflict" ? "warn" : "ok"}">${esc(r.result)}</span></td><td class="num">${fmtBytes(r.bytes)}</td><td class="small muted">${esc(r.detail)}</td></tr>`).join("")}</tbody></table>`
      : `<div class="empty small">None.</div>`;
  };
  modal(`<h3>Files in this wave</h3><div class="row" style="justify-content:space-between"><div class="seg" id="lg_tabs">${[["failed", "Failed"], ["conflict", "Conflicts"], ["copied", "Copied"], ["would-copy", "Dry run"]].map(([k, l], i) => `<button data-k="${k}" class="${i ? "" : "on"}">${l}</button>`).join("")}</div>
    <a class="btn sm" href="/api/migrations/${id}/waves/${wid}/ledger?format=csv&limit=10000000">${icon("download", 12)} CSV</a></div>
    <div id="lg_out" style="max-height:60vh;overflow:auto;margin-top:10px"></div><div class="row end"><button class="btn" id="lg_x">Close</button></div>`, (m) => {
    m.style.maxWidth = "1000px";
    $("#lg_x", m).onclick = () => m.close();
    $$("#lg_tabs button", m).forEach((b) => (b.onclick = () => { $$("#lg_tabs button", m).forEach((x) => x.classList.toggle("on", x === b)); tryApi(() => show(m, b.dataset.k)); }));
    tryApi(() => show(m, "failed"));
  });
}

// ---------- actions ----------
document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-act]");
  if (!b) return;
  const id = +b.dataset.id, act = b.dataset.act;
  const acts = {
    "tw-ack": async () => { await api(`/api/tripwire/alerts/${id}/ack`, { method: "POST" }); route(); },
    "tw-resolve": async () => { await api(`/api/tripwire/alerts/${id}/resolve`, { method: "POST" }); route(); },
    "tw-block": async () => {
      if (await confirmTyped("Block account", `Deny <b>${esc(b.dataset.name)}</b> on every share of this file server and close its open files. Unblock from the alert.`, "block") === null) return;
      const r = await api(`/api/tripwire/alerts/${id}/block`, { method: "POST" }); toast(`Blocked on ${r.shares.length} share${r.shares.length === 1 ? "" : "s"}`); route();
    },
    "tw-unblock": async () => { if (!confirm(`Give ${b.dataset.name} access again?`)) return; const r = await api(`/api/tripwire/alerts/${id}/unblock`, { method: "POST" }); toast(`Unblocked on ${r.shares.length} share${r.shares.length === 1 ? "" : "s"}`); route(); },
    "tw-decoys-on": async () => {
      if (b.dataset.audited !== "1" && !confirm("Auditing is off for this share, so a touched decoy would go unnoticed. Plant the decoys anyway and turn auditing on afterwards?")) return;
      if (!confirm(`Write up to 22 small hidden decoy files into ${b.dataset.name}? They are excluded from reports and can be removed at any time.`)) return;
      const r = await api(`/api/tripwire/decoys/${id}`, { method: "POST" });
      const ok = r.results.filter((x) => x.result === "planted").length;
      toast(`${ok} decoys planted${ok < r.results.length ? `, ${r.results.length - ok} failed: ` + r.results.find((x) => x.result !== "planted").result : ""}`, ok < r.results.length); route();
    },
    "tw-decoys-off": async () => {
      if (!confirm(`Remove the decoy files from ${b.dataset.name}? Decoys that changed since they were planted are left in place as evidence.`)) return;
      const r = await api(`/api/tripwire/decoys/${id}`, { method: "DELETE" });
      const kept = r.results.filter((x) => x.result.startsWith("left")).length;
      toast(`${r.results.filter((x) => x.result === "removed" || x.result === "already gone").length} removed${kept ? `, ${kept} changed and kept as evidence` : ""}`); route();
    },
    "mig-new": () => migrationForm(),
    "mig-plan": async () => { toast("Rebuilding the plan…"); await api(`/api/migrations/${id}/plan`, { method: "POST", body: {} }); route(); },
    "mig-del": async () => { if (await confirmTyped("Delete migration", "Removes the plan and the copy log. Files already copied stay where they are.", b.dataset.name) === null) return; await api("/api/migrations/" + id, { method: "DELETE" }); location.hash = "#/migrations"; },
    "mig-wave": async () => {
      const x = b.dataset.x;
      if (x === "run" && !confirm("Copy this wave to the target now?")) return;
      await api(`/api/migrations/${id}/waves/${b.dataset.w}/${x}`, { method: "POST" });
      toast(x === "cancel" ? "Stopping after the current batch" : x === "dry-run" ? "Dry run started" : "Copy started"); route();
    },
    "mig-ledger": () => migrationLedger(id, +b.dataset.w),
  };
  if (acts[act]) { e.preventDefault(); e.stopImmediatePropagation(); await tryApi(acts[act]); }
}, true);
