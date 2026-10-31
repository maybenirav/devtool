// ReleaseGuard frontend: plain JavaScript, no build step.
"use strict";

const DEMO_REPO = "https://github.com/maybenirav/releaseguard-demo";
const app = document.getElementById("app");
let state = null;

// ---------- helpers ----------
const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = (sha) => (sha || "").slice(0, 7);
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* not JSON */ }
  if (!res.ok) throw new Error((data && data.detail) || `Request failed (${res.status})`);
  return data;
}

function ago(iso) {
  if (!iso) return "never";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 45) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${plural(m, "minute")} ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${plural(h, "hour")} ago`;
  return `${plural(Math.round(h / 24), "day")} ago`;
}

function fmtDate(iso) {
  return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

function toast(message) {
  const el = document.createElement("div");
  el.className = "toast";
  el.setAttribute("role", "status");
  el.textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

function copyText(text) {
  navigator.clipboard?.writeText(text).then(() => toast("Copied"), () => toast("Copy failed"));
}

// ---------- routing ----------
function route() {
  const m = location.pathname.match(/^\/repo\/([^/]+)\/([^/]+)\/?$/);
  if (m) renderRepo(decodeURIComponent(m[1]), decodeURIComponent(m[2]));
  else renderHome();
}

// ---------- home ----------
async function renderHome() {
  document.title = "ReleaseGuard: is this release safe to ship?";
  app.innerHTML = `
    <section class="hero">
      <h1>Is this release safe to ship?</h1>
      <p>Paste a public GitHub repo. ReleaseGuard checks each recent commit for leaked secrets,
      vulnerable libraries and risky settings, then shows which commit made the release unsafe.</p>
    </section>
    <form class="scan-form" id="scanForm" novalidate>
      <label for="repoInput" class="sr">GitHub repo link</label>
      <input id="repoInput" name="repo" placeholder="https://github.com/owner/repo"
             autocomplete="off" spellcheck="false" required>
      <button class="btn primary" type="submit">Scan repo</button>
    </form>
    <p class="form-hint">No login needed. Try the demo repo:
      <button class="linkish" type="button" id="fillDemo">${esc(DEMO_REPO.replace("https://github.com/", ""))}</button></p>
    <p class="form-error" id="formError" role="alert" hidden></p>

    <div class="checks">
      <div><h3>Leaked secrets</h3><p>AWS, GitHub, Stripe, Google, OpenAI and more, including keys deleted in a later commit.</p></div>
      <div><h3>Vulnerable libraries</h3><p>requirements.txt and package.json versions checked against OSV.dev, with the version that fixes them.</p></div>
      <div><h3>Risky settings</h3><p>Debug mode, disabled certificate checks, open CORS and wildcard hosts.</p></div>
    </div>

    <section class="section">
      <header><h2>Recently scanned</h2></header>
      <div class="panel"><ul class="recent" id="recent"><li class="empty">Loading…</li></ul></div>
    </section>`;

  $("#fillDemo").addEventListener("click", () => { $("#repoInput").value = DEMO_REPO; $("#repoInput").focus(); });
  $("#scanForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = $("#repoInput"), btn = e.submitter || $("#scanForm button"), err = $("#formError");
    err.hidden = true;
    if (!input.value.trim()) { err.textContent = "Paste a GitHub repo link first."; err.hidden = false; return; }
    btn.disabled = true; btn.textContent = "Starting scan…";
    try {
      const res = await api("/api/scan", { method: "POST", body: { repo: input.value } });
      location.assign(`/repo/${res.repoId}?scan=${encodeURIComponent(res.scanId)}`);
    } catch (ex) {
      err.textContent = ex.message; err.hidden = false;
      btn.disabled = false; btn.textContent = "Scan repo";
    }
  });

  try {
    const repos = await api("/api/repos");
    $("#recent").innerHTML = repos.length ? repos.map((r) => `
      <li>
        <span class="chip v-${esc(r.lastVerdict || "none")}">${esc(r.lastVerdict || "NOT SCANNED")}</span>
        <a href="/repo/${esc(r._id)}">${esc(r.fullName || r._id)}</a>
        <span class="when">${esc(ago(r.lastScanAt))}</span>
      </li>`).join("")
      : `<li class="empty">Nothing scanned yet. Paste a repo link above to run the first scan.</li>`;
  } catch (ex) {
    $("#recent").innerHTML = `<li class="empty">Could not load recent scans: ${esc(ex.message)}</li>`;
  }
}

// ---------- repo page ----------
async function renderRepo(owner, name) {
  const repoId = `${owner}/${name}`.toLowerCase();
  const params = new URLSearchParams(location.search);
  let scanId = params.get("scan");
  document.title = `${owner}/${name}: ReleaseGuard`;
  app.innerHTML = `<p class="loading">Loading report…</p>`;

  state = { owner, name, repoId, report: null, filter: "open", explained: {} };
  let report = null;
  try {
    report = await api(`/api/repos/${owner}/${name}/report`);
  } catch (ex) {
    if (!scanId) { renderNotScanned(owner, name); return; }
  }
  // the repo is known but its first scan has not finished yet: no verdict to show
  if (report && !report.repo.lastScanAt) {
    scanId = scanId || report.runningScanId;
    report = null;
    if (!scanId) { renderNotScanned(owner, name); return; }
  }
  state.report = report;

  if (state.report) {
    const known = state.report.scans.find((s) => s.scanId === scanId);
    if (known && known.status !== "running") scanId = null;
    scanId = scanId || state.report.runningScanId;
  }
  if (!scanId) history.replaceState(null, "", location.pathname);

  draw({ live: Boolean(scanId) });
  if (scanId) startLive(scanId);
}

function renderNotScanned(owner, name) {
  app.innerHTML = `
    <div class="panel not-scanned">
      <h2>${esc(owner)}/${esc(name)} has not been scanned yet</h2>
      <p>Run the first scan to see its release verdict and risk history.</p>
      <button class="btn primary" id="firstScan">Scan this repo</button>
      <p class="form-error" id="formError" role="alert" hidden></p>
    </div>`;
  $("#firstScan").addEventListener("click", async (e) => {
    e.target.disabled = true;
    try {
      const res = await api("/api/scan", { method: "POST", body: { repo: `${owner}/${name}` } });
      location.assign(`/repo/${res.repoId}?scan=${encodeURIComponent(res.scanId)}`);
    } catch (ex) {
      $("#formError").textContent = ex.message; $("#formError").hidden = false; e.target.disabled = false;
    }
  });
}

function draw({ live = false, landStamp = false } = {}) {
  const r = state.report;
  app.innerHTML = `
    ${slipHTML(r, live, landStamp)}
    <div id="live"></div>
    ${r ? `
    <div class="grid2">
      <section class="section" aria-labelledby="risksTitle">
        <header><h2 id="risksTitle">What needs fixing</h2>${tabsHTML(r)}</header>
        <ul class="risks" id="riskList">${risksHTML(r)}</ul>
      </section>
      <section class="section" aria-labelledby="historyTitle">
        <header><h2 id="historyTitle">History</h2><p>Risk level after each commit, newest first.</p></header>
        <div class="panel">${railHTML(r)}</div>
      </section>
    </div>
    ${compareHTML(r)}
    ${automateHTML(r)}
    ${hoodHTML(r)}` : ""}`;
  if (r) wire();
}

// ----- the release slip -----
function slipHTML(r, live, landStamp) {
  if (!r) {
    return `<div class="panel slip">
      <div><div class="repo-name">${esc(state.owner)}/${esc(state.name)}</div>
      <p class="meta">First scan in progress. Findings appear below as they are found.</p></div>
      <div class="stamp pending" aria-label="Verdict pending">WAIT<small>scanning</small></div></div>`;
  }
  const repo = r.repo, v = r.verdict, c = v.counts;
  const latest = r.timeline.length ? r.timeline[r.timeline.length - 1] : null;
  const summary = [
    c.block && `${c.block} must be fixed before release`,
    c.risky && `${c.risky} to review`,
    c.fixed && `${c.fixed} already fixed`,
    c.dismissed && `${c.dismissed} dismissed`,
  ].filter(Boolean).join(", ");
  return `<div class="panel slip">
    <div>
      <div class="repo-name"><a href="${esc(repo.url)}" target="_blank" rel="noopener">${esc(repo.fullName || repo._id)}</a></div>
      <p class="meta">Scanned ${esc(ago(repo.lastScanAt))}${latest
        ? `. Latest commit <code>${esc(short(latest.sha))}</code> “${esc(latest.message)}”` : ""}.</p>
      <div class="actions">
        <button class="btn primary" id="rescan" ${live ? "disabled" : ""}>${live ? "Scanning…" : "Scan again"}</button>
        <a class="btn" href="#automate">Auto-scan on every push</a>
      </div>
    </div>
    <div class="stamp ${esc(v.verdict)} ${landStamp ? "land" : ""}" role="status" aria-label="Release verdict ${esc(v.verdict)}">
      ${esc(v.verdict)}<small>release verdict</small></div>
    <div class="reasons">
      ${v.verdict === "SAFE"
        ? `<p class="all-clear">No open risks in the scanned commits.${summary ? ` (${esc(summary)})` : ""}</p>`
        : `<h3>Why: ${esc(summary)}</h3><ul>${v.reasons.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`}
    </div>
  </div>`;
}

// ----- risks -----
function bucket(risk) {
  if (risk.dismissed) return "dismissed";
  return risk.status === "fixed" ? "fixed" : "open";
}

function tabsHTML(r) {
  const n = { open: 0, fixed: 0, dismissed: 0 };
  r.risks.forEach((x) => n[bucket(x)]++);
  const tab = (key, label) =>
    `<button class="tab" data-filter="${key}" aria-pressed="${state.filter === key}">${label} (${key === "all" ? r.risks.length : n[key]})</button>`;
  return `<div class="tabs" role="group" aria-label="Filter risks">${tab("open", "Open")}${tab("fixed", "Fixed")}${tab("dismissed", "Dismissed")}${tab("all", "All")}</div>`;
}

function risksHTML(r) {
  const list = r.risks.filter((x) => state.filter === "all" || bucket(x) === state.filter);
  if (!list.length) {
    const msg = { open: "No open risks. Nice.", fixed: "Nothing has been fixed yet.",
      dismissed: "No dismissed findings.", all: "No findings in the scanned commits." }[state.filter];
    return `<li class="panel empty">${msg}</li>`;
  }
  return list.map((x) => riskHTML(x, r.repo)).join("");
}

function riskHTML(x, repo) {
  const d = x.details || {}, intro = x.introduced || {}, fx = x.fixedEvent;
  const commitLink = (sha) => `<a href="${esc(repo.url)}/commit/${esc(sha)}" target="_blank" rel="noopener"><code>${esc(short(sha))}</code></a>`;
  const span = `${plural(x.exposureDays, "day")} across ${plural(x.liveForCommits, "commit")}`;
  let story = `Introduced in ${commitLink(intro.sha)} by ${esc(intro.author)} on ${esc(fmtDate(intro.at))}. `;
  if (x.status === "in_history") {
    story += `Deleted in ${commitLink(fx.sha)}, <span class="warn">but still readable in git history. Rotate this secret.</span>`;
  } else if (x.status === "fixed") {
    story += `Fixed in ${commitLink(fx.sha)} after ${span}.`;
  } else {
    story += `Still present, exposed for ${span}.`;
  }
  const facts = [];
  if (d.masked) facts.push(`Value <strong class="mono">${esc(d.masked)}</strong>`);
  if (d.fixedVersion) facts.push(`Upgrade to <strong class="mono">${esc(d.fixedVersion)}</strong>`);
  if (d.vulnIds && d.vulnIds.length) {
    facts.push(d.vulnIds.slice(0, 3).map((id) =>
      `<a href="https://osv.dev/vulnerability/${esc(id)}" target="_blank" rel="noopener">${esc(id)}</a>`).join(", ")
      + (d.vulnCount > 3 ? ` and ${d.vulnCount - 3} more` : ""));
  }
  if (d.snippet) facts.push(`<code>${esc(d.snippet)}</code>`);
  if (x.dismissed) facts.push(`Dismissed: ${esc(x.dismissReason || "false positive")}`);
  const explained = state.explained[x._id];
  return `<li class="panel risk s-${esc(x.severity)}" data-fp="${esc(x._id)}">
    <div class="top">
      <span class="sev sev-${esc(x.severity)}">${esc(x.severity)}</span>
      <span class="title">${esc(x.title)}</span>
      <span class="where">${esc(x.file)}${intro.line ? `:${esc(intro.line)}` : ""}</span>
    </div>
    <p class="story">${story}</p>
    ${facts.length ? `<div class="facts">${facts.map((f) => `<span>${f}</span>`).join("")}</div>` : ""}
    <div class="tools">
      <button class="btn small" data-act="explain">${explained ? "Hide explanation" : "Explain"}</button>
      <button class="btn small" data-act="${x.dismissed ? "undismiss" : "dismiss"}">${x.dismissed ? "Restore" : "Mark as false positive"}</button>
    </div>
    ${explained ? `<div class="explain">${esc(explained.text)}<span class="src">${explained.source === "ai" ? "Explained by Claude" : "Built-in explanation"}</span></div>` : ""}
  </li>`;
}

// ----- history rail -----
function railHTML(r) {
  if (!r.timeline.length) return `<p class="empty">No commits scanned yet.</p>`;
  const max = Math.max(1, ...r.timeline.map((c) => c.openRisk));
  return `<ol class="rail" reversed>${[...r.timeline].reverse().map((c) => {
    const dir = c.delta > 0 ? "up" : (c.delta < 0 ? "down" : "");
    const change = [c.added && `+${c.added} risk${c.added > 1 ? "s" : ""}`,
      c.removed && `−${c.removed} removed`].filter(Boolean).join(", ");
    const pct = Math.round((c.openRisk / max) * 100);
    return `<li>
      <span class="dot ${dir}" aria-hidden="true"></span>
      <div>
        <div class="msg">${esc(c.message || "(no message)")}</div>
        <div class="sub"><a href="${esc(c.url || "#")}" target="_blank" rel="noopener"><code>${esc(short(c.sha))}</code></a>
          by ${esc(c.author)}, ${esc(fmtDate(c.committedAt))}${change ? `. ${esc(change)}` : ""}${c.partial ? ". Diff partly scanned (too large)" : ""}</div>
      </div>
      <div class="meter"><span>Risk level ${esc(c.openRisk)}</span>
        <div class="bar"><span class="${pct > 60 ? "hot" : ""}" style="width:${pct}%"></span></div></div>
    </li>`;
  }).join("")}</ol>`;
}

// ----- compare -----
function compareHTML(r) {
  if (r.timeline.length < 2) return "";
  const opts = (selected) => [...r.timeline].reverse().map((c) =>
    `<option value="${esc(c.sha)}" ${c.sha === selected ? "selected" : ""}>${esc(short(c.sha))}: ${esc((c.message || "").slice(0, 50))}</option>`).join("");
  const oldest = r.timeline[0].sha, newest = r.timeline[r.timeline.length - 1].sha;
  return `<section class="section" aria-labelledby="cmpTitle">
    <header><h2 id="cmpTitle">Compare two releases</h2><p>Pick two commits to see which risks appeared and which were fixed in between.</p></header>
    <div class="panel compare">
      <form id="cmpForm">
        <label>Older release<select name="a">${opts(oldest)}</select></label>
        <label>Newer release<select name="b">${opts(newest)}</select></label>
        <button class="btn primary" type="submit">Compare</button>
      </form>
      <div class="compare-result" id="cmpResult" aria-live="polite"></div>
    </div>
  </section>`;
}

function compareResultHTML(res) {
  if (res.identical) return `<p>Same commit selected, so nothing changed.</p>`;
  const label = { worse: "Riskier", better: "Safer", same: "Same risk level" }[res.trend];
  const list = (items) => items.length ? `<ul>${items.map((x) => `<li>${esc(x.title)}</li>`).join("")}</ul>` : `<p class="empty" style="padding:4px 0">None</p>`;
  return `<p class="trend ${esc(res.trend)}">${label}: risk score ${esc(res.scoreA)} → ${esc(res.scoreB)}</p>
    <div class="grid2" style="gap:18px;margin-top:10px">
      <div><h3>New in <code>${esc(short(res.b))}</code> (${res.new.length})</h3>${list(res.new)}</div>
      <div><h3>Fixed since <code>${esc(short(res.a))}</code> (${res.fixed.length})</h3>${list(res.fixed)}</div>
    </div>`;
}

// ----- automate -----
function automateHTML(r) {
  const L = r.links;
  const md = `[![ReleaseGuard](${L.badge})](${L.report})`;
  const alertsList = r.alerts.length ? `<ul class="steps">${r.alerts.map((a) =>
    `<li>${esc(a.verdict)} alert ${esc(a.status)}${a.test ? " (test)" : ""}, ${esc(ago(a.createdAt))}${a.error ? `: ${esc(a.error)}` : ""}</li>`).join("")}</ul>` : "";
  return `<section class="section" id="automate" aria-labelledby="autoTitle">
    <header><h2 id="autoTitle">Automate it</h2><p>Scan on every push, alert your team when a release turns BLOCK, and show the verdict in your README.</p></header>
    <div class="cards3">
      <div class="panel">
        <h3>Scan on every push</h3>
        <p>Add a GitHub webhook to this repo:</p>
        <ol class="steps">
          <li>Repo Settings, then Webhooks, then Add webhook.</li>
          <li>Payload URL: the link below. Content type: application/json.</li>
          <li>Secret: the WEBHOOK_SECRET value set on the ReleaseGuard server.</li>
          <li>Events: just the push event.</li>
        </ol>
        <div class="copy"><input readonly value="${esc(L.webhook)}" aria-label="Webhook URL"><button class="btn small" data-copy="${esc(L.webhook)}">Copy</button></div>
        <p class="status-line">${r.webhookConfigured ? `<span class="ok">Server is ready for webhooks.</span>` : `<span class="bad">WEBHOOK_SECRET is not set on the server yet.</span>`}</p>
      </div>
      <div class="panel">
        <h3>Alert when it turns BLOCK</h3>
        <p>ReleaseGuard posts to an n8n workflow, which forwards the alert to Discord, Slack or email. Alerts fire only when the verdict changes, so there is no spam.</p>
        <p class="status-line">${r.alertsConfigured ? `<span class="ok">n8n is connected.</span>` : `<span class="bad">N8N_WEBHOOK_URL is not set yet.</span>`}</p>
        <div class="copy"><button class="btn small" id="testAlert">Send test alert</button></div>
        <div id="alertResult" aria-live="polite">${alertsList}</div>
      </div>
      <div class="panel">
        <h3>README badge</h3>
        <p>Shows the latest verdict and updates after every scan.</p>
        <p style="margin-top:10px"><img src="${esc(L.badge)}?t=${Date.now()}" alt="ReleaseGuard badge, current verdict ${esc(r.verdict.verdict)}" height="20"></p>
        <div class="copy"><input readonly value="${esc(md)}" aria-label="Badge markdown"><button class="btn small" data-copy="${esc(md)}">Copy</button></div>
      </div>
    </div>
  </section>`;
}

// ----- under the hood -----
function hoodHTML(r) {
  const scans = r.scans.map((s) => `<tr>
    <td>${esc(ago(s.startedAt))}</td><td>${esc(s.trigger)}</td>
    <td>${s.status === "failed" ? `<span class="bad">failed</span>${s.error ? `: ${esc(s.error)}` : ""}` : esc(s.status)}</td>
    <td>${esc(s.commitsScanned ?? 0)} scanned, ${esc(s.commitsSkipped ?? 0)} skipped</td>
    <td>${esc(s.findingsAdded ?? 0)}</td>
    <td>${s.verdict ? `<span class="chip v-${esc(s.verdict)}">${esc(s.verdict)}</span>` : ""}</td></tr>`).join("");
  return `<section class="section" aria-labelledby="hoodTitle">
    <header><h2 id="hoodTitle">Under the hood: MongoDB</h2>
      <p>Every scan, commit and finding is stored in MongoDB Atlas. These buttons run real writes against the database so you can watch its rules work.</p></header>
    <div class="proofs">
      <div class="panel proof"><h3>Save the same finding twice</h3>
        <p>Every finding has a stable ID built from repo, commit, risk and line. A unique index refuses a second copy, so re-scans never double-count.</p>
        <button class="btn" data-demo="duplicate">Try saving a duplicate</button><pre hidden></pre></div>
      <div class="panel proof"><h3>Save a broken finding</h3>
        <p>Schema validation requires a commit, severity and type on every finding, while the details field stays flexible.</p>
        <button class="btn" data-demo="invalid">Try saving a broken finding</button><pre hidden></pre></div>
      <div class="panel proof"><h3>Receive the same webhook twice</h3>
        <p>GitHub can deliver a push event more than once. The delivery ID is unique, and old deliveries expire after 7 days (TTL index).</p>
        <button class="btn" data-demo="webhook-replay">Replay a delivery</button><pre hidden></pre></div>
    </div>
    <div class="panel" style="margin-top:14px;padding:18px 20px">
      <h3>How the report is computed</h3>
      <p style="color:var(--muted);font-size:.92rem;margin-top:4px;max-width:90ch">Findings are stored as events (added or removed in a commit). An aggregation pipeline groups them by fingerprint to find the introducing and fixing commit, uses <code>$lookup</code> on commits and dismissals for exposure and false positives, and <code>$setWindowFields</code> builds the running risk level shown in History. Live updates come from a change stream.</p>
      <div id="hoodData"><p class="empty">Loading collections and indexes…</p></div>
    </div>
    <h3 style="margin:22px 0 0">Scan history</h3>
    <div class="panel table-wrap" style="padding:6px 8px">
      <table><caption class="sr">Scan history</caption>
        <thead><tr><th>Started</th><th>Trigger</th><th>Status</th><th>Commits</th><th>New findings</th><th>Verdict</th></tr></thead>
        <tbody>${scans}</tbody></table>
    </div>
  </section>`;
}

async function loadHood() {
  const box = $("#hoodData");
  if (!box) return;
  try {
    const data = await api(`/api/under-the-hood?repo=${encodeURIComponent(state.repoId)}`);
    const rows = data.collections.map((c) => `<tr>
      <td><code>${esc(c.name)}</code></td><td>${esc(c.documents)}</td>
      <td>${c.requiredFields.map((f) => `<code>${esc(f)}</code>`).join(", ")}</td>
      <td>${c.indexes.map((i) => `<span class="idx ${i.unique ? "u" : ""}" title="${esc(i.keys.join(", "))}">${esc(i.name)}${i.unique && i.name !== "_id_" ? " (unique)" : ""}${i.ttlSeconds ? " (TTL)" : ""}</span>`).join("")}</td></tr>`).join("");
    const plans = data.queryPlans.map((p) => `<li>${esc(p.question)}: uses index <code>${esc(p.indexUsed)}</code></li>`).join("");
    box.innerHTML = `<div class="table-wrap"><table>
        <thead><tr><th>Collection</th><th>Documents</th><th>Required fields</th><th>Indexes</th></tr></thead>
        <tbody>${rows}</tbody></table></div>
      ${plans ? `<h3 style="margin-top:16px">Query plans (from explain())</h3><ul class="steps">${plans}</ul>` : ""}`;
  } catch (ex) {
    box.innerHTML = `<p class="empty">Could not load: ${esc(ex.message)}</p>`;
  }
}

// ---------- events ----------
function wire() {
  const base = `/api/repos/${state.owner}/${state.name}`;

  $("#rescan")?.addEventListener("click", async (e) => {
    e.target.disabled = true; e.target.textContent = "Starting…";
    try {
      const res = await api("/api/scan", { method: "POST", body: { repo: state.repoId } });
      e.target.textContent = "Scanning…";
      startLive(res.scanId);
    } catch (ex) {
      toast(ex.message); e.target.disabled = false; e.target.textContent = "Scan again";
    }
  });

  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
    state.filter = t.dataset.filter;
    document.querySelectorAll(".tab").forEach((b) => b.setAttribute("aria-pressed", String(b === t)));
    $("#riskList").innerHTML = risksHTML(state.report);
  }));

  $("#riskList")?.addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-act]");
    if (!btn) return;
    const fp = btn.closest(".risk").dataset.fp;
    const act = btn.dataset.act;
    btn.disabled = true;
    try {
      if (act === "explain") {
        if (state.explained[fp]) delete state.explained[fp];
        else { btn.textContent = "Explaining…"; state.explained[fp] = await api(`${base}/explain`, { method: "POST", body: { fingerprint: fp } }); }
        $("#riskList").innerHTML = risksHTML(state.report);
        return;
      }
      if (act === "dismiss") {
        const reason = prompt("Why is this a false positive?", "Test value, not a real secret");
        if (reason === null) { btn.disabled = false; return; }
        await api(`${base}/dismiss`, { method: "POST", body: { fingerprint: fp, reason } });
        toast("Marked as false positive");
      } else {
        await api(`${base}/undismiss`, { method: "POST", body: { fingerprint: fp } });
        toast("Restored");
      }
      state.report = await api(`${base}/report`);
      draw();
    } catch (ex) { toast(ex.message); btn.disabled = false; }
  });

  $("#cmpForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const out = $("#cmpResult");
    out.innerHTML = `<p class="empty" style="padding:0">Comparing…</p>`;
    try {
      const res = await api(`${base}/compare`, { method: "POST", body: { a: f.get("a"), b: f.get("b") } });
      out.innerHTML = compareResultHTML(res);
    } catch (ex) { out.innerHTML = `<p class="bad">${esc(ex.message)}</p>`; }
  });

  document.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", () => copyText(b.dataset.copy)));

  $("#testAlert")?.addEventListener("click", async (e) => {
    e.target.disabled = true;
    try {
      const a = await api(`${base}/test-alert`, { method: "POST" });
      const msg = a.status === "sent" ? "Test alert sent to n8n." : `Alert ${a.status}: ${a.error || ""}`;
      $("#alertResult").insertAdjacentHTML("afterbegin", `<p class="status-line ${a.status === "sent" ? "ok" : "bad"}">${esc(msg)}</p>`);
    } catch (ex) { toast(ex.message); }
    e.target.disabled = false;
  });

  document.querySelectorAll("[data-demo]").forEach((b) => b.addEventListener("click", async () => {
    const pre = b.nextElementSibling;
    b.disabled = true;
    try {
      const res = await api(`/api/demo/${b.dataset.demo}`, { method: "POST", body: { repo: state.repoId } });
      const blocked = res.blocked ?? res.results?.some((x) => x.result.startsWith("ignored"));
      pre.innerHTML = `<span class="${blocked ? "ok" : "bad"}">${blocked ? "Refused by MongoDB, as intended." : "Unexpected: it was saved."}</span>\n` + esc(JSON.stringify(res, null, 2));
    } catch (ex) { pre.textContent = ex.message; }
    pre.hidden = false; b.disabled = false;
  }));

  loadHood();
}

// ---------- live scan (MongoDB change stream -> Server-Sent Events) ----------
function startLive(scanId) {
  const box = $("#live");
  box.innerHTML = `<div class="panel live" aria-live="polite">
    <div class="row"><h2>Scanning</h2><span class="status" id="liveCount">0 findings so far</span></div>
    <div class="progress"><span id="liveBar"></span></div>
    <p class="status" id="liveStatus">Fetching commits from GitHub…</p>
    <ul class="feed" id="liveFeed"></ul>
  </div>`;
  const seen = new Set();
  let finished = false, poller = null, source = null;

  const onScan = (s) => {
    const total = s.commitsToScan || 0, done = s.commitsScanned || 0;
    const pct = s.status !== "running" ? 100 : (total ? Math.max(4, (done / total) * 100) : 4);
    $("#liveBar").style.width = `${pct}%`;
    let text;
    if (s.status === "failed") text = `Scan failed: ${s.error || "unknown error"}`;
    else if (s.status === "completed") text = "Scan complete.";
    else if (total) text = `Checking commit ${done} of ${total}${s.currentCommit ? ` (${short(s.currentCommit)})` : ""}.`;
    else text = "Fetching commits from GitHub…";
    if (s.commitsSkipped) text += ` ${plural(s.commitsSkipped, "commit")} already scanned, skipped.`;
    $("#liveStatus").textContent = text;
  };

  const onFinding = (f) => {
    if (seen.has(f.findingId)) return;
    seen.add(f.findingId);
    $("#liveFeed").insertAdjacentHTML("afterbegin", `<li class="new">
      <span class="act">${esc(f.action)}</span><span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span>
      <span>${esc(f.title)} <span class="where mono">${esc(f.file)} in ${esc(short(f.commitSha))}</span></span></li>`);
    $("#liveCount").textContent = `${plural(seen.size, "finding")} so far`;
  };

  const finish = async (s) => {
    if (finished) return;
    finished = true;
    source?.close();
    clearInterval(poller);
    onScan(s);
    if (s.status === "failed") {
      $("#liveStatus").insertAdjacentHTML("afterend", `<p style="margin-top:10px"><button class="btn primary" id="retry">Try again</button></p>`);
      $("#retry").addEventListener("click", () => location.assign(location.pathname));
      return;
    }
    history.replaceState(null, "", location.pathname);
    try {
      state.report = await api(`/api/repos/${state.owner}/${state.name}/report`);
      draw({ landStamp: true });
      toast(`Scan complete: ${state.report.verdict.verdict}`);
    } catch (ex) { toast(ex.message); }
  };

  const fallbackToPolling = () => {
    source?.close();
    if (poller || finished) return;
    poller = setInterval(async () => {
      try {
        const [s, fs] = await Promise.all([api(`/api/scans/${scanId}`), api(`/api/scans/${scanId}/findings`)]);
        fs.forEach(onFinding);
        onScan(s);
        if (s.status !== "running") finish(s);
      } catch (_) { /* keep trying */ }
    }, 2500);
  };

  if (!("EventSource" in window)) { fallbackToPolling(); return; }
  source = new EventSource(`/api/scans/${encodeURIComponent(scanId)}/events`);
  source.addEventListener("scan", (e) => onScan(JSON.parse(e.data)));
  source.addEventListener("finding", (e) => onFinding(JSON.parse(e.data)));
  source.addEventListener("done", (e) => finish(JSON.parse(e.data)));
  source.addEventListener("stream-error", fallbackToPolling);
  source.onerror = () => { if (!finished) fallbackToPolling(); };
}

route();
