/* AI Cybersecurity Log Analyzer: frontend (Stage 7).

   Flow:  upload screen -> POST /api/analyze (returns a job id) -> processing screen polls
          GET /api/jobs/{id} for REAL stage progress -> GET /api/jobs/{id}/report ->
          clean screen (no findings) or dashboard (findings) -> threat details side panel.

   Rules this file follows:
   - Every number on screen comes from the report the backend returned. Nothing is hard-coded.
   - Log content is UNTRUSTED. Text is only ever inserted with textContent / text nodes (see h()),
     never innerHTML, so a malicious log line cannot inject markup or script.
   - Starting a new upload throws away the previous report, charts and panel before anything else. */

"use strict";

// ====================================================================================== constants
const POLL_INTERVAL_MS = 350;
const MAX_POLL_FAILURES = 5;
const THREATS_PAGE_SIZE = 25;
const CHART_LOCAL = "assets/vendor/chart.umd.min.js";
const CHART_CDN = "https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js";
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const COLORS = {
  green: "#00ff66", red: "#ff4d4d", orange: "#ff8a3d", amber: "#ffb020", low: "#2fbf71",
  grid: "#2a2a2a", muted: "#8a8a8a",
};
const SEVERITY_COLOR = { CRITICAL: COLORS.red, HIGH: COLORS.orange, MEDIUM: COLORS.amber, LOW: COLORS.low };
const STAGE_MARK = { pending: "[  ]", running: "[>>]", done: "[OK]", failed: "[!!]" };

// ====================================================================================== state
const state = {
  limits: null,          // {allowed_extensions, max_file_size_bytes} from /api/config
  backendOnline: false,
  file: null,            // the File chosen by the user (valid only)
  token: 0,              // bumped on every new run / reset; async work for an older token is ignored
  jobId: null,
  report: null,
  charts: [],            // live Chart.js instances (destroyed on reset)
  deferredCharts: [],    // chart-drawing functions run once the screen is visible
  threatFilter: "ALL",
  threatsShown: THREATS_PAGE_SIZE,
  abort: null,           // AbortController of an in-flight upload
  elapsedTimer: null,
  panelTrigger: null,    // element to return focus to when the panel closes
};

// ====================================================================================== tiny helpers
const $ = (id) => document.getElementById(id);

/** Create an element. Strings become TEXT nodes (never parsed as HTML): this is the XSS guard. */
function h(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

const fmtInt = (n) => Number(n).toLocaleString("en-US");
const pct = (fraction) => `${(fraction * 100).toFixed(1)}%`;
const dash = (value) => (value === null || value === undefined || value === "" ? "—" : value);

function fmtBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const severityBadge = (severity) => h("span", { class: `badge sev-${severity}` }, severity);

/** Turn a failed fetch Response into a readable message. */
async function errorMessage(response) {
  try {
    const body = await response.json();
    if (body && body.error && body.error.message) return { code: body.error.code, message: body.error.message };
  } catch (_) { /* not JSON: fall through */ }
  return { code: "http_error", message: `The server rejected the request (HTTP ${response.status}).` };
}

// ====================================================================================== screens
const SCREENS = ["upload", "processing", "dashboard", "clean"];

function showScreen(name) {
  for (const screen of SCREENS) $(`screen-${screen}`).hidden = screen !== name;
  const isResult = name === "dashboard" || name === "clean";
  $("new-analysis").hidden = !isResult;
  const download = $("download-report");
  download.hidden = !isResult;
  if (isResult && state.jobId) download.setAttribute("href", `/api/jobs/${encodeURIComponent(state.jobId)}/report.md`);
  window.scrollTo(0, 0);
  $("main").focus({ preventScroll: true });
}

// ====================================================================================== backend status + limits
async function checkBackend() {
  const badge = $("backend-status");
  try {
    const [health, config] = await Promise.all([fetch("/api/health"), fetch("/api/config")]);
    if (!health.ok || !config.ok) throw new Error("bad status");
    state.limits = await config.json();
    state.backendOnline = true;
    badge.textContent = "Backend: online";
    badge.className = "status status-online";
    $("limits-text").textContent =
      `Supported: ${state.limits.allowed_extensions.join("  ")}  ·  Maximum size: ${fmtBytes(state.limits.max_file_size_bytes)}`;
    $("file-input").setAttribute("accept", state.limits.allowed_extensions.join(","));
    updateAnalyzeButton();
  } catch (_) {
    state.backendOnline = false;
    badge.textContent = "Backend: unreachable";
    badge.className = "status status-offline";
    updateAnalyzeButton();
    setTimeout(checkBackend, 4000);          // keep trying: the user may just have started the server
  }
}

// ====================================================================================== SCREEN 1: upload
function showUploadError(message) {
  const box = $("upload-error");
  box.textContent = message;
  box.hidden = !message;
}

function updateAnalyzeButton() {
  $("analyze").disabled = !(state.file && state.backendOnline);
}

/** Client-side checks are a convenience. The backend re-validates everything. */
function validateFile(file) {
  if (!state.limits) return "The backend is not reachable yet, so file limits are unknown. Start the server and try again.";
  const dot = file.name.lastIndexOf(".");
  const extension = dot >= 0 ? file.name.slice(dot).toLowerCase() : "";
  if (!state.limits.allowed_extensions.includes(extension)) {
    return `Files of type '${extension || "no extension"}' are not supported. Upload one of: ${state.limits.allowed_extensions.join(", ")}.`;
  }
  if (file.size === 0) return "The file is empty. Upload a log file that contains records.";
  if (file.size > state.limits.max_file_size_bytes) {
    return `The file is ${fmtBytes(file.size)}, which is larger than the ${fmtBytes(state.limits.max_file_size_bytes)} limit.`;
  }
  return null;
}

function selectFile(fileList) {
  showUploadError("");
  const file = fileList && fileList[0];
  if (!file) return;
  const problem = validateFile(file);
  if (problem) {
    clearSelectedFile();
    showUploadError(problem);
    return;
  }
  state.file = file;
  $("selected-name").textContent = file.name;
  $("selected-size").textContent = fmtBytes(file.size);
  $("selected-file").hidden = false;
  if (fileList.length > 1) showUploadError("Only the first file is analyzed. Upload files one at a time.");
  updateAnalyzeButton();
}

function clearSelectedFile() {
  state.file = null;
  $("file-input").value = "";
  $("selected-file").hidden = true;
  updateAnalyzeButton();
}

function initUpload() {
  const zone = $("dropzone");
  $("browse").addEventListener("click", () => $("file-input").click());
  $("file-input").addEventListener("change", (event) => selectFile(event.target.files));
  $("clear-file").addEventListener("click", () => { clearSelectedFile(); showUploadError(""); });
  $("analyze").addEventListener("click", startAnalysis);

  zone.addEventListener("dragenter", (event) => { event.preventDefault(); zone.classList.add("is-over"); });
  zone.addEventListener("dragover", (event) => { event.preventDefault(); zone.classList.add("is-over"); });
  zone.addEventListener("dragleave", (event) => { if (!zone.contains(event.relatedTarget)) zone.classList.remove("is-over"); });
  zone.addEventListener("drop", (event) => {
    event.preventDefault();
    zone.classList.remove("is-over");
    selectFile(event.dataTransfer.files);
  });
  // A file dropped anywhere else must not make the browser navigate away from the app.
  window.addEventListener("dragover", (event) => event.preventDefault());
  window.addEventListener("drop", (event) => event.preventDefault());
}

// ====================================================================================== analysis run
async function startAnalysis() {
  if (!state.file) return;
  const token = ++state.token;
  const button = $("analyze");
  button.disabled = true;
  button.textContent = "Uploading…";
  showUploadError("");

  state.abort = new AbortController();
  const form = new FormData();
  form.append("file", state.file, state.file.name);
  try {
    const response = await fetch("/api/analyze", { method: "POST", body: form, signal: state.abort.signal });
    if (token !== state.token) return;
    if (!response.ok) {
      const { message } = await errorMessage(response);
      showUploadError(message);
      return;
    }
    const job = await response.json();
    state.jobId = job.job_id;
    $("processing-file").textContent = job.filename;
    buildStageList(job.stages);
    $("processing-error").hidden = true;
    $("processing-cancel").textContent = "Cancel";
    startElapsedTimer();
    showScreen("processing");
    pollJob(token, job.job_id);
  } catch (error) {
    if (token !== state.token || error.name === "AbortError") return;
    showUploadError("Could not reach the backend. Check that the server is running and try again.");
  } finally {
    button.textContent = "Analyze Logs";
    updateAnalyzeButton();
  }
}

function startElapsedTimer() {
  stopElapsedTimer();
  const started = performance.now();
  const label = $("processing-elapsed");
  label.textContent = "0.0s";
  state.elapsedTimer = setInterval(() => { label.textContent = `${((performance.now() - started) / 1000).toFixed(1)}s`; }, 100);
}

function stopElapsedTimer() {
  if (state.elapsedTimer) clearInterval(state.elapsedTimer);
  state.elapsedTimer = null;
}

// ---- processing screen: stage list mirrors what the server reports
function buildStageList(stages) {
  const list = $("stage-list");
  list.replaceChildren(...stages.map((stage) =>
    h("li", { class: `stage stage-${stage.state}`, "data-stage": stage.id },
      h("span", { class: "stage-mark", "aria-hidden": "true" }, STAGE_MARK[stage.state]),
      h("span", { class: "stage-label" }, stage.label),
      h("span", { class: "stage-state" }, stageStateText(stage.state, false)))));
}

function stageStateText(stageState, jobFailed) {
  if (stageState === "pending") return jobFailed ? "NOT RUN" : "WAITING";
  return { running: "RUNNING", done: "DONE", failed: "FAILED" }[stageState];
}

function renderStages(stages, jobFailed) {
  for (const stage of stages) {
    const item = document.querySelector(`#stage-list [data-stage="${stage.id}"]`);
    if (!item) continue;
    item.className = `stage stage-${stage.state}`;
    item.querySelector(".stage-mark").textContent = STAGE_MARK[stage.state];
    item.querySelector(".stage-state").textContent = stageStateText(stage.state, jobFailed);
  }
}

function showProcessingError(message) {
  stopElapsedTimer();
  $("processing-error-message").textContent = message;
  $("processing-error").hidden = false;
  $("processing-cancel").textContent = "Upload another file";
}

async function pollJob(token, jobId) {
  let failures = 0;
  while (token === state.token) {
    try {
      const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`);
      if (token !== state.token) return;
      if (!response.ok) {
        const { code, message } = await errorMessage(response);
        if (code === "job_not_found") { showProcessingError(message); return; }
        throw new Error(message);
      }
      const job = await response.json();
      if (token !== state.token) return;
      failures = 0;
      renderStages(job.stages, job.status === "error");
      if (job.status === "error") { showProcessingError(job.error.message); return; }
      if (job.status === "done") { await loadReport(token, jobId); return; }
    } catch (_) {
      if (token !== state.token) return;
      failures += 1;
      if (failures >= MAX_POLL_FAILURES) {
        showProcessingError("Lost contact with the backend while the analysis was running. Check that the server is still running, then upload the file again.");
        return;
      }
    }
    await sleep(POLL_INTERVAL_MS);
  }
}

async function loadReport(token, jobId) {
  const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/report`);
  if (token !== state.token) return;
  if (!response.ok) {
    showProcessingError((await errorMessage(response)).message);
    return;
  }
  const report = await response.json();
  if (token !== state.token) return;
  stopElapsedTimer();
  state.report = report;
  renderReport(report);
}

/** Drop EVERYTHING from the previous analysis so results can never mix with the next one. */
function resetToUpload() {
  state.token += 1;                         // any still-running poll / fetch becomes a no-op
  if (state.abort) state.abort.abort();
  stopElapsedTimer();
  closePanel(false);
  destroyCharts();
  const oldJob = state.jobId;
  state.jobId = null;
  state.report = null;
  state.threatFilter = "ALL";
  state.threatsShown = THREATS_PAGE_SIZE;
  $("screen-dashboard").replaceChildren();
  $("screen-clean").replaceChildren();
  $("stage-list").replaceChildren();
  $("processing-error").hidden = true;
  clearSelectedFile();
  showUploadError("");
  if (oldJob) fetch(`/api/jobs/${encodeURIComponent(oldJob)}`, { method: "DELETE" }).catch(() => {});   // best effort
  showScreen("upload");
}

// ====================================================================================== charts (Chart.js)
let chartReady = null;

function loadScript(src) {
  return new Promise((resolve) => {
    const script = document.createElement("script");
    script.src = src;
    script.onload = () => resolve(true);
    script.onerror = () => { script.remove(); resolve(false); };
    document.head.append(script);
  });
}

/** Chart.js is looked up locally first (assets/vendor/), then on a pinned CDN version. If both fail the
 *  app still works: every chart is replaced by a note and all the numbers remain in the tables. */
function ensureChartLibrary() {
  if (!chartReady) {
    chartReady = (async () => {
      if (window.Chart) return true;
      if (!(await loadScript(CHART_LOCAL)) && !(await loadScript(CHART_CDN))) return false;
      Chart.defaults.color = COLORS.muted;
      Chart.defaults.borderColor = COLORS.grid;
      Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
      Chart.defaults.font.size = 11;
      return true;
    })();
  }
  return chartReady;
}

function destroyCharts() {
  for (const chart of state.charts) chart.destroy();
  state.charts = [];
  state.deferredCharts = [];
}

/** A titled chart container. `draw(canvas)` runs later, once the screen is visible and sized. */
function chartBox(title, label, draw) {
  const canvas = h("canvas", { role: "img", "aria-label": label });
  const wrap = h("div", { class: "chart-canvas" }, canvas);
  const box = h("div", { class: "chart-box" }, h("h3", null, title), wrap);
  state.deferredCharts.push({ wrap, canvas, draw });
  return box;
}

function noteBox(title, message) {
  return h("div", { class: "chart-box" }, h("h3", null, title), h("p", { class: "chart-note" }, message));
}

async function flushCharts() {
  const jobs = state.deferredCharts;
  state.deferredCharts = [];
  const available = await ensureChartLibrary();
  for (const { wrap, canvas, draw } of jobs) {
    if (!available) {
      wrap.replaceChildren(h("p", { class: "chart-note" }, "Charts are unavailable because the Chart.js library could not be loaded. The tables on this page show the same data."));
      continue;
    }
    state.charts.push(draw(canvas));
  }
}

function axisOptions(extra) {
  return { grid: { color: COLORS.grid }, ticks: { color: COLORS.muted }, border: { color: COLORS.grid }, ...extra };
}

function barConfig({ labels, values, colors, horizontal = false, max, tooltipExtra }) {
  return {
    type: "bar",
    data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
    options: {
      indexAxis: horizontal ? "y" : "x", responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { display: false }, tooltip: { callbacks: tooltipExtra ? { afterLabel: tooltipExtra } : {} } },
      scales: {
        x: axisOptions(horizontal ? { beginAtZero: true, ticks: { precision: 0, color: COLORS.muted }, max } : { ticks: { color: COLORS.muted, maxTicksLimit: 10, maxRotation: 0 } }),
        y: axisOptions(horizontal ? {} : { beginAtZero: true, ticks: { precision: 0, color: COLORS.muted }, max }),
      },
    },
  };
}

function severityChart(report) {
  const { labels, values } = report.charts.severity_distribution;
  const summary = labels.map((label, i) => `${label} ${values[i]}`).join(", ");
  return chartBox("Severity distribution", `Findings by severity: ${summary}`, (canvas) =>
    new Chart(canvas, barConfig({ labels, values, colors: labels.map((l) => SEVERITY_COLOR[l]) })));
}

function activityChart(report) {
  const data = report.charts.activity_over_time;
  if (!data) return noteBox("Log activity over time", "This log has no usable timestamps, so activity over time cannot be drawn.");
  const series = [{ label: "Events", values: data.events, color: COLORS.green }];
  if (data.failed_logins) series.push({ label: "Failed logins", values: data.failed_logins, color: COLORS.red });
  if (data.http_4xx) series.push({ label: "HTTP 4xx", values: data.http_4xx, color: COLORS.amber });
  if (data.http_5xx) series.push({ label: "HTTP 5xx", values: data.http_5xx, color: COLORS.orange });
  return chartBox("Log activity over time", `Events per time bucket across ${data.labels.length} buckets`, (canvas) =>
    new Chart(canvas, {
      type: "line",
      data: {
        labels: data.labels,
        datasets: series.map((s) => ({ label: s.label, data: s.values, borderColor: s.color, backgroundColor: s.color, borderWidth: 1.5, pointRadius: data.labels.length > 60 ? 0 : 2, tension: 0 })),
      },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false, interaction: { mode: "index", intersect: false },
        plugins: { legend: { display: series.length > 1, labels: { color: COLORS.muted, boxWidth: 10 } } },
        scales: { x: axisOptions({ ticks: { color: COLORS.muted, maxTicksLimit: 8, maxRotation: 0 } }), y: axisOptions({ beginAtZero: true, ticks: { precision: 0, color: COLORS.muted } }) },
      },
    }));
}

function eventTypeChart(report) {
  const { labels, values } = report.charts.event_type_distribution;
  if (!labels.length) return noteBox("Event type distribution", "No event types were extracted from this log.");
  return chartBox("Event type distribution", `Log entries by event type, ${labels.length} types`, (canvas) =>
    new Chart(canvas, barConfig({ labels, values, colors: COLORS.green, horizontal: true })));
}

function timelineChart(report) {
  const data = report.charts.suspicious_timeline;
  if (!data) return noteBox("Suspicious activity timeline", "This log has no usable timestamps, so a timeline cannot be drawn.");
  return chartBox("Suspicious activity timeline", "Suspicious log records per time bucket", (canvas) =>
    new Chart(canvas, barConfig({ labels: data.labels, values: data.values, colors: COLORS.red })));
}

function topIpsChart(report) {
  const ips = report.charts.top_suspicious_ips;
  if (!ips.length) return noteBox("Top suspicious source IPs", "None of the findings has a source IP, so there is nothing to rank.");
  return chartBox("Top suspicious source IPs", "Highest risk score per source IP", (canvas) =>
    new Chart(canvas, barConfig({
      labels: ips.map((i) => i.source_ip), values: ips.map((i) => i.max_risk_score), colors: ips.map((i) => SEVERITY_COLOR[i.severity]),
      horizontal: true, max: 100,
      tooltipExtra: (ctx) => `${ips[ctx.dataIndex].severity}, ${ips[ctx.dataIndex].findings} finding(s), ${fmtInt(ips[ctx.dataIndex].occurrences)} log records`,
    })));
}

// ====================================================================================== shared report pieces
function section(title, ...children) {
  return h("section", { class: "section" }, h("h2", null, title), ...children);
}

function simpleTable(headers, rows, numericColumns = []) {
  const head = h("tr", null, headers.map((text, i) => h("th", { class: numericColumns.includes(i) ? "num" : null, scope: "col" }, text)));
  const body = rows.map((cells) => h("tr", null, cells.map((cell, i) => h("td", { class: numericColumns.includes(i) ? "num" : null }, cell))));
  return h("div", { class: "table-wrap" }, h("table", null, h("thead", null, head), h("tbody", null, body)));
}

function fileStrip(report) {
  const { meta } = report;
  const range = meta.time_range ? `${meta.time_range.start} → ${meta.time_range.end}` : "no usable timestamps";
  const items = [
    ["File", meta.filename], ["Format", meta.detected_format], ["Size", fmtBytes(meta.size_bytes)],
    ["Analyzed", meta.analyzed_at], ["Log period", range],
  ];
  const strip = h("div", { class: "file-strip" }, items.map(([label, value]) => h("span", null, `${label}: `, h("strong", null, value))));
  const parts = [strip];
  const notes = [];
  if (meta.malformed_records) notes.push(`${fmtInt(meta.malformed_records)} line(s) could not be parsed and were skipped.`);
  notes.push(...meta.parse_warnings);
  if (notes.length) {
    parts.push(h("details", { class: "parse-notes" }, h("summary", null, `Parsing notes (${notes.length})`),
      h("ul", null, notes.map((text) => h("li", null, text)))));
  }
  return parts;
}

function logSummarySection(report) {
  const summary = report.log_summary;
  const blocks = [];

  blocks.push(h("div", null, h("h3", null, "Most frequent events"),
    simpleTable(["Event", "Entries", "Share"], summary.most_frequent_events.map((e) => [e.event, fmtInt(e.count), pct(e.share)]), [1, 2])));

  if (summary.most_active_source_ips && summary.most_active_source_ips.length) {
    const headers = ["Source IP", "Events"], rows = summary.most_active_source_ips.map((r) => [r.source_ip, fmtInt(r.events)]);
    if (summary.authentication) {
      headers.push("Failed logins", "Successful logins");
      summary.most_active_source_ips.forEach((r, i) => rows[i].push(fmtInt(r.failed_logins), fmtInt(r.successful_logins)));
    }
    if (summary.http) {
      headers.push("HTTP 4xx");
      summary.most_active_source_ips.forEach((r, i) => rows[i].push(fmtInt(r.http_4xx)));
    }
    blocks.push(h("div", null, h("h3", null, "Most active source IPs"), simpleTable(headers, rows, headers.map((_, i) => i).slice(1))));
  }

  const stats = [];
  if (summary.authentication) {
    const a = summary.authentication;
    stats.push(h("div", { class: "panel" }, h("h3", null, "Authentication"), kvList([
      ["Successful logins", fmtInt(a.successful_logins)], ["Failed logins", fmtInt(a.failed_logins)],
      ["Failed ratio", a.failed_ratio === null ? null : pct(a.failed_ratio)], ["Distinct usernames", fmtInt(a.unique_usernames)]])));
  }
  if (summary.http) {
    const w = summary.http;
    stats.push(h("div", { class: "panel" }, h("h3", null, "HTTP"), kvList([
      ["Requests", fmtInt(w.requests)], ["Client errors (4xx)", `${fmtInt(w.client_errors_4xx)} (${pct(w.rate_4xx)})`],
      ["Server errors (5xx)", `${fmtInt(w.server_errors_5xx)} (${pct(w.rate_5xx)})`]])));
  }
  if (summary.network) {
    const n = summary.network;
    stats.push(h("div", { class: "panel" }, h("h3", null, "Network"), kvList([
      ["Distinct destination IPs", fmtInt(n.unique_destination_ips)], ["Distinct destination ports", fmtInt(n.unique_destination_ports)]])));
  }
  if (stats.length) blocks.push(h("div", { class: "grid grid-two" }, stats));

  blocks.push(h("div", { class: "panel" }, h("h3", null, "Log insights"), h("ul", null, report.activity_summary.map((line) => h("li", null, line)))));
  return section("Log summary", h("div", { class: "grid" }, blocks));
}

/** <dl> of label/value pairs; pairs whose value is null/empty are left out. */
function kvList(pairs) {
  const list = h("dl", { class: "kv" });
  for (const [label, value] of pairs) {
    if (value === null || value === undefined || value === "" || (Array.isArray(value) && !value.length)) continue;
    list.append(h("dt", null, label), h("dd", null, Array.isArray(value) ? value.join(", ") : String(value)));
  }
  return list;
}

function analysisDetailsSection(report) {
  const { rules, machine_learning: ml, notes } = report.analysis_details;
  const ruleRows = rules.map((r) => [r.title, r.ran ? `Ran: ${r.findings} finding(s)` : `Skipped: ${r.skipped_reason || "not applicable to this log"}`]);
  const mlText = ml.ran
    ? `Isolation Forest ran on ${fmtInt(ml.windows_analyzed)} time windows and flagged ${fmtInt(ml.windows_flagged_by_model)} as statistically unusual. These are anomalies, not confirmed attacks.`
    : `Isolation Forest did not run: ${ml.reason || "not enough data"}.`;
  return h("details", { class: "section" },
    h("summary", null, "How this analysis was performed (rules checked, machine learning status)"),
    h("h3", null, "Detection rules"), simpleTable(["Rule", "Result"], ruleRows),
    h("h3", null, "Machine learning"), h("p", { class: "small" }, mlText),
    notes.length ? h("ul", { class: "small" }, notes.map((n) => h("li", null, n))) : null);
}

// ====================================================================================== SCREEN 3 / 4: render the report
function renderReport(report) {
  destroyCharts();
  const clean = report.status.overall_status === "clean";
  if (clean) renderCleanScreen(report); else renderDashboard(report);
  showScreen(clean ? "clean" : "dashboard");
  flushCharts();
}

// ---------------------------------------------------------------------------------- SCREEN 4: clean
function renderCleanScreen(report) {
  const o = report.overview;
  const check = h("div", { class: "clean-check", "aria-hidden": "true" }, $("tpl-checkmark").content.firstElementChild.cloneNode(true));

  const stats = h("div", { class: "grid grid-cards section" },
    statCard("Total logs analyzed", fmtInt(o.total_logs_processed)),
    statCard("Anomalies", fmtInt(o.total_anomalies)),
    statCard("Analysis timestamp", report.meta.analyzed_at, null, true));

  const ranRules = report.analysis_details.rules.filter((r) => r.ran).length;
  const skipped = report.analysis_details.rules.filter((r) => !r.ran);
  const coverage = h("div", { class: "panel" }, h("h3", null, "What was checked"),
    h("p", { class: "small" }, `${ranRules} of ${report.analysis_details.rules.length} detection rules applied to this log` +
      (report.analysis_details.machine_learning.ran ? ", plus statistical anomaly detection (Isolation Forest)." : ".")),
    skipped.length ? h("ul", { class: "small muted" }, skipped.map((r) => h("li", null, `${r.title}: not applicable (${r.skipped_reason || "the log lacks the needed fields"})`))) : null);

  $("screen-clean").replaceChildren(
    h("div", { class: "clean-hero" }, check, h("h1", null, "Your Logs Look Normal"), h("p", null, report.status.message), h("p", { class: "muted small" }, report.status.note)),
    ...fileStrip(report),
    stats,
    section("Activity", h("div", { class: "grid grid-charts" }, activityChart(report), eventTypeChart(report))),
    section("Summary of normal activity", h("div", { class: "panel" }, h("ul", null, report.activity_summary.map((line) => h("li", null, line)))), h("div", { class: "section" }, coverage)),
    h("div", { class: "clean-actions" }, h("button", { class: "btn btn-primary", type: "button", onclick: resetToUpload }, "Upload and analyze another file")));
}

function statCard(label, value, className, small) {
  return h("div", { class: `card ${className || ""}` }, h("div", { class: "card-label" }, label),
    h("div", { class: "card-value" }, small ? h("span", { class: "small" }, value) : value));
}

// ---------------------------------------------------------------------------------- SCREEN 3: dashboard
function renderDashboard(report) {
  state.threatFilter = "ALL";
  state.threatsShown = THREATS_PAGE_SIZE;
  const o = report.overview;

  const banner = h("div", { class: `status-banner status-${report.status.overall_status}` },
    h("h1", null, report.status.status_label), h("p", null, report.status.message), h("p", { class: "note" }, report.status.note));

  const cards = h("div", { class: "grid grid-cards section" },
    statCard("Total logs processed", fmtInt(o.total_logs_processed)),
    statCard("Total anomalies", fmtInt(o.total_anomalies)),
    statCard("Critical alerts", fmtInt(o.critical_alerts), o.critical_alerts ? "card-critical" : ""),
    statCard("High-risk events", fmtInt(o.high_risk_events), o.high_risk_events ? "card-high" : ""),
    o.unique_source_ips === null ? null : statCard("Unique source IPs", fmtInt(o.unique_source_ips)),
    statCard("Suspicious log records", fmtInt(o.suspicious_events)));

  const charts = h("div", { class: "grid grid-charts" },
    severityChart(report), activityChart(report), eventTypeChart(report), timelineChart(report), topIpsChart(report));

  const threatsHost = h("div", { id: "threats-host" });
  const remediation = h("ol", { class: "priority-list" }, report.remediation_summary.map((item) => {
    const finding = report.findings.find((f) => f.finding_id === item.finding_id);
    return h("li", { class: "priority-item" },
      h("div", { class: "priority-head" }, h("strong", null, `#${item.priority}`), severityBadge(item.severity),
        h("strong", null, item.threat_name), item.source_ip ? h("span", { class: "muted" }, item.source_ip) : null,
        h("button", { class: "btn btn-small", type: "button", onclick: (event) => openThreat(finding.finding_id, event.currentTarget) }, "View details")),
      h("ul", null, item.actions.map((a) => h("li", null, a))));
  }));

  $("screen-dashboard").replaceChildren(
    ...fileStrip(report), banner, cards,
    section("Visualizations", charts),
    section(`Detected threats (${report.findings.length})`, threatsHost),
    section("Remediation priorities", remediation),
    logSummarySection(report),
    analysisDetailsSection(report),
    h("p", { class: "disclaimer" }, report.disclaimer));
  renderThreatsTable();
}

function renderThreatsTable() {
  const report = state.report;
  const host = $("threats-host");
  const matching = report.findings.filter((f) => state.threatFilter === "ALL" || f.severity === state.threatFilter);
  const visible = matching.slice(0, state.threatsShown);

  const chip = (value, text) => h("button", {
    class: "chip", type: "button", "aria-pressed": String(state.threatFilter === value),
    onclick: () => { state.threatFilter = value; state.threatsShown = THREATS_PAGE_SIZE; renderThreatsTable(); },
  }, text);
  const toolbar = h("div", { class: "toolbar", role: "group", "aria-label": "Filter by severity" },
    chip("ALL", `All (${report.findings.length})`),
    SEVERITY_ORDER.filter((s) => report.severity_distribution[s] > 0).map((s) => chip(s, `${s} (${report.severity_distribution[s]})`)));

  const head = h("tr", null, ["Timestamp", "Threat", "Source IP", "Severity", "Risk score"].map((t, i) => h("th", { scope: "col", class: i === 4 ? "num" : null }, t)));
  const rows = visible.map((f) => {
    const open = (target) => openThreat(f.finding_id, target);
    const button = h("button", { class: "row-link", type: "button", onclick: (event) => { event.stopPropagation(); open(event.currentTarget); } }, f.threat_name);
    return h("tr", { class: "is-clickable", onclick: (event) => open(event.currentTarget.querySelector(".row-link")) },
      h("td", { class: "mono-break" }, dash(f.first_seen)), h("td", null, button), h("td", { class: "mono-break" }, f.source_ip || "n/a"),
      h("td", null, severityBadge(f.severity)), h("td", { class: "num" }, `${f.risk_score}/100`));
  });
  const table = h("div", { class: "table-wrap" }, h("table", null, h("thead", null, head), h("tbody", null, rows)));

  const foot = h("div", { class: "table-foot" },
    h("span", { class: "muted small" }, `Showing ${visible.length} of ${matching.length}. Click a threat to see evidence and solutions.`),
    matching.length > visible.length
      ? h("button", { class: "btn btn-small", type: "button", onclick: () => { state.threatsShown += THREATS_PAGE_SIZE; renderThreatsTable(); } }, "Show more")
      : null);
  host.replaceChildren(toolbar, table, foot);
}

// ====================================================================================== SCREEN 5: threat details panel
function listOrNull(items, ordered) {
  if (!items || !items.length) return null;
  return h(ordered ? "ol" : "ul", null, items.map((text) => h("li", null, text)));
}

function panelSection(title, ...content) {
  const filtered = content.filter((c) => c !== null && c !== undefined);
  if (!filtered.length) return null;
  return h("section", { class: "panel-section" }, h("h3", null, title), ...filtered);
}

function openThreat(findingId, trigger) {
  const report = state.report;
  const f = report && report.findings.find((x) => x.finding_id === findingId);
  if (!f) return;
  const reopening = !$("threat-panel").hidden;
  if (!reopening) state.panelTrigger = trigger || document.activeElement;

  const evidenceRows = f.evidence.map((e) => h("tr", null,
    h("td", { class: "num" }, e.line_no), h("td", { class: "mono-break" }, dash(e.timestamp)), h("td", null, h("pre", null, dash(e.raw_line)))));
  const evidence = f.evidence.length
    ? [h("p", { class: "muted small" }, `Showing ${f.evidence.length} of ${fmtInt(f.evidence_total)} matching log record(s). Log text is displayed as plain text.`),
       h("div", { class: "table-wrap evidence" }, h("table", null,
         h("thead", null, h("tr", null, h("th", { class: "num", scope: "col" }, report.meta.line_label), h("th", { scope: "col" }, "Timestamp"), h("th", { scope: "col" }, "Log record"))),
         h("tbody", null, evidenceRows)))]
    : [h("p", { class: "muted" }, "No individual log lines are attached to this finding.")];

  const factors = f.risk_factors.map((factor) => h("div", { class: "factor" },
    h("div", { class: "factor-head" }, h("span", null, factor.name), h("span", null, `${factor.points}/${factor.max_points}`)),
    h("div", { class: "bar" }, h("span", { "data-w": factor.max_points ? Math.round((factor.points / factor.max_points) * 100) : 0 })),
    h("div", { class: "muted small" }, factor.explanation)));

  const related = (f.related_finding_ids || []).map((id) => report.findings.find((x) => x.finding_id === id)).filter(Boolean);

  const refCommands = (f.reference_commands || []).map((c) =>
    h("div", { class: "refcmd" }, h("strong", null, c.label), h("pre", null, c.lines.join("\n"))));

  const body = $("panel-body");
  body.replaceChildren(
    h("h2", { id: "panel-title", class: "panel-title" }, f.threat_name),
    h("div", { class: "panel-badges" }, severityBadge(f.severity), h("span", { class: "risk-score" }, `RISK ${f.risk_score}/100`),
      h("span", { class: "badge badge-neutral" }, f.category), h("span", { class: "badge badge-neutral" }, `PRIORITY: ${f.priority}`),
      f.confidence ? h("span", { class: "badge badge-neutral" }, `CONFIDENCE: ${String(f.confidence).toUpperCase()}`) : null),
    panelSection("Overview", kvList([
      ["Source IP", f.source_ip], ["Destination IPs", f.destination_ips], ["Destination ports", f.destination_ports],
      ["Services", f.affected_services], ["Hosts", f.affected_hosts], ["Accounts involved", f.accounts_involved], ["URLs involved", f.urls_involved],
      ["First seen", f.first_seen], ["Last seen", f.last_seen], ["Suspicious occurrences", fmtInt(f.occurrences)],
      ["Detection method", f.detection_method], ["Rule IDs", f.rule_ids]])),
    panelSection("What was observed", h("p", null, f.description)),
    panelSection("Why this is suspicious", h("p", null, f.why_suspicious), h("p", { class: "muted small" }, f.classification_basis)),
    panelSection("Possible harmless explanations", listOrNull(f.possible_benign_explanations, false)),
    panelSection("Confidence basis", listOrNull(f.confidence_basis, false)),
    panelSection("Supporting log evidence", ...evidence),
    panelSection("Possible consequences", listOrNull(f.possible_impact, false)),
    panelSection("Recommended solutions", listOrNull(f.recommended_solutions, true)),
    panelSection("Immediate mitigation steps", listOrNull(f.immediate_mitigation, true)),
    refCommands.length ? panelSection("Reference commands", h("p", { class: "muted small" }, "Examples for reference only. This application never runs them. Review and adapt them to your environment before use."), ...refCommands) : null,
    panelSection("How the risk score was calculated", h("p", { class: "small" }, f.risk_explanation), ...factors,
      f.risk_caps && f.risk_caps.length ? h("ul", { class: "small muted" }, f.risk_caps.map((c) => h("li", null, c))) : null),
    related.length ? panelSection("Related findings from the same source", h("div", { class: "toolbar" }, related.map((r) =>
      h("button", { class: "chip", type: "button", onclick: (event) => openThreat(r.finding_id, state.panelTrigger || event.currentTarget) }, `${r.threat_name} (${r.severity})`)))) : null);

  // Bar widths are set through the DOM (CSSOM), which a strict Content-Security-Policy allows.
  body.querySelectorAll(".bar > span").forEach((bar) => { bar.style.width = `${bar.getAttribute("data-w")}%`; bar.removeAttribute("data-w"); });
  body.scrollTop = 0;

  $("panel-overlay").hidden = false;
  $("threat-panel").hidden = false;
  document.body.classList.add("body-lock");
  $("panel-close").focus();
}

function closePanel(restoreFocus = true) {
  if ($("threat-panel").hidden) return;
  $("threat-panel").hidden = true;
  $("panel-overlay").hidden = true;
  $("panel-body").replaceChildren();
  document.body.classList.remove("body-lock");
  const target = state.panelTrigger;
  state.panelTrigger = null;
  if (restoreFocus && target && document.contains(target)) target.focus();
}

function initPanel() {
  $("panel-close").addEventListener("click", () => closePanel());
  $("panel-overlay").addEventListener("click", () => closePanel());
  document.addEventListener("keydown", (event) => {
    if ($("threat-panel").hidden) return;
    if (event.key === "Escape") { closePanel(); return; }
    if (event.key !== "Tab") return;
    // keep keyboard focus inside the open panel
    const focusable = [...$("threat-panel").querySelectorAll("button, [href], summary, [tabindex]:not([tabindex='-1'])")].filter((el) => !el.disabled);
    if (!focusable.length) return;
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  });
}

// ====================================================================================== start
function init() {
  initUpload();
  initPanel();
  $("new-analysis").addEventListener("click", resetToUpload);
  $("processing-cancel").addEventListener("click", resetToUpload);
  ensureChartLibrary();      // start loading Chart.js early
  checkBackend();
  showScreen("upload");
}

init();
