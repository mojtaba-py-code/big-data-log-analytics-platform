"use strict";
const $ = (id) => document.getElementById(id);
const KEY_STORAGE = "loga.apikey";

/* ---------- helpers ---------- */
const fmtInt = (n) => (n === null || n === undefined || isNaN(n)) ? "-" : Number(n).toLocaleString();
const fmtMs  = (n) => (n === null || n === undefined || isNaN(n)) ? "-" : Number(n).toFixed(1) + " ms";
const fmtPct = (n) => (n === null || n === undefined || isNaN(n)) ? "-" : (Number(n) * 100).toFixed(2) + "%";

function banner(message){
  const el = $("banner");
  if(!message){ el.style.display = "none"; return; }
  el.textContent = message;           // textContent, never innerHTML
  el.style.display = "block";
}

async function api(path, params){
  const url = new URL(path, window.location.origin);
  const query = Object.assign({ hours: $("range").value }, params || {});
  const service = $("service").value;
  if(service) query.service = service;
  for(const [k, v] of Object.entries(query)){
    if(v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
  }
  const headers = {};
  const key = $("apikey").value.trim();
  if(key) headers["X-API-Key"] = key;
  const response = await fetch(url, { headers });
  if(response.status === 401 || response.status === 403){
    throw new Error("Authentication failed - check the API key");
  }
  if(!response.ok){
    throw new Error("Request failed: " + response.status + " " + path);
  }
  return response.json();
}

/* ---------- SVG chart primitives (no external libraries) ---------- */
const NS = "http://www.w3.org/2000/svg";
function el(name, attrs){
  const node = document.createElementNS(NS, name);
  for(const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
  return node;
}
function css(name){ return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

function lineChart(target, points, options){
  const host = $(target);
  host.textContent = "";
  const opts = options || {};
  if(!points || points.length === 0){ host.append(emptyNote()); return; }

  const W = 620, H = 200, padL = 52, padR = 12, padT = 12, padB = 26;
  const values = points.map(p => p.value);
  const max = Math.max(...values, 1);
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img" });
  const x = (i) => padL + (i * (W - padL - padR)) / Math.max(points.length - 1, 1);
  const y = (v) => H - padB - (v / max) * (H - padT - padB);

  for(let i = 0; i <= 4; i++){
    const gy = padT + (i * (H - padT - padB)) / 4;
    svg.append(el("line", { x1: padL, y1: gy, x2: W - padR, y2: gy,
                            stroke: css("--border"), "stroke-width": 1 }));
    const label = el("text", { x: padL - 8, y: gy + 4, "text-anchor": "end",
                               fill: css("--muted"), "font-size": 10 });
    label.textContent = fmtInt(Math.round(max * (1 - i / 4)));
    svg.append(label);
  }

  const path = points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join(" ");
  const area = `${path} L${x(points.length - 1).toFixed(1)},${H - padB} L${padL},${H - padB} Z`;
  const colour = opts.color || css("--accent");
  svg.append(el("path", { d: area, fill: colour, "fill-opacity": .12 }));
  svg.append(el("path", { d: path, fill: "none", stroke: colour, "stroke-width": 2,
                          "stroke-linejoin": "round" }));

  [0, Math.floor(points.length / 2), points.length - 1].forEach(i => {
    if(i < 0 || i >= points.length) return;
    const t = el("text", { x: x(i), y: H - 8, "text-anchor": i === 0 ? "start" : (i === points.length - 1 ? "end" : "middle"),
                           fill: css("--muted"), "font-size": 10 });
    t.textContent = new Date(points[i].bucket).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    svg.append(t);
  });

  points.forEach((p, i) => {
    const dot = el("circle", { cx: x(i), cy: y(p.value), r: 6, fill: "transparent" });
    const title = el("title", {});
    title.textContent = `${new Date(p.bucket).toLocaleString()}: ${fmtInt(p.value)}`;
    dot.append(title);
    svg.append(dot);
  });
  host.append(svg);
}

function barChart(target, entries){
  const host = $(target);
  host.textContent = "";
  if(!entries || entries.length === 0){ host.append(emptyNote()); return; }
  const W = 620, H = 200, padL = 52, padB = 26, padT = 12;
  const max = Math.max(...entries.map(e => e.value), 1);
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}` });
  const bandWidth = (W - padL - 12) / entries.length;
  entries.forEach((entry, i) => {
    const height = (entry.value / max) * (H - padT - padB);
    svg.append(el("rect", {
      x: padL + i * bandWidth + bandWidth * .15,
      y: H - padB - height,
      width: bandWidth * .7,
      height: Math.max(height, 1),
      rx: 3,
      fill: entry.color || css("--accent")
    }));
    const label = el("text", { x: padL + i * bandWidth + bandWidth / 2, y: H - 8,
                               "text-anchor": "middle", fill: css("--muted"), "font-size": 10 });
    label.textContent = entry.key;
    svg.append(label);
    const value = el("text", { x: padL + i * bandWidth + bandWidth / 2, y: H - padB - height - 5,
                               "text-anchor": "middle", fill: css("--fg"), "font-size": 10 });
    value.textContent = fmtInt(entry.value);
    svg.append(value);
  });
  host.append(svg);
}

function emptyNote(){
  const div = document.createElement("div");
  div.className = "empty";
  div.textContent = "No data in this window";
  return div;
}

function renderTable(target, columns, rows){
  const host = $(target);
  host.textContent = "";
  if(!rows || rows.length === 0){ host.append(emptyNote()); return; }
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  columns.forEach(col => {
    const th = document.createElement("th");
    th.textContent = col.label;
    if(col.numeric) th.className = "num";
    headRow.append(th);
  });
  thead.append(headRow);
  table.append(thead);

  const tbody = document.createElement("tbody");
  rows.forEach(row => {
    const tr = document.createElement("tr");
    columns.forEach(col => {
      const td = document.createElement("td");
      const value = col.render ? col.render(row) : row[col.field];
      if(value instanceof Node) td.append(value);
      else td.textContent = value === null || value === undefined ? "-" : String(value);
      td.className = [col.numeric ? "num" : "", col.truncate ? "trunc" : ""].join(" ").trim();
      tr.append(td);
    });
    tbody.append(tr);
  });
  table.append(tbody);
  host.append(table);
}

function severityPill(severity){
  const span = document.createElement("span");
  span.className = "pill sev-" + String(severity || "info").toLowerCase();
  span.textContent = severity;
  return span;
}

function tiles(overview, anomalyCount, findingCount){
  const host = $("tiles");
  host.textContent = "";
  const items = [
    ["Total records", fmtInt(overview.total_records)],
    ["Requests", fmtInt(overview.total_requests)],
    ["Errors", fmtInt(overview.total_errors)],
    ["Error rate", fmtPct(overview.error_rate)],
    ["Avg latency", fmtMs(overview.average_latency_ms)],
    ["P95 latency", fmtMs(overview.p95_latency_ms)],
    ["P99 latency", fmtMs(overview.p99_latency_ms)],
    ["Services", fmtInt(overview.active_services)],
    ["Anomalies", fmtInt(anomalyCount)],
    ["Security findings", fmtInt(findingCount)],
  ];
  items.forEach(([label, value]) => {
    const tile = document.createElement("div");
    tile.className = "tile";
    const l = document.createElement("div"); l.className = "label"; l.textContent = label;
    const v = document.createElement("div"); v.className = "value"; v.textContent = value;
    tile.append(l, v);
    host.append(tile);
  });
}

/* ---------- data loading ---------- */
const STATUS_COLORS = { "2xx": "--ok", "3xx": "--accent", "4xx": "--warn", "5xx": "--err" };

async function loadServices(){
  try{
    const data = await api("/logs/fields/service/values", { limit: 50 });
    const select = $("service");
    const current = select.value;
    select.textContent = "";
    const all = document.createElement("option");
    all.value = ""; all.textContent = "All services";
    select.append(all);
    (data.values || []).forEach(name => {
      const option = document.createElement("option");
      option.value = name; option.textContent = name;
      select.append(option);
    });
    select.value = current;
  }catch(err){ /* filters are optional; never block the dashboard */ }
}

async function refresh(){
  banner("");
  const bucket = $("window").value;
  try{
    const [overview, errors, traffic, latency, status, services, anomalies, security] =
      await Promise.all([
        api("/analytics/overview"),
        api("/analytics/errors", { window: bucket }),
        api("/analytics/traffic", { window: bucket }),
        api("/analytics/latency", { window: bucket }),
        api("/analytics/status-codes"),
        api("/analytics/services", { limit: 12 }),
        api("/analytics/anomalies", { window: bucket, limit: 40 }),
        api("/analytics/security", { limit: 40 }),
      ]);

    tiles(overview, anomalies.count || 0, security.count || 0);

    lineChart("chart-requests", (traffic.over_time || {}).points || []);
    lineChart("chart-errors", (errors.over_time || {}).points || [], { color: css("--err") });
    lineChart("chart-latency", (latency.over_time || {}).points || [], { color: css("--warn") });

    barChart("chart-status", Object.entries(status.by_class || {})
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([key, value]) => ({ key, value, color: css(STATUS_COLORS[key] || "--accent") })));

    renderTable("table-endpoints",
      [{ label: "Endpoint", field: "key", truncate: true },
       { label: "Requests", field: "count", numeric: true, render: r => fmtInt(r.count) },
       { label: "Share", field: "percentage", numeric: true, render: r => r.percentage.toFixed(1) + "%" }],
      traffic.top_endpoints || []);

    renderTable("table-ips",
      [{ label: "Address", field: "key" },
       { label: "Requests", field: "count", numeric: true, render: r => fmtInt(r.count) },
       { label: "Share", field: "percentage", numeric: true, render: r => r.percentage.toFixed(1) + "%" }],
      traffic.top_ips || []);

    renderTable("table-errsvc",
      [{ label: "Service", field: "key" },
       { label: "Errors", field: "count", numeric: true, render: r => fmtInt(r.count) },
       { label: "Share", field: "percentage", numeric: true, render: r => r.percentage.toFixed(1) + "%" }],
      errors.by_service || []);

    renderTable("table-services",
      [{ label: "Service", field: "service" },
       { label: "Requests", numeric: true, render: r => fmtInt(r.requests) },
       { label: "Errors", numeric: true, render: r => fmtInt(r.errors) },
       { label: "Failure", numeric: true, render: r => fmtPct(r.failure_rate) },
       { label: "P95", numeric: true, render: r => fmtMs(r.latency.p95) },
       { label: "Status", render: r => {
           const span = document.createElement("span");
           span.className = r.status === "healthy" ? "status-ok" :
                            (r.status === "degraded" ? "status-degraded" : "status-err");
           span.textContent = r.status;
           return span;
         } }],
      services.services || []);

    renderTable("table-anomalies",
      [{ label: "Time", render: r => new Date(r.bucket).toLocaleString() },
       { label: "Type", field: "type" },
       { label: "Metric", field: "metric" },
       { label: "Observed", numeric: true, render: r => fmtInt(Math.round(r.observed)) },
       { label: "Expected", numeric: true, render: r => fmtInt(Math.round(r.expected)) },
       { label: "Score", numeric: true, render: r => r.score.toFixed(1) },
       { label: "Severity", render: r => severityPill(r.severity) },
       { label: "Detector", field: "detector" }],
      anomalies.anomalies || []);

    renderTable("table-security",
      [{ label: "Subject", field: "subject" },
       { label: "Type", field: "type" },
       { label: "Events", numeric: true, render: r => fmtInt(r.event_count) },
       { label: "Risk", numeric: true, render: r => r.risk_score.toFixed(0) },
       { label: "Severity", render: r => severityPill(r.severity) },
       { label: "Detail", field: "description", truncate: true }],
      security.findings || []);

    $("generated").textContent = "updated " + new Date().toLocaleTimeString();
  }catch(err){
    banner(err.message || "Failed to load dashboard data");
  }
}

/* ---------- wiring ---------- */
let timer = null;
$("refresh").addEventListener("click", refresh);
$("range").addEventListener("change", refresh);
$("window").addEventListener("change", refresh);
$("service").addEventListener("change", refresh);
$("apikey").addEventListener("change", () => {
  // Session storage, not local storage: the key dies with the tab.
  sessionStorage.setItem(KEY_STORAGE, $("apikey").value.trim());
  loadServices().then(refresh);
});
$("auto").addEventListener("change", (event) => {
  if(timer){ clearInterval(timer); timer = null; }
  if(event.target.checked) timer = setInterval(refresh, 30000);
});

$("apikey").value = sessionStorage.getItem(KEY_STORAGE) || "";
loadServices().then(refresh);
