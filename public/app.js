const form = document.querySelector("#analyze-form");
const input = document.querySelector("#url-input");
const submit = document.querySelector("#submit-button");
const panel = document.querySelector("#analysis-panel");
const title = document.querySelector("#analysis-title");
const statusPill = document.querySelector("#status-pill");
const urlLabel = document.querySelector("#analysis-url");
const progressList = document.querySelector("#progress-list");
const errorBox = document.querySelector("#error-box");
const reportNode = document.querySelector("#report");
const progressSummary = document.querySelector("#progress-summary");
const themeToggle = document.querySelector("#theme-toggle");

const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;",
}[char]));

function setStatus(status) {
  statusPill.textContent = status.toUpperCase();
  statusPill.dataset.status = status;
}

function renderProgress(events) {
  const current = new Map();
  for (const event of events) current.set(event.id, event);
  const latest = [...current.values()];
  const finished = latest.filter((event) => ["completed", "unavailable", "failed"].includes(event.status)).length;
  progressSummary.textContent = `${finished} of ${latest.length} announced checks resolved`;
  progressSummary.style.setProperty("--progress", `${latest.length ? (finished / latest.length) * 100 : 0}%`);
  progressList.replaceChildren(...latest.map((event) => {
    const item = document.createElement("li");
    item.className = "progress-item";
    item.dataset.status = event.status;
    const icon = event.status === "completed" ? "✓" : event.status === "failed" ? "!" : event.status === "running" ? "…" : "·";
    item.innerHTML = `<span class="progress-icon">${icon}</span><span class="progress-copy"><strong>${escapeHtml(event.label)}</strong><small>${escapeHtml(event.detail)}</small></span>`;
    return item;
  }));
}

function formatMetric(value, suffix = "") {
  return value === null || value === undefined ? "Not available" : `${escapeHtml(value)}${suffix}`;
}

function makeBarChart(title, description, rows, unit) {
  const available = rows.filter((row) => Number.isFinite(row.value) && row.value >= 0);
  if (!available.length) {
    return `<article class="chart-card"><div class="chart-heading"><h3>${escapeHtml(title)}</h3></div><p class="chart-unavailable">Chart unavailable: these values were not measured.</p><small>${escapeHtml(description)}</small></article>`;
  }
  const max = Math.max(...available.map((row) => row.value), 1);
  const height = rows.length * 42 + 14;
  const items = rows.map((row, index) => {
    const y = index * 42 + 8;
    const value = Number.isFinite(row.value) && row.value >= 0 ? row.value : null;
    const width = value === null ? 0 : Math.max(value > 0 ? 2 : 0, 342 * value / max);
    return `<text x="0" y="${y + 14}" class="chart-label">${escapeHtml(row.label)}</text>
      <rect x="160" y="${y}" width="342" height="19" rx="4" class="chart-track"></rect>
      ${value === null ? `<text x="170" y="${y + 14}" class="chart-unavailable-label">Not available</text>` : `<rect x="160" y="${y}" width="${width}" height="19" rx="4" class="chart-bar"></rect><text x="${Math.min(510, 169 + width)}" y="${y + 14}" class="chart-value">${escapeHtml(value)}${escapeHtml(unit)}</text>`}`;
  }).join("");
  return `<article class="chart-card"><div class="chart-heading"><h3>${escapeHtml(title)}</h3><span>${escapeHtml(unit)}</span></div><svg class="report-chart" viewBox="0 0 620 ${height}" role="img" aria-label="${escapeHtml(title)}">${items}</svg><small>${escapeHtml(description)}</small></article>`;
}

function makeSecurityChart(report) {
  const h = report.response?.securityHeaders || {};
  const rows = [
    ["HTTPS", report.security.https],
    ["Valid TLS certificate", report.security.tls?.valid === true],
    ["HSTS", Boolean(h["strict-transport-security"])],
    ["Content-Security-Policy", Boolean(h["content-security-policy"])],
    ["Framing restriction", Boolean(h["x-frame-options"]) || Boolean(h["content-security-policy"]?.toLowerCase().includes("frame-ancestors"))],
    ["X-Content-Type-Options", Boolean(h["x-content-type-options"])],
    ["Referrer-Policy", Boolean(h["referrer-policy"])],
    ["Permissions-Policy", Boolean(h["permissions-policy"])],
  ];
  const observed = rows.filter(([, value]) => value).length;
  return `<article class="chart-card security-chart"><div class="chart-heading"><h3>Observable security controls</h3><span>${observed} / ${rows.length} observed</span></div>
    <p class="chart-disclaimer">A checklist of response signals, not a security score or proof the site is safe.</p>
    <ul class="control-list">${rows.map(([label, present]) => `<li><span class="control-dot" data-present="${present}"></span><span>${escapeHtml(label)}</span><strong>${present ? "Observed" : "Not observed"}</strong></li>`).join("")}</ul></article>`;
}

function renderReport(id, report) {
  const metrics = report.metrics;
  const cards = [
    ["HTTP status", report.httpStatus ? `HTTP ${report.httpStatus}` : "Not available", "Measured by server"],
    ["DNS lookup", formatMetric(metrics.dnsMs?.value, " ms"), metrics.dnsMs?.dataSource],
    ["TCP connection", formatMetric(metrics.tcpConnectMs?.value, " ms"), metrics.tcpConnectMs?.dataSource],
    ["TLS handshake", formatMetric(metrics.tlsHandshakeMs?.value, " ms"), metrics.tlsHandshakeMs?.dataSource],
    ["Time to first byte", formatMetric(metrics.timeToFirstByteMs?.value, " ms"), metrics.timeToFirstByteMs?.dataSource],
    ["Page size", formatMetric(metrics.pageSizeBytes?.value, " bytes"), metrics.pageSizeBytes?.dataSource],
    ["Browser vitals", "Not available", metrics.browserVitals?.dataSource],
    ["Device suitability", "Unable to determine", metrics.deviceSuitability?.dataSource],
  ];
  const issues = report.issues.map((issue) => `<li data-severity="${escapeHtml(issue.severity)}"><strong>${escapeHtml(issue.title)}</strong>${escapeHtml(issue.evidence)}${issue.recommendation ? `<small>Recommendation: ${escapeHtml(issue.recommendation)}</small>` : ""}</li>`).join("");
  const assessment = report.assessment || {};
  const completeness = assessment.analysisCompleteness || "partial";
  const latencyChart = makeBarChart("Measured connection timings", "Server-side phases, not browser page-load time. Values are measured independently.", [
    { label: "DNS lookup", value: metrics.dnsMs?.value },
    { label: "TCP connect", value: metrics.tcpConnectMs?.value },
    { label: "TLS handshake", value: metrics.tlsHandshakeMs?.value },
    { label: "Time to response headers", value: metrics.timeToFirstByteMs?.value },
  ], " ms");
  const budgetRows = report.deviceRecommendations?.categories || [];
  reportNode.innerHTML = `
    <nav class="report-nav" aria-label="Report sections"><a href="#report-overview">Overview</a><a href="#report-performance">Measured timings</a><a href="#report-security">Security signals</a><a href="#report-devices">Device budgets</a></nav>
    <section id="report-overview" class="report-section">
      <div class="report-meta">REPORT ${escapeHtml(id)} · ${escapeHtml(report.createdAt)} · ${escapeHtml(report.finalUrl)}</div>
      <div class="assessment-banner" data-completeness="${escapeHtml(completeness)}"><div><span class="assessment-kicker">SERVER RESPONSE</span><strong>${escapeHtml(assessment.summary || "Analysis results reflect only available signals.")}</strong></div><span class="assessment-state">${completeness === "partial" ? "PARTIAL" : "LIMITED"}</span></div>
      <div class="safety-banner"><span class="safety-icon" aria-hidden="true">?</span><div><strong>Is it safe to browse? Unable to verify</strong><p>${escapeHtml(assessment.browseSafetyReason || report.security.malwareRisk.reason)}</p></div></div>
      <div class="metric-grid">${cards.map(([label, value, source]) => `<article class="metric-card"><span>${escapeHtml(label)}</span><strong>${value}</strong><small>${escapeHtml(source || "Unavailable")}</small></article>`).join("")}</div>
    </section>
    <section id="report-performance" class="report-section"><div class="section-title"><div><span class="section-kicker">MEASURED, NOT MODELED</span><h3>Connection timings</h3></div><span class="data-pill">Server measurements</span></div><div class="chart-grid">${latencyChart}</div></section>
    <section id="report-security" class="report-section"><div class="section-title"><div><span class="section-kicker">PUBLIC RESPONSE ONLY</span><h3>Security observations</h3></div><span class="data-pill">Not a security audit</span></div><div class="chart-grid">${makeSecurityChart(report)}</div><ul class="findings">${issues || `<li data-severity="info"><strong>No header findings</strong>No missing-header findings were generated for this response.</li>`}</ul></section>
    <section id="report-devices" class="report-section"><div class="section-title"><div><span class="section-kicker">NO GUESSED PRODUCT PICKS</span><h3>Phones, tablets &amp; laptops</h3></div><span class="data-pill">Unable to determine</span></div><div class="device-note"><strong>${escapeHtml(report.deviceRecommendations?.status || "Unable to determine")}</strong><p>${escapeHtml(report.deviceRecommendations?.reason || metrics.deviceSuitability?.note || "No device measurements were collected.")}</p><p>${escapeHtml(report.deviceRecommendations?.budgetPrices || "Current prices are not verified.")}</p></div><div class="budget-grid">${budgetRows.map((row) => `<article><span>${escapeHtml(row.budget)}</span><strong>Not enough evidence</strong><small>${escapeHtml(row.result)}</small></article>`).join("")}</div></section>
    <section class="report-section"><div class="section-title"><div><span class="section-kicker">READ BEFORE RELYING ON RESULTS</span><h3>Scope &amp; limitations</h3></div></div><ul class="findings">${report.limitations.map((item) => `<li data-severity="info">${escapeHtml(item)}</li>`).join("")}</ul></section>
    <div class="report-actions"><button id="download-json" type="button">Export JSON</button><button id="download-csv" type="button">Export CSV metrics</button><button id="print-report" type="button">Print / Save PDF</button></div>`;
  reportNode.classList.remove("hidden");
  document.querySelector("#download-json").addEventListener("click", () => download(`devicefit-${id}.json`, JSON.stringify({ analysisId: id, report }, null, 2), "application/json"));
  document.querySelector("#download-csv").addEventListener("click", () => {
    const rows = [["Metric", "Value", "Data source"], ...Object.entries(metrics).map(([key, item]) => [key, item?.value ?? "Not available", item?.dataSource || "Unavailable"])];
    download(`devicefit-${id}.csv`, rows.map((row) => row.map(csvCell).join(",")).join("\r\n"), "text/csv");
  });
  document.querySelector("#print-report").addEventListener("click", () => window.print());
}

function csvCell(value) {
  return `"${String(value).replaceAll("\"", "\"\"")}"`;
}

function download(name, text, type) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([text], { type }));
  link.download = name;
  link.click();
  URL.revokeObjectURL(link.href);
}

async function poll(id) {
  for (;;) {
    const response = await fetch(`/api/analyze/${id}`, { cache: "no-store" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not retrieve analysis status.");
    setStatus(data.status);
    renderProgress(data.progress);
    if (data.status === "completed") {
      title.textContent = data.report?.assessment?.analysisCompleteness === "partial" ? "Analysis complete · partial evidence" : "Analysis complete";
      renderReport(id, data.report);
      return;
    }
    if (data.status === "failed") throw new Error(data.error || "Could not complete this test.");
    await new Promise((resolve) => setTimeout(resolve, 700));
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  panel.classList.remove("hidden");
  reportNode.classList.add("hidden");
  errorBox.classList.add("hidden");
  progressList.replaceChildren();
  progressSummary.textContent = "";
  progressSummary.style.setProperty("--progress", "0%");
  title.textContent = "Starting live checks";
  urlLabel.textContent = input.value.trim();
  setStatus("queued");
  submit.disabled = true;
  try {
    const response = await fetch("/api/analyze", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: input.value.trim() }),
    });

    function applyTheme(theme) {
      document.documentElement.dataset.theme = theme;
      themeToggle.setAttribute("aria-pressed", String(theme === "dark"));
    }

    let savedTheme = "light";
    try {
      savedTheme = localStorage.getItem("devicefit-theme") === "dark" ? "dark" : "light";
    } catch {}
    applyTheme(savedTheme);
    themeToggle.addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      applyTheme(next);
      try {
        localStorage.setItem("devicefit-theme", next);
      } catch {}
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to start analysis.");
    title.textContent = "Checking public signals";
    await poll(data.analysisId);
  } catch (error) {
    setStatus("failed");
    title.textContent = "Analysis could not be completed";
    errorBox.textContent = error.message;
    errorBox.classList.remove("hidden");
  } finally {
    submit.disabled = false;
  }
});
