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
const safeBrowsingOptIn = document.querySelector("#safe-browsing-optin");
const safeBrowsingStatus = document.querySelector("#safe-browsing-status");

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
  const vitals = metrics.browserVitals?.value;
  const vitalsSummary = vitals
    ? [
      vitals.fcpMs === null ? null : `FCP ${formatMetric(vitals.fcpMs, " ms")}`,
      vitals.lcpMs === null ? null : `LCP ${formatMetric(vitals.lcpMs, " ms")}`,
      vitals.cls === null ? null : `CLS ${formatMetric(vitals.cls)}`,
    ].filter(Boolean).join(" · ") || "No paint metrics observed"
    : "Unavailable";
  const cards = [
    ["HTTP status", report.httpStatus ? `HTTP ${report.httpStatus}` : "Not available", "Measured by server"],
    ["DNS lookup", formatMetric(metrics.dnsMs?.value, " ms"), metrics.dnsMs?.dataSource],
    ["TCP connection", formatMetric(metrics.tcpConnectMs?.value, " ms"), metrics.tcpConnectMs?.dataSource],
    ["TLS handshake", formatMetric(metrics.tlsHandshakeMs?.value, " ms"), metrics.tlsHandshakeMs?.dataSource],
    ["Time to first byte", formatMetric(metrics.timeToFirstByteMs?.value, " ms"), metrics.timeToFirstByteMs?.dataSource],
    ["Page size", formatMetric(metrics.pageSizeBytes?.value, " bytes"), metrics.pageSizeBytes?.dataSource],
    ["Browser vitals", vitalsSummary, metrics.browserVitals?.dataSource],
    ["Device-class estimates", metrics.deviceSuitability?.value ? `${formatMetric(metrics.deviceSuitability.value)} / 3 profiles` : "Unavailable", metrics.deviceSuitability?.dataSource],
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
  const profileRows = report.deviceSuitability || [];
  const lcpChart = makeBarChart("Largest Contentful Paint by emulated device", "Observed by Chromium under the CPU and network conditions listed for each profile.", profileRows.map((profile) => ({ label: profile.category, value: profile.metrics?.lcpMs })), " ms");
  const pageWeightChart = makeBarChart("Downloaded page resources", "Total response-body bytes received by the safe browser request bridge; shown in megabytes.", profileRows.map((profile) => ({ label: profile.category, value: profile.metrics?.pageBytes === null || profile.metrics?.pageBytes === undefined ? null : Math.round(profile.metrics.pageBytes / (1024 * 1024) * 100) / 100 })), " MB");
  const resourceChart = makeBarChart("Browser resource requests", "Resource timing entries observed by Chromium; third-party domains and failed requests are listed in the profile results.", profileRows.map((profile) => ({ label: profile.category, value: profile.metrics?.requests ?? null })), " requests");
  const clsRows = profileRows.map((profile) => ({ label: profile.category, value: profile.metrics?.cls === null || profile.metrics?.cls === undefined ? null : Math.round(profile.metrics.cls * 1000) / 1000 }));
  const clsChart = makeBarChart("Cumulative Layout Shift by profile", "Real browser layout-shift observer values. Lower is more stable; no target-specific pass score is inferred.", clsRows, " CLS");
  const profileCards = profileRows.map((profile) => {
    const result = profile.result;
    const pageRendered = profile.renderStatus === "rendered";
    return `<article class="device-result" data-result="${pageRendered ? "measured" : "unavailable"}">
      <div class="device-result-top"><span class="device-type">${escapeHtml(profile.category)}</span><span class="data-pill">${pageRendered ? "Page rendered" : "No visible page content"}</span></div>
      <h4>${escapeHtml(profile.profile)}</h4>
      <div class="device-score">${result?.value === null || result?.value === undefined ? "Not scored" : `${escapeHtml(result.value)}<small>/ 100</small>`}</div>
      <strong>${escapeHtml(result?.label || "Unable to estimate")}</strong>
      <p>${escapeHtml(result?.note || result?.reason || "Browser results were unavailable for this profile.")}</p>
      <div class="device-evidence">${profile.metrics ? `<span>LCP <b>${formatMetric(profile.metrics.lcpMs, " ms")}</b></span><span>Data <b>${formatMetric(profile.metrics.pageBytes, " bytes")}</b></span><span>CLS <b>${formatMetric(profile.metrics.cls)}</b></span><span>Overflow <b>${profile.metrics.horizontalOverflow ? "Yes" : "No"}</b></span>` : ""}</div>
      ${result?.estimatedPriceBand ? `<small class="budget-source">Budget class estimate: ${escapeHtml(result.estimatedPriceBand)}</small>` : ""}
      <small>Actual device test: No · CPU ${escapeHtml(profile.cpuSlowdown || "")}× · ${escapeHtml(profile.network?.label || "Not available")}</small>
      </article>`;
  }).join("");
  const screenshots = [...(report.browserAnalysis?.screenshots || []), ...(report.browserAnalysis?.viewportScreenshots || [])].map((shot) => `<figure class="screenshot-card"><img loading="lazy" src="${escapeHtml(shot.url)}" alt="Real Chromium screenshot for ${escapeHtml(shot.label)}" width="360"><figcaption><strong>${escapeHtml(shot.label)}</strong><span>${escapeHtml(shot.bytes)} bytes · ${escapeHtml(shot.mimeType)}</span></figcaption></figure>`).join("");
  const profileData = report.browserAnalysis?.profiles || [];
  const accessibilitySummary = profileData.filter((profile) => profile.accessibility?.status === "measured").map((profile) => `<article class="a11y-card"><strong>${escapeHtml(profile.label)}</strong><span>${escapeHtml(profile.accessibility.violations.length)} axe violations · ${escapeHtml(profile.accessibility.passes)} rules passed · ${escapeHtml(profile.accessibility.incomplete)} need manual review</span></article>`).join("");
  const technologyTags = (report.technologyDetection?.detected || []).map((technology) => `<span class="tech-tag">${escapeHtml(technology)}</span>`).join("");
  const risk = report.security?.malwareRisk || { classification: "UNKNOWN", reason: "Unable to verify." };
  const riskTitle = risk.classification === "HIGH" ? "Known threat-list match detected" :
    risk.classification === "LOW" ? "No current threat-list match reported" : "Browsing safety could not be verified";
  const riskSummary = risk.status === "not_requested"
    ? "No external threat lookup was requested; the target URL was not sent to an intelligence provider."
    : risk.reason;
  reportNode.innerHTML = `
    <nav class="report-nav" aria-label="Report sections"><a href="#report-overview">Overview</a><a href="#report-performance">Measured timings</a><a href="#report-security">Security signals</a><a href="#report-devices">Device budgets</a></nav>
    <section id="report-overview" class="report-section">
      <div class="report-meta">REPORT ${escapeHtml(id)} · ${escapeHtml(report.createdAt)} · ${escapeHtml(report.finalUrl)}</div>
      <div class="assessment-banner" data-completeness="${escapeHtml(completeness)}"><div><span class="assessment-kicker">SERVER RESPONSE</span><strong>${escapeHtml(assessment.summary || "Analysis results reflect only available signals.")}</strong></div><span class="assessment-state">${completeness === "measured" ? "MEASURED" : completeness === "partial" ? "PARTIAL" : "LIMITED"}</span></div>
      <div class="safety-banner" data-risk="${escapeHtml(risk.classification)}"><span class="safety-icon" aria-hidden="true">${risk.classification === "HIGH" ? "!" : risk.classification === "LOW" ? "✓" : "?"}</span><div><strong>${escapeHtml(riskTitle)}</strong><p>${escapeHtml(riskSummary)}</p><p>${risk.classification === "LOW" ? "A clean reputation lookup does not prove a site is safe or free of malware." : "Public browser and TLS checks do not establish that browsing is safe."}</p></div></div>
      <div class="metric-grid">${cards.map(([label, value, source]) => `<article class="metric-card"><span>${escapeHtml(label)}</span><strong>${value}</strong><small>${escapeHtml(source || "Unavailable")}</small></article>`).join("")}</div>
    </section>
    <section id="report-performance" class="report-section"><div class="section-title"><div><span class="section-kicker">REAL CHROMIUM + SERVER SIGNALS</span><h3>Performance comparison</h3></div><span class="data-pill">Data provenance on every chart</span></div><div class="chart-grid">${latencyChart}${lcpChart}${pageWeightChart}${resourceChart}${clsChart}</div></section>
    <section id="report-security" class="report-section"><div class="section-title"><div><span class="section-kicker">PUBLIC RESPONSE ONLY</span><h3>Security observations</h3></div><span class="data-pill">Not a security audit</span></div><div class="chart-grid">${makeSecurityChart(report)}</div><ul class="findings">${issues || `<li data-severity="info"><strong>No header findings</strong>No missing-header findings were generated for this response.</li>`}</ul></section>
    <section id="report-devices" class="report-section"><div class="section-title"><div><span class="section-kicker">REAL TESTS · EMULATED HARDWARE</span><h3>Device-class suitability</h3></div><span class="data-pill">Not a physical device test</span></div><div class="device-note"><strong>Evidence-based scenario fit; not a specific product pick</strong><p>Chromium rendered the page using a real browser with CPU and network throttling. These profiles estimate website load fit for broad phone, tablet and laptop budget classes; hardware, RAM and retail prices are not simulated or verified.</p><p>${escapeHtml(report.deviceRecommendations?.budgetPrices || "Current product prices are not checked; budget bands are planning estimates only.")}</p></div><div class="device-results">${profileCards || `<article class="device-result"><h4>Device scenario unavailable</h4><p>${escapeHtml(metrics.deviceSuitability?.note || "Chromium did not produce a page rendering.")}</p></article>`}</div><div class="budget-grid">${budgetRows.map((row) => `<article><span>${escapeHtml(row.budget)}</span><strong>${escapeHtml(row.result)}</strong><small>${escapeHtml(row.profile)} · ${escapeHtml(row.estimatedPriceBand || "No page rendering; no recommendation")}. Prices were not checked live.</small></article>`).join("")}</div></section>
    <section class="report-section"><div class="section-title"><div><span class="section-kicker">RESPONSIVE SCREEN CAPTURES</span><h3>Real browser screenshots</h3></div></div><div class="screenshot-grid">${screenshots || `<p class="chart-unavailable">Screenshots are unavailable because the browser could not render the page.</p>`}</div></section>
    <section class="report-section"><div class="section-title"><div><span class="section-kicker">AUTOMATED WCAG RULES</span><h3>Accessibility signals</h3></div><span class="data-pill">Not a compliance certificate</span></div><div class="a11y-grid">${accessibilitySummary || `<p class="chart-unavailable">Automated accessibility checks could not run because no page rendered.</p>`}</div></section>
    <section class="report-section"><div class="section-title"><div><span class="section-kicker">PUBLICLY OBSERVED</span><h3>Technology hints</h3></div></div><div class="technology-panel">${technologyTags || "No known framework was detected by browser markers."} <small>Detected technologies are heuristic public signals; this is not exhaustive.</small></div></section>
    <section class="report-section"><div class="section-title"><div><span class="section-kicker">NETWORK REQUESTS</span><h3>Resources &amp; third-party hosts</h3></div></div><div class="network-summary"><div><strong>${escapeHtml(report.networkAnalysis?.totalRequests ?? 0)}</strong><span>Browser requests</span></div><div><strong>${escapeHtml(report.networkAnalysis?.bytesReceived ?? 0)}</strong><span>Response bytes</span></div><div><strong>${escapeHtml(report.networkAnalysis?.redirectCount ?? 0)}</strong><span>Redirects</span></div><div><strong>${escapeHtml(report.networkAnalysis?.failedResources ?? 0)}</strong><span>Blocked or failed</span></div></div><p class="network-hosts">Observed third-party hosts: ${escapeHtml((report.networkAnalysis?.thirdPartyDomains || []).join(", ") || "None observed")}</p><div class="chart-grid">${clsChart}</div></section>
    <section class="report-section"><div class="section-title"><div><span class="section-kicker">PRICE DATA</span><h3>Current device prices</h3></div></div><div class="device-note"><strong>Not checked — live product price source is not configured.</strong><p>Budget category estimates above come from the emulated performance class; they are not live prices or model recommendations. This avoids presenting invented market data as current.</p></div></section>
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
      body: JSON.stringify({ url: input.value.trim(), shareUrlForThreatCheck: safeBrowsingOptIn.checked }),
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

fetch("/api/security/providers", { cache: "no-store" })
  .then((response) => response.json())
  .then((providers) => {
    const available = providers.googleSafeBrowsing?.configured === true;
    safeBrowsingOptIn.disabled = !available;
    safeBrowsingStatus.textContent = available ? "Configured · optional opt-in" : "Not configured here";
    safeBrowsingStatus.dataset.available = String(available);
  })
  .catch(() => {
    safeBrowsingOptIn.disabled = true;
    safeBrowsingStatus.textContent = "Provider status unavailable";
  });
