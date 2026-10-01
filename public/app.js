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

const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;",
}[char]));

function setStatus(status) {
  statusPill.textContent = status.toUpperCase();
  statusPill.dataset.status = status;
}

function renderProgress(events) {
  progressList.replaceChildren(...events.map((event) => {
    const item = document.createElement("li");
    item.className = "progress-item";
    item.dataset.status = event.status;
    const icon = event.status === "completed" ? "✓" : event.status === "failed" ? "!" : event.status === "running" ? "…" : "·";
    item.innerHTML = `<span class="progress-icon">${icon}</span><span class="progress-copy"><strong>${escapeHtml(event.label)}</strong><small>${escapeHtml(event.detail)}</small></span>`;
    return item;
  }));
}

function fmt(metric, suffix = "") {
  if (metric?.value === null || metric?.value === undefined) return "Not available";
  return `${escapeHtml(metric.value)}${suffix}`;
}

function renderReport(id, report) {
  const metrics = report.metrics;
  const cards = [
    ["HTTP status", report.httpStatus ? `HTTP ${report.httpStatus}` : "Not available", "Measured by server"],
    ["DNS lookup", fmt(metrics.dnsMs, " ms"), metrics.dnsMs.dataSource],
    ["TCP connection", fmt(metrics.tcpConnectMs, " ms"), metrics.tcpConnectMs.dataSource],
    ["TLS handshake", fmt(metrics.tlsHandshakeMs, " ms"), metrics.tlsHandshakeMs.dataSource],
    ["Time to first byte", fmt(metrics.timeToFirstByteMs, " ms"), metrics.timeToFirstByteMs.dataSource],
    ["Page size", fmt(metrics.pageSizeBytes, " bytes"), metrics.pageSizeBytes.dataSource],
    ["Browser vitals", "Not available", metrics.browserVitals.dataSource],
    ["Device suitability", "Unable to determine", metrics.deviceSuitability.dataSource],
  ];
  const issues = report.issues.map((issue) => `<li data-severity="${escapeHtml(issue.severity)}"><strong>${escapeHtml(issue.title)}</strong>${escapeHtml(issue.evidence)}${issue.recommendation ? `<small>Recommendation: ${escapeHtml(issue.recommendation)}</small>` : ""}</li>`).join("");
  reportNode.innerHTML = `
    <div class="report-meta">REPORT ${escapeHtml(id)} · ${escapeHtml(report.createdAt)} · ${escapeHtml(report.finalUrl)}</div>
    <div class="metric-grid">${cards.map(([label, value, source]) => `<article class="metric-card"><span>${escapeHtml(label)}</span><strong>${value}</strong><small>${escapeHtml(source)}</small></article>`).join("")}</div>
    <div class="report-section"><h3>Publicly observable security signals</h3><ul class="findings">${issues}</ul></div>
    <div class="report-section"><h3>Scope &amp; limitations</h3><ul class="findings">${report.limitations.map((item) => `<li data-severity="info">${escapeHtml(item)}</li>`).join("")}</ul></div>
    <div class="report-actions"><button id="download-json" type="button">Export JSON</button><button id="download-csv" type="button">Export CSV metrics</button><button id="print-report" type="button">Print / Save PDF</button></div>`;
  reportNode.classList.remove("hidden");
  document.querySelector("#download-json").addEventListener("click", () => download(`devicefit-${id}.json`, JSON.stringify({ analysisId: id, report }, null, 2), "application/json"));
  document.querySelector("#download-csv").addEventListener("click", () => {
    const rows = [["Metric", "Value", "Data source"], ...Object.entries(metrics).map(([key, item]) => [key, item.value ?? "Not available", item.dataSource])];
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
      title.textContent = "Analysis complete";
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
  title.textContent = "Starting live checks";
  urlLabel.textContent = input.value.trim();
  setStatus("queued");
  submit.disabled = true;
  try {
    const response = await fetch("/api/analyze", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: input.value.trim() }),
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
