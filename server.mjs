import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeWebsite } from "./lib/analyzer.mjs";
import { validateTarget } from "./lib/safety.mjs";

const ROOT = fileURLToPath(new URL(".", import.meta.url));
const PUBLIC_DIR = resolve(ROOT, "public");
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "127.0.0.1";
const MAX_BODY_BYTES = 8 * 1024;
const MAX_JOBS = 2;
const MAX_QUEUE = 8;
const RATE_LIMIT_COUNT = 5;
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;
const JOB_TTL_MS = 60 * 60 * 1000;
const jobs = new Map();
const rateLimits = new Map();
const queue = [];
let activeJobs = 0;

function json(res, status, value) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  });
  res.end(JSON.stringify(value));
}

function clientAddress(req) {
  return req.socket.remoteAddress || "unknown";
}

function allowedByRateLimit(address) {
  const now = Date.now();
  const prior = (rateLimits.get(address) || []).filter((at) => now - at < RATE_LIMIT_WINDOW_MS);
  if (prior.length >= RATE_LIMIT_COUNT) {
    rateLimits.set(address, prior);
    return false;
  }
  prior.push(now);
  rateLimits.set(address, prior);
  return true;
}

function pruneJobs() {
  const cutoff = Date.now() - JOB_TTL_MS;
  for (const [id, job] of jobs) {
    if (job.updatedAt < cutoff && !["queued", "running"].includes(job.status)) jobs.delete(id);
  }
  for (const [address, timestamps] of rateLimits) {
    const recent = timestamps.filter((at) => Date.now() - at < RATE_LIMIT_WINDOW_MS);
    if (recent.length) rateLimits.set(address, recent);
    else rateLimits.delete(address);
  }
}

function updateJob(job, update) {
  Object.assign(job, update, { updatedAt: Date.now() });
}

async function runQueue(analyzer = analyzeWebsite) {
  while (activeJobs < MAX_JOBS && queue.length) {
    const job = queue.shift();
    if (!job || job.status !== "queued") continue;
    activeJobs += 1;
    updateJob(job, { status: "running" });
    analyzer(job.url, (event) => {
      job.progress.push(event);
      updateJob(job, {});
    }).then((report) => {
      updateJob(job, { status: "completed", report, completedAt: new Date().toISOString() });
    }).catch((error) => {
      job.progress.push({ id: "analysis", label: "Analysis", status: "failed", detail: error.message, at: new Date().toISOString() });
      updateJob(job, { status: "failed", error: error.message, completedAt: new Date().toISOString() });
    }).finally(() => {
      activeJobs -= 1;
      runQueue(analyzer);
    });
  }
}

async function readJson(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error("Request body exceeds 8 KB.");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("Request body must be valid JSON.");
  }
}

async function serveStatic(pathname, res) {
  const path = pathname === "/" ? "/index.html" : pathname;
  const file = resolve(PUBLIC_DIR, `.${path}`);
  if (!file.startsWith(`${PUBLIC_DIR}${sep}`)) {
    res.writeHead(404).end();
    return;
  }
  try {
    const body = await readFile(file);
    const contentTypes = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml" };
    res.writeHead(200, {
      "content-type": contentTypes[extname(file)] || "application/octet-stream",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "cache-control": "no-cache",
      "content-security-policy": "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    });
    res.end(body);
  } catch (error) {
    if (error.code === "ENOENT") res.writeHead(404).end("Not found");
    else throw error;
  }
}

export function createAppServer({ analyzer = analyzeWebsite } = {}) {
  return createServer(async (req, res) => {
    try {
      const pathname = new URL(req.url || "/", "http://localhost").pathname;
      if (req.method === "POST" && pathname === "/api/analyze") {
        if (!allowedByRateLimit(clientAddress(req))) return json(res, 429, { error: "Rate limit reached. Try again later." });
        let body;
        try {
          body = await readJson(req);
          validateTarget(body.url);
        } catch (error) {
          return json(res, 400, { error: error.message });
        }
        pruneJobs();
        if (activeJobs >= MAX_JOBS && queue.length >= MAX_QUEUE) return json(res, 503, { error: "Analysis queue is full; try again shortly." });
        const id = randomUUID();
        const job = {
          id, url: body.url, status: "queued", createdAt: new Date().toISOString(),
          updatedAt: Date.now(), progress: [], report: null, error: null,
        };
        jobs.set(id, job);
        queue.push(job);
        runQueue(analyzer);
        return json(res, 202, { analysisId: id, status: job.status });
      }

      const match = pathname.match(/^\/api\/analyze\/([0-9a-f-]{36})(?:\/(report|progress))?$/i);
      if (req.method === "GET" && match) {
        const job = jobs.get(match[1]);
        if (!job) return json(res, 404, { error: "Analysis not found or expired." });
        if (match[2] === "report") {
          if (job.status !== "completed") return json(res, 409, { error: "Report is not ready.", status: job.status, detail: job.error });
          return json(res, 200, { analysisId: job.id, report: job.report });
        }
        return json(res, 200, {
          analysisId: job.id, status: job.status, createdAt: job.createdAt,
          progress: job.progress, error: job.error,
          report: job.status === "completed" ? job.report : undefined,
        });
      }
      if (req.method === "GET" && pathname === "/api/device-profiles") {
        return json(res, 200, { available: false, profiles: [], reason: "Browser emulation is not configured in this deployment." });
      }
      if (req.method === "GET" && pathname === "/api/health") {
        return json(res, 200, { status: "ok", queueDepth: queue.length, activeJobs, browserWorker: "unavailable" });
      }
      if (req.method === "GET") return await serveStatic(pathname, res);
      json(res, 404, { error: "Not found." });
    } catch (error) {
      if (!res.headersSent) json(res, 500, { error: "Unexpected server error." });
      else res.destroy(error);
      console.error(error);
    }
  });
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const server = createAppServer();
  server.listen(PORT, HOST, () => console.log(`DeviceFit AI listening on http://${HOST}:${PORT}`));
  const cleanup = setInterval(pruneJobs, 5 * 60 * 1000);
  cleanup.unref();
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => server.close(() => process.exit(0)));
  }
}
