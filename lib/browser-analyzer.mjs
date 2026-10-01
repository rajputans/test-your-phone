import { readFile } from "node:fs/promises";
import { chromium } from "playwright";
import { safeFetch, MAX_REQUEST_BYTES } from "./safe-fetch.mjs";
import { resolvePublicHost, validateTarget } from "./safety.mjs";
import { analyzeCookies } from "./cookie-analysis.mjs";

const AXE_SOURCE = await readFile(new URL("../node_modules/axe-core/axe.min.js", import.meta.url), "utf8");
const MAX_PROFILES = 3;
const MAX_PAGE_REQUESTS = 60;
const MAX_ANALYSIS_REQUESTS = 150;
const MAX_ANALYSIS_BYTES = 24 * 1024 * 1024;
const MAX_ANALYSIS_DURATION_MS = 75_000;
const MAX_SCREENSHOT_BYTES = 400 * 1024;
const EXTRA_VIEWPORTS = {
  "budget-phone": [{ width: 390, height: 844 }, { width: 412, height: 915 }],
  "mid-tablet": [{ width: 768, height: 1024 }],
  "budget-laptop": [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }],
};

const PROFILE_DEFINITIONS = [
  {
    id: "budget-phone",
    label: "Budget Android phone (emulated)",
    category: "Phone",
    viewport: { width: 360, height: 800 },
    isMobile: true,
    deviceScaleFactor: 1,
    userAgent: "Mozilla/5.0 (Linux; Android 13; DeviceFit Budget Phone) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    cpuSlowdown: 4,
    network: { id: "slow-4g", latencyMs: 150, downlinkKbps: 1_600, label: "Slow 4G estimate" },
    estimatedBudget: "₹8,000–₹20,000 class; current product price not checked",
  },
  {
    id: "mid-tablet",
    label: "Mid-range Android tablet (emulated)",
    category: "Tablet",
    viewport: { width: 820, height: 1180 },
    isMobile: true,
    deviceScaleFactor: 1,
    userAgent: "Mozilla/5.0 (Linux; Android 13; DeviceFit Tablet) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    cpuSlowdown: 2.5,
    network: { id: "4g", latencyMs: 70, downlinkKbps: 4_000, label: "4G estimate" },
    estimatedBudget: "₹12,000–₹30,000 class; current product price not checked",
  },
  {
    id: "budget-laptop",
    label: "Budget Windows laptop (emulated)",
    category: "Laptop",
    viewport: { width: 1366, height: 768 },
    isMobile: false,
    deviceScaleFactor: 1,
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    cpuSlowdown: 2,
    network: { id: "4g", latencyMs: 45, downlinkKbps: 8_000, label: "Fast 4G estimate" },
    estimatedBudget: "₹25,000–₹60,000 class; current product price not checked",
  },
];

export const NETWORK_SCENARIOS = [
  { id: "fast-4g", latencyMs: 45, downlinkKbps: 8_000, label: "Fast 4G emulation" },
  { id: "4g", latencyMs: 70, downlinkKbps: 4_000, label: "4G emulation" },
  { id: "slow-4g", latencyMs: 150, downlinkKbps: 1_600, label: "Slow 4G emulation" },
];

function progress(onProgress, id, label, status, detail) {
  onProgress({ id, label, status, detail, at: new Date().toISOString() });
}

function hostLabel(value) {
  try {
    return new URL(value).hostname;
  } catch {
    return "unknown";
  }
}

function sanitizeMessage(message) {
  return String(message).replace(/https?:\/\/[^\s"'<>]+/gi, "[URL]").slice(0, 220);
}

function resourceCategory(type, contentType = "") {
  if (type === "script" || /javascript|ecmascript/i.test(contentType)) return "javascript";
  if (type === "stylesheet" || /text\/css/i.test(contentType)) return "css";
  if (type === "image" || /^image\//i.test(contentType)) return "image";
  return "other";
}

function waitFor(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function throttle(bytes, network) {
  const transferMs = bytes * 8 / (network.downlinkKbps * 1000) * 1000;
  await waitFor(Math.min(network.latencyMs + transferMs, 5_000));
}

function createLayoutScript() {
  return `(() => {
    for (const name of ["RTCPeerConnection", "webkitRTCPeerConnection", "RTCRtpSender", "WebTransport"]) {
      try { Object.defineProperty(window, name, { configurable: false, value: undefined }); } catch {}
    }
    try { Object.defineProperty(navigator, "sendBeacon", { configurable: false, value: () => false }); } catch {}
    window.__devicefit = { lcp: null, cls: 0, longTaskMs: 0, longTaskBlockingMs: 0, longTaskCount: 0 };
    try {
      new PerformanceObserver(list => {
        const entries = list.getEntries();
        if (entries.length) window.__devicefit.lcp = entries[entries.length - 1].startTime;
      }).observe({ type: "largest-contentful-paint", buffered: true });
      new PerformanceObserver(list => {
        for (const entry of list.getEntries()) {
          if (!entry.hadRecentInput) window.__devicefit.cls += entry.value;
        }
      }).observe({ type: "layout-shift", buffered: true });
      new PerformanceObserver(list => {
        for (const entry of list.getEntries()) {
          window.__devicefit.longTaskMs += entry.duration;
          window.__devicefit.longTaskBlockingMs += Math.max(0, entry.duration - 50);
          window.__devicefit.longTaskCount += 1;
        }
      }).observe({ type: "longtask", buffered: true });
    } catch {}
  })();`;
}

async function inspectLayout(page) {
  return page.evaluate(() => {
    const root = document.documentElement;
    const body = document.body;
    const width = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const overflow = Math.max(root.scrollWidth, body?.scrollWidth || 0) > width + 1;
    const outOfBounds = [];
    const smallTargets = [];
    const items = [...document.querySelectorAll("a,button,input,select,textarea,[role=button],[onclick],img,video,canvas")];
    for (const element of items) {
      const rect = element.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) continue;
      if (rect.right > width + 2 || rect.left < -2) {
        outOfBounds.push({ tag: element.tagName.toLowerCase(), text: (element.getAttribute("aria-label") || element.textContent || "").trim().slice(0, 50), right: Math.round(rect.right), width: Math.round(rect.width) });
      }
      if (element.matches("a,button,input,select,textarea,[role=button],[onclick]") && Math.min(rect.width, rect.height) < 44) {
        smallTargets.push({ tag: element.tagName.toLowerCase(), label: (element.getAttribute("aria-label") || element.textContent || "").trim().slice(0, 45), width: Math.round(rect.width), height: Math.round(rect.height) });
      }
    }
    const images = [...document.images].filter((image) => image.getBoundingClientRect().right > width + 2).length;
    const viewportMeta = Boolean(document.querySelector('meta[name="viewport"]'));
    const bodyTextLength = (body?.innerText || "").trim().length;
    const nav = performance.getEntriesByType("navigation")[0];
    const paints = performance.getEntriesByType("paint");
    const paint = (name) => paints.find((entry) => entry.name === name)?.startTime ?? null;
    const resources = performance.getEntriesByType("resource");
    const totals = { javascript: 0, css: 0, image: 0, other: 0, thirdPartyRequests: 0, knownTransferredBytes: 0 };
    for (const resource of resources) {
      const kind = resource.initiatorType === "script" ? "javascript" : resource.initiatorType === "css" ? "css" : ["img", "image"].includes(resource.initiatorType) ? "image" : "other";
      totals[kind] += resource.transferSize || resource.encodedBodySize || 0;
      totals.knownTransferredBytes += resource.transferSize || 0;
      try { if (new URL(resource.name).origin !== location.origin) totals.thirdPartyRequests += 1; } catch {}
    }
    return {
      viewport: { width, height: viewportHeight, documentWidth: Math.max(root.scrollWidth, body?.scrollWidth || 0) },
      horizontalOverflow: overflow,
      outOfBoundsCount: outOfBounds.length,
      outOfBoundsElements: outOfBounds.slice(0, 10),
      overflowingImageCount: images,
      touchTargetsUnder44px: smallTargets.length,
      smallTouchTargetExamples: smallTargets.slice(0, 8),
      viewportMetaPresent: viewportMeta,
      bodyTextLength,
      navigation: nav ? {
        domContentLoadedMs: nav.domContentLoadedEventEnd ? nav.domContentLoadedEventEnd - nav.startTime : null,
        loadEventMs: nav.loadEventEnd ? nav.loadEventEnd - nav.startTime : null,
        responseStartMs: nav.responseStart || null,
        transferSize: nav.transferSize || null,
      } : null,
      fcpMs: paint("first-contentful-paint"),
      lcpMs: window.__devicefit?.lcp ?? null,
      cls: window.__devicefit?.cls ?? null,
      longTaskMs: window.__devicefit?.longTaskMs ?? null,
      longTaskBlockingMs: window.__devicefit?.longTaskBlockingMs ?? null,
      longTaskCount: window.__devicefit?.longTaskCount ?? 0,
      resources: totals,
      resourceCount: resources.length,
    };
  });
}

async function runAccessibility(page, cdp) {
  try {
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: AXE_SOURCE, runImmediately: true });
  } catch {
    await page.addScriptTag({ content: AXE_SOURCE });
  }
  const result = await page.evaluate(async () => {
    const audit = await window.axe.run(document, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] },
    });
    return {
      violations: audit.violations.map((item) => ({
        id: item.id,
        impact: item.impact || "unknown",
        help: item.help,
        helpUrl: item.helpUrl,
        affectedElementCount: item.nodes.length,
      })),
      passes: audit.passes.length,
      incomplete: audit.incomplete.length,
      rulesRun: audit.passes.length + audit.violations.length + audit.incomplete.length,
    };
  });
  return result;
}

async function captureResponsiveViewports(page, profile, shared, onProgress, onScreenshot) {
  const sizes = EXTRA_VIEWPORTS[profile.id] || [];
  const results = [];
  if (!sizes.length) return results;
  progress(onProgress, `responsive-${profile.id}`, `Additional ${profile.category.toLowerCase()} viewport checks`, "running",
    `Testing ${sizes.map(({ width, height }) => `${width}×${height}`).join(", ")} in the same real Chromium session.`);
  for (const viewport of sizes) {
    await page.setViewportSize(viewport);
    await waitFor(120);
    const layout = await inspectLayout(page);
    const screenshotId = `${profile.id}-${viewport.width}x${viewport.height}`;
    const shot = await page.screenshot({ type: "jpeg", quality: 55, fullPage: false, animations: "disabled", timeout: 3_000 }).catch(() => null);
    let screenshot = null;
    if (shot && shot.length <= MAX_SCREENSHOT_BYTES) {
      screenshot = { url: `/api/analyze/${shared.analysisId}/screenshots/${screenshotId}`, mimeType: "image/jpeg", bytes: shot.length };
      onScreenshot(screenshotId, screenshot.mimeType, shot);
    }
    const result = { profile: profile.label, viewport, layout, screenshot };
    results.push(result);
    shared.responsiveChecks.push(result);
    if (layout.horizontalOverflow) {
      shared.issues.push({
        severity: "medium",
        category: "Responsiveness",
        title: `Horizontal overflow at ${viewport.width}×${viewport.height}`,
        evidence: `Document width ${layout.viewport.documentWidth}px exceeds viewport width ${viewport.width}px in Chromium.`,
        recommendation: "Inspect fixed-width content and responsive breakpoints at this viewport.",
        affectedDevices: [profile.label],
      });
    }
    if (profile.isMobile && !layout.viewportMetaPresent) {
      shared.issues.push({
        severity: "medium",
        category: "Responsiveness",
        title: `Viewport meta tag not found at ${viewport.width}×${viewport.height}`,
        evidence: "The page did not expose a meta viewport tag in this mobile Chromium session.",
        recommendation: 'Set a viewport meta tag such as width=device-width, initial-scale=1.',
        affectedDevices: [profile.label],
      });
    }
  }
  progress(onProgress, `responsive-${profile.id}`, `Additional ${profile.category.toLowerCase()} viewport checks`, "completed",
    `Captured ${results.filter((result) => result.screenshot).length} additional viewport screenshot(s); checked layout at ${results.length} sizes.`);
  return results;
}

function withTimeout(promise, timeoutMs, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} exceeded ${timeoutMs} ms.`)), timeoutMs); }),
  ]).finally(() => clearTimeout(timer));
}

export function calculateScenarioSuitability(profile) {
  const performanceMetrics = profile.metrics;
  const layout = profile.layout;
  if (!performanceMetrics?.lcpMs && performanceMetrics?.lcpMs !== 0) return null;
  const lcp = performanceMetrics.lcpMs;
  const size = profile.network.totalBytes;
  const blocking = performanceMetrics.longTaskMs ?? 0;
  let score = (lcp <= 2500 ? 30 : lcp <= 4000 ? 20 : 8)
    + (size <= 2 * 1024 * 1024 ? 20 : size <= 5 * 1024 * 1024 ? 12 : 4)
    + (blocking <= 200 ? 20 : blocking <= 600 ? 12 : 4)
    + (!layout.horizontalOverflow ? 15 : 0)
    + (layout.touchTargetsUnder44px === 0 ? 10 : 5)
    + (layout.viewportMetaPresent ? 5 : 0);
  score = Math.max(0, Math.min(100, score));
  return {
    value: score,
    label: score >= 85 ? "Smooth in this emulated scenario" : score >= 65 ? "Usable; some optimization may help" : "Likely constrained in this emulated scenario",
    method: "Measured LCP, downloaded response bytes, observed long tasks, viewport overflow, small touch targets, and viewport metadata.",
    note: "This scenario score is an estimate from emulated browser conditions, not a test of a physical device or a universal suitability guarantee.",
  };
}

export function hasRenderedContent(layout, metrics) {
  return layout.bodyTextLength > 0 || metrics.fcpMs !== null || metrics.lcpMs !== null;
}

async function runProfile(browser, baseUrl, profile, shared, onProgress, onScreenshot, fetchPublicResource) {
  const userAgent = profile.userAgent.replace(/Chrome\/\d+/, `Chrome/${browser.version().split(".")[0]}`);
  progress(onProgress, `browser-${profile.id}`, profile.label, "running", `Launching real Chromium at ${profile.viewport.width}×${profile.viewport.height} with ${profile.cpuSlowdown}× CPU and ${profile.network.label} throttling.`);
  const context = await browser.newContext({
    viewport: profile.viewport,
    deviceScaleFactor: profile.deviceScaleFactor,
    isMobile: profile.isMobile,
    hasTouch: profile.isMobile,
    userAgent,
    serviceWorkers: "block",
    acceptDownloads: false,
    ignoreHTTPSErrors: false,
    javaScriptEnabled: true,
  });
  const cdp = await context.newCDPSession(await context.newPage());
  await cdp.send("Emulation.setCPUThrottlingRate", { rate: profile.cpuSlowdown });
  await cdp.send("Network.enable");
  await cdp.send("Network.emulateNetworkConditions", {
    offline: false,
    latency: profile.network.latencyMs,
    downloadThroughput: profile.network.downlinkKbps * 125,
    uploadThroughput: 128 * 1024,
    connectionType: "cellular4g",
  });
  const page = context.pages()[0];
  const state = {
    originHost: new URL(baseUrl).hostname,
    requestCount: 0,
    resources: [],
    domains: new Set(),
    failures: [],
    mixedContent: [],
    redirects: [],
  };
  let profileBytes = 0;
  const consoleCounts = { errors: 0, warnings: 0, pageErrors: 0 };
  let finalHttpStatus = null;
  let finalUrl = baseUrl;

  await context.addInitScript({ content: createLayoutScript() });
  page.on("console", (message) => {
    if (message.type() === "error") consoleCounts.errors += 1;
    if (message.type() === "warning") consoleCounts.warnings += 1;
  });
  page.on("pageerror", () => { consoleCounts.pageErrors += 1; });
  page.on("response", async (response) => {
    if (response.request().isNavigationRequest() && response.frame() === page.mainFrame()) {
      finalHttpStatus = response.status();
      finalUrl = response.url();
    }
  });
  context.on("page", (popup) => { if (popup !== page) popup.close().catch(() => {}); });

  await context.route("**/*", async (route) => {
    const request = route.request();
    const requestUrl = request.url();
    const method = request.method();
    let protocol;
    try {
      protocol = new URL(requestUrl).protocol;
    } catch {
      return route.abort("blockedbyclient");
    }
    if (!["http:", "https:"].includes(protocol)) return route.abort("blockedbyclient");
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) return route.abort("blockedbyclient");
    if (request.resourceType() === "websocket") return route.abort("blockedbyclient");
    if (baseUrl.startsWith("https:") && protocol === "http:") {
      state.mixedContent.push(hostLabel(requestUrl));
      shared.mixedContent.add(hostLabel(requestUrl));
      shared.issues.push({
        severity: "high", category: "Mixed content",
        title: "Insecure HTTP resource referenced by an HTTPS page",
        evidence: `Chromium attempted an HTTP subresource request to ${hostLabel(requestUrl)}. The analyzer blocked the insecure request.`,
        recommendation: "Serve the resource over HTTPS and update its URL.",
        affectedDevices: [profile.label],
      });
      return route.abort("blockedbyclient");
    }
    if (state.requestCount >= MAX_PAGE_REQUESTS || shared.requestCount >= MAX_ANALYSIS_REQUESTS) {
      shared.failures.push({ host: hostLabel(requestUrl), reason: "browser request limit reached" });
      return route.abort("blockedbyclient");
    }
    state.requestCount += 1;
    try {
      const target = validateTarget(requestUrl);
      state.domains.add(target.hostname);
      shared.domains.add(target.hostname);
      const result = await fetchPublicResource(target, shared, { method, headers: await request.allHeaders() });
      profileBytes += result.body.length;
      const contentType = String(result.headers["content-type"] || "");
      const kind = resourceCategory(request.resourceType(), contentType);
      state.resources.push({ host: target.hostname, bytes: result.body.length, kind, status: result.status });
      if (result.headers["content-type"]) shared.contentTypes.add(contentType.split(";")[0]);
      await throttle(result.body.length, profile.network);
      const headers = {
        "content-type": contentType || "application/octet-stream",
        "x-content-type-options": "nosniff",
      };
      for (const name of [
        "content-encoding", "content-language", "content-security-policy",
        "content-security-policy-report-only", "cache-control", "expires",
        "access-control-allow-origin", "access-control-allow-credentials",
        "access-control-allow-headers", "access-control-allow-methods", "vary",
        "strict-transport-security", "x-frame-options", "referrer-policy",
        "permissions-policy", "cross-origin-resource-policy", "cross-origin-opener-policy",
      ]) {
        if (result.headers[name]) headers[name] = Array.isArray(result.headers[name])
          ? result.headers[name].join(", ")
          : String(result.headers[name]);
      }
      if (result.headers.location) headers.location = result.headers.location;
      if ([301, 302, 303, 307, 308].includes(result.status)) {
        shared.redirectCount += 1;
        if (shared.redirectCount > 10) throw new Error("Analysis redirect limit reached.");
        state.redirects.push({ status: result.status, from: hostLabel(requestUrl), to: hostLabel(result.headers.location) });
      }
      if (result.headers["content-length"] && result.status !== 301 && result.status !== 302 && result.status !== 303 && result.status !== 307 && result.status !== 308) {
        headers["content-length"] = String(result.body.length);
      }
      if (request.isNavigationRequest() && request.frame() === page.mainFrame()) {
        const finalTarget = validateTarget(result.url);
        await resolvePublicHost(finalTarget.hostname);
        const safeHeaderNames = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "set-cookie"];
        for (const name of safeHeaderNames) {
          if (result.headers[name] && name !== "set-cookie") shared.responseHeaders[name] = Array.isArray(result.headers[name]) ? result.headers[name].join(", ") : String(result.headers[name]);
        }
        shared.responseCookies = analyzeCookies(result.headers["set-cookie"]);
      }
      await route.fulfill({ status: result.status || 502, headers, body: method === "HEAD" || method === "OPTIONS" ? undefined : result.body });
    } catch (error) {
      state.failures.push({ host: hostLabel(requestUrl), reason: sanitizeMessage(error.message) });
      shared.failures.push({ host: hostLabel(requestUrl), reason: sanitizeMessage(error.message) });
      await route.abort("failed").catch(() => {});
    }
  });
  const socketRouting = context.routeWebSocket;
  if (typeof socketRouting === "function") {
    await context.routeWebSocket("**/*", (socket) => socket.close());
  }

  let layout = null;
  let accessibility = { status: "unavailable", reason: null, violations: [], passes: 0, incomplete: 0 };
  let screenshot = null;
  const started = Date.now();
  try {
    page.setDefaultTimeout(8_000);
    const elapsed = Date.now() - shared.startedAt;
    const profileTimeRemaining = Math.max(1_000, Math.min(15_000, MAX_ANALYSIS_DURATION_MS - elapsed));
    const response = await page.goto(baseUrl, { waitUntil: "domcontentloaded", timeout: profileTimeRemaining });
    finalHttpStatus = response?.status() ?? finalHttpStatus;
    finalUrl = page.url();
    await page.waitForLoadState("networkidle", { timeout: Math.min(2_000, profileTimeRemaining) }).catch(() => {});
    await page.waitForTimeout(400);
    layout = await inspectLayout(page);
    accessibility = { status: "measured", ...(await withTimeout(runAccessibility(page, cdp), 6_000, "axe-core audit")) };
    const shot = await page.screenshot({ type: "jpeg", quality: 60, fullPage: false, animations: "disabled", timeout: 3_000 });
    if (shot.length <= MAX_SCREENSHOT_BYTES) {
      screenshot = { mimeType: "image/jpeg", bytes: shot };
      onScreenshot(profile.id, screenshot.mimeType, shot);
    }
    const responsiveChecks = await captureResponsiveViewports(page, profile, shared, onProgress, onScreenshot);
    const imageUrls = await page.locator("img").evaluateAll((images) => images.map((image) => image.currentSrc).filter(Boolean).slice(0, 30));
    const frameHosts = await page.locator("iframe").evaluateAll((frames) => frames.map((frame) => {
      try { return new URL(frame.src).hostname; } catch { return null; }
    }).filter(Boolean).slice(0, 30));
    const downloadLinks = await page.locator("a[href]").evaluateAll((links) => links.map((link) => {
      try {
        const url = new URL(link.href);
        return /\.(?:exe|msi|bat|cmd|ps1|sh|apk|dmg|pkg|app|com|scr)(?:$|\/)/i.test(url.pathname);
      } catch { return false; }
    }).filter(Boolean).length);
    const metrics = await page.evaluate(() => {
      const navigation = performance.getEntriesByType("navigation")[0];
      const value = (item) => Number.isFinite(item) && item >= 0 ? item : null;
      const paint = performance.getEntriesByType("paint").find((entry) => entry.name === "first-contentful-paint");
      return {
        fcpMs: value(paint?.startTime),
        lcpMs: value(window.__devicefit?.lcp),
        cls: value(window.__devicefit?.cls),
        longTaskMs: value(window.__devicefit?.longTaskMs),
        longTaskBlockingMs: value(window.__devicefit?.longTaskBlockingMs),
        longTaskCount: window.__devicefit?.longTaskCount || 0,
        domContentLoadedMs: value(navigation?.domContentLoadedEventEnd),
        loadEventMs: value(navigation?.loadEventEnd),
        resourceCount: performance.getEntriesByType("resource").length,
        browserMemoryBytes: value(performance.memory?.usedJSHeapSize),
      };
    });
    const pageRendered = hasRenderedContent(layout, metrics);
    if (!pageRendered) {
      accessibility = {
        ...accessibility,
        status: "not_representative",
        note: "The response produced no visible text or paint timing; accessibility results may describe a block/challenge page rather than the intended site.",
      };
      shared.issues.push({
        severity: "medium",
        category: "Browser analysis",
        title: `No visible page content rendered in ${profile.label}`,
        evidence: `Chromium received HTTP ${finalHttpStatus ?? "unknown"}, but observed no visible text, First Contentful Paint, or Largest Contentful Paint.`,
        recommendation: "The site may serve an anti-bot challenge, require authentication, or defer content beyond the analysis window. Retry or review the page manually; device suitability is not estimated.",
        affectedDevices: [profile.label],
      });
    }
    const hostCounts = new Map();
    let jsBytes = 0;
    let cssBytes = 0;
    let imageBytes = 0;
    for (const resource of state.resources) {
      hostCounts.set(resource.host, (hostCounts.get(resource.host) || 0) + resource.bytes);
      if (resource.kind === "javascript") jsBytes += resource.bytes;
      if (resource.kind === "css") cssBytes += resource.bytes;
      if (resource.kind === "image") imageBytes += resource.bytes;
    }
    const thirdPartyDomains = [...state.domains].filter((host) => host !== state.originHost);
    const failedRequests = state.failures;
    const brokenImageCount = imageUrls.length ? await page.locator("img").evaluateAll((images) => images.filter((image) => !image.complete || image.naturalWidth === 0).length) : 0;
    if (layout.horizontalOverflow) {
      shared.issues.push({
        severity: "medium", category: "Responsiveness",
        title: `Horizontal overflow at ${profile.viewport.width}×${profile.viewport.height}`,
        evidence: `Document width ${layout.viewport.documentWidth}px exceeds viewport width ${profile.viewport.width}px.`,
        recommendation: "Inspect fixed-width content and responsive breakpoints at this viewport.",
        affectedDevices: [profile.label],
      });
    }
    if (!layout.viewportMetaPresent && profile.isMobile) {
      shared.issues.push({
        severity: "medium", category: "Responsiveness", title: "Viewport meta tag not found",
        evidence: "The page does not expose a meta viewport tag in this mobile browser session.",
        recommendation: 'Set a viewport meta tag such as width=device-width, initial-scale=1.',
        affectedDevices: [profile.label],
      });
    }
    if (brokenImageCount > 0) {
      shared.issues.push({
        severity: "low", category: "Resources",
        title: `${brokenImageCount} image(s) failed in ${profile.label}`,
        evidence: `The browser found ${brokenImageCount} image elements that did not load successfully.`,
        recommendation: "Check image URLs and public resource availability.",
        affectedDevices: [profile.label],
      });
    }
    if (profile.isMobile && layout.smallTouchTargetExamples.length > 0) {
      shared.issues.push({
        severity: "low", category: "Touch usability", title: "Small interactive targets observed",
        evidence: `${layout.touchTargetsUnder44px} visible interactive elements measured under 44 CSS pixels in at least one dimension.`,
        recommendation: "Increase interactive target size or spacing where appropriate.",
        affectedDevices: [profile.label],
      });
    }
    const technologies = await page.evaluate(() => {
      const scripts = [...document.scripts].map((script) => script.src).filter(Boolean);
      const metaGenerator = document.querySelector('meta[name="generator"]')?.content || null;
      const matches = [
        ["Next.js", () => Boolean(window.next || document.querySelector("#__next"))],
        ["React", () => Boolean(window.React || document.querySelector("[data-reactroot], [data-reactroot='']"))],
        ["Vue", () => Boolean(window.Vue || document.querySelector("[data-v-app], #app[data-v-app]"))],
        ["Angular", () => Boolean(window.angular || document.querySelector("[ng-version]"))],
        ["jQuery", () => Boolean(window.jQuery || window.$?.fn?.jquery)],
        ["WordPress", () => Boolean(window.wp || /wp-content|wp-includes/i.test(location.pathname) || scripts.some((src) => /wp-content|wp-includes/i.test(src)))],
        ["Google Tag Manager", () => Boolean(window.google_tag_manager || scripts.some((src) => /googletagmanager\.com/i.test(src)))],
        ["Cloudflare", () => Boolean(window.__cf_bm || document.querySelector('script[src*="cloudflare"]'))],
      ];
      return { metaGenerator, detected: matches.filter(([, test]) => { try { return test(); } catch { return false; } }).map(([name]) => name) };
    });
    const score = finalHttpStatus >= 400 || !pageRendered
      ? null
      : calculateScenarioSuitability({ metrics, layout, network: { totalBytes: profileBytes } });
    const result = {
      id: profile.id,
      label: profile.label,
      category: profile.category,
      configuration: {
        viewport: profile.viewport,
        deviceScaleFactor: profile.deviceScaleFactor,
        userAgent,
        cpuSlowdown: profile.cpuSlowdown,
        network: profile.network,
        actualPhysicalDeviceTest: false,
        browserVersion: browser.version(),
      },
      status: "measured",
      renderStatus: pageRendered ? "rendered" : "empty_or_blocked",
      httpStatus: finalHttpStatus,
      finalUrl,
      measuredAt: new Date().toISOString(),
      durationMs: Date.now() - started,
      metrics: {
        ...metrics,
        inpMs: null,
        inpNote: "No real user input occurred; INP cannot be measured in this automated page load.",
        javascriptBytes: jsBytes,
        cssBytes,
        imageBytes,
        totalResourceBytes: profileBytes,
        thirdPartyRequestCount: state.resources.filter((resource) => resource.host !== state.originHost).length,
        resourceCount: state.resources.length,
        performanceResourceTimingCount: metrics.resourceCount,
        thirdPartyDomains,
        redirectCount: state.redirects.length,
        mixedContentRequestsBlocked: state.mixedContent.length,
        failedRequestCount: failedRequests.length,
        brokenImageCount,
        consoleErrorCount: consoleCounts.errors,
        consoleWarningCount: consoleCounts.warnings,
        pageErrorCount: consoleCounts.pageErrors,
        iframeCount: frameHosts.length,
        iframeHosts: frameHosts,
        executableDownloadLinksObserved: downloadLinks,
        mixedContentRequestsBlocked: state.mixedContent.length,
        ...layout.resources,
      },
      technologies: {
        dataSource: "Observed browser globals, DOM markers, script URLs, and public generator metadata",
        metaGenerator: technologies.metaGenerator,
        detected: technologies.detected,
      },
      security: {
        setCookieFlags: shared.responseCookies || analyzeCookies(undefined),
        note: "Response headers were observed by the safe request bridge; cookie values are excluded from report data.",
      },
      securityHeaders: { ...shared.responseHeaders },
      layout,
      accessibility: {
        ...accessibility,
        note: "Automated axe-core WCAG tag checks are not a complete accessibility audit.",
      },
      responsiveChecks,
      suitability: score
        ? { ...score, estimatedPriceBand: profile.estimatedBudget, dataSource: "Estimated from actual Chromium measurements in an emulated CPU/network profile; not a product recommendation or physical-device test." }
        : { value: null, label: "Not estimated", reason: pageRendered ? "Largest Contentful Paint was unavailable." : "The browser received no visible page content or paint timing; suitability would not be representative." },
      issues: failedRequests,
      screenshot: screenshot ? { url: `/api/analyze/${shared.analysisId}/screenshots/${profile.id}`, mimeType: screenshot.mimeType, bytes: screenshot.bytes } : null,
    };
    shared.profiles.push(result);
    for (const host of hostCounts.keys()) shared.domains.add(host);
    for (const host of thirdPartyDomains) shared.thirdPartyDomains.add(host);
    if (finalHttpStatus && finalHttpStatus >= 400) {
      shared.issues.push({
        severity: "medium", category: "Reachability", title: `HTTP ${finalHttpStatus} in ${profile.label}`,
        evidence: `Real Chromium navigation received HTTP ${finalHttpStatus}.`,
        recommendation: "Confirm the expected public landing page and whether bot checks or method restrictions are involved.",
        affectedDevices: [profile.label],
      });
    }
    progress(onProgress, `browser-${profile.id}`, profile.label, "completed",
      pageRendered
        ? `Chromium rendered visible page content; collected layout, resource, accessibility and screenshot measurements in ${Date.now() - started} ms.`
        : `Chromium received a response but rendered no visible page content; suitability was not estimated (${Date.now() - started} ms).`);
    return result;
  } catch (error) {
    const pageError = sanitizeMessage(error.message);
    shared.issues.push({
      severity: "medium", category: "Browser analysis",
      title: `Could not complete ${profile.label}`,
      evidence: pageError,
      recommendation: "The site may block automated browsing, require authentication, or exceed a request/time/resource limit.",
      affectedDevices: [profile.label],
    });
    progress(onProgress, `browser-${profile.id}`, profile.label, "failed", `Browser test failed: ${pageError}`);
    const result = {
      id: profile.id,
      label: profile.label,
      category: profile.category,
      configuration: { viewport: profile.viewport, cpuSlowdown: profile.cpuSlowdown, network: profile.network, actualPhysicalDeviceTest: false, browserVersion: browser.version() },
      status: "failed",
      httpStatus: finalHttpStatus,
      finalUrl,
      error: pageError,
      durationMs: Date.now() - started,
      screenshot: screenshot ? { url: `/api/analyze/${shared.analysisId}/screenshots/${profile.id}`, mimeType: screenshot.mimeType, bytes: screenshot.bytes } : null,
    };
    shared.profiles.push(result);
    return result;
  } finally {
    await context.close().catch(() => {});
    await cdp.detach().catch(() => {});
  }
}

export async function runBrowserAnalysis(input, onProgress = () => {}, analysisId, onScreenshot = () => {}, fetchPublicResource = safeFetch) {
  const target = validateTarget(input);
  const started = Date.now();
  const shared = {
    analysisId,
    startedAt: Date.now(),
    profiles: [],
    issues: [],
    requestCount: 0,
    redirectCount: 0,
    totalBytes: 0,
    maxTotalBytes: MAX_ANALYSIS_BYTES,
    maxResourceBytes: MAX_REQUEST_BYTES,
    maxRequests: MAX_ANALYSIS_REQUESTS,
    inFlightBytes: 0,
    domains: new Set(),
    thirdPartyDomains: new Set(),
    failures: [],
    contentTypes: new Set(),
    responseHeaders: {},
    responseCookies: null,
    mixedContent: new Set(),
    screenshots: [],
    responsiveChecks: [],
  };
  progress(onProgress, "browser", "Isolated Chromium worker", "running", "Starting a real browser in per-analysis contexts with request interception and network limits.");
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    progress(onProgress, "browser", "Isolated Chromium worker", "completed", `Chromium ${browser.version()} started; untrusted pages cannot make direct browser HTTP requests.`);
    const storeScreenshot = (id, mimeType, bytes) => {
      const entry = {
        id,
        label: id.replaceAll("-", " "),
        url: `/api/analyze/${analysisId}/screenshots/${id}`,
        mimeType,
        bytes: bytes.length,
      };
      shared.screenshots.push(entry);
      onScreenshot(id, mimeType, bytes);
    };
    for (let index = 0; index < Math.min(PROFILE_DEFINITIONS.length, MAX_PROFILES); index += 1) {
      await runProfile(browser, target.toString(), PROFILE_DEFINITIONS[index], shared, onProgress, storeScreenshot, fetchPublicResource);
    }
  } catch (error) {
    progress(onProgress, "browser", "Isolated Chromium worker", "failed", `Browser worker could not complete: ${sanitizeMessage(error.message)}`);
    shared.issues.push({
      severity: "medium", category: "Browser analysis", title: "Browser worker unavailable",
      evidence: sanitizeMessage(error.message),
      recommendation: "Install the Playwright Chromium browser and ensure the worker has its required runtime dependencies.",
      affectedDevices: PROFILE_DEFINITIONS.map((profile) => profile.label),
    });
  } finally {
    await browser?.close().catch(() => {});
  }
  return {
    status: shared.profiles.some((profile) => profile.status === "measured") ? "measured" : "unavailable",
    engine: shared.profiles.some((profile) => profile.status === "measured") ? "Playwright Chromium" : "Unavailable",
    browserVersion: shared.profiles.find((profile) => profile.status === "measured")?.configuration.browserVersion || null,
    securityHeaders: shared.responseHeaders,
    responseCookies: shared.responseCookies,
    profiles: shared.profiles.map(({ screenshot, ...profile }) => screenshot ? { ...profile, screenshot: { url: screenshot.url, mimeType: screenshot.mimeType, bytes: screenshot.bytes.length } } : profile),
    screenshots: shared.profiles.filter((profile) => profile.screenshot).map((profile) => ({
      id: profile.id,
      label: profile.label,
      url: profile.screenshot.url,
      mimeType: profile.screenshot.mimeType,
      bytes: profile.screenshot.bytes.length,
    })),
    viewportScreenshots: shared.screenshots,
    responsiveChecks: shared.responsiveChecks,
    issues: shared.issues,
    network: {
      totalRequests: shared.requestCount,
      redirectCount: shared.redirectCount,
      bytesReceived: shared.totalBytes,
      domainsObserved: [...shared.domains],
      thirdPartyDomains: [...shared.thirdPartyDomains],
      failedResources: shared.failures.length,
      mixedContentHostsBlocked: [...shared.mixedContent],
      resourceContentTypesObserved: [...shared.contentTypes],
      requestLimits: {
        maxRequests: MAX_ANALYSIS_REQUESTS,
        maxBytes: MAX_ANALYSIS_BYTES,
        maxResourceBytes: MAX_REQUEST_BYTES,
      },
    },
    durationMs: Date.now() - started,
    note: "Chromium rendering, CPU slowdowns, resource byte counts, screenshots, layout observations, and axe-core findings are measured in emulated browser sessions. Devices remain emulated, not physical. CPU/network settings are reproducible scenarios, not exact handset hardware or a full real-world carrier path. All browser HTTP requests pass through a URL/DNS/IP-checking request bridge and are pinned to public IPs; write methods, downloads, service workers, WebSockets, WebRTC, and beacon telemetry are blocked.",
  };
}

export function getDeviceProfiles() {
  return PROFILE_DEFINITIONS.map(({ id, label, category, viewport, isMobile, deviceScaleFactor, cpuSlowdown, network, estimatedBudget }) => ({
    id, label, category, viewport, isMobile, deviceScaleFactor, cpuSlowdown, network,
    estimationOnly: true,
    estimatedBudgetBand: estimatedBudget,
    physicalDevicesTested: false,
  }));
}
