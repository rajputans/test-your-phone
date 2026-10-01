import http from "node:http";
import https from "node:https";
import { performance } from "node:perf_hooks";
import { resolvePublicHost, validateTarget } from "./safety.mjs";
import { analyzeCookies } from "./cookie-analysis.mjs";
import { runBrowserAnalysis } from "./browser-analyzer.mjs";
import { checkSafeBrowsing } from "./safe-browsing.mjs";

const REQUEST_TIMEOUT_MS = 10_000;
const DNS_TIMEOUT_MS = 5_000;
const MAX_REDIRECTS = 5;
const MAX_HEADER_BYTES = 16 * 1024;

async function resolveWithTimeout(hostname, resolveHost = resolvePublicHost) {
  let timeout;
  try {
    return await Promise.race([
      resolveHost(hostname),
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error("DNS lookup timed out after 5 seconds.")), DNS_TIMEOUT_MS);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function emit(onProgress, id, label, status, detail) {
  onProgress({ id, label, status, detail, at: new Date().toISOString() });
}

function pinnedRequest(url, address, family, method = "HEAD") {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    let connectedAt = null;
    let tlsAt = null;
    const transport = url.protocol === "https:" ? https : http;
    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    const request = transport.request({
      protocol: url.protocol,
      hostname,
      port: url.protocol === "https:" ? 443 : 80,
      method,
      path: `${url.pathname}${url.search}`,
      headers: {
        "user-agent": "DeviceFitAI/1.0 (+public diagnostic; bounded headers only)",
        accept: "*/*",
        connection: "close",
        ...(method === "GET" ? { range: "bytes=0-0" } : {}),
      },
      agent: false,
      rejectUnauthorized: true,
      maxHeaderSize: MAX_HEADER_BYTES,
      lookup: (_host, options, callback) => {
        if (options?.all) callback(null, [{ address, family }]);
        else callback(null, address, family);
      },
    }, (response) => {
      const headersAt = performance.now();
      const headers = response.headers;
      const statusCode = response.statusCode ?? 0;
      const result = {
        statusCode,
        method,
        headers,
        httpVersion: response.httpVersion,
        timing: {
          connectMs: connectedAt === null ? null : +(connectedAt - started).toFixed(1),
          tlsMs: tlsAt === null || connectedAt === null ? null : +(tlsAt - connectedAt).toFixed(1),
          ttfbMs: +(headersAt - started).toFixed(1),
          totalMs: +(headersAt - started).toFixed(1),
        },
        certificate: null,
      };
      const socket = response.socket;
      if (url.protocol === "https:" && socket?.authorized !== undefined) {
        const cert = socket.getPeerCertificate();
        result.certificate = {
          valid: socket.authorized,
          authorizationError: socket.authorizationError || null,
          expiresAt: cert.valid_to ? new Date(cert.valid_to).toISOString() : null,
          issuer: cert.issuer?.O || cert.issuer?.CN || null,
          protocol: socket.getProtocol?.() || null,
        };
      }
      response.destroy();
      resolve(result);
    });
    const wallTimeout = setTimeout(() => request.destroy(new Error("Request timed out after 10 seconds.")), REQUEST_TIMEOUT_MS);
    request.once("close", () => clearTimeout(wallTimeout));
    request.on("socket", (socket) => {
      socket.once("connect", () => { connectedAt = performance.now(); });
      socket.once("secureConnect", () => { tlsAt = performance.now(); });
    });
    request.setTimeout(REQUEST_TIMEOUT_MS, () => request.destroy(new Error("Request timed out after 10 seconds.")));
    request.once("error", (error) => {
      reject(new Error(error.code === "CERT_HAS_EXPIRED" || error.code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
        error.code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ? "TLS certificate validation failed." : error.message));
    });
    request.end();
  });
}

export async function requestPublicURL(startUrl, { resolveHost = resolvePublicHost, probe = pinnedRequest } = {}) {
  let current = startUrl;
  const redirects = [];
  const timings = [];
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    current = validateTarget(current.toString());
    const dnsStarted = performance.now();
    const addresses = await resolveWithTimeout(current.hostname, resolveHost);
    const dnsMs = +(performance.now() - dnsStarted).toFixed(1);
    const address = addresses[0];
    let response = await probe(current, address.address, address.family, "HEAD");
    let method = "HEAD";
    if ([405, 501].includes(response.statusCode)) {
      method = "GET";
      response = await probe(current, address.address, address.family, method);
    }
    timings.push({ dnsMs, ...response.timing, method });
    const location = response.headers.location;
    if ([301, 302, 303, 307, 308].includes(response.statusCode) && location) {
      if (hop === MAX_REDIRECTS) throw new Error("The target exceeded the 5-redirect safety limit.");
      const next = new URL(location, current);
      redirects.push({ statusCode: response.statusCode, from: current.origin, to: next.origin });
      current = next;
      continue;
    }
    return { finalUrl: current.toString(), redirects, timings, response };
  }
  throw new Error("The redirect limit was exceeded.");
}

function headerIssue(headers, name, label, recommendation) {
  const value = headers[name];
  return value
    ? { severity: "info", category: "Security headers", title: `${label} present`, evidence: `${name}: ${String(value).slice(0, 300)}`, recommendation: null }
    : { severity: "medium", category: "Security headers", title: `${label} not observed`, evidence: `The final response did not include ${name}.`, recommendation };
}

function securityHeaderIssues(headers, https, cookies) {
  const issues = [
    headerIssue(headers, "content-security-policy", "Content Security Policy", "Consider a restrictive Content-Security-Policy tailored to the site."),
    headerIssue(headers, "x-content-type-options", "MIME-sniffing protection", "Send X-Content-Type-Options: nosniff."),
    headerIssue(headers, "referrer-policy", "Referrer policy", "Set a Referrer-Policy appropriate for the site's privacy requirements."),
    headerIssue(headers, "permissions-policy", "Permissions policy", "Set a Permissions-Policy to disable browser features the site does not use."),
  ];
  const framePolicy = headers["content-security-policy"]?.toLowerCase().includes("frame-ancestors") || headers["x-frame-options"];
  issues.push(framePolicy
    ? { severity: "info", category: "Security headers", title: "Framing restriction observed", evidence: "X-Frame-Options or CSP frame-ancestors was present.", recommendation: null }
    : { severity: "medium", category: "Security headers", title: "Framing restriction not observed", evidence: "Neither X-Frame-Options nor CSP frame-ancestors was present.", recommendation: "Set CSP frame-ancestors or X-Frame-Options if embedding is not required." });
  if (https) issues.push(headerIssue(headers, "strict-transport-security", "HSTS", "Send Strict-Transport-Security after confirming HTTPS is deployed across the site."));
  if (cookies?.count && (!cookies.allSecure || !cookies.allHttpOnly || !cookies.allSameSite)) {
    issues.push({
      severity: "medium",
      category: "Cookies",
      title: "Some cookie security attributes are not present",
      evidence: `Cookie attributes observed on ${cookies.count} Set-Cookie headers: Secure ${cookies.secureCount}/${cookies.count}; HttpOnly ${cookies.httpOnlyCount}/${cookies.count}; SameSite ${cookies.sameSiteCount}/${cookies.count}. Cookie values were not retained.`,
      recommendation: "Review each cookie against its purpose; HttpOnly is not applicable to cookies intentionally read by client-side scripts.",
    });
  }
  return issues;
}

function measurement(value, dataSource, note = null) {
  return { value, dataSource, note };
}

export async function analyzeWebsite(input, onProgress = () => {}, { analysisId = null, onScreenshot = () => {}, shareUrlForThreatCheck = false } = {}) {
  const startedAt = new Date().toISOString();
  emit(onProgress, "url", "URL safety validation", "running", "Validating the URL and allowed protocol.");
  const url = validateTarget(input);
  emit(onProgress, "url", "URL safety validation", "completed", "HTTP(S) URL passed protocol and hostname checks.");

  emit(onProgress, "reachability", "DNS and reachability", "running", "Resolving the host and checking every returned address.");
  const { finalUrl, redirects, timings, response } = await requestPublicURL(url);
  const pageReachable = response.statusCode >= 200 && response.statusCode < 400;
  const methodRejected = [405, 501].includes(response.statusCode);
  emit(onProgress, "reachability", "DNS and reachability", pageReachable ? "completed" : "unavailable",
    `The host responded with HTTP ${response.statusCode}${methodRejected ? "; HEAD and bounded GET were rejected." : ""}`);

  emit(onProgress, "tls", "TLS certificate", "running", "Checking the final response connection.");
  const tls = finalUrl.startsWith("https:") ? response.certificate : null;
  emit(onProgress, "tls", "TLS certificate", finalUrl.startsWith("https:") && tls?.valid ? "completed" : "unavailable",
    finalUrl.startsWith("https:") ? (tls?.valid ? "Certificate accepted by the system trust store." : "A verified certificate was not available.") : "The final URL does not use HTTPS.");

  emit(onProgress, "headers", "Public security headers", "running", "Inspecting response headers without fetching page content.");
  const headers = response.headers;
  const cookies = analyzeCookies(headers["set-cookie"]);
  emit(onProgress, "headers", "Public security headers", "completed", `${Object.keys(headers).length} response header names inspected.`);

  emit(onProgress, "browser", "Real browser/device emulation", "running", "Running real Chromium against phone, tablet and laptop-class emulated profiles.");
  const browser = await runBrowserAnalysis(finalUrl, onProgress, analysisId, onScreenshot);
  emit(onProgress, "accessibility", "Automated accessibility scan", browser.profiles.some((profile) => profile.accessibility?.status === "measured") ? "completed" : "unavailable",
    browser.profiles.some((profile) => profile.accessibility?.status === "measured")
      ? `axe-core ran in ${browser.profiles.filter((profile) => profile.accessibility?.status === "measured").length} Chromium profile(s).`
      : "No Chromium page rendered; automated accessibility testing was not available.");
  emit(onProgress, "network", "Network and resource analysis", browser.network.totalRequests > 0 ? "completed" : "unavailable",
    browser.network.totalRequests > 0
      ? `Chromium requested ${browser.network.totalRequests} public resources and measured ${browser.network.bytesReceived} response bytes.`
      : "The browser worker did not produce resource measurements.");
  emit(onProgress, "threat-intelligence", "Optional malware reputation check",
    shareUrlForThreatCheck ? "running" : "unavailable",
    shareUrlForThreatCheck ? "Sending the submitted URL to Google Safe Browsing, if the provider is configured." : "Not requested; the submitted URL was not sent to an external threat-intelligence provider.");
  const malwareRisk = shareUrlForThreatCheck
    ? await checkSafeBrowsing(url.toString())
    : {
      classification: "UNKNOWN",
      status: "not_requested",
      provider: null,
      reason: "No external threat-intelligence check was requested. The URL was not sent to a reputation provider.",
      matches: [],
    };
  if (shareUrlForThreatCheck) {
    emit(onProgress, "threat-intelligence", "Optional malware reputation check",
      malwareRisk.status === "checked" ? "completed" : "unavailable", malwareRisk.reason);
  }

  const lastTiming = timings[timings.length - 1];
  const finalBrowserProfile = browser.profiles.find((profile) =>
    profile.status === "measured" && profile.renderStatus === "rendered" &&
    profile.httpStatus >= 200 && profile.httpStatus < 400);
  const renderedProfileCount = browser.profiles.filter((profile) =>
    profile.status === "measured" && profile.renderStatus === "rendered" &&
    profile.httpStatus >= 200 && profile.httpStatus < 400).length;
  const allProfilesRendered = renderedProfileCount === 3;
  const browserCookies = finalBrowserProfile?.security?.setCookieFlags;
  const browserHeaders = browser.securityHeaders || {};
  const effectiveHeaders = finalBrowserProfile ? { ...headers, ...browserHeaders } : headers;
  const allIssues = [
    ...securityHeaderIssues(effectiveHeaders, finalUrl.startsWith("https:"), browserCookies?.count ? browserCookies : cookies),
    ...browser.issues,
  ];
  for (const profile of browser.profiles) {
    if (profile.renderStatus !== "rendered") continue;
    for (const violation of profile.accessibility?.violations || []) {
      if (!allIssues.some((issue) => issue.category === "Accessibility" && issue.ruleId === violation.id)) {
        allIssues.push({
          severity: violation.impact === "critical" || violation.impact === "serious" ? "high" : violation.impact === "moderate" ? "medium" : "low",
          category: "Accessibility",
          title: `axe-core: ${violation.help}`,
          ruleId: violation.id,
          evidence: `${violation.affectedElementCount} affected element(s); axe impact: ${violation.impact}.`,
          recommendation: `Review ${violation.helpUrl}`,
          affectedDevices: [profile.label],
        });
      }
    }
  }
  const report = {
    createdAt: startedAt,
    requestedUrl: url.toString(),
    finalUrl,
    httpStatus: response.statusCode,
    assessment: {
      reachability: pageReachable || finalBrowserProfile ? "reachable" : "unavailable",
      response: pageReachable ? "HTTP response received" : "Server responded, but the requested page response was not successful",
      analysisCompleteness: allProfilesRendered ? "measured" : finalBrowserProfile ? "partial" : "limited",
      summary: allProfilesRendered
        ? `Chromium opened the website with phone, tablet and laptop-class emulation.${methodRejected ? " The server-side HEAD/Range probe was rejected, but the browser opened the page." : ""} Scenario scores are estimates, not physical-device tests.`
        : finalBrowserProfile
          ? `Chromium rendered visible content in ${renderedProfileCount} of 3 device-class scenarios. Other scenarios did not produce a representative page; see per-profile results.`
        : methodRejected
          ? "The host is reachable, but both the HEAD and bounded GET probe were rejected. The browser did not obtain a successful page response."
          : pageReachable && renderedProfileCount === 0
            ? `The server returned HTTP ${response.statusCode}, but Chromium observed no visible page content in any device scenario. An anti-bot challenge, access requirement, or deferred content may be involved; device suitability is not estimated.`
          : pageReachable && browser.status !== "measured"
            ? "The server responded, but Chromium did not produce a successful rendered page; browser performance and responsive behavior are incomplete."
            : `The server responded, but returned HTTP ${response.statusCode}. Do not interpret this as a successful page load.`,
      browseSafety: malwareRisk.classification,
      browseSafetyReason: malwareRisk.reason,
    },
    redirects,
    location: "Not determined; server region is not configured.",
    browser: browser.engine === "Playwright Chromium" ? `Measured by Playwright Chromium ${browser.browserVersion}; scenarios emulate CPU/network/device parameters.` : "Browser worker unavailable.",
    metrics: {
      dnsMs: measurement(timings.reduce((sum, item) => sum + item.dnsMs, 0), "Measured by server", "DNS lookup durations across the redirect chain."),
      tcpConnectMs: measurement(lastTiming.connectMs, "Measured by server"),
      tlsHandshakeMs: measurement(lastTiming.tlsMs, finalUrl.startsWith("https:") ? "Measured by server" : "Unavailable", finalUrl.startsWith("https:") ? null : "Final URL is HTTP."),
      timeToFirstByteMs: measurement(lastTiming.ttfbMs, "Measured by server", `${lastTiming.method} response headers; not browser navigation TTFB.`),
      responseHeaderTimeMs: measurement(lastTiming.totalMs, "Measured by server"),
      pageSizeBytes: measurement(finalBrowserProfile?.metrics.totalResourceBytes ?? null, finalBrowserProfile ? "Measured by browser" : "Unavailable", "Sum of actual response-body bytes received by the safe Chromium network bridge."),
      browserVitals: measurement(finalBrowserProfile ? {
        fcpMs: finalBrowserProfile.metrics.fcpMs,
        lcpMs: finalBrowserProfile.metrics.lcpMs,
        cls: finalBrowserProfile.metrics.cls,
        longTaskMs: finalBrowserProfile.metrics.longTaskMs,
        longTaskBlockingMs: finalBrowserProfile.metrics.longTaskBlockingMs,
      } : null, finalBrowserProfile ? "Measured by browser" : "Unavailable", "FCP, LCP, CLS, long tasks are browser-observed in the selected emulation. INP requires real user interaction."),
      screenshots: measurement(browser.profiles.filter((profile) => profile.screenshot).length, browser.status === "measured" ? "Measured by browser" : "Unavailable", browser.status === "measured" ? "Captured Chromium screenshots available from the report." : "No browser worker is configured."),
      deviceSuitability: measurement(
        browser.profiles.filter((profile) => profile.suitability?.value !== null && profile.suitability?.value !== undefined).length,
        browser.status === "measured" ? "Estimated from browser measurements" : "Unavailable",
        browser.status === "measured" ? "Per-profile scenario suitability is derived from measured LCP, transferred bytes, long tasks and viewport findings; see estimated device profiles below." : "No browser rendering or device emulation measurements were collected.",
      ),
      fcpMs: measurement(finalBrowserProfile?.metrics.fcpMs ?? null, finalBrowserProfile ? "Measured by browser" : "Unavailable"),
      lcpMs: measurement(finalBrowserProfile?.metrics.lcpMs ?? null, finalBrowserProfile ? "Measured by browser" : "Unavailable"),
      cls: measurement(finalBrowserProfile?.metrics.cls ?? null, finalBrowserProfile ? "Measured by browser" : "Unavailable"),
      longTaskMs: measurement(finalBrowserProfile?.metrics.longTaskMs ?? null, finalBrowserProfile ? "Measured by browser" : "Unavailable"),
      longTaskBlockingMs: measurement(finalBrowserProfile?.metrics.longTaskBlockingMs ?? null, finalBrowserProfile ? "Measured by browser" : "Unavailable", "Sum of observed long-task duration exceeding 50 ms; not Lighthouse TBT."),
      domContentLoadedMs: measurement(finalBrowserProfile?.metrics.domContentLoadedMs ?? null, finalBrowserProfile ? "Measured by browser" : "Unavailable"),
      browserResourceCount: measurement(finalBrowserProfile?.metrics.resourceCount ?? null, finalBrowserProfile ? "Measured by browser" : "Unavailable"),
      pageBytes: measurement(finalBrowserProfile?.metrics.totalResourceBytes ?? null, finalBrowserProfile ? "Measured by browser" : "Unavailable", "Actual response bytes collected by the constrained browser request bridge."),
      mobileINP: measurement(null, "Unavailable", "Interaction to Next Paint requires representative real user input; automated page load alone is insufficient."),
      speedIndex: measurement(null, "Unavailable", "Speed Index needs video-based visual progress analysis; it is not inferred from other timing metrics."),
    },
    response: {
      httpVersion: `HTTP/${response.httpVersion}`,
      contentType: headers["content-type"] || null,
      contentLengthBytes: Number.isFinite(Number(headers["content-length"])) ? Number(headers["content-length"]) : null,
      cacheControl: headers["cache-control"] || null,
      serverHintObserved: Boolean(headers.server),
      cdnHint: headers["cf-ray"] ? "Cloudflare header observed" : headers["x-amz-cf-id"] ? "CloudFront header observed" : null,
      securityHeaders: Object.fromEntries([
        "strict-transport-security", "content-security-policy", "x-frame-options",
        "x-content-type-options", "referrer-policy", "permissions-policy",
      ].filter((name) => effectiveHeaders[name]).map((name) => [name, String(effectiveHeaders[name]).slice(0, 300)])),
      setCookieFlags: browserCookies?.count ? browserCookies : cookies,
    },
    security: {
      https: finalUrl.startsWith("https:"),
      tls,
      hsts: effectiveHeaders["strict-transport-security"] || null,
      malwareRisk,
      notChecked: [
        "Mixed content",
        "JavaScript and iframe behavior",
        "Known vulnerable dependencies",
        ...(malwareRisk.status === "checked" ? [] : ["Safe Browsing reputation"]),
        "Full TLS configuration",
      ],
    },
    browserAnalysis: browser,
    networkAnalysis: browser.network,
    deviceSuitability: browser.profiles.map((profile) => ({
      profile: profile.label,
      category: profile.category,
      viewport: profile.configuration.viewport,
      network: profile.configuration.network,
      cpuSlowdown: profile.configuration.cpuSlowdown,
      result: profile.suitability,
      renderStatus: profile.renderStatus,
      metrics: profile.metrics ? {
        lcpMs: profile.metrics.lcpMs,
        fcpMs: profile.metrics.fcpMs,
        cls: profile.metrics.cls,
        pageBytes: profile.metrics.totalResourceBytes,
        requests: profile.metrics.resourceCount,
        horizontalOverflow: profile.layout.horizontalOverflow,
        axeViolations: profile.accessibility.violations.length,
      } : null,
      status: profile.status,
    })),
    technologyDetection: finalBrowserProfile?.technologies || { status: "Unavailable", results: [] },
    testConfiguration: {
      method: timings.map((timing) => timing.method).includes("GET")
        ? "HEAD; bounded GET fallback only when the server rejects HEAD"
        : "HEAD only",
      maxRedirects: MAX_REDIRECTS,
      requestTimeoutMs: REQUEST_TIMEOUT_MS,
      dnsTimeoutMs: DNS_TIMEOUT_MS,
      maxResponseHeaderBytes: MAX_HEADER_BYTES,
      responseBodyParsed: false,
      responseBodyStored: false,
      requestedPageContentStored: false,
      note: "The response body is not parsed or stored. On 405/501 only, a GET is sent with Range: bytes=0-0 and its response is destroyed immediately after headers; servers may ignore Range and some response bytes may reach the network before the connection closes.",
    },
    deviceRecommendations: {
      status: browser.profiles.some((profile) => profile.suitability?.value !== null && profile.suitability?.value !== undefined)
        ? "estimated_from_emulation"
        : "unavailable",
      reason: browser.profiles.some((profile) => profile.suitability?.value !== null && profile.suitability?.value !== undefined)
        ? "Broad device-class fit estimates are based on live Chromium measurements under the listed emulated CPU/network conditions; they are not physical-device or product recommendations."
        : "Chromium did not produce the measurements needed to estimate broad device-class fit.",
      budgetPrices: "Not checked: no live product or price source is configured.",
      categories: [
        ...browser.profiles.map((profile) => ({
          budget: `${profile.category}: ${profile.configuration.network.label}`,
          profile: profile.label,
          result: profile.suitability?.label || "Browser test incomplete; cannot estimate fit.",
          evidence: profile.suitability?.method || "No successful measured browser rendering.",
          estimatedPriceBand: profile.suitability?.estimatedPriceBand || null,
        })),
      ],
    },
    issues: allIssues,
    limitations: [
      "Server-side DNS, TCP, TLS, and HEAD-response timings are separate from browser-navigation performance measurements.",
      "Chromium browser tests use emulated CPU/network profiles, not physical phones, tablets, laptops, or real carrier paths.",
      "Automated axe-core checks cannot prove full accessibility; INP requires real user interaction and is not inferred.",
      "Security header observations are not a penetration test and do not prove a site is secure.",
      malwareRisk.status === "checked"
        ? "The optional Safe Browsing lookup is a limited reputation signal, not a complete scan or a guarantee that the website is safe."
        : "No Safe Browsing reputation lookup was completed; browsing safety remains UNKNOWN.",
      "HEAD responses may differ from GET responses. When HEAD is rejected, the analyzer sends a bounded GET with Range: bytes=0-0 and closes after response headers; some servers may ignore Range.",
      "A reachable host or valid TLS certificate does not establish that browsing the website is safe.",
      "Budget tiers are estimates derived from the browser profile scenario, not model-specific recommendations; current product prices are not sourced.",
    ],
  };
  emit(onProgress, "report", "Report generated", "completed", "Report contains measured values and explicit unavailable states.");
  return report;
}
