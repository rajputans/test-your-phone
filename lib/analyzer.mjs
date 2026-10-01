import http from "node:http";
import https from "node:https";
import { performance } from "node:perf_hooks";
import { resolvePublicHost, validateTarget } from "./safety.mjs";

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

export function analyzeCookies(setCookie) {
  if (!setCookie) {
    return {
      checked: true, count: 0,
      secureCount: null, httpOnlyCount: null, sameSiteCount: null,
      allSecure: null, allHttpOnly: null, allSameSite: null,
    };
  }
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  const flags = cookies.map((cookie) => ({
    secure: /(?:^|;)\s*secure(?:;|$)/i.test(cookie),
    httpOnly: /(?:^|;)\s*httponly(?:;|$)/i.test(cookie),
    sameSite: /(?:^|;)\s*samesite=/i.test(cookie),
  }));
  return {
    checked: true,
    count: flags.length,
    secureCount: flags.filter((cookie) => cookie.secure).length,
    httpOnlyCount: flags.filter((cookie) => cookie.httpOnly).length,
    sameSiteCount: flags.filter((cookie) => cookie.sameSite).length,
    allSecure: flags.every((cookie) => cookie.secure),
    allHttpOnly: flags.every((cookie) => cookie.httpOnly),
    allSameSite: flags.every((cookie) => cookie.sameSite),
  };
}

function measurement(value, dataSource, note = null) {
  return { value, dataSource, note };
}

export async function analyzeWebsite(input, onProgress = () => {}) {
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
  if (finalUrl.startsWith("https:")) {
    issues.push(headerIssue(headers, "strict-transport-security", "HSTS", "Send Strict-Transport-Security after confirming HTTPS is deployed across the site."));
  }
  const cookies = analyzeCookies(headers["set-cookie"]);
  if (cookies.count && (!cookies.allSecure || !cookies.allHttpOnly || !cookies.allSameSite)) {
    issues.push({
      severity: "medium",
      category: "Cookies",
      title: "Some cookie security attributes are not present",
      evidence: `Cookie attributes observed on ${cookies.count} Set-Cookie headers: Secure ${cookies.secureCount}/${cookies.count}; HttpOnly ${cookies.httpOnlyCount}/${cookies.count}; SameSite ${cookies.sameSiteCount}/${cookies.count}. Cookie values were not retained.`,
      recommendation: "Review each cookie against its purpose; HttpOnly is not applicable to cookies intentionally read by client-side scripts.",
    });
  }
  emit(onProgress, "headers", "Public security headers", "completed", `${Object.keys(headers).length} response header names inspected.`);

  const lastTiming = timings[timings.length - 1];
  const report = {
    createdAt: startedAt,
    requestedUrl: url.toString(),
    finalUrl,
    httpStatus: response.statusCode,
    assessment: {
      reachability: "reachable",
      response: pageReachable ? "HTTP response received" : "Server responded, but the requested page response was not successful",
      analysisCompleteness: pageReachable ? "partial" : "limited",
      summary: methodRejected
        ? "The website server is reachable, but it rejected both HEAD and a bounded GET request. Page-level analysis is incomplete."
        : pageReachable
          ? "The website server responded. Browser rendering, page safety reputation, and real-device suitability were not tested."
          : `The server is reachable, but returned HTTP ${response.statusCode}. Do not interpret this as a successful page load.`,
      browseSafety: "UNKNOWN",
      browseSafetyReason: "No malware-reputation service or active browser inspection is configured. This report cannot say whether it is safe to browse.",
    },
    redirects,
    location: "Not determined; server region is not configured.",
    browser: "Not run: this deployment has no isolated Playwright browser worker.",
    metrics: {
      dnsMs: measurement(timings.reduce((sum, item) => sum + item.dnsMs, 0), "Measured by server", "DNS lookup durations across the redirect chain."),
      tcpConnectMs: measurement(lastTiming.connectMs, "Measured by server"),
      tlsHandshakeMs: measurement(lastTiming.tlsMs, finalUrl.startsWith("https:") ? "Measured by server" : "Unavailable", finalUrl.startsWith("https:") ? null : "Final URL is HTTP."),
      timeToFirstByteMs: measurement(lastTiming.ttfbMs, "Measured by server", `${lastTiming.method} response headers; not browser navigation TTFB.`),
      responseHeaderTimeMs: measurement(lastTiming.totalMs, "Measured by server"),
      pageSizeBytes: measurement(null, "Unavailable", "HEAD-only checks do not download the page or its resources."),
      browserVitals: measurement(null, "Unavailable", "FCP, LCP, INP, CLS, TBT, and Speed Index require a browser run."),
      screenshots: measurement(null, "Unavailable", "No browser worker is configured."),
      deviceSuitability: measurement("Unable to determine", "Unavailable", "No browser rendering or device emulation measurements were collected."),
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
      ].filter((name) => headers[name]).map((name) => [name, String(headers[name]).slice(0, 300)])),
      setCookieFlags: cookies,
    },
    security: {
      https: finalUrl.startsWith("https:"),
      tls,
      hsts: headers["strict-transport-security"] || null,
      malwareRisk: { classification: "UNKNOWN", reason: "No malware-intelligence provider is configured; this service does not establish that a site is malware-free." },
      notChecked: ["Mixed content", "JavaScript and iframe behavior", "Known vulnerable dependencies", "Safe Browsing reputation", "Full TLS configuration"],
    },
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
      status: "Unable to determine",
      reason: "No page rendering, JavaScript execution, resource transfer measurements, or device-emulation results are available.",
      budgetPrices: "Not checked: no live product or price source is configured.",
      categories: [
        "₹8,000–₹12,000", "₹12,000–₹20,000", "₹20,000–₹30,000", "₹30,000–₹50,000", "₹50,000+",
        "Tablet: budget / mid-range / iPad-style",
        "Laptop: ₹25,000–₹40,000", "₹40,000–₹60,000", "₹60,000–₹80,000", "₹80,000+",
      ].map((budget) => ({ budget, result: "Not enough measured evidence; no current prices checked." })),
    },
    issues,
    limitations: [
      "This report measures server-side DNS, connection, TLS, and HEAD-response signals only.",
      "No browser execution, viewport checks, screenshots, accessibility audit, device emulation, or network throttling was run.",
      "Security header observations are not a penetration test and do not prove a site is secure.",
      "No malware or vulnerability intelligence API is configured.",
      "HEAD responses may differ from GET responses. When HEAD is rejected, the analyzer sends a bounded GET with Range: bytes=0-0 and closes after response headers; some servers may ignore Range.",
      "A reachable host or valid TLS certificate does not establish that browsing the website is safe.",
      "Device recommendations and current product prices require browser measurements and a live product data source; neither is configured.",
    ],
  };
  emit(onProgress, "report", "Report generated", "completed", "Report contains measured values and explicit unavailable states.");
  return report;
}
