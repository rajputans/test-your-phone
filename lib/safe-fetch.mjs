import http from "node:http";
import https from "node:https";
import { isPublicAddress, resolvePublicHost, validateTarget } from "./safety.mjs";

export const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 8_000;
const DNS_TIMEOUT_MS = 5_000;
const MAX_HEADER_BYTES = 16 * 1024;

async function resolveHostWithTimeout(resolveHost, hostname, errorMessage) {
  let timer;
  try {
    return await Promise.race([
      resolveHost(hostname),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(errorMessage)), DNS_TIMEOUT_MS); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function fetchPinned(url, address, family, limits, method, headers = {}) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === "https:" ? https : http;
    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    const chunks = [];
    let bytes = 0;
    let done = false;
    const request = transport.request({
      protocol: url.protocol,
      hostname,
      port: url.protocol === "https:" ? 443 : 80,
      method,
      path: `${url.pathname}${url.search}`,
      headers: {
        "user-agent": headers["user-agent"] || "DeviceFitAI/1.0 (+isolated public-site browser check)",
        accept: headers.accept || "*/*",
        "accept-encoding": "identity",
        connection: "close",
        ...headers,
      },
      agent: false,
      rejectUnauthorized: true,
      maxHeaderSize: MAX_HEADER_BYTES,
      lookup: (_hostname, options, callback) => {
        if (options?.all) callback(null, [{ address, family }]);
        else callback(null, address, family);
      },
    }, (response) => {
      const headers = response.headers;
      const redirect = [301, 302, 303, 307, 308].includes(response.statusCode) && headers.location;
      if (redirect) {
        response.destroy();
        done = true;
        resolve({ status: response.statusCode, statusText: response.statusMessage || "", headers, body: Buffer.alloc(0), url: url.toString(), redirect: true });
        return;
      }
      response.on("data", (chunk) => {
        if (done) return;
        if (bytes + chunk.length > limits.maxResourceBytes ||
            limits.totalBytes + chunk.length > limits.maxTotalBytes) {
          limits.inFlightBytes -= bytes;
          done = true;
          response.destroy(new Error("Browser resource download limit exceeded."));
          request.destroy();
          reject(new Error("Browser resource download limit exceeded."));
          return;
        }
        bytes += chunk.length;
        limits.totalBytes += chunk.length;
        limits.inFlightBytes += chunk.length;
        chunks.push(chunk);
      });
      response.once("end", () => {
        if (done) return;
        done = true;
        limits.inFlightBytes -= bytes;
        resolve({
          status: response.statusCode || 0,
          statusText: response.statusMessage || "",
          headers,
          body: Buffer.concat(chunks, bytes),
          url: url.toString(),
          redirect: false,
        });
      });
      response.once("error", (error) => {
        if (done) return;
        done = true;
        limits.inFlightBytes -= bytes;
        reject(error);
      });
    });
    request.setTimeout(TIMEOUT_MS, () => request.destroy(new Error("Website resource request timed out.")));
    request.once("error", (error) => {
      if (done) return;
      done = true;
      if (bytes) limits.inFlightBytes -= bytes;
      reject(error);
    });
    const wallTimeout = setTimeout(() => request.destroy(new Error("Website resource request exceeded the 8-second hard deadline.")), TIMEOUT_MS);
    request.once("close", () => clearTimeout(wallTimeout));
    request.end();
  });
}

export async function safeFetch(input, limits, { resolveHost = resolvePublicHost, request = fetchPinned, method = "GET", headers = {} } = {}) {
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) throw new Error("Browser request method is not allowed.");
  let url = validateTarget(typeof input === "string" ? input : input.toString());
  for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount += 1) {
    if (limits.requestCount >= limits.maxRequests) throw new Error("Browser request limit reached.");
    limits.requestCount += 1;
    const addresses = await resolveHostWithTimeout(resolveHost, url.hostname, "Browser DNS lookup exceeded its 5-second deadline.");
    if (!addresses?.length || addresses.some(({ address }) => !isPublicAddress(address))) {
      throw new Error("Browser target resolves to a non-public address.");
    }
    const address = addresses[0];
    const safeHeaders = {};
    for (const name of ["user-agent", "accept", "accept-language", "origin", "referer", "range", "access-control-request-method", "access-control-request-headers", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user"]) {
      const value = headers[name];
      if (typeof value === "string" && !/[\r\n]/.test(value)) safeHeaders[name] = value;
    }
    const result = await request(url, address.address, address.family, limits, method, safeHeaders);
    if (!result.redirect) return result;
    if (limits.redirectCount >= 10) throw new Error("Analysis redirect limit reached.");
    if (limits.redirectCount >= MAX_REDIRECTS) throw new Error("Website resource exceeded the 5-redirect safety limit.");
    const nextUrl = validateTarget(new URL(result.headers.location, url).toString());
    const nextAddresses = await resolveHostWithTimeout(resolveHost, nextUrl.hostname, "Redirect DNS lookup exceeded its 5-second deadline.");
    if (!nextAddresses?.length || nextAddresses.some(({ address }) => !isPublicAddress(address))) {
      throw new Error("Redirect target resolves to a non-public address.");
    }
    limits.redirectCount += 1;
    return { ...result, headers: { ...result.headers, location: nextUrl.toString() }, url: url.toString() };
  }
  throw new Error("Website resource exceeded the 5-redirect safety limit.");
}
