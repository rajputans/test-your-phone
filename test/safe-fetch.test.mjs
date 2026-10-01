import test from "node:test";
import assert from "node:assert/strict";
import { safeFetch } from "../lib/safe-fetch.mjs";

function limits() {
  return {
    requestCount: 0,
    totalBytes: 0,
    inFlightBytes: 0,
    redirectCount: 0,
    maxRequests: 8,
    maxTotalBytes: 1024,
    maxResourceBytes: 512,
  };
}

test("browser safe-fetch blocks a redirect to localhost before any internal connection", async () => {
  const requestedHosts = [];
  await assert.rejects(safeFetch("https://public.example.com/", limits(), {
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    request: async (url) => {
      requestedHosts.push(url.hostname);
      return { status: 302, headers: { location: "http://127.0.0.1/admin" }, body: Buffer.alloc(0), redirect: true };
    },
  }), /publicly routable/);
  assert.deepEqual(requestedHosts, ["public.example.com"]);
});

test("browser safe-fetch re-resolves and blocks private DNS redirect destinations", async () => {
  const requestedHosts = [];
  await assert.rejects(safeFetch("https://public.example.com/", limits(), {
    resolveHost: async (host) => host === "private.example.com"
      ? [{ address: "192.168.1.10", family: 4 }]
      : [{ address: "8.8.8.8", family: 4 }],
    request: async (url) => {
      requestedHosts.push(url.hostname);
      return { status: 302, headers: { location: "https://private.example.com/secret" }, body: Buffer.alloc(0), redirect: true };
    },
  }), /non-public/);
  assert.deepEqual(requestedHosts, ["public.example.com"]);
});

test("browser safe-fetch constrains methods to safe read-only requests", async () => {
  await assert.rejects(safeFetch("https://example.com", limits(), { method: "POST" }), /not allowed/);
});

test("browser safe-fetch does not forward content compression negotiation", async () => {
  let receivedHeaders;
  await safeFetch("https://example.com", limits(), {
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    request: async (_url, _address, _family, _limits, _method, headers) => {
      receivedHeaders = headers;
      return { status: 200, headers: {}, body: Buffer.from("ok"), redirect: false };
    },
    headers: { "accept-encoding": "gzip, br" },
  });
  assert.equal(receivedHeaders["accept-encoding"], undefined);
});
