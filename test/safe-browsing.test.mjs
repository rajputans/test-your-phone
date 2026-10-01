import test from "node:test";
import assert from "node:assert/strict";
import { checkSafeBrowsing } from "../lib/safe-browsing.mjs";

test("does not call an external provider when no key is configured", async () => {
  let called = false;
  const result = await checkSafeBrowsing("https://example.com", {
    apiKey: "",
    request: async () => { called = true; },
  });
  assert.equal(called, false);
  assert.equal(result.status, "not_configured");
  assert.equal(result.classification, "UNKNOWN");
});

test("classifies a clean Safe Browsing result as a limited low-risk signal", async () => {
  let requestBody;
  const result = await checkSafeBrowsing("https://example.com/path", {
    apiKey: "test-key",
    request: async (url, options) => {
      assert.equal(new URL(url).hostname, "safebrowsing.googleapis.com");
      requestBody = JSON.parse(options.body);
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  assert.equal(result.classification, "LOW");
  assert.match(result.reason, /does not establish that the site is safe/);
  assert.equal(requestBody.threatInfo.threatEntries[0].url, "https://example.com/path");
});

test("reports only threat categories when the provider finds a match", async () => {
  const result = await checkSafeBrowsing("https://example.com", {
    apiKey: "test-key",
    request: async () => new Response(JSON.stringify({
      matches: [{ threatType: "MALWARE", platformType: "ANY_PLATFORM", threat: { url: "https://example.com/private" } }],
    }), { status: 200 }),
  });
  assert.equal(result.classification, "HIGH");
  assert.deepEqual(result.matches, [{ threatType: "MALWARE", platformType: "ANY_PLATFORM" }]);
  assert.equal(JSON.stringify(result).includes("private"), false);
});

test("leaves reputation unknown when Google is unavailable", async () => {
  const result = await checkSafeBrowsing("https://example.com", {
    apiKey: "test-key",
    request: async () => { throw new TypeError("network failure"); },
  });
  assert.equal(result.classification, "UNKNOWN");
  assert.equal(result.status, "unavailable");
});
