import test from "node:test";
import assert from "node:assert/strict";
import { calculateScenarioSuitability, hasRenderedContent, runBrowserAnalysis } from "../lib/browser-analyzer.mjs";

test("requires visible content or browser paint before calling an emulation a successful render", () => {
  assert.equal(hasRenderedContent({ bodyTextLength: 0 }, { fcpMs: null, lcpMs: null }), false);
  assert.equal(hasRenderedContent({ bodyTextLength: 0 }, { fcpMs: 80, lcpMs: null }), true);
  assert.equal(hasRenderedContent({ bodyTextLength: 12 }, { fcpMs: null, lcpMs: null }), true);
});

test("calculates transparent scenario suitability only from rendered measurements", () => {
  const good = calculateScenarioSuitability({
    metrics: { lcpMs: 1_500, longTaskMs: 120 },
    layout: { horizontalOverflow: false, touchTargetsUnder44px: 0, viewportMetaPresent: true },
    network: { totalBytes: 1_000_000 },
  });
  assert.equal(good.value, 100);
  assert.match(good.note, /not a test of a physical device/);
  assert.equal(calculateScenarioSuitability({
    metrics: { lcpMs: null, longTaskMs: null },
    layout: { horizontalOverflow: false, touchTargetsUnder44px: 0, viewportMetaPresent: true },
    network: { totalBytes: 0 },
  }), null);
});

test("renders real Chromium device profiles and screenshots through a test-only fixture bridge", async () => {
  const screenshotRecords = [];
  let bridgeRequests = 0;
  const fixtureHtml = Buffer.from(`<!doctype html>
    <html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Fixture target</title>
    <style>body{font:16px sans-serif;margin:1rem}img{max-width:100%}</style></head>
    <body><main><h1>Fixture website</h1><p>Public test fixture content.</p>
    <img src="/image.svg" alt="Test illustration"><button type="button">Continue</button></main></body></html>`);
  const fixtureFetch = async (url, limits) => {
    bridgeRequests += 1;
    limits.requestCount += 1;
    const body = url.pathname.endsWith(".svg")
      ? Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" fill="#26785b"/></svg>')
      : fixtureHtml;
    limits.totalBytes += body.length;
    return {
      status: 200,
      statusText: "OK",
      headers: { "content-type": url.pathname.endsWith(".svg") ? "image/svg+xml" : "text/html; charset=utf-8" },
      body,
      url: url.toString(),
      redirect: false,
    };
  };
  const report = await runBrowserAnalysis(
    "https://example.com/",
    () => {},
    "browser-fixture",
    (id, mimeType, bytes) => screenshotRecords.push({ id, mimeType, bytes: bytes.length }),
    fixtureFetch,
  );
  assert.equal(report.status, "measured");
  assert.equal(report.profiles.length, 3);
  assert.ok(report.profiles.every((profile) => profile.status === "measured"));
  assert.ok(report.profiles.every((profile) => profile.renderStatus === "rendered"));
  assert.ok(report.profiles.every((profile) => profile.accessibility.status === "measured"));
  assert.ok(report.profiles.every((profile) => profile.layout.viewportMetaPresent));
  assert.ok(report.profiles.every((profile) => typeof profile.suitability.value === "number"));
  assert.equal(report.responsiveChecks.length, 5);
  assert.equal(screenshotRecords.length, 8);
  assert.ok(bridgeRequests >= 6);
  assert.equal(report.network.bytesReceived > 0, true);
  assert.equal(report.profiles[0].configuration.actualPhysicalDeviceTest, false);
});
