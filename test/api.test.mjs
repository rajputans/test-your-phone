import test from "node:test";
import assert from "node:assert/strict";
import { createAppServer } from "../server.mjs";

test("analysis API validates requests, reports real job status, and advertises emulated device profiles", async (context) => {
  const server = createAppServer({
    analyzer: async (_url, onProgress, options) => {
      onProgress({ id: "fixture", label: "Test fixture", status: "completed", detail: "API test only" });
      options.onScreenshot("budget-phone", "image/jpeg", Buffer.from("screenshot"));
      return { metrics: { test: { value: 1, dataSource: "Test fixture" } }, limitations: [] };
    },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  context.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;

  const bad = await fetch(`${base}/api/analyze`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: "http://127.0.0.1" }) });
  assert.equal(bad.status, 400);
  const accepted = await fetch(`${base}/api/analyze`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: "https://example.com" }) });
  assert.equal(accepted.status, 202);
  const { analysisId } = await accepted.json();
  let result;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    result = await fetch(`${base}/api/analyze/${analysisId}`).then((response) => response.json());
    if (result.status === "completed") break;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.equal(result.status, "completed");
  assert.equal(result.report.metrics.test.dataSource, "Test fixture");
  const report = await fetch(`${base}/api/analyze/${analysisId}/report`).then((response) => response.json());
  assert.equal(report.analysisId, analysisId);
  assert.equal(report.report.metrics.test.value, 1);
  const screenshotIndex = await fetch(`${base}/api/analyze/${analysisId}/screenshots`).then((response) => response.json());
  assert.equal(screenshotIndex.screenshots.length, 1);
  const screenshot = await fetch(`${base}${screenshotIndex.screenshots[0].url}`);
  assert.equal(screenshot.headers.get("content-type"), "image/jpeg");
  assert.equal(await screenshot.text(), "screenshot");
  const profiles = await fetch(`${base}/api/device-profiles`).then((response) => response.json());
  assert.equal(profiles.available, true);
  assert.equal(profiles.physicalDevicesTested, false);
  assert.equal(profiles.profiles.length, 3);
  assert.ok(profiles.profiles.every((profile) => profile.estimationOnly));
  const providers = await fetch(`${base}/api/security/providers`).then((response) => response.json());
  assert.equal(typeof providers.googleSafeBrowsing.configured, "boolean");
  assert.equal(providers.googleSafeBrowsing.optInRequired, true);
});
