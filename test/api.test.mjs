import test from "node:test";
import assert from "node:assert/strict";
import { createAppServer } from "../server.mjs";

test("analysis API validates requests, reports real job status, and exposes no fake device profiles", async (context) => {
  const server = createAppServer({
    analyzer: async (_url, onProgress) => {
      onProgress({ id: "fixture", label: "Test fixture", status: "completed", detail: "API test only" });
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
  const profiles = await fetch(`${base}/api/device-profiles`).then((response) => response.json());
  assert.equal(profiles.available, false);
  assert.deepEqual(profiles.profiles, []);
});
