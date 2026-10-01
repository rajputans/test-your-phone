import test from "node:test";
import assert from "node:assert/strict";
import { analyzeCookies } from "../lib/analyzer.mjs";

test("reports cookie flag counts without retaining cookie values", () => {
  const result = analyzeCookies([
    "session-secret=do-not-store; Secure; HttpOnly; SameSite=Lax",
    "preference=private-value; SameSite=Lax",
  ]);
  assert.equal(result.count, 2);
  assert.equal(result.secureCount, 1);
  assert.equal(result.httpOnlyCount, 1);
  assert.equal(result.sameSiteCount, 2);
  assert.equal(result.allSecure, false);
  assert.equal(JSON.stringify(result).includes("do-not-store"), false);
  assert.equal(JSON.stringify(result).includes("private-value"), false);
});

test("represents absent Set-Cookie headers as not applicable", () => {
  const result = analyzeCookies(undefined);
  assert.equal(result.count, 0);
  assert.equal(result.allSecure, null);
  assert.equal(result.allSameSite, null);
});
