import test from "node:test";
import assert from "node:assert/strict";
import { isPublicAddress, validateTarget } from "../lib/safety.mjs";

test("accepts only public HTTP(S) URLs on standard ports", () => {
  assert.equal(validateTarget("https://example.com/path").hostname, "example.com");
  for (const value of ["file:///etc/passwd", "javascript:alert(1)", "ftp://example.com", "http://localhost",
    "http://127.0.0.1", "http://169.254.169.254", "http://10.0.0.1", "http://[::1]", "http://service.internal",
    "https://user:pass@example.com", "http://example.com:8080"]) {
    assert.throws(() => validateTarget(value), { message: /./ });
  }
});

test("blocks non-public IPv4 and IPv6 ranges, including mapped IPv4", () => {
  for (const address of ["0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.1.1",
    "172.20.0.1", "192.168.1.1", "198.18.0.1", "203.0.113.1", "224.0.0.1", "::", "::1",
    "fc00::1", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1"]) {
    assert.equal(isPublicAddress(address), false, `${address} should be blocked`);
  }
  assert.equal(isPublicAddress("8.8.8.8"), true);
  assert.equal(isPublicAddress("2606:4700:4700::1111"), true);
});
