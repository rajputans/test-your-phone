import test from "node:test";
import assert from "node:assert/strict";
import { requestPublicURL } from "../lib/analyzer.mjs";

const publicResolver = async () => [{ address: "8.8.8.8", family: 4 }];

test("revalidates redirect targets and blocks a redirect to loopback before connecting", async () => {
  let requests = 0;
  await assert.rejects(
    requestPublicURL("https://public.example/", {
      resolveHost: publicResolver,
      probe: async () => {
        requests += 1;
        return { statusCode: 302, headers: { location: "http://127.0.0.1/admin" } };
      },
    }),
    /publicly routable/,
  );
  assert.equal(requests, 1);
});

test("enforces the redirect limit", async () => {
  let requests = 0;
  await assert.rejects(
    requestPublicURL("https://public.example/", {
      resolveHost: publicResolver,
      probe: async () => {
        requests += 1;
        return { statusCode: 302, headers: { location: `https://public.example/${requests}` } };
      },
    }),
    /5-redirect safety limit/,
  );
  assert.equal(requests, 6);
});
