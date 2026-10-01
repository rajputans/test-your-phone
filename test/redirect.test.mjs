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

test("retries a rejected HEAD with a bounded GET and uses that response", async () => {
  const methods = [];
  const result = await requestPublicURL("https://public.example/", {
    resolveHost: publicResolver,
    probe: async (_url, _address, _family, method) => {
      methods.push(method);
      return method === "HEAD"
        ? { statusCode: 405, headers: {} }
        : { statusCode: 200, headers: { "content-type": "text/html" }, method };
    },
  });
  assert.deepEqual(methods, ["HEAD", "GET"]);
  assert.equal(result.response.statusCode, 200);
  assert.equal(result.timings[0].method, "GET");
});
