const GOOGLE_SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
const MAX_INTELLIGENCE_RESPONSE_BYTES = 32 * 1024;
const REQUEST_TIMEOUT_MS = 4_000;

async function readBoundedResponse(response) {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_INTELLIGENCE_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("Threat-intelligence response exceeded its 32 KB safety limit.");
      }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks, size);
  } finally {
    reader.releaseLock();
  }
}

export async function checkSafeBrowsing(url, {
  apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY,
  request = fetch,
} = {}) {
  if (!apiKey) {
    return {
      status: "not_configured",
      classification: "UNKNOWN",
      provider: null,
      reason: "Google Safe Browsing is not configured. No threat-list check was performed.",
      matches: [],
    };
  }
  const endpoint = new URL(GOOGLE_SAFE_BROWSING_ENDPOINT);
  endpoint.searchParams.set("key", apiKey);
  let response;
  try {
    response = await request(endpoint, {
      method: "POST",
      redirect: "error",
      cache: "no-store",
      headers: { "content-type": "application/json", accept: "application/json" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      body: JSON.stringify({
        client: { clientId: "devicefit-ai", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
    });
  } catch (error) {
    return {
      status: "unavailable",
      classification: "UNKNOWN",
      provider: "Google Safe Browsing",
      reason: error.name === "TimeoutError"
        ? "Google Safe Browsing timed out; threat status could not be checked."
        : "Google Safe Browsing could not be reached; threat status could not be checked.",
      matches: [],
    };
  }
  if (!response.ok) {
    return {
      status: "unavailable",
      classification: "UNKNOWN",
      provider: "Google Safe Browsing",
      reason: `Google Safe Browsing returned HTTP ${response.status}; threat status could not be checked.`,
      matches: [],
    };
  }
  try {
    const data = JSON.parse((await readBoundedResponse(response)).toString("utf8"));
    const matches = (Array.isArray(data.matches) ? data.matches : []).slice(0, 20).map((match) => ({
      threatType: String(match.threatType || "UNKNOWN").slice(0, 80),
      platformType: String(match.platformType || "UNKNOWN").slice(0, 80),
    }));
    return matches.length
      ? {
        status: "checked",
        classification: "HIGH",
        provider: "Google Safe Browsing",
        reason: "Google Safe Browsing returned one or more known threat-list matches for the submitted URL. This is an intelligence signal, not a complete site scan.",
        matches,
      }
      : {
        status: "checked",
        classification: "LOW",
        provider: "Google Safe Browsing",
        reason: "Google Safe Browsing reported no current threat-list match for this URL. A clean lookup does not establish that the site is safe or malware-free.",
        matches: [],
      };
  } catch (error) {
    return {
      status: "unavailable",
      classification: "UNKNOWN",
      provider: "Google Safe Browsing",
      reason: error.message.includes("32 KB")
        ? "Google Safe Browsing returned an oversized response; threat status could not be checked."
        : "Google Safe Browsing returned invalid data; threat status could not be checked.",
      matches: [],
    };
  }
}
