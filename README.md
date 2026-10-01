# DeviceFit AI

DeviceFit AI runs a live, real Chromium analysis of a public website. Each report launches isolated Playwright contexts for a budget Android phone, an Android tablet, and a budget Windows laptop, then captures five additional viewport sizes for responsiveness screenshots. It collects real browser paint/layout/resource metrics, axe-core accessibility findings, TLS and DNS timings, public security headers and estimated device-class suitability. The report includes charts, screenshots, JSON/CSV export, dark mode, and print-to-PDF. It does not fabricate scores or claim a physical handset test.

## Run locally

Requirements: Node.js 20 or later. Install dependencies and the Playwright Chromium browser once:

```sh
npm install
npx playwright install chromium
npm run dev
```

Open <http://127.0.0.1:3000>. Paste a public URL such as `https://example.com` to start a live browser analysis. A normal analysis runs three device/network scenarios and takes longer than a header-only check. `npm start` starts the same server. The server binds to loopback by default. To enable the optional Safe Browsing lookup, copy `.env.example` to `.env`, provide `GOOGLE_SAFE_BROWSING_API_KEY`, restart, and opt in for each submitted URL. The URL is sent to Google only for that opted-in analysis.

For a resource-limited, non-root Chromium runtime, Docker Compose is provided:

```sh
docker compose up --build
```

The local service is published on loopback port 3000. Container CPU and memory limits are set in `docker-compose.yml`.

Run the automated checks with:

```sh
npm test
```

## API

- `POST /api/analyze` — JSON `{ "url": "https://example.com" }`; returns a queued job ID.
- `GET /api/analyze/:id` — live job status and completed report.
- `GET /api/analyze/:id/progress` — progress events (same progress resource).
- `GET /api/analyze/:id/report` — completed report.
- `GET /api/analyze/:id/screenshots` and `GET /api/analyze/:id/screenshots/:profile` — temporary in-memory Chromium captures.
- `GET /api/device-profiles` — the three Chromium emulation profiles and test parameters (not physical devices).
- `GET /api/security/:id` — public security observations from the completed report.
- `GET /api/health` — queue depth and worker availability.

Jobs run asynchronously in a bounded in-process queue. To cap browser resource use, the service runs one analysis at a time, queues at most five additional jobs, accepts at most five submissions per client address per hour, bounds server/browser requests and response sizes, and expires reports and screenshot bytes from memory after one hour. Restarting the process clears all jobs.

## Measurement provenance

DNS duration, TCP connection time, TLS handshake duration, response-header time, TLS validation, status, redirects, and headers come from a pinned server request. Then real Chromium renders the website and collects FCP, LCP, CLS, long tasks, navigation timing, resource counts, downloaded response bytes by type, third-party hostnames, browser errors, viewport overflow, touch-target sizes and screenshot captures. axe-core runs WCAG-tagged automated checks. Network speed and CPU slowdown are deliberately emulated, so they are test scenarios rather than actual carrier or specific processor measurements.

Physical-device tests are impossible in this hosted browser worker; phone/tablet/laptop profiles are clearly labeled Chromium emulations. Scenario scores are estimates derived from the collected LCP, response bytes, long tasks and responsive signals and do not attest to a specific product or device memory class. Current product specifications/prices remain **not checked** because no authoritative live price feed is configured. Malware reputation is **UNKNOWN** unless a configured threat provider is explicitly requested. An optional clean Safe Browsing lookup is only a limited signal, not a safety verdict. INP is unavailable without genuine user interaction; Speed Index is unavailable because this service does not record visual video frames. A reachable host, successful render or accepted TLS certificate does not establish that a site is safe to browse. The queue and reports are in process memory, not PostgreSQL/Redis-backed.

## Safety and deployment notes

Only HTTP and HTTPS on their standard ports are accepted. Local/internal hostnames and non-public IPv4/IPv6 destinations are rejected. Every browser-originated HTTP request and redirect is checked against public IP ranges and pinned to a resolved public address. Browser POST/other write methods, downloads, service workers, WebSockets, WebRTC, mixed HTTP resources on HTTPS pages and unsafe/non-web protocols are blocked. Timeouts, redirect limits, byte/request budgets, CPU slowdown, concurrency and API rate limits cap resource use. The in-container browser process remains an attack surface; network egress filtering is still required for internet-facing deployments.

For internet-facing deployment, run the service in the included dedicated, unprivileged resource-limited container and additionally enforce outbound network policy that blocks private, loopback, link-local, and cloud-metadata destinations at the host/cloud firewall. Set ingress rate limits and use a durable queue/database only after adding retention and access controls. The current in-memory queue is for a single-process deployment, not horizontal scale or durable production processing. Do not expose it publicly without network egress controls.

## Limitations

Emulation estimates broad device classes but cannot reproduce a specific phone's RAM, GPU, thermal state, browser build, battery state, radio/network path or real-world physical-device behavior. Automated accessibility scans cannot certify compliance. Device budget bands are indicative scenario categories only; product specs/prices must come from a configured current vendor/catalog source before naming models. Safe Browsing requires an API key and explicit per-analysis consent; a clean lookup can still miss threats and is not a safety guarantee. CAPTCHA, bot defenses, authentication, rate limits and some application flows may prevent representative analysis. Target URLs, screenshots and metrics remain in volatile job memory up to one hour; cookie values and page content are not retained in reports. No account or user-device personal information is collected.
