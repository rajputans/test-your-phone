# DeviceFit AI

DeviceFit AI is a runnable website diagnostics service. It performs real, server-side DNS resolution, a bounded HTTP `HEAD` request (with a `GET` fallback only when HEAD returns 405/501), redirect validation, TLS certificate validation, and public response-header checks. The responsive report includes evidence-based timing and security-observation charts, a dark-mode switch, JSON/CSV export, and print-to-PDF. It does **not** fabricate browser or device measurements.

## Run locally

Requirements: Node.js 20 or later. No npm dependencies are required.

```sh
npm run dev
```

Open <http://127.0.0.1:3000>. Paste a public URL such as `https://example.com` to run a live check. `npm start` starts the same server. `HOST` and `PORT` can be set in the environment; `.env.example` documents the optional values. The server binds to loopback by default.

Run the automated checks with:

```sh
npm test
```

## API

- `POST /api/analyze` — JSON `{ "url": "https://example.com" }`; returns a queued job ID.
- `GET /api/analyze/:id` — live job status and completed report.
- `GET /api/analyze/:id/progress` — progress events (same progress resource).
- `GET /api/analyze/:id/report` — completed report.
- `GET /api/device-profiles` — explicitly reports browser profiles as unavailable.
- `GET /api/health` — queue depth and worker availability.

Jobs run asynchronously in a bounded in-process queue. The service allows two concurrent checks, queues at most eight additional checks, accepts at most five submissions per client address per hour, times out requests after ten seconds, follows at most five redirects, and expires completed job data from memory after one hour. Restarting the process clears all jobs.

## Measurement provenance

DNS duration, TCP connection time, TLS handshake duration, response-header time, TLS certificate validation, HTTP status, redirect chain, and observed response headers come from actual server-side checks. The request normally uses `HEAD`. If the server rejects HEAD with 405/501, it retries once with a `GET` and `Range: bytes=0-0`, then destroys the response after headers without parsing or storing the page body. A server may ignore Range and some bytes may arrive before the connection closes; public HTTP requests can have target-specific side effects, so this remains a low-impact diagnostic, not a guarantee of zero impact. Cookie values are not retained.

Browser Core Web Vitals, resource timing/page weight, screenshots, responsive behavior, accessibility, physical-device testing, device suitability, malware reputation, and third-party vulnerability intelligence are **unavailable**. Therefore all mobile/tablet/laptop budget recommendations and current product prices are explicitly unverified. The charts visualize only measured connection timings and observed response-header controls; the control count is not a security score. A reachable host or accepted TLS certificate does not establish that a site is safe to browse. This deployment has no isolated browser worker, external intelligence API, database, or Redis queue. No score is shown where evidence is insufficient.

## Safety and deployment notes

Only HTTP and HTTPS on their standard ports are accepted. Local/internal hostnames and non-public IPv4/IPv6 destinations are rejected. DNS answers are checked and each connection is pinned to a validated address; every redirect is validated and resolved again. Requests have a timeout, do not follow more than five redirects, and are bounded by concurrency/rate limits. On HEAD rejection, one bounded GET fallback is used as described above. This minimizes but does not eliminate operational risk.

For internet-facing deployment, run the service in a dedicated, unprivileged container with outbound network policy that blocks private, loopback, link-local, and metadata ranges; set platform-level CPU/memory limits and ingress rate limits; use a persistent queue/database only after adding explicit retention and access controls. The current in-memory queue is intended for a single-process local deployment, not horizontal scale or durable production job processing. Do not expose the service publicly without network egress controls.

## Limitations

The service does not browse or render submitted sites and therefore cannot provide viewport screenshots, mobile/tablet/laptop compatibility, browser performance metrics, automated accessibility results, JavaScript/iframe inspection, mixed-content detection, or accurate device recommendations. It does not source live phone/tablet/laptop product specifications or prices. Security observations are not a penetration test and do not guarantee safety. Malware risk remains `UNKNOWN` without a configured trusted reputation service. Some sites reject both HEAD and GET or return headers that differ from their rendered page response. No user account or login flow exists, and the service does not collect personal device information.
