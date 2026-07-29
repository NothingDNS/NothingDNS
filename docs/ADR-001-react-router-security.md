# ADR-001: React Router Security Posture (SPA, No Downgrade)

**Date:** 2026-07-29  
**Status:** Accepted  
**Scope:** `web/` (React SPA dashboard)

---

## Context

The npm audit on `react-router-dom@7.18.2` reports **2 HIGH severity findings** (GHSA-qwww-vcr4-c8h2). The natural first response — downgrade to a version outside the vulnerable range — was investigated and rejected.

## Decision

**Stay on `react-router-dom@7.18.2`.** Do not downgrade.

## Rationale

| Option | HIGH CVEs | Verdict |
|--------|-----------|---------|
| **7.18.2 (current)** | 1 advisory — RSC Mode CSRF bypass | ✅ **Not applicable** — SPA has no RSC mode |
| **7.11.0 (downgrade target)** | 14 advisories — XSS, open redirects, DoS, arbitrary constructor injection, CSRF | ❌ **Rejected** — many apply to classic SPAs |

The single CVE in 7.18.2 is scoped to React Server Components (RSC) mode — a feature NothingDNS's dashboard does not use. The dashboard is a classic client-side SPA: an empty `<div id="root">` shell hydrated in the browser with no server-rendered React, no `__RSC` markers, and no `data-rsc` attributes.

A downgrade to 7.11.0 would trade one non-applicable advisory for 14 HIGH CVEs that **do** apply to SPAs — including open redirects, XSS via open redirects, and unauthenticated DoS via inefficient route matching. This is a net-negative security outcome.

## Mitigations in place

1. **Regression test** (`web/src/lib/verify-spa-mode.test.ts`) — asserts the built `index.html` has no RSC markers, confirming the architecture that makes the CVE non-applicable.
2. **CSP reporting** (`POST /api/v1/csp-report`) — the CSP header includes `report-uri /api/v1/csp-report` so policy violations are logged for monitoring.
3. **Two additional security headers** — `X-DNS-Prefetch-Control: off` and `X-Permitted-Cross-Domain-Policies: none` added to `securityHeadersMiddleware`.
4. **Advisory monitor** (`.github/workflows/advisory-monitor.yml`) — weekly check that files a GitHub Issue when new react-router advisories appear.
5. **npm audit allowlist** (`web/.nsprc`) — suppresses the known non-applicable advisory so CI doesn't block on it, while remaining open to NEW advisories.

## Refresh cadence

Re-evaluate this posture when either:

- A new react-router patch (>7.18.2 or >8.2.0) is released that fixes the 7.12.0-8.2.0 CVEs.
- A new advisory appears (the monitor workflow will detect it).
- The dashboard adopts any RSC or SSR feature (unlikely — stay SPA).

Run `npm view react-router-dom versions` to check for newer releases.

## References

- GHSA-qwww-vcr4-c8h2: https://github.com/advisories/GHSA-qwww-vcr4-c8h2
- `.nsprc`: `web/.nsprc`
- SPA regression test: `web/src/lib/verify-spa-mode.test.ts`
- Advisory monitor: `.github/workflows/advisory-monitor.yml`
