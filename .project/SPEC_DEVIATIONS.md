# SPEC Deviations

> Documented deviations from SPEC.md and rationale

## Overview

This document tracks intentional deviations from the SPEC.md specification, explaining why they occurred and their current status.

---

## 1. React 19 Frontend (SPEC §17)

**Spec Requirement:** "Embedded vanilla JS dashboard (no framework)"

**Actual Implementation:** React 19 SPA with Tailwind CSS and 9 npm dependencies

**Deviation Date:** 2026-04-05 (v0.1.0 release)

**Rationale:**
- Vanilla JS dashboard development proved too slow for the v0.1.0 deadline
- React ecosystem provides better component reusability and state management
- Modern React with concurrent features offers better UX performance
- Team had existing React expertise

**Dependencies Added:**
```
react@19
react-dom@19
tailwindcss@latest
lucide-react@latest
@tanstack/react-query@latest
zustand@latest
recharts@latest
clsx@latest
tailwind-merge@latest
```

**Impact:**
- Supply chain risk from npm packages (9 dependencies)
- Larger bundle size (not measured)
- Violates zero-dependency philosophy

**Mitigation:**
- All npm packages are well-maintained with good security track records
- Bundle served over HTTPS (DoH/DoH proxy endpoints)
- React SPA is optional - API remains fully functional

**Resolution:** Accepted as permanent exception to zero-dependency policy for frontend only

---

## 2. SWIM Default (SPEC §10)

**Spec Requirement:** "Cluster-First — Raft consensus for zone replication"

**Original Default:** SWIM gossip protocol

**Deviation Date:** 2026-04-05 (v0.1.0 release)

**Rationale:**
- SWIM was more stable at v0.1.0 release time
- Raft implementation was newer and less battle-tested
- SWIM handles single-node deployments more gracefully

**Resolution:** SWIM remains default; Raft requires peer configuration that complicates single-node setups. Raft available but not default.

---

## 3. XoT (RFC 9103)

**Spec Requirement:** "XoT (DNS Zone Transfer over TLS) — RFC 9103"

**Original Status:** Stub implementation (xot.go existed but handleMessage was empty)

**Deviation Date:** 2026-04-05 (v0.1.0 release)

**Resolution:** Fully implemented in 2026-04-11

---

## 4. Frontend Login Flow (SPEC §17)

**Spec Requirement:** "Secure authentication with JWT tokens"

**Original Implementation:** The React login page asked users for a raw JWT token and validated it via `/api/v1/status` instead of using the backend `/api/v1/auth/login` endpoint.

**Deviation Date:** 2026-04-05 (v0.1.0 release)

**Risk:** This bypassed login rate limiting, session tracking, and password validation. The frontend was essentially self-authenticating without server-side validation.

**Resolution:** ✅ **FIXED** - The login page now properly collects `username` and `password`, POSTs to `/api/v1/auth/login`, and stores the returned token in both cookies and the Zustand auth store. Error handling for 401 (Invalid credentials) and 429 (Rate limited) is implemented.

---

## 5. Frontend Mock Data Pages

**Spec Requirement:** "Real-time dashboard with live data"

**Original Implementation:** Three dashboard pages served hardcoded mock data:
- GeoIP page: Mock GeoDNS statistics
- DNS64/Cookies page: Mock configuration values
- Zone Transfer page: Mock slave zone status

**Deviation Date:** 2026-04-05 (v0.1.0 release)

**Risk:** Operators could not trust the UI for system state, leading to operational errors.

**Resolution:** ✅ **FIXED** - All pages now wire to real API endpoints:
- GeoIP: `/api/v1/geoip/stats`
- DNS64/Cookies: `/api/v1/server/config`
- Zone Transfer: `/api/v1/zones/transfers`

---

## 6. Read-Only Settings Page

**Spec Requirement:** "Runtime configuration changes via dashboard"

**Original Implementation:** Settings page was read-only, displaying configuration values but not allowing updates.

**Deviation Date:** 2026-04-05 (v0.1.0 release)

**Risk:** All config changes required YAML edits and SIGHUP reload, reducing operational flexibility.

**Resolution:** ✅ **FIXED** - Settings page now supports editing:
- Logging level (via `/api/v1/config/logging` PUT)
- Rate limiting (via `/api/v1/config/rrl` PUT)
- Cache configuration (via `/api/v1/config/cache` PUT)

Uses TanStack Query mutations with proper loading states and error handling.

---

## 7. Missing Logout Button

**Spec Requirement:** "Secure session management"

**Original Implementation:** No logout button existed in the UI. Users had to manually clear browser storage.

**Deviation Date:** 2026-04-05 (v0.1.0 release)

**Risk:** Users could not easily terminate sessions, especially on shared computers.

**Resolution:** ✅ **FIXED** - Logout button added to sidebar bottom. Calls `useAuthStore.getState().clearAuth()`, clears the `ndns_token` cookie, and redirects to `/login`.

---

*Document Version: 1.1*
*Generated: 2026-04-15*
*Last Updated: 2026-04-15*
