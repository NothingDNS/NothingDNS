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

*Document Version: 1.0*
*Generated: 2026-04-11*
*Last Updated: 2026-04-11*
