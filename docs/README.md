# NothingDNS Documentation

This directory contains NothingDNS design, usage, and operations documentation.

## Getting Started

| Document | Contents |
|---|---|
| [../README.md](../README.md) | Project overview, feature list, and quick start |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Dev environment, build/test commands, PR process |
| [../QUICK_START.md](../QUICK_START.md) | 5-minute quick start with Docker, binary, or Kubernetes |
| [SECURITY.md](SECURITY.md) | Security policy, vulnerability reporting |

## Architecture & Design

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture, 21-stage request pipeline, component diagrams |
| [SPECIFICATION.md](SPECIFICATION.md) | Functional specification: protocols, architecture, feature scope |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | Implementation details: package structure, init order, algorithms |

## Operations

| Document | Contents |
|---|---|
| [OPERATIONS.md](OPERATIONS.md) | Deployment, hot reload, backup/recovery, monitoring, cluster ops |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues and solutions |
| [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md) | Pre-deployment and installation checklists |
| [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) | Production deployment best practices |
| [PRODUCTION_PROOF_CHECKLIST.md](PRODUCTION_PROOF_CHECKLIST.md) | Evidence-driven release and runtime verification checklist |
| [CONFIG_REFERENCE.md](CONFIG_REFERENCE.md) | YAML config reference: fields, types, defaults, hot-reload behavior |

## Management & CLI

| Document | Contents |
|---|---|
| [CLI_REFERENCE.md](CLI_REFERENCE.md) | dnsctl command reference (zone, record, cache, cluster, etc.) |
| [API_REFERENCE.md](API_REFERENCE.md) | REST API endpoints and examples |

## Performance & Testing

| Document | Contents |
|---|---|
| [PERFORMANCE.md](PERFORMANCE.md) | Performance tuning, benchmarks, profiling, caching strategies |
| [TESTING.md](TESTING.md) | Testing pyramid, patterns for unit/integration/E2E, fuzzing |

## Reference

| Document | Contents |
|---|---|
| [GLOSSARY.md](GLOSSARY.md) | 400+ DNS terms, RFC index (60+ references), quick reference tables |
| [DEPENDENCIES.md](DEPENDENCIES.md) | Go module dependencies and minimal-dependency philosophy |

## Community & Project

| Document | Contents |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | Semantic version changelog: Added/Fixed/Changed |
| [.project/SPEC_DEVIATIONS.md](../.project/SPEC_DEVIATIONS.md) | Intentional deviations from SPEC.md with rationale |
| [.project/AUTH_KDF.md](../.project/AUTH_KDF.md) | Custom PBKDF2 implementation design document |

## Quick Links

```
docs/
├── ARCHITECTURE.md      # Start here to understand the system
├── CONFIG_REFERENCE.md  # Every config option explained
├── OPERATIONS.md        # Day-to-day operations runbook
├── CLI_REFERENCE.md     # dnsctl full command reference
└── TROUBLESHOOTING.md   # Issue → solution lookup
```
