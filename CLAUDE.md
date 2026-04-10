## MANDATORY LOAD

Before any work in this project, read and obey AGENT_DIRECTIVES.md in the project root.

All rules in that file are hard overrides. They govern:
- Pre-work protocol (dead code cleanup, phased execution)
- Code quality (senior dev override, forced verification, type safety)
- Context management (sub-agent swarming, decay awareness, read budget)
- Edit safety (re-read before/after edit, grep-based rename, import hygiene)
- Commit discipline (atomic commits, no broken commits)
- Communication (state plan, report honestly, no hallucinated APIs)

Violation of any rule is a blocking issue.

---

## Project Overrides

### Language & Tooling

- Language: Go
- Min version: 1.22+
- Build: `go build ./...`
- Lint: `go vet ./...`
- Test: `go test ./... -count=1 -short`
- Dependency policy: **strict-zero** — no external dependencies, everything is hand-rolled

### Architecture Notes

- Single binary DNS server (`cmd/nothingdns/`) with CLI companion (`cmd/dnsctl/`)
- Custom YAML parser/tokenizer in `internal/config/` (not gopkg.in/yaml)
- Custom DNS protocol parser in `internal/protocol/` (no miekg/dns)
- All internal packages follow `internal/<package>/` layout
- Server transports: UDP, TCP, TLS, DoH — each in `internal/server/`
- Zone file parser handles BIND format in `internal/zone/`
- API dashboard served from `internal/api/` and `internal/dashboard/`

### Dependency Policy

**ZERO external dependencies.** The entire codebase uses only Go stdlib. Do not add any third-party imports. This is a core design constraint.

### Known Gotchas

- The config YAML parser is custom — it handles most YAML but not advanced features like anchors/aliases or multiline strings
- Port 53 requires root on Unix; use 5354+ for testing
- `protocol.CanonicalWireName()` is the shared canonical name encoder — do not create new ones
- The parser's `advance()` and `peek()` skip `TokenComment` automatically — never handle comments in parse logic
- Health check goroutines use per-round `sync.WaitGroup` — do not reuse the main WG
- `sync.Pool` buffers: copy before passing to `defer pool.Put()`, the reference may be reclaimed
- Upstream TCP messages must check `len(packed) > 65535` before sending
- UDP truncation must be record-boundary-aware (remove answers from the end, not byte-level cut)

### RTK Commands

This project uses [RTK](https://github.com/nothingdns/rtk) for token-optimized command output. RTK prefixes commands automatically:
- `rtk go build ./...` — compact build output
- `rtk go test ./...` — failures only (90%+ token savings)
- `rtk go vet ./...` — grouped violations
- `rtk git status` — compact status
- `rtk gh pr view <num>` — compact PR view

### Web Dashboard

The React 19 SPA dashboard is in `web/src/` and compiled assets served from `internal/dashboard/static/dist/`. WebSocket endpoint `/ws` streams live queries. API handlers in `internal/api/` serve both REST endpoints and the SPA.
