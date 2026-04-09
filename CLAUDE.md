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


<!-- rtk-instructions v2 -->
# RTK (Rust Token Killer) - Token-Optimized Commands

## Golden Rule

**Always prefix commands with `rtk`**. If RTK has a dedicated filter, it uses it. If not, it passes through unchanged. This means RTK is always safe to use.

**Important**: Even in command chains with `&&`, use `rtk`:
```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
rtk git add . && rtk git commit -m "msg" && rtk git push
```

## RTK Commands by Workflow

### Build & Compile (80-90% savings)
```bash
rtk cargo build         # Cargo build output
rtk cargo check         # Cargo check output
rtk cargo clippy        # Clippy warnings grouped by file (80%)
rtk tsc                 # TypeScript errors grouped by file/code (83%)
rtk lint                # ESLint/Biome violations grouped (84%)
rtk prettier --check    # Files needing format only (70%)
rtk next build          # Next.js build with route metrics (87%)
```

### Test (90-99% savings)
```bash
rtk cargo test          # Cargo test failures only (90%)
rtk vitest run          # Vitest failures only (99.5%)
rtk playwright test     # Playwright failures only (94%)
rtk test <cmd>          # Generic test wrapper - failures only
```

### Git (59-80% savings)
```bash
rtk git status          # Compact status
rtk git log             # Compact log (works with all git flags)
rtk git diff            # Compact diff (80%)
rtk git show            # Compact show (80%)
rtk git add             # Ultra-compact confirmations (59%)
rtk git commit          # Ultra-compact confirmations (59%)
rtk git push            # Ultra-compact confirmations
rtk git pull            # Ultra-compact confirmations
rtk git branch          # Compact branch list
rtk git fetch           # Compact fetch
rtk git stash           # Compact stash
rtk git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

### GitHub (26-87% savings)
```bash
rtk gh pr view <num>    # Compact PR view (87%)
rtk gh pr checks        # Compact PR checks (79%)
rtk gh run list         # Compact workflow runs (82%)
rtk gh issue list       # Compact issue list (80%)
rtk gh api              # Compact API responses (26%)
```

### JavaScript/TypeScript Tooling (70-90% savings)
```bash
rtk pnpm list           # Compact dependency tree (70%)
rtk pnpm outdated       # Compact outdated packages (80%)
rtk pnpm install        # Compact install output (90%)
rtk npm run <script>    # Compact npm script output
rtk npx <cmd>           # Compact npx command output
rtk prisma              # Prisma without ASCII art (88%)
```

### Files & Search (60-75% savings)
```bash
rtk ls <path>           # Tree format, compact (65%)
rtk read <file>         # Code reading with filtering (60%)
rtk grep <pattern>      # Search grouped by file (75%)
rtk find <pattern>      # Find grouped by directory (70%)
```

### Analysis & Debug (70-90% savings)
```bash
rtk err <cmd>           # Filter errors only from any command
rtk log <file>          # Deduplicated logs with counts
rtk json <file>         # JSON structure without values
rtk deps                # Dependency overview
rtk env                 # Environment variables compact
rtk summary <cmd>       # Smart summary of command output
rtk diff                # Ultra-compact diffs
```

### Infrastructure (85% savings)
```bash
rtk docker ps           # Compact container list
rtk docker images       # Compact image list
rtk docker logs <c>     # Deduplicated logs
rtk kubectl get         # Compact resource list
rtk kubectl logs        # Deduplicated pod logs
```

### Network (65-70% savings)
```bash
rtk curl <url>          # Compact HTTP responses (70%)
rtk wget <url>          # Compact download output (65%)
```

### Meta Commands
```bash
rtk gain                # View token savings statistics
rtk gain --history      # View command history with savings
rtk discover            # Analyze Claude Code sessions for missed RTK usage
rtk proxy <cmd>         # Run command without filtering (for debugging)
rtk init                # Add RTK instructions to CLAUDE.md
rtk init --global       # Add RTK to ~/.claude/CLAUDE.md
```

## Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget | 65-70% |

Overall average: **60-90% token reduction** on common development operations.
<!-- /rtk-instructions -->
