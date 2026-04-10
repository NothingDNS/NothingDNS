# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] - 2026-04-09

### Changed

- Migrated to agentskills.io standard (folder-based `skills/sc-xxx/SKILL.md` format)
- Primary install method is now `npx skills add ersinkoc/security-check`
- Skills are maintained in a single canonical `skills/` directory (was triplicated)
- Checklists bundled inside language skill `references/` subdirectories
- Comprehensive installer scripts: `skills.sh` (macOS/Linux) and `skills.ps1` (Windows)
- Added Roo Code and Amp to supported platforms

### Fixed

- Critical: CLAUDE.md now references all 48 skills correctly (was missing 33 skills)
- Fixed `detect_platform()` stdout contamination in skills.sh
- Fixed `$Args` parameter shadowing in skills.ps1
- All documentation updated to reflect new file structure

### Removed

- Redundant `scan-target/.claude/skills/` and `scan-target/.agents/skills/` copies
- Standalone `checklists/` directory (now in skill `references/`)
- `install.sh` and `install.ps1` wrapper scripts

## [1.0.0] - 2026-04-08

### Added

- Initial release of security-check
- 40+ vulnerability detection skills across all major categories
  - Injection: SQL, NoSQL, GraphQL, XSS, SSTI, XXE, LDAP, Command, Header
  - Code Execution: RCE, Insecure Deserialization
  - Access Control: Authentication, Authorization, Privilege Escalation, Session
  - Data Exposure: Secrets, Sensitive Data, Cryptography Misuse
  - Server-Side: SSRF, Path Traversal, File Upload, Open Redirect
  - Client-Side: CSRF, CORS, Clickjacking, WebSocket
  - Logic: Business Logic, Race Conditions, Mass Assignment
  - API: API Security, Rate Limiting, JWT
  - Infrastructure: IaC, Docker, CI/CD
- 7 language-specific deep security scanners
  - Go, TypeScript/JavaScript, Python, PHP, Rust, Java/Kotlin, C#/.NET
- 400+ item security checklists per language
- 4-phase scanning pipeline: Recon, Hunt, Verify, Report
- Confidence scoring (0-100) with CVSS v3.1-style severity
- Supply chain and dependency analysis
- Infrastructure-as-Code scanning
- Diff mode for PR-level incremental scans
- Support for Claude Code, Codex, Cursor, Opencode, Windsurf, Gemini CLI
- One-command installation script
- Modular plugin architecture with templates
- Comprehensive documentation
