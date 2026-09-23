# Changelog

All notable changes to NothingDNS are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.8] — 2026-09-23

### Fixed

- Same installer credentials fix as 1.2.7, **locally verified** before release:
  fresh bootstrap, secret refresh, reinstall keep, and stale-`users.json`
  reclaim all write `username`/`password` and print them at finish.

### Added

- `scripts/test-install-credentials.sh` — local no-sudo integration harness for
  the installer credential/bootstrap flow (used to gate this release).

## [1.2.7] — 2026-09-23

### Fixed

- **Installer finish banner and credentials omitted username/password**:
  bootstrap now writes `username` + `password` into `/etc/nothingdns/credentials`
  before calling the API, retries while the HTTP API comes up, and on
  "Old password required" (stale `users.json`) resets runtime users once and
  retries. The installation summary always prints Dashboard URL, Username, and
  Password when those lines are present.

## [1.2.6] — 2026-09-23

### Fixed

- **Installer could leave no usable admin password**: rewriting
  `/etc/nothingdns/credentials` with only `api_auth_secret` wiped a previous
  admin password; a later bootstrap then failed with "Old password required"
  when `users.json` already had an admin. Credentials now preserve
  username/password across secret refresh, bootstrap passwords are longer
  (≥16), responses are handled explicitly, and the finish summary always
  points at the credentials file.

## [1.2.5] — 2026-09-23

### Fixed

- **`curl | bash` install fell back to 5353 on Ubuntu**: stdin is a pipe so the
  installer treated the session as non-interactive and refused to free the
  `systemd-resolved` stub. Prompts now use `/dev/tty` when available, and when
  only the resolved stub (127.0.0.53/54) holds port 53 the installer frees it
  automatically and continues on port 53. Other DNS packages still require a
  TTY choice or `NOTHINGDNS_STOP_HOST_DNS=1`.

## [1.2.4] — 2026-09-23

Installer readiness for Raft clustering, a Raft-aware cluster topology in the
dashboard, and clearer port-53 takeover during install on Ubuntu and similar hosts.

### Added

- **Raft topology in the dashboard and API**: `GET /api/v1/cluster/nodes` returns
  configured Raft peers (not only the local gossip self-entry) with `role`
  (`leader` / `follower` / `candidate`). The Cluster page draws a leader-centric
  topology diagram and labels members. Status `node_count` / `alive_count` match
  the peer set.
- **Installer prepares cluster data dirs**: `install.sh` / `setup.sh` create
  `/var/lib/nothingdns/cluster` owned by the `nothingdns` user (`0750`), and the
  default config sets `cluster.data_dir` / `consensus_mode: raft` (still
  `enabled: false`). Docker image includes `/data/cluster` for UID 1000.

### Changed

- **Port 53 conflict UX**: when another DNS process holds port 53, the installer
  identifies process/pid/unit (e.g. Ubuntu `systemd-resolved`), offers to free
  port 53 (stop/disable known DNS units; resolved stub-only), or install on
  5353. If freeing fails, previous DNS is restored and install completes on
  5353. Non-interactive installs still require `NOTHINGDNS_STOP_HOST_DNS=1` to
  take over port 53.

## [1.2.3] — 2026-09-18

### Fixed

- **Dashboard hard refresh logged users out**: the bearer token is kept only in
  memory (not `localStorage`) for XSS resistance, so Ctrl+F5 cleared
  `isAuthenticated` even though the HttpOnly `ndns_token` cookie was still
  valid. The SPA now calls `GET /api/v1/auth/session` on load to rebuild the
  in-memory bearer from that cookie before showing the login screen.

## [1.2.2] — 2026-09-17

Dashboard and API improvements for live operations: ACL rule editing, answer
RDATA in the live query stream, working Metrics History charts, a clearer path
to the API explorer, and runtime-persisted settings that do not need a restart.

### Added

- **ACL Rules CRUD in the dashboard**: the ACL page can add, edit and remove
  general ACL rules (ALLOW / DENY / REDIRECT) via `PUT /api/v1/acl`, alongside
  the existing recursion allow list. Changes persist in `access_policy.json`.
- **Answer RDATA in the live query stream and query log**: each event now
  carries a short summary of answer records (type and RDATA), so the Dashboard
  live stream and Query Log show what was returned, not only the question.
- **Runtime config overrides (`runtime_overrides.json`)**: hot-reloadable
  tunables changed through `PUT /api/v1/config/*` (logging level, RRL, cache,
  resolution, DNS64/cookie toggles, upstream server list) are saved under
  `<storage.data_dir>/runtime_overrides.json` and re-applied over the YAML at
  start and on every reload.
- **Settings UI for no-restart options**: Resolution, Upstream, Rate Limit,
  DNS64 and DNS Cookie pages can edit the live config and persist it without
  rewriting the YAML file.
- **API Docs entry points**: the API explorer (`/api/docs`) is linked from the
  sidebar and prominently from About, not only a footer line.

### Fixed

- **Metrics History charts drew flat / empty bars**: the bar chart used
  `h-full` inside a flex `items-end` container (height collapsed to 0), and the
  series were cumulative counters rather than per-minute rates. Charts now use
  absolute pixel heights and delta-based per-minute values.

## [1.2.1] — 2026-09-17

Fixes found by testing a real installation end to end: DNSSEC false SERVFAILs,
local zones hidden by cached upstream answers, records lost on restart, host
DNS broken by the installer, and a set of dashboard and API defects. No
configuration changes are required to upgrade.

### Fixed

- **Local zones hidden by cached upstream data**: the cache and the aggressive NSEC cache (RFC 8198) were consulted before the server's own zones, so an upstream NXDOMAIN or NSEC proof for a parent name — the root proving `.lan`, `.test` or `.internal` does not exist, or the public view of a split-horizon domain — made local zones answer NXDOMAIN to every client allowed recursion. Split-horizon views, authoritative zones and in-zone CNAMEs are now resolved before the caches.
- **Records whose owner starts with `_` lost on restart**: zones stored in the persistent database skipped every owner name beginning with an underscore as metadata when loaded, so SRV (`_sip._tcp`), DMARC (`_dmarc`), DKIM (`_domainkey`) and ACME (`_acme-challenge`) records disappeared after a restart and were removed permanently by the next change to the zone.
- **Negative answers had TTL 0 after a restart**: the SOA TTL was not restored for zones loaded from the persistent database (or received by zone transfer), so NXDOMAIN/NODATA answers, AXFR and zone exports carried TTL 0. The negative-answer SOA TTL now follows RFC 2308 (the lesser of the SOA TTL and MINIMUM).
- **CAA values served with literal quotes**: `0 issue "letsencrypt.org"` was served as `"\"letsencrypt.org\""`. Quoted CAA values are now parsed as character-strings.
- **Zone export dropped NS records and double-quoted TXT**: exports of zones created or loaded through the API had no NS records and wrote TXT values as `"\"v=spf1 ...\""`, so re-importing the file broke the zone.
- **Bulk PTR wrote forward A records into the reverse zone**: with "Also add A records", names such as `host-192-0-2-1.example.com` became `host-192-0-2-1.example.com.2.0.192.in-addr.arpa.` in the reverse zone. Pattern names are now absolute host names, A records go to the loaded zone that contains each name, and a name outside every loaded zone is rejected before anything is written.
- **RPZ could not be enabled from the dashboard or API**: without `rpz.enabled: true` in the config there was no RPZ engine, so Enable and Add Rule always failed with 503. Rules entered with a trailing dot (`bad.example.`) never matched.
- **Response EDNS OPT record**: recursive answers passed the upstream's OPT record through (DO=1 and a 512-byte payload even when the client had not set DO) and could carry an OPT to non-EDNS clients. Responses now carry an OPT only for EDNS requests, with the request's DO bit (RFC 3225) and this server's payload size.
- **Dashboard dialogs rendered inline**: the Create Zone, Add/Edit Record and Bulk PTR forms were always visible on the page instead of opening as dialogs.
- **Dashboard records table**: long record names wrapped onto several lines, long values pushed the edit/delete buttons out of view, and rows appeared in a different order on every load. Names stay on one line, values wrap, and records are sorted (SOA and NS first, then by name hierarchy with numeric ordering).
- **Viewer role in the dashboard**: viewers were offered pages whose API calls they are not allowed to make (every page showed "Operator role required"). They now see the Dashboard live stream and About only, and the live stream of a previous session (with unmasked client IPs) is cleared on logout.
- **Query log**: `/api/v1/queries` and the Query Log page now list the newest queries first.
- **Upstreams page**: showed a single aggregate entry named `direct-upstream`. `GET /api/v1/upstreams` now also returns each configured server with its health and last query latency, and the page lists them.
- **Settings → Logging**: after changing the log level at runtime the page kept showing the config-file level and could not switch back to it; `GET /api/v1/config` now reports the level in effect.
- **Unknown API paths**: any unknown path under `/api/` returned the dashboard HTML with status 200; it now returns `404 {"error":"Not found"}`.
- **Misleading startup warning**: "No users configured. Default admin account created." was logged on every start even when users were loaded from the users file.

- **DNSSEC: false SERVFAIL for names inside signed zones**: the chain of trust was built down to the query name, so every name that is not itself a zone cut (`www.isc.org`, `deb.debian.org`, `security.debian.org`, `gouv.fr`) failed with "DS empty … but no authenticated denial proof". The chain now ends at the zone that signed the answer (RRSIG signer, in bailiwick of the query name). Empty DS answers are classified from the parent's authenticated NSEC/NSEC3 or signed CNAME as not-a-zone-cut, name error or insecure delegation; anything else still fails closed as a downgrade attempt.
- **DNSSEC: NXDOMAIN under NSEC3 zones and cross-zone CNAMEs**: nonexistent names in NSEC3-signed zones (`.tr`, `.nl`) and CNAME targets signed by another zone (`www.iana.org`, `www.gov.uk`, `www.sidn.nl`) now validate each RRset against its own signer's chain instead of returning SERVFAIL. A DS query the upstream answers with SERVFAIL is treated as a fetch failure (Indeterminate), and DS records for other owners are ignored.
- **install.sh left the host without DNS**: taking over port 53 stopped `systemd-resolved` before downloading the release (so the download itself failed) and left `/etc/resolv.conf` pointing at the dead `127.0.0.53` stub. The installer now downloads and verifies first, keeps `systemd-resolved` running with only `DNSStubListener=no`, points `/etc/resolv.conf` at resolved's upstream servers, repairs hosts already broken this way, and restores the previous resolver setup if NothingDNS fails to start. `uninstall.sh` re-enables the stub; `setup.sh` warns when port 53 is taken and prints the safe steps.
- **Logging: rotated log files stopped receiving writes**: the shipped logrotate rules moved the open `query.log`/`server.log` aside and only sent a reload, which does not reopen them, so new lines went to the rotated file and were lost at the next rotation. The rules now use `copytruncate`; `install.sh` rewrites existing rules.
- **Logging: `logging.output` file paths and package-level log calls**: `output` accepted a file path in docs and examples but always wrote to stdout. It now accepts `stdout`, `stderr` or an absolute file path (validated, as is `query_log_file`). Log lines from the API, dashboard and config packages ignored `logging.level`, `format` and `output`; they now use the configured logger.
- **Query log RCODE**: the query log's `rcode=` field was always empty, and the dashboard query log showed NOERROR for NXDOMAIN, SERVFAIL and other answers. Both now record the RCODE of the response actually sent.
- **ACL rules accept single IPs; redirect targets validated**: ACL `networks` accept bare IPs (as `/32`/`/128`) like `allow_recursion`, and a `redirect` rule must name a domain (IP addresses and empty targets are rejected by config validation and the API).

## [1.2.0] — 2026-09-17

Recursion allow list with dashboard management, a verified API reference and
explorer, and fixes for ODoH, zone management, IP privacy and user errors.
See **Upgrade notes** before upgrading.

### Added

- **Recursion allow list (`allow_recursion`)**: recursion — upstream forwarding, iterative resolution and cached answers — is now controlled separately from the general ACL. Clients outside the list still receive answers from the server's own zones; other names are refused (REFUSED, EDE 18 "Prohibited", RA=0), and the shared cache is not served to them. The general `acl` keeps applying to every query.
- **Dashboard: "Allow Recursion" on the ACL page**: administrators can add and remove networks (CIDRs or single IPs), with confirmation before opening recursion to `0.0.0.0/0`/`::/0` or removing the last network. Backed by the new `GET/PUT /api/v1/acl/recursion` endpoint; `GET /api/v1/acl` also returns the recursion list and whether changes persist.
- **Persistent access policy**: ACL and recursion changes made through the API or dashboard are saved to `<storage.data_dir>/access_policy.json` (mode 0600) and survive restarts and SIGHUP reloads; the file overrides `acl`/`allow_recursion` from the config file. A failed save rolls the change back.

### Changed

- **Default: authoritative answers for everyone, recursion for local networks**: with no `acl` and no `allow_recursion`, every client can query the server's own zones and only loopback/private networks may recurse. Previously a forwarding server with no ACL was an open resolver, and a recursive server with no ACL refused every client including its own zones. Installer, Docker and example configs now express the local-network restriction as `allow_recursion` instead of a general ACL.
- Configs that already have `acl` rules but no `allow_recursion` keep their behaviour: every client the ACL admits may recurse.

### Fixed

- **ACL rules could not be added from the API when none were configured**: the server installed no ACL checker, so `PUT /api/v1/acl` answered 503. A checker now always exists; rules added at runtime refuse unmatched clients exactly like configured rules.
- **ACL changes made through the API were lost on restart or reload**; they are now persisted (see above).
- The ACL page listed DROP and REFUSE actions the server does not support; it now shows ALLOW, DENY and REDIRECT.
- **`blocklist.base_dir` was never read from the config file** (regression from 1.1.11): the field existed but the loader did not parse it, so adding blocklist files through the API always failed. It is now parsed.
- **ODoH target mode could not start**: the config only accepts the RFC 9180 KEM id 32 (0x0020) while the runtime compared against a private ordinal (4), so every ODoH-enabled server exited with "unsupported HPKE suite". `internal/odoh` now uses RFC 9180 ids for KEMs and AEADs. **AEAD ids changed accordingly**: `1` = AES-128-GCM (default), `2` = AES-256-GCM; `3` (ChaCha20-Poly1305) is rejected. Previously `1` selected AES-256-GCM and `3` AES-128-GCM.
- **API explorer works in browsers**: `/api/docs` loaded Swagger UI from unpkg.com, which the server's own CSP (`script-src 'self'`) blocked, so the page stayed blank. It is now a self-contained explorer served from `/api/docs/app.js` (no CDN, no third-party script in the authenticated origin), linked from the dashboard's About page.
- **Record updates without `ttl` reset the TTL to 0**: `PUT /api/v1/zones/{zone}/records` now keeps the record's current TTL when `ttl` is omitted; an explicit `0` is still honoured. Updating a record that does not exist returns `404`.
- **Zones created without `admin_email` lost their SOA after a restart**: the SOA RNAME was empty, leaving six RDATA fields the persistence layer could not parse back. RNAME now defaults to `hostmaster.<zone>`, `user@domain` addresses are converted, SOA/NS names without a trailing dot are qualified, and an address that cannot be an RNAME (dots in the user part) is rejected with `400`.
- **Deleting a zone deleted config-owned zone files**: `DELETE /api/v1/zones/{zone}` removed the zone's file even when it was listed under `zones:` in the config. Only files inside `zone_dir` are removed now; config-listed files are kept.
- **Client IPs were not masked for non-admins** in `/api/dashboard/queries` and the `/ws` live stream (open to viewers), unlike `/api/v1/queries`. Both now mask the last octet or group for non-admins.
- **Invalid user input returned 409**: creating a user (or bootstrapping) with a too-short password returned `409 Conflict`; validation errors now return `400`, and `409` is reserved for a taken username.
- **CI npm audit never failed**: with `web/.nsprc` present the audit output was piped into `head`, discarding its exit status. The obsolete allowlist (react-router 8.3.0 fixes GHSA-qwww-vcr4-c8h2) is removed and the audit is strict.

### Documentation

- `docs/API_REFERENCE.md` rewritten and verified against the handlers: every route with method, required role, request and response bodies, status codes, authentication (bearer, session cookie, legacy token, bootstrap), ACL and recursion, DNS privacy transports and known issues. `docs/API_ZONES.md` corrected (zone endpoints require the operator role; `POST /zones/reload` requires admin), and the OpenAPI spec documents every route with its required role.
- `docs/CLI_REFERENCE.md` documents `dnsctl server bootstrap`; `docs/CONFIG_REFERENCE.md` documents `allow_recursion` and the access policy file; supported versions updated in `SECURITY.md`.

### Removed

- Personal editor/agent tooling and internal planning notes from version control (`.cursorrules`, `.windsurfrules`, `.wrongstack/`, `.project/`), the unused `.githooks/` copy, and the outdated `.github/CONTRIBUTING.md` (it claimed a zero-dependency policy and shadowed the root `CONTRIBUTING.md` on GitHub). `.gitignore` now covers common editor, AI-assistant and agent state directories.

### Upgrade notes

- **Recursion is limited by default.** Configs with neither `acl` nor `allow_recursion` now answer their own zones for everyone but recurse only for loopback and private networks. Add `allow_recursion` (or use the dashboard's ACL page) if public clients must recurse. Configs with `acl` rules and no `allow_recursion` behave as before.
- **ODoH AEAD ids follow RFC 9180**: `1` = AES-128-GCM (default), `2` = AES-256-GCM; `3` is rejected. Previously `1` meant AES-256-GCM and `3` AES-128-GCM.
- **Access policy file**: after the first ACL or recursion change on the dashboard, `<storage.data_dir>/access_policy.json` overrides `acl` and `allow_recursion` in the config file. Delete it to return to the config.
- **Zone deletion keeps config-listed files**: remove the zone from `zones:` as well to delete it permanently.
- **User creation errors**: validation failures now return `400` instead of `409`.

## [1.1.12] — 2026-09-16

Installation release. install.sh, setup.sh, update.sh, config.sh and
uninstall.sh were exercised on Ubuntu 24.04 under systemd, Docker Compose was
run from a bare compose file, the Helm chart was rendered and its config
validated, and install.ps1's config generation was run under PowerShell 7.
A fresh install with the previous scripts produced a server that did not
start.

### Fixed — installation

- **Installer configs made the server exit at startup**: `install.sh`, `setup.sh`, `install.ps1` and `deploy/config-node{1,2,3}.yaml` enabled metrics on `:9153` without `auth_token`, which the server refuses — while `-validate-config` reported the file as valid. Generated configs now bind metrics to `127.0.0.1:9153`, the node configs take `auth_token` from `NOTHINGDNS_METRICS_AUTH_TOKEN`, and `-validate-config` rejects a non-loopback metrics bind without a token.
- **Metrics without a token work on loopback**: the error message already said "bind metrics to localhost only", but the server refused that too, and the handler answered 401 to local scrapers. A tokenless endpoint is now allowed on loopback and serves only loopback peers.
- **systemd service could not start**: it ran as `nobody:nogroup` (no `nogroup` on RHEL) while the config was root-owned `0600`, the binary was installed `0700` via `mktemp` + `mv`, and there was no `WorkingDirectory`, so the IXFR journal store failed on the read-only `/`. The scripts now create a `nothingdns` system user, install binaries with `install -m 0755`, own `/var/lib/nothingdns` and `/var/log/nothingdns` by that user, keep the config `root:nothingdns 0640`, set `storage.data_dir: /var/lib/nothingdns`, and the units (including `deploy/nothingdns.service`) use `WorkingDirectory=/var/lib/nothingdns`.
- **Dashboard users were lost on restart**: users created through the bootstrap endpoint, the dashboard or the API lived only in memory, so the installer's admin password stopped working after the first restart. They are now persisted to `server.http.users_file` (default `<storage.data_dir>/users.json`, mode 0600); config-defined users keep precedence and are never written there.
- **`setup.sh` aborted immediately**: `${#missing[@}` is a bash "bad substitution" error in the prerequisite check.
- **`install.sh` could delete the installed binary**: re-running it on an up-to-date system removed `/usr/local/bin/nothingdns` and then skipped the download. It also compared `1.1.11` with `v1.1.11` and always reported an available upgrade, matched `:5353` as port 53, turned `port: 5353` into `port: 535353` on re-runs, wrote the config without `sudo`, printed the admin password to stdout, and required an unused `gzip`.
- **`update.sh` installed unverified binaries**: it now checks `SHA256SUMS` like the installers, validates the current config with the new binary before stopping the service, and uses bare-semver version comparison.
- **`config.sh` validation never worked**: it called a non-existent `--validate` flag and relied on PyYAML. It now uses `nothingdns -validate-config`, refuses to reload an invalid config, and handles the root-owned config with `sudo`.
- **Generated configs were open resolvers** and used an unknown `upstream.timeout` key: installer configs now carry an ACL for loopback and private networks.
- **Windows install could not succeed**: releases had no Windows binaries (now built for `windows/amd64` and `windows/arm64`), `RandomNumberGenerator.GetBytes(int)` does not exist on Windows PowerShell 5.1, and `Out-File -Encoding UTF8` wrote a byte order mark.
- **A UTF-8 BOM hid the first config section**: `\ufeffserver` was treated as an unknown key, so `server:` was silently ignored. The loader strips the BOM.
- **Docker quick start failed**: `docker-compose.yml` mounted `./config.example.yaml` (a directory once Docker creates the missing path) whose relative zone path does not exist in the container, and `/data` was root-owned while the container runs as UID 1000. The image now ships `deploy/docker/nothingdns.yaml` as its default config and a `/data` owned by UID 1000.
- **No way to create the first admin in Docker**: bootstrap only accepts localhost, and the scratch image has no shell or curl. New `dnsctl server bootstrap` (password from stdin or `NOTHINGDNS_ADMIN_PASSWORD`) works via `docker exec -i nothingdns dnsctl server bootstrap`.
- **Helm installed an old image**: `appVersion` was `1.0.0`, the default image tag. It now tracks the release, enforced by `TestHelmChartAppVersionMatchesVersionFile`.
- **`deploy/staging.yaml` refused every query**: its allow rule was limited to QTYPE `ANY`.

### Fixed — server

- **DNS listens on every `server.bind` address**: only the first entry was used and the rest were silently ignored, so `bind: [127.0.0.1, 192.168.0.18]` never answered on the second address. Each address (and each `udp_bind` / `tcp_bind` entry) now gets its own listener. A wildcard (`0.0.0.0` / `::`) already covers every local address through a dual-stack socket, so other entries on the same port are folded into it instead of failing with "address already in use".
- **Example config answers local queries**: the sample ACL allowed only RFC 1918 ranges, so `dig @127.0.0.1` against the shipped `config.example.yaml` returned REFUSED. Loopback (`127.0.0.0/8`, `::1/128`) is now allowed.
- **config: plain scalars may start with a colon**: the YAML tokenizer treated the leading `:` of an unquoted `- ::1/128` as a mapping indicator and failed to parse. A colon is now an indicator only when followed by whitespace, end of line or a flow indicator.
- **Version fallback matches the release**: binaries built without `-ldflags` reported `v1.1.4`. The fallback now tracks `VERSION`, enforced by `TestVersionFallbackMatchesVersionFile`.

### Added

- `scripts/validate-shipped-configs.sh`, run in CI: validates `config.example.yaml`, `deploy/*.yaml`, the Docker and Kubernetes configs, and the configs generated by `install.sh`, `setup.sh` and `install.ps1` with the real binary. CI also runs shellcheck on the install scripts.

### Upgrade notes

- Existing systemd installs keep running as before. To move to the new layout, re-run `install.sh` (config and credentials are kept) or create the `nothingdns` user, `chown` `/var/lib/nothingdns`, and add `storage.data_dir: /var/lib/nothingdns` to the config.
- A config with metrics enabled on a non-loopback address and no `auth_token` now fails `-validate-config` (it already failed at startup).
- Users previously created at runtime were never saved; create them once more after upgrading and they will persist.

## [1.1.11] — 2026-09-16

Security scan release. 1.1.9 and 1.1.10 were documented but never tagged;
their fixes ship in this release as well.

### Security

- **Message pool: DoH, DNS-over-WebSocket and DoQ writers no longer double-Release responses**: `ResponseWriter.Write` in `doh.dohResponseWriter`, `doh.wsResponseWriter` and the DoQ adapter called `msg.Release()` on the message the pipeline owns and releases itself at stage exit. The resulting double `Put` could hand the same `*protocol.Message` to two concurrent requests — responses mixed between clients. Writers now leave ownership with the caller. Caught by the race detector in `internal/doh`.
- **DNS-over-WebSocket releases each query per frame**: a `defer query.Release()` inside the read loop held every query of a long-lived connection until it closed (unbounded per-connection memory). Each query is now served and released in `serveQuery`.
- **Blocklist API: runtime file sources require `blocklist.base_dir`**: `BaseDir` (VULN-067) was never wired from config, so an admin API call could make the server read any process-visible path. New `blocklist.base_dir` config key; `POST /api/v1/blocklists` with a `file` is rejected unless it is set, and the file is opened via its symlink-resolved path.
- **Resolver: no TXID 0 exemption**: `sendQuery` accepted responses with ID 0, which a blind spoofer could always send. Responses must now echo the query ID.
- **deps**: `google.golang.org/grpc` v1.83.2 (GO-2026-6443, indirect via the OTLP exporter), `golang.org/x/net` v0.58.0; web `vitest` / `@vitest/coverage-v8` 4.1.11 (path traversal in `@vitest/mocker`, dev only).

### Fixed

- **cache: hot-reload no longer races with lookups**: `UpdateConfig` wrote TTL/prefetch/stale settings that `Get`/`Set` read lock-free. The configuration is now an immutable snapshot behind `atomic.Pointer`.
- **reload: whole reloads are serialized**: the lock added in 1.1.10 covered only the final pointer swap, so concurrent SIGHUP + API reloads could both snapshot and stop the same managers and leak one new set. The duplicate `Stop()` of the old security manager is removed.
- **upstream: `QueryContext` returns promptly on cancellation**: it waited for the upstream timeout (plus TCP fallback) after ctx was cancelled. The query now runs on a copy of the message and a late response is released in the background. Guarded by `TestQueryContextReturnsPromptlyOnCancel`.
- **dnssec: chain links hold detached DS records** instead of records from a released pooled message.
- **web: TXT/CAA quoting escapes backslashes where needed**: a trailing backslash swallowed the closing quote; `quoteDNSString` / `stripOuterQuotes` are now exact inverses while `\.`-style escapes pass through.
- **CI**: gofmt drift, staticcheck/errorlint findings, a `sync.Pool` identity assumption in `TestUpstreamPoolTypeConsistency` that failed under `-race`, and a hardcoded asset hash in `TestSPAHandlerCacheControl`. The pinned staticcheck moves to 2026.2.1 (Go 1.26 aware).

### Upgrade notes

- Adding blocklist **files** through the API now requires `blocklist.base_dir`. Files listed in the config are unaffected unless `base_dir` is set, in which case they must live inside it.

## [1.1.10] — 2026-09-10

### Fixed

- **Protocol: pooled `Name` structs are no longer recycled**: records sharing one `*Name` each called `Name.Release()`, putting the same struct into `namePool` once per record; later `ParseName` calls received that struct again and the last writer clobbered every other name's content. `Name.Release()` now returns only the wire buffer (already decoupled via a local header Put) and leaves the struct to the GC. Root cause of the order-dependent `TestGenerateNSEC3_OptOutClassification`, `TestBuildChainWithDelegation`, and resolver DNAME synthesis failures.
- **Protocol: `UnpackMessage` enforces the zero-length section invariant at pool Get**: a pooled `*Message` mutated by a user after `Release()` carried leftover Questions across pool cycles, so a single-question wire message unpacked with duplicate questions (order-dependent `TestServeDNS_DNS64Synthesis` SERVFAIL, "got 2" question mismatch). All four section slices are truncated right after `messagePool.Get()`; dropped leftovers are simply GC-reclaimed.
- **Protocol: RFC 6891 extended RCODEs reconstructed at unpack**: `UnpackMessage` read only the 4-bit header RCODE, so upstream EDNS extended codes were misread — BADVERS (16) unpacked as NOERROR (0) and BADCOOKIE (23) as YXRRSET (7). The OPT record's TTL now contributes `EXTENDED-RCODE << 4` via the existing `ParseEDNS0Header` helper (extended byte 0 responses are unchanged). Covered by `TestUnpackMessage_ReconstructsExtendedRCODE`.
- **cmd: BADCOOKIE responses now carry the extended RCODE on the wire**: the cookie stage set RCODE 23 in memory, but `SetEDNS0` builds the OPT TTL with extended byte 0, so external clients decoded the response as YXRRSET (7). The stage now writes `BuildEDNSTTL(RcodeBadCookie>>4, …)`, mirroring the BADVERS site in the request-policy stage. Asserted by `TestServeDNS_DNSCookie_Invalid`.
- **dnssec: three pooled-message leaks fixed in the chain-build fetchers**: `fetchDNSKEY`, `fetchDNSKEYAndSigs`, and `fetchNSEC3PARAM` leaked one pooled `*Message` per call and returned records that `Release()` would zero; every path now Releases the message and returned records are detached via a `detachRecord` helper. Regression-tested by the four `fetch*_pool_leak_test.go` suites.
- **odoh: the target snapshots the response wire at Write and no longer double-Releases**: the ODoH target packed the inner handler's response *after* the pipeline had Released it at stage exit (empty/corrupted ODoH answers under concurrency) and Released it a second time (double-Put into `messagePool`). `odohResponseWriter` now captures the wire inside `Write` and the target never reads or Releases the handler's message. Guarded by `TestODoHTarget_PipelineReleasedResponseEncrypted`.
- **doh: JSON responses snapshotted via `Message.Copy`**: `jsonResponseWriter` held the handler's response pointer while the JSON handler encoded *and* Released it after the pipeline's stage-exit Release — upstream-path `application/dns-json` answers were Status-0/empty and the pooled message was double-Put. The writer now stores a detached `Message.Copy()`.
- **resolver: DNAME synthesis deep-copies owner and rdata**: the synthesized DNAME record shared its `*Name` and `*RDataDNAME` with the pooled upstream response, which `Release()` then recycled; the copy is now fully detached.
- **cmd: test fixtures under single ownership**: `mockUpstream`, `mockResolverTransport`, and the dnssec/ODoH stubs return detached per-call copies (shared templates were put into `messagePool` while still in use — the dirt source behind several order-dependent failures), `mockResolverTransport` echoes the query TXID per the resolver's RFC 5452 binding, and `captureWriter` snapshots with `Message.Copy()` (wire round-trips normalize extended RCODEs).
- **deps: `golang.org/x/crypto` upgraded to v0.56.0** (with companion `x/text` v0.41.0): fixes three `x/crypto/ssh` advisories — GO-2026-6355/CVE-2026-56855 and GO-2026-6354/CVE-2026-78662 (malicious-peer channel-message deadlocks) and GO-2026-6303/CVE-2026-56854 (source-address restrictions in `Permissions` silently ignored on the `PasswordCallback`/`KeyboardInteractive`/`NoClientAuth`/GSSAPI auth paths). GO-2026-5932 (the unmaintained-by-design `x/crypto/openpgp` package) has no fixed version and remains, but is unreachable here: nothing in the repo imports `openpgp` and govulncheck's symbol analysis reports zero reachability. Verified by a govulncheck rescan (0 symbol/package findings, one module-level residual) and the full test suite.
- **util: text-format log injection fixed**: `formatText` sanitized field values but interpolated the raw `msg` — attacker-influenced error strings (the established `util.Warnf("…: %v", err)` pattern) forged fake log entries on the default TextFormat path (the JSON format was safe via `json.Marshal`). The same CR/LF replacement now applies to the message. Guarded by `TestWarnfMsgSanitizedInTextFormat`.
- **config: the ODoH KEM whitelist accepts the implemented suite and validates it unconditionally**: `isValidODoHKEM` accepted only KEM 4 (no standard HPKE KEM) while the odoh runtime implements KEM 0x0020, so every validator-accepted ODoH config was rejected by the runtime — and a garbage KEM behind a configured `target_url` skipped the suite check entirely. The whitelist now accepts 0x0020 and the suite validation runs whenever ODoH is enabled. Covered by `validation_odoh_test.go`.
- **config: unknown keys inside sequence items are now reported**: `walkUnknownKeys` descended only into mapping children, so a typo'd key inside any list-of-structs section (`dnssec.signing.keys`, `slave_zones`, `upstreams`) was silently ignored — the exact failure the check exists to close. The walk now descends into sequence items against the element type. Guarded by `TestWarnUnknownNestedKeys_SequenceItems`.
- **config: single-quoted YAML strings handle the doubled-quote escape**: `readQuotedString` terminated at the first quote of the pair instead of implementing YAML 1.2 §7.3.1's `''` → `'` rule, so any single-quoted config value containing an escaped quote (e.g. `key: 'it''s'`) mis-tokenized into a truncated value plus garbage tokens. The doubling escape is now implemented, correctly scoped to single-quoted strings only. Guarded by `TestSingleQuotedStringHandlesDoubledQuote`.
- **transfer: DDNS updates apply atomically per RFC 2136 §3.4.2**: `ApplyUpdate` ran operations sequentially and returned on the first error, leaving prior operations applied in memory while the serial bump was skipped — the change was invisible to secondaries, unjournaled, and vanished on restart. Every add is now validated before any mutation. Guarded by `TestApplyUpdateIsAtomicOnMalformedRData`.
- **transfer: AXFR responses no longer release the pooled messages they return from**: `receiveAXFRResponse` appended pooled-message record pointers to the returned slice while deferring `msg.Release()` — the deferred releases gutted every returned record before the caller read it (live via the slave's AXFR refresh at slave.go:455). The messages are intentionally left for the garbage collector. Guarded by `TestAXFRClientReturnsIntactRecords`.
- **transfer: an up-to-date single-SOA IXFR response is terminal**: `receiveIXFRResponse` required two SOAs to terminate, so the RFC 1995 §2 up-to-date response fell through to a spurious EOF transport error — every up-to-date IXFR refresh failed. A single-SOA message is now always terminal; the same function also no longer releases pooled messages whose records it returns. Guarded by `TestIXFRClientHandlesUpToDateSingleSOA`.
- **dashboard: proper Cache-Control headers for the SPA**: `SPAHandler` set no Cache-Control at all — browsers heuristic-cached `index.html`, and after a redeploy the cached stale index requested rotated content-hashed assets that 404'd. `/assets/*` now serves `immutable` (Vite content-hashed), the unhashed root files and the index fallback serve `no-cache`. Guarded by `TestSPAHandlerCacheControl`.
- **api: 405 responses carry the RFC 7231 §6.5.5 `Allow` header**: `requireMethod` — the chokepoint for every 405 across all API routes — wrote the status without the mandated header. Guarded by `TestRequireMethodSetsAllowHeader`.
- **api: the config-redaction boundary is regression-guarded**: the boundary's only protection was an in-code comment citing `TestConfigGet_RedactsSecrets`, which had never been written. The test now exists: nine secret-bearing fields seeded through the real `handleConfigGet`, asserting none reach the response.
- **web: an explicit TTL 0 in the zone-editor's inline TTL edit is preserved**: `parseInt(v, 10) || r.ttl` treated an explicit no-caching TTL of 0 as falsy and silently reverted it to the record's previous value on every inline save. The `Number.isNaN` guard now preserves the explicit 0. Guarded by the inline-edit regression test in `index.test.tsx`.
- **transfer: XoT AXFR/IXFR responses echo the query ID**: `sendAXFRResponse` hardcoded `ID: 0` on every stream message, violating RFC 5936 §2.2 — compliant secondaries (including this project's own slave client) reject the mismatched stream, so XoT transfers failed end-to-end. Responses now carry the query's ID. Guarded by `TestXoTServerSendAXFRResponseEchoesRequestID`.
- **transfer: the canonical record sort is O(n log n)**: `sortRecordsCanonically` ran a quadratic selection sort (with two `strings.ToLower(String())` conversions per comparison) on the full zone record set during every AXFR/IXFR generation — a 20,000-record zone measured 9.44s on the transfer path. `sort.Slice` with the same comparator completes in 4.59ms. Guarded by `TestSortRecordsCanonicallyHandles20kRecordZone`.
- **zone: `UpdateRecord` validates RData (parity with `AddRecord`)**: the update path accepted injection-shaped RDATA — storable through the API zones-records PUT or the cluster Raft apply — and wrote it verbatim into the zone file on the next persist. `UpdateRecord` now runs the same `ValidateRecordData` pre-pass `AddRecord` always did. Guarded by `TestUpdateRecordRejectsInjectionShapedRData`.
- **cache: NSEC denial-proof entries survive their source message's release**: `AddFromResponse` stored the NSEC Owner/NextDomain/TypeBitMap as shared references into the pooled upstream response that the pipeline releases at stage exit, leaving cached entries reading freed wire bytes — synthesized NXDOMAIN answers carried empty owners and range checks missed. The fields are now detached copies. Guarded by `TestNSECCacheEntriesSurviveSourceMessageRelease`.

## [1.1.9] — 2026-09-08

### Fixed

- **Protocol: pooled Name buffers now released on all short-buffer Unpack paths**: in every `Unpack` method that allocates a temporary `Name` via `UnpackName` before validating the offset or rdlength, the pooled `Name` was leaked if the subsequent bounds check failed. Patches added `name.Release()` before early returns on `ErrBufferTooSmall` and rdlength-overflow in: `RDataCNAME`, `RDataDNAME`, `RDataNS`, `RDataPTR`, `RDataSOA` (MName/RName), `RDataSRV`, `RDataRP`, `RDataAFSDB`, `RDataKX`, `RDataNAPTR`, `RDataIPSECKEY`, `RDataHIP`, `RDataNSEC`, `RDataRRSIG`, and `RDataSVCB`. The `releaseWireNameBuffer` function also fixed to pass `*[]byte` so `pool.Put` reclaims the actual element.
- **`sync.Pool` buffer leaks fixed across the codebase**: pooled `*[]byte` write buffers were not returned in `server/handler.go` and `upstream/loadbalancer.go` when `writeMsgUDP` or `WriteMsgUDP` received an undersized buffer; pooled `*Message` was leaked in `doh.Handler.serveJSON` after JSON encoding, `odoh.ServeTarget` after response encoding, `cache.evict/replace/clear`, `resolver.DNAME` synthesis, `upstream.queryTCP`, `load.sendQuery` (TCP and UDP), and `dnsctl cmdDig` after response printing. All paths now call `Release()` on the pooled object on every exit path.
- **Seven independent bug fixes**: `serialIsNewer` (likely incorrect timestamp comparison), `BindPort` fallback added to five cluster gossip broadcast functions that only called `BindPort` without acting on its return value, `sync.Pool` map-range safety corrected in dnssec cache eviction (`f13b5ff`) and filter `pruneStale` (`9e693ca`), IXFR journal EOF safety, env var expansion for empty keys, and upstream load balancing rounding.
- **`internal/zone`: `parseGenerateRange` integer overflow guard**: `maxEnd - start + 1` computed with `int` could overflow for large `$GENERATE` ranges on 32-bit platforms. Now checked before use.
- **RCODE 6 (YXDOMAIN, RFC 2136) added to `rcodeToString`**: `cmd/nothingdns` now correctly maps RCODE 6 to its string name in responses and logs.
- **Cluster gossip: `BindPort` fallback added to broadcast functions**: five gossip broadcast functions only called `BindPort` but ignored its return value; fallback port selection now works correctly when the primary port is unavailable.

## [1.1.8] — 2026-08-19

### Fixed
- **Path-less OTLP endpoints no longer 404**: `otlptracehttp.WithEndpointURL` exports to the URL exactly as given, so a `tracing.endpoint` like `http://jaeger:4318` (no path) sent every span batch to `/` and the collector answered 404 — spans silently never arrived. `withOTLPPath()` now appends the OTLP/HTTP default `/v1/traces` when the configured URL has no path; explicit paths are preserved verbatim and query strings survive. `CONFIG_REFERENCE.md` and `config.example.yaml` document the normalization. Regression-tested via `TestWithOTLPPath` and `TestTracerEndpointNormalized`.

## [1.1.7] — 2026-08-19

### Changed
- **Tracing migrated to the official OpenTelemetry SDK** (`internal/otel/`): the hand-rolled tracer, OTLP JSON exporter, and Jaeger exporter are replaced by a facade over `go.opentelemetry.io/otel` — `sdktrace.TracerProvider` with `ParentBased(TraceIDRatioBased)` sampling, `BatchSpanProcessor` + `otlptracehttp` exporter (OTLP/HTTP+protobuf) when an endpoint is configured, and a bounded in-memory recorder otherwise. **W3C TraceContext propagation** (`traceparent`/`tracestate`) is now extracted/injected by the HTTP middleware, so inbound requests join upstream traces and downstream calls continue them. New `tracing:` config section (`enabled`, `level`, `sample_rate`, `endpoint`; falls back to `OTEL_EXPORTER_OTLP_*` env vars). The consumer-facing API (`Tracer`/`Span`/`Attr`/`StartSpan`/`EndSpan`/`Middleware`) is unchanged; `Tracer.Shutdown` is wired into graceful server shutdown. Direct deps: `go.opentelemetry.io/otel`, `otel/sdk`, `otel/trace`, `otlptracehttp`.

## [1.1.6] — 2026-08-19

### Added

- **Grafana dashboard shipped** (`deploy/grafana/nothingdns-overview.json`):
  13-panel overview covering query rate and per-record-type traffic, cache
  hit ratio, blocklist and rate-limit counters, upstream queries by server,
  p50/p95/p99 latency (`histogram_quantile` over
  `nothingdns_query_duration_seconds`), UDP/TCP transport counters, and
  cluster health/nodes/gossip. Every metric name was validated against a
  live production `/metrics` scrape before shipping.

### Fixed

- **Helm PrometheusRule alert expressions validated against live metrics;
  three stale metric names corrected**: the error-rate, latency, and
  cluster-node alerts referenced metric names the server never emits, so
  they could never fire (or would misfire). `nothingdns_dns_requests_total{rcode="SERVFAIL"}`
  → `nothingdns_responses_total{rcode="2"}` (SERVFAIL is rcode 2; the label
  is numeric), `nothingdns_dns_request_duration_seconds_bucket` →
  `nothingdns_query_duration_seconds_bucket`, and `nothingdns_cluster_nodes`
  → `nothingdns_cluster_nodes_alive`. The error-rate expression was also
  fixed for vector matching: `sum(rate(...))` on both sides, since dividing
  the rcode-filtered series by the unfiltered one divides SERVFAIL by
  itself. All alert expressions verified against a live production
  `/metrics` scrape.

- **dnsctl `dnssec status` and `dnssec keys` now under test**: the last two
  dnsctl DNSSEC subcommands with zero coverage (`cmdDNSSECStatus`,
  `cmdDNSSECKeys`) gain success, error, empty-list, and table-rendering
  tests via the package's HTTP-transport mock. Both functions now at 100%
  statement coverage; `cmd/dnsctl` package coverage 86.9% → 89.0%.

## [1.1.5] — 2026-08-19

### Fixed

- **Version strings now have one canonical format across all build
  paths**: release binaries built by `scripts/build-release.sh` reported
  `v1.1.4` (the raw git-describe tag) while container images built by the
  Dockerfile reported `1.1.4` (the VERSION-file form), and the startup
  log consequently printed `vv1.1.4`. The canonical form is bare semver
  without the `v` prefix: the script now strips it (`VERSION="${VERSION#v}"`),
  and `util.Version` normalizes itself at init so any `-X` injection of a
  `v`-prefixed tag cannot reintroduce the mismatch. The compile-time
  fallback in `version.go` is also synced to `1.1.4`. Covered by new
  unit tests (`TestNormalizeVersion`, `TestVersionIsBareSemver`).

## [1.1.4] — 2026-08-19

### Fixed

- **Official container images now report the released version**: the
  Dockerfile never passed `-X` to inject `util.Version` at build time —
  unlike `scripts/build-release.sh`, which stamps release binaries — so
  every published GHCR image reported the stale compile-time default
  (`1.1.1`), including the v1.1.3 image. The image build now takes the
  version from the `VERSION` build-arg (defaulting to the `VERSION` file
  in the build context) and passes it to both binary builds via
  `-X github.com/nothingdns/nothingdns/internal/util.Version`.

## [1.1.3] — 2026-08-19

### Security

- **Cluster gossip now rejects Leader/Heartbeat frames from impostor
  senders**: `handleLeader` and `handleHeartbeat` accepted any
  AEAD-authenticated gossip peer's announcement naming an arbitrary
  `LeaderID`. A compromised keyring peer could forge a higher-term
  announcement naming a victim node, get adopted by every follower
  (`adopt=true` on higher term), and then pass the
  `msg.From == currentLeader` gate on forged ZoneUpdate/ConfigSync
  frames — full cluster takeover. Only the leader itself may announce
  its leadership or send heartbeats (`msg.From == payload.LeaderID`),
  mirroring the impostor checks already present in
  handlePing/handleAck/handleZoneUpdate.
- **Go toolchain 1.26.5 → 1.26.6**: clears all six Go standard-library
  vulnerabilities flagged by `govulncheck` (GO-2026-5972 `encoding/asn1`
  unbounded recursion via DNSSEC private-key parsing, GO-2026-5026
  IDNA/punycode validation, plus four more reachable through `net/http`,
  `crypto/x509`, and the standard library). Applies to the root `go.mod`,
  `web/go.mod`, and the Dockerfile build stage (`golang:1.26.6-alpine`).
  Post-upgrade scan: 0 vulnerabilities affecting code paths.
- **AXFR/IXFR clients now enforce a 512 MiB aggregate transfer cap**:
  `receiveAXFRResponse`/`receiveIXFRResponse` tracked only a 1M-record
  safety limit, which admitted gigabytes of RDATA from a hostile or
  misbehaving master before tripping — unbounded memory growth on the
  slave. The wire-byte total is now capped at `maxTransferBytes`
  (512 MiB, comfortably above the largest real-world zones) and the
  transfer aborts with a descriptive error when exceeded.

### Fixed

- **`transfer.allow_list` now also authorizes RFC 1996 NOTIFY**: the NOTIFY
  handler's allow list was never populated in production (only tests called
  `AddNotifyAllowed`), so every incoming NOTIFY was refused and NOTIFY-triggered
  slave-zone replication was silently broken. The transfer allow list is now
  shared authorization for AXFR/IXFR and NOTIFY — a master permitted for
  transfers may send NOTIFY, and sources not in the list are refused
  (deny-by-default when the list is empty).
- **NOTIFY responses with mismatched transaction IDs are now rejected**:
  `SendNOTIFY` never compared the response's transaction ID against the
  request's, so a spoofed or stale reply carrying the wrong ID was accepted
  as success. The random TXID (RFC 1996 §3.2.2 / RFC 1035 §4.1.1) exists
  precisely to bind a reply to its request; the sender now enforces it.
- **DNSSEC key rollover no longer mints duplicate replacement keys**:
  `maybeRolloverZSK`/`maybeRolloverKSK` only inspected ACTIVE keys, so once
  a rollover triggered (active key inside `PublishSafety` of `Retire`),
  every scheduler tick generated another replacement — an unbounded pile of
  Published-but-inactive keys accumulating over the safety window. A
  pending-key guard (`hasPendingZSK`/`hasPendingKSK`) now waits for the
  in-flight replacement to activate before considering another rollover.
- **NSEC3 opt-out now engages for unsigned delegations (RFC 5155 §6.1.1)**:
  `generateNSEC3` treated the presence of any non-NS record — including
  RRSIG — as making a delegation "secure". A signed parent always carries
  RRSIGs over the delegation NS RRset, so every delegation was classified
  secure and the opt-out flag never engaged, bloating the NSEC3 chain.
  Opt-out now applies only to unsigned delegations (NS, no SOA, no DS, no
  other records); the zone apex and signed delegations are never opt-out.
- **TCP responses no longer set TC when only Additional records are dropped
  (RFC 2181 §9)**: `packFramedDNSPayload` pre-set `TC=1` before calling
  `Truncate`, so a response needing only its Additional section trimmed
  (OPT, glue) went out with TC set even though no required data was
  omitted — inconsistent with the UDP writer. `Truncate`'s own RFC 2181 §9
  logic (set TC only when Answer/Authority records are dropped or the
  message still doesn't fit) now decides.

### Changed

- **Helm chart: preStop hook + 45s termination grace period**: the
  Deployment now sleeps 5s in preStop before SIGTERM reaches the
  process, letting Kubernetes deregister the endpoint first so in-flight
  DNS queries finish and TCP/DoT/DoH sessions close cleanly instead of
  truncating client transfers on rollout. `terminationGracePeriodSeconds: 45`
  accommodates the 5s hook plus the default 30s `shutdown_timeout`
  with headroom.
- **geodns: removed a dead identical-argument retry in `mmdbLookup`**: the
  retry re-ran the MMDB decode with the same arguments after a failure — a
  duplicate of the same error, never a recovery. A single decode at the
  spec-computed absolute offset (`record_value - node_count +
  search_tree_size`) is correct; a comment now documents why no retry
  exists.

## [1.1.1] — 2026-08-05

### Security

- **react-router 7.18.2 → 8.3.0**: closes GHSA-qwww-vcr4-c8h2 (RSC mode
  CSRF bypass). React Router v8 removes the `react-router-dom` re-export
  package — all imports now source from `react-router` directly.
- **undici 7.28.0 → 7.29.0**: closes 5 advisories (CRLF injection, cookie
  attribute injection, cross-user info disclosure ×2, response
  desynchronization).
- **brace-expansion**: closes DoS bypass (GHSA-rgw5-rvv9-x895).

## [1.1.0] — 2026-08-05

### Security

- **SSRF fail-closed + DNS rebinding pinning** in upstream API
  (`validateAndPinUpstream`): the PUT `/api/v1/upstreams` handler
  previously allowed unresolvable hostnames through (fail-open),
  enabling DNS rebinding attacks. Now resolves once, validates all IPs,
  and pins the resolved IP literal into `Server.Address` so `net.Dial`
  never re-resolves the hostname.
- **`IsPrivateIP` gaps fixed**: `0.0.0.0/8` (routes to localhost on
  Linux), `100.64.0.0/10` (CGNAT, RFC 6598), and IPv6 `::` (unspecified)
  were missing from the private-IP check, allowing SSRF bypass via
  `0.0.0.0:53`.
- **gosec annotations** added for all protocol-mandated SHA-1 usage
  (NSEC3 RFC 5155, DS digest RFC 4034, WebSocket RFC 6455, TSIG
  RFC 4635) and TLS configs (validated by `ValidateTLSProfile`).

### Fixed

- **DoQ `Serve()`/`Addr()` data race**: the root accept goroutine was
  registered (`wg.Add`) without holding `closeMu`, racing against
  `Stop()` which clears the listener under the lock. Classic
  `Add`/`Wait` panic. Now holds `closeMu` across the startup check.
- **`Truncate()` O(n²)→O(n)**: the DNS message truncation algorithm
  called `WireLength()` (full re-serialization) on every loop
  iteration. Replaced with a running byte counter that subtracts each
  removed record's cached `WireLength()`.
- **bodyclose**: 5 unclosed `http.Response.Body` leaks in integration
  tests.
- **errcheck**: 2 unhandled `SetDeadline` calls in load-tester and TLS
  server.
- **advisory-monitor CI workflow**: YAML heredoc indentation caused
  `actionlint` to fail parsing the workflow file.

### Added

- **XoT port separation**: DoT (:853) and XoT now have distinct
  listeners (XoT defaults to :8853) with a config validator that
  rejects bind collisions. Wired across Dockerfile, Helm, and deploy
  configs.
- **`transfer.journal_dir`** config option for custom IXFR journal path.
- **Backup/restore scripts**: `scripts/backup.sh`, `scripts/restore.sh`,
  and `scripts/backup-restore-smoke.sh` (CI round-trip verification).
  Makefile targets: `backup`, `restore`, `backup-restore-test`.
- **Helm PodMonitor** template for Prometheus Operator.
- **ServiceMonitor hardening**: fail guards that validate
  `config.metrics.enabled` and namespace scoping before rendering.
- **Config parser conformance tests** (634 lines) covering YAML scalar,
  sequence, comment, and nesting edge cases.
- **Web page tests** (9 files, 1,364 lines) covering all dashboard pages.
- **CI**: `go mod verify` step, helm template validation for monitoring
  and XoT, backup/restore smoke test.

### Changed

- **`NewCacheManager`**: removed misleading always-nil error return;
  updated all callers.
- **`writePacket`** / **`readFull`**: removed unused `int` return values;
  simplified to return `error` only.
- **`react-router-dom`** bumped 7.17.0 → 7.18.2.
- **Dialog accessibility**: `aria-describedby` is now conditional,
  preserving Radix auto-linking when a `DialogDescription` is present.

## [1.0.0] — 2026-07-15

### Security

- **Go toolchain bump 1.26.4 → 1.26.5** across the root module,
  embedded web module, and Docker builder to pull in the patched
  `crypto/tls` stdlib release for GO-2026-5856. `govulncheck` is
  expected to pass on CI with the patched toolchain.
- **Go toolchain bump 1.26.2 → 1.26.4** across the root module and
  embedded web module to pull in patched stdlib releases.
- **Web tooling Babel pin**: `web/package.json` now overrides transitive
  `@babel/core` to `7.29.7`, resolving GHSA-4x5r-pxfx-6jf8 /
  CVE-2026-49356 in development/build tooling. `npm audit --audit-level=low`
  is clean after the lockfile update.
- **Data race on `enabled` flag** in `RateLimiter`, `RRL`, and
  `Blocklist`: hot-path predicate read the bool without a lock while
  `SetEnabled`/`Reload` wrote it under the package mutex. Converted
  to `sync/atomic.Bool` — wait-free reads, visibility-guaranteed
  writes.
- **GOST DS digest type 3 explicitly rejected** (previous
  `hashGOST94` used a placeholder S-box that produced
  non-conformant hashes — silent miscompare risk). Deprecated by
  RFC 8624 §3.2 anyway.

### Added

#### Dashboard and management API

- **Real active-client metric**: the management metrics API now reports
  connected dashboard/websocket clients, and the embedded React dashboard
  displays it as a first-class status tile.
- **Web build token guard**: `npm run build` in `web/` now runs
  `scripts/verify-css-tokens.mjs` so required design-system color tokens
  cannot disappear silently.

#### Real implementations replacing previous honest-fail stubs

- **F127/F129 — DSO TLV wire-format pipeline (RFC 8490)**:
  `protocol.Message.RawBody` captures DSO bodies; `OpcodeDSO=6`
  constant. `extractTLVs` enforces RFC 8490 §5.2 (DSO opcode +
  zero section counts). `SendKeepalive` frames a real DSO
  keepalive TLV + DNS header + TCP length prefix and writes to the
  session connection.
- **F138 — Real MaxMind DB binary-format parser**
  (`internal/geodns/mmdb.go`, ~440 LOC) with the MMDB §1.4 IPv4-in-
  IPv6 expansion, all 15 type codes, 24/28/32-bit record sizes, and
  MSB-first BST traversal. Earlier follow-up fixed a
  data-pointer arithmetic bug (was double-adding `treeBytes`).
- **F122 — RFC 9180 HPKE base mode + RFC 9230 ODoH wire format**
  (`internal/odoh/hpke.go` + `rfc9230.go`). Hand-rolled with
  Go stdlib only (`crypto/ecdh` X25519, `crypto/hkdf` HKDF-SHA256,
  `crypto/aes`+`crypto/cipher` AES-GCM). HPKE math validated
  byte-for-byte against RFC 9180 §A.1 test vectors (DHKEM
  shared_secret, KeySchedule base_nonce, AEAD seal[0]). Full
  Client→Proxy→Target→handler round-trip green.

#### Raft consensus

- **Leader-redirect error type**: `*raft.ErrNotLeader` now carries
  the known leader's `NodeID` so admin clients calling
  `AddNodeViaLeader` / `RemoveNodeViaLeader` on a follower can
  retry directly against the leader instead of probing every peer.
  Followers track `leaderID` from `AppendEntries.LeaderID`.

#### Test infrastructure

- **Fuzz harnesses** for all attacker-controlled wire-format
  parsers (none run by default; invoke with `-fuzz=Name`):
  - `protocol`: FuzzUnpackMessage, FuzzUnpackName,
    FuzzUnpackResourceRecord
  - `zone`: FuzzParseZoneFile
  - `dso`: FuzzUnpackTLV, FuzzHandleDSORequest
  - `odoh`: FuzzParseODoHMessage, FuzzParseConfigContents,
    FuzzDecryptQuery
  Local 3-minute runs reached 25M+ iterations on
  `FuzzUnpackMessage` with zero panics.
- **CI fuzz job**: `go.yml` runs each target 30s on every PR with
  corpus caching; on any panic, the corpus and any
  `internal/*/testdata/fuzz` artifacts are uploaded.
- **mmdb_writer_test.go**: small in-memory MMDB binary-format
  writer so unit tests can produce real fixtures the production
  parser decodes, replacing six tests that were skipped because
  hand-crafted bytes from the honest-fail era didn't form valid
  records.

### Fixed

- **DNSSEC validation end-to-end**: direct handler and pipeline serving
  paths now both perform DNSSEC validation correctly, including chain
  building, DS authentication, and denial proof handling.
- **Resolver cache correctness**: side records no longer clobber primary
  cache entries, and negative DNSSEC denial proofs are preserved instead
  of being dropped during cache writes.
- **Extended DNS Error codes**: protocol constants and OPT handling now
  align with the IANA EDE registry.
- **Management API hardening**: cache-disable requests are rejected
  explicitly, duration headers are parsed safely, server configuration is
  populated consistently, and API responses use stronger error handling.
- **Web dashboard UX and record editing**: pages now show real error/empty
  states with mutation feedback and accessibility fixes; the zone editor
  uses stable record identity/edit semantics instead of ambiguous display
  values.
- **Blocklist plain-domain input**: file loading now accepts simple
  domain-per-line blocklists in addition to hosts-style entries.
- **JoinSeed nil-deref before Start**: calling `Cluster.JoinSeed`
  on a non-started cluster panicked because the gossip layer
  reached `gp.conn.WriteToUDP` on a nil conn. Added an explicit
  "cluster must be started" guard.
- **MMDB pointer arithmetic** (`internal/geodns/mmdb.go`):
  `mmdbLookup` returned `rec - nodeCount - 16 + treeBytes` and the
  caller in `geodns.go` added `treeBytes + 16` on top, double-adding
  the tree size. Records were decoded from an offset 12+ bytes
  past the real one. Replaced with the canonical
  `abs_file_offset = treeBytes + (rec - nodeCount)` formula used
  by MaxMind-DB-Reader-python.
- **DNSSL multi-label encoder** (`internal/resolver/rdnss.go`):
  `encodeDNSSLLabel` was a single-label calculator misnamed and
  called with full domains. Renamed to `encodeDNSSLDomain`, split
  on ".", and the RFC 8106 §5.2 8-byte padding fixed.
- **NSEC3 closest-encloser SECURE test** rebuilt with a 3-record
  fixture satisfying RFC 5155 §8.4 (closest encloser exact match +
  next-closer cover + wildcard cover). Was a stale skip.
- **KV Close-with-active-tx** stale skip: F060 changed
  `Begin` to hold the store lock for tx lifetime, so `Close` now
  blocks on in-flight tx. Replaced the skip with a real
  concurrency test that exercises the new behavior.

### Coverage

Lifted across multiple packages:

| Package | Before | After | Δ |
|---|---|---|---|
| filter | 57.8% | 92.4% | +34.6 |
| geodns | 70.3% | 85.0% | +14.7 |
| cluster/raft | 51.9% | 63.8% | +11.9 |
| api | 79.2% | 82.3% | +3.1 |
| dso | 89.1% | 91.9% | +2.8 |
| cmd/nothingdns | 69.3% | 71.3% | +2.0 |

### Removed

- Dead code: legacy `hashGOST94` (placeholder S-box),
  `loadMMDBFromBytes`, `mocks.go` → `mocks_test.go` (test-only
  symbols no longer shipped in the production binary),
  `ErrMMDBNotSupported` sentinel (LoadMMDB returns specific decode
  errors now), unused `DynamicDNSHandler.closed` field.
- Stale `web/go.mod` artifact, orphaned `web/pnpm-workspace.yaml`.
- Coverage `.out` files from git tracking (already gitignored).
- `docs/archive/NOTHING.md`, `docs/archive/PRODUCTION_READINESS.md` moved to `docs/legacy/`.

### Refactored

- **Hot-reload logic extraction**: SIGHUP handler and `/config/reload` API
  callback consolidated into `reloadConfig()` in `cmd/nothingdns/reload.go`.
  Net **-116 lines** in `main.go`. (Phase 2-A)
- **Handler sub-structs**: 12 flat `integratedHandler` fields grouped into
  `SecurityComponents` (7) and `TransferComponents` (5) sub-structs.
  ~365 net lines removed across 15 files. (Phase 2-B)
- **Codebase audit**: Full static analysis (security-check, bug-hunter) with
  8 code-quality fixes, 6 infrastructure cleanups, 4 documentation corrections.
  `go vet ./...` and all tests pass after fixes.

### Testing

- **Frontend unit test suite**: Vitest v4 + React Testing Library v16 with
  jsdom environment. 51 tests across 8 files covering the API client
  (`api.ts`), auth store (`authStore.ts`), configuration mutation hooks,
  theme context, `ErrorBoundary`, `ErrorState`/`EmptyState`, `ConfirmDialog`,
  and utility functions. Wired into CI via `npm test` in the web workflow.
  (Phase 3-A)

## [0.1.1] — 2026-04-12

### Added

#### E2E Tests
- **DoT (DNS over TLS) Tests**: Full test suite with self-signed certificates for TLS handshake, multiple connections, connection reuse, and error handling
- **AXFR/IXFR Zone Transfer Tests**: Comprehensive tests for full zone transfers (AXFR) and incremental zone transfers (IXFR) with real TCP streaming
- **Real Server Tests**: UDP/TCP server tests with concurrent query handling, graceful shutdown, and panic recovery
- **DoH (DNS over HTTPS) Tests**: HTTP-based DNS query tests with POST and GET methods

#### Web UI
- **Error Handling**: Fixed 401 API error handling with proper non-JSON response parsing
- **WebSocket Reconnection**: Added exponential backoff with maximum 10 retry attempts
- **Race Condition Fixes**: Fixed RAF cleanup race condition in query-log page using cancellation pattern
- **Key Prop Issues**: Fixed React key prop warnings in dashboard and top-domains components

### Fixed

#### Web UI
- `api.ts`: Fixed 401 errors not being caught properly for non-JSON responses
- `useWebSocket.ts`: Fixed token double-encoding issue and improved reconnection logic
- `query-log.tsx`: Fixed index-as-key warnings, fixed RAF cleanup race condition
- `dashboard.tsx`: Fixed key prop issues
- `blocklist.tsx`: Fixed total_rules display using `!= null` instead of `??`
- `upstreams.tsx`: Fixed health bar to show success percentage (queries/total) instead of failure percentage
- `zone-editor.tsx`: Fixed deleteSelected to track failures with alert, fixed deleteRecord revert on API failure

### Changed
- **Pre-commit Hook**: Improved version-sensitive checks and local CI validation

## [0.1.0] — 2026-04-05

### Added

#### Protocol
- **DNAME (RFC 6672)**: Full DNAME record support with chain following in the resolver and synthesis in authoritative responses. DNAME at a superdomain synthesizes a CNAME for matching subdomains.
- **NSEC3 Hardening (RFC 5155)**: NSEC3 validation now verifies the type bitmap for exact hash matches per RFC 5155 §8.2. NSEC3PARAM records are fetched during chain building to validate algorithm and iteration parameters.
- **IXFR Journal Persistence**: IXFR incremental transfer journal is persisted to disk via `KVJournalStore` (file-per-serial layout under `dataDir/ixfr-journals/<zone>/<serial>.journal`). Reloaded on restart.

#### Performance
- **Response Buffer Pooling**: UDP and TCP response paths now use `sync.Pool` for zero-alloc buffer reuse. `UDPServer.responsePool` and `TCPServer.responsePool` eliminate per-query heap allocations in the hot path.
- **KVStore Read Lock Fix**: `KVStore.Begin(false)` now acquires a read lock instead of a write lock for read-only transactions, allowing concurrent readers.
- **ZoneStore RWMutex**: `ZoneStore` upgraded from `sync.Mutex` to `sync.RWMutex`, enabling concurrent read access for `LoadZone` and `ListZones`.
- **DNSSEC Validation Cache**: `Validator` now caches validation results by `(name, qtype)` with a 5-minute TTL, avoiding repeated cryptographic chain building.

#### Storage
- **WAL Journal**: Write-Ahead Log for zone changes enables crash recovery by replaying committed entries on startup.
- **KV Store Persistence**: Custom B-tree based KV store with transaction support, atomic disk persistence via `gob` encoding, and `ZoneStore` for zone-scoped key storage.

### Changed
- **`go vet ./...`**: Zero warnings. All code passes strict static analysis.
- **Build**: current release builds use `scripts/build-release.sh` via `make build-release`, producing `nothingdns` and `dnsctl` assets for Linux and macOS amd64/arm64 plus `SHA256SUMS`.

### Fixed
- `KVStore.Rollback()`: Fixed to handle read-only transactions without spurious write-lock acquisition.
- Phase 4.6 IXFR completeness: `generateIncrementalIXFR` now loads from persistent journal when in-memory journal is empty.

### Security
- See [SECURITY.md](SECURITY.md) for responsible disclosure policy.

### Dependencies
**Minimal external dependencies.** Core DNS logic is hand-rolled; current external modules are limited to necessary DoQ/platform/crypto/network support.
