# NothingDNS Zone Management API Reference

> Reference for the zone and record endpoints.
> Base URL: `http://127.0.0.1:8080/api/v1`
> Authentication, roles, rate limits and the general error format are described
> in [API_REFERENCE.md](API_REFERENCE.md).

---

## Authentication and roles

Send a token with every request:

```
Authorization: Bearer <token>
```

The `ndns_token` session cookie is accepted for `GET` requests only; `POST`,
`PUT` and `DELETE` must use the `Authorization` header.

| Role | Zone endpoints |
|------|----------------|
| `admin` | Everything, including `POST /zones/reload` |
| `operator` | Everything except `POST /zones/reload` |
| `viewer` | **No access** (every zone endpoint returns `403 Operator role required`) |

There is no per-zone access control: an operator can change every zone.

---

## Endpoints overview

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| `GET` | `/zones` | operator | List all zones |
| `POST` | `/zones` | operator | Create a zone |
| `GET` | `/zones/{zone}` | operator | Zone details |
| `DELETE` | `/zones/{zone}` | operator | Delete a zone |
| `GET` | `/zones/{zone}/records` | operator | List records |
| `POST` | `/zones/{zone}/records` | operator | Add a record |
| `PUT` | `/zones/{zone}/records` | operator | Replace a record |
| `DELETE` | `/zones/{zone}/records` | operator | Delete records |
| `GET` | `/zones/{zone}/export` | operator | Export as a BIND zone file |
| `POST` | `/zones/{zone}/ptr-bulk` | operator | Bulk PTR generation for an IPv4 range |
| `GET` | `/zones/{zone}/ptr6-lookup` | operator | IPv6 PTR lookup |
| `POST` | `/zones/reload` | admin | Reload one zone from its file |
| `GET` | `/zones/transfers` | operator | Secondary zone status (see [API_REFERENCE.md](API_REFERENCE.md#16-zone-transfers)) |

Any other sub-path under `/zones/{zone}/` returns `404 {"error":"Not found"}`.

---

## Zone names, persistence and clustering

**Zone names in paths.** Zones are stored lowercase with a trailing dot
(`example.com.`). Use that exact form in paths.

- `GET /zones/{zone}`, `POST /zones/{zone}/ptr-bulk`,
  `GET /zones/{zone}/ptr6-lookup` and `POST /zones/reload?zone=` look the
  name up **exactly**: `example.com` (no dot) or `Example.com.` returns 404.
- `DELETE /zones/{zone}`, the `/records` endpoints and `/export` normalise the
  name (lowercase, trailing dot added), so `example.com` also works there.
- A zone name that is itself `reload` or `transfers` cannot be addressed with
  `GET /zones/{zone}` because those paths are separate routes.

**Owner names.** Record `name` fields may be relative to the zone (`www`) or
absolute (`www.example.com.`). They are lowercased and stored as absolute
names; responses always show absolute names.

**Persistence.** Every successful zone or record change is:

1. applied in memory and served immediately;
2. saved to the embedded database under `storage.data_dir` (when configured)
   and reloaded from there at start;
3. written to a zone file when `zone_dir` is configured: new zones as
   `<zone_dir>/<zone>.zone`, record changes to the zone's file.

File and database write failures are logged but do not fail the request.
The SOA serial is bumped (`YYYYMMDDnn`) on every record change.

**Raft clusters.** When the cluster runs in Raft mode, create zone, delete
zone and the four record operations are proposed through Raft and applied on
every node before the API answers. A node that is not the leader answers
`421 {"error":"not the Raft leader; retry against <leader>"}`; other replication
failures return `503`. `ptr-bulk` is applied locally and is not replicated.

---

## GET /zones

List all loaded zones (at most 5000).

### Request

```bash
curl -s http://127.0.0.1:8080/api/v1/zones -H "Authorization: Bearer $TOKEN"
```

### Response

**200 OK**
```json
{
  "zones": [
    {"name": "example.com.", "serial": 2024010101, "records": 12},
    {"name": "apidoc.test.", "serial": 2026091605, "records": 4}
  ],
  "total": 2
}
```

| Field | Type | Description |
|-------|------|-------------|
| `zones` | array | Zone summaries, in no particular order |
| `zones[].name` | string | Zone origin (lowercase, trailing dot) |
| `zones[].serial` | uint32 | SOA serial (0 when the zone has no SOA) |
| `zones[].records` | int | Number of records, including SOA and NS |
| `total` | int | Number of zones before capping |
| `truncated` | bool | Present and `true` only when more than 5000 zones exist |

---

## POST /zones

Create an authoritative zone with an SOA and NS records.

### Request

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/zones \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "name": "example.org.",
    "ttl": 3600,
    "admin_email": "hostmaster.example.org.",
    "nameservers": ["ns1.example.org.", "ns2.example.org."]
  }'
```

### Request fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Zone origin. Lowercased and a trailing dot is added. The root and reserved names are rejected. |
| `nameservers` | string[] | **Yes** | At least one. The first one becomes the SOA MNAME; each becomes an NS record at the apex. |
| `admin_email` | string | Recommended | SOA RNAME in DNS form (`hostmaster.example.org.`). There is no default: when omitted the SOA RNAME is empty, which produces an invalid SOA. |
| `ttl` | uint32 | No | Default TTL, also used for the SOA and NS records. `0` or omitted means 3600. |

The SOA gets serial `1`, refresh `3600`, retry `600`, expire `604800` and
minimum `86400`. These cannot be set through the API.

### Response

**201 Created**
```json
{
  "message": "Zone example.org. created",
  "name": "example.org."
}
```

`message` and `name` echo the name exactly as sent (without normalisation).

### Error responses

| Status | Error | Cause |
|--------|-------|-------|
| `400` | `Zone name is required` | Missing `name` |
| `400` | `At least one nameserver is required` | Missing or empty `nameservers` |
| `400` | `Invalid request body` | Malformed JSON or body over 64 KiB |
| `409` | `zone example.org. already exists` | Duplicate |
| `409` | `invalid zone origin` / `zone origin "..." is reserved and cannot be created` | Bad name |
| `421` | `not the Raft leader; ...` | Raft follower |
| `503` | `Zone manager not available` / replication error | Subsystem unavailable |

---

## GET /zones/{zone}

Zone details. The name must match exactly (lowercase, trailing dot).

### Request

```bash
curl -s http://127.0.0.1:8080/api/v1/zones/example.com. -H "Authorization: Bearer $TOKEN"
```

### Response

**200 OK**
```json
{
  "name": "example.com.",
  "serial": 2024010101,
  "records": 12,
  "soa": {
    "mname": "ns1.example.com.",
    "rname": "admin.example.com.",
    "serial": 2024010101,
    "refresh": 3600,
    "retry": 900,
    "expire": 86400,
    "minimum": 300
  },
  "nameservers": ["ns1.example.com.", "ns2.example.com."]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Zone origin |
| `serial` | uint32 | SOA serial (omitted when 0) |
| `records` | int | Total record count |
| `soa` | object | SOA fields; omitted when the zone has no SOA |
| `nameservers` | string[] | Apex NS targets; `null` when none |

### Error responses

| Status | Error | Cause |
|--------|-------|-------|
| `404` | `Zone example.com not found` | Unknown zone, or the name was not given in exact form |

---

## DELETE /zones/{zone}

Delete a zone with all its records.

> **Warning:** if the zone was loaded from a file (listed under `zones:` in the
> config or found in `zone_dir`) or written to `zone_dir`, **that file is
> deleted from disk**. The zone is also removed from the embedded database.

### Request

```bash
curl -s -X DELETE http://127.0.0.1:8080/api/v1/zones/example.org. -H "Authorization: Bearer $TOKEN"
```

### Response

**200 OK**
```json
{
  "message": "Zone example.org. deleted"
}
```

### Error responses

| Status | Error | Cause |
|--------|-------|-------|
| `404` | `zone example.org. not found` | Unknown zone, or the zone file could not be deleted |
| `421` | `not the Raft leader; ...` | Raft follower |

---

## GET /zones/{zone}/records

List the records of a zone (at most 5000).

### Request

```bash
curl -s "http://127.0.0.1:8080/api/v1/zones/example.com./records?name=www" \
  -H "Authorization: Bearer $TOKEN"
```

### Query parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | No | Owner name, relative (`www`) or absolute (`www.example.com.`). **Exact match**, not a prefix search. |

There is no `type` filter; filter on the client.

### Response

**200 OK**
```json
{
  "records": [
    {"name": "www.example.com.", "type": "A", "ttl": 3600, "class": "IN", "data": "192.0.2.10"},
    {"name": "www.example.com.", "type": "AAAA", "ttl": 3600, "class": "IN", "data": "2001:db8::10"}
  ],
  "total": 2
}
```

| Field | Type | Description |
|-------|------|-------------|
| `records` | array | Records, in no particular order; `[]` when nothing matches |
| `records[].name` | string | Absolute owner name |
| `records[].type` | string | Record type |
| `records[].ttl` | uint32 | TTL in seconds |
| `records[].class` | string | Class (normally `IN`) |
| `records[].data` | string | RDATA in presentation form (the SOA record is included, as `mname rname serial refresh retry expire minimum`) |
| `total` | int | Number of matching records before capping |
| `truncated` | bool | Present and `true` only when more than 5000 records match |

### Error responses

| Status | Error | Cause |
|--------|-------|-------|
| `404` | `zone example.com. not found` | Unknown zone |

---

## POST /zones/{zone}/records

Add one record.

### Request

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/zones/example.com./records \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "www", "type": "A", "ttl": 3600, "data": "192.0.2.10"}'
```

### Request fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Owner name, relative or absolute. Must not contain `;`, space, tab, `"`, `(`, `)` or control characters. |
| `type` | string | **Yes** | Record type |
| `data` | string | **Yes** | RDATA in presentation form. Must not contain newlines or NUL. |
| `ttl` | uint32 | No | `0` or omitted: the zone's default TTL, or 3600 |

The class is always `IN`. Adding a record does not replace existing records
with the same name and type; it appends another one.

> RDATA is **not** validated against the record type. `{"type":"A","data":"not-an-ip"}`
> is accepted and written to the zone file. Validate input on the client side.

### Common data formats

| Type | `data` example |
|------|----------------|
| `A` | `192.0.2.1` |
| `AAAA` | `2001:db8::1` |
| `CNAME` | `www.example.com.` |
| `MX` | `10 mail.example.com.` |
| `TXT` | `v=spf1 include:_spf.example.com -all` (no surrounding quotes; the zone-file writer adds and escapes them) |
| `NS` | `ns1.example.com.` |
| `PTR` | `host.example.com.` |
| `SRV` | `10 5 5269 xmpp.example.com.` |
| `CAA` | `0 issue "letsencrypt.org"` |

Use absolute names with a trailing dot inside RDATA.

### Response

**201 Created**
```json
{
  "message": "Record added"
}
```

### Error responses

| Status | Error | Cause |
|--------|-------|-------|
| `400` | `name, type, and data are required` | Missing field |
| `400` | `Invalid request body` | Malformed JSON |
| `404` | `zone example.com. not found` | Unknown zone |
| `404` | `Not found` / name validation message | Forbidden characters in `name` or `data` (reported as 404) |
| `421` | `not the Raft leader; ...` | Raft follower |

---

## PUT /zones/{zone}/records

Replace one existing record. The first record whose owner name and type match
and whose RDATA equals `old_data` (case-insensitive) is replaced by the new
record.

### Request

```bash
curl -s -X PUT http://127.0.0.1:8080/api/v1/zones/example.com./records \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "www", "type": "A", "old_data": "192.0.2.10", "data": "192.0.2.11", "ttl": 3600}'
```

### Request fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Owner name, relative or absolute |
| `type` | string | **Yes** | Record type |
| `old_data` | string | **Yes** | Current RDATA of the record to replace |
| `data` | string | **Yes** | New RDATA |
| `ttl` | uint32 | Effectively yes | New TTL. **When omitted or 0 the record is stored with TTL 0**; it does not keep the old TTL or fall back to the zone default. |

### Response

**200 OK**
```json
{
  "message": "Record updated"
}
```

### Error responses

| Status | Error | Cause |
|--------|-------|-------|
| `400` | `name, type, old_data, and data are required` | Missing field |
| `404` | `zone example.com. not found` | Unknown zone |
| `404` | `no records found for www.example.com.` | No records at that name |
| `404` | `record not found: www.example.com. A 192.0.2.99` | No record matches `old_data` |
| `421` | `not the Raft leader; ...` | Raft follower |

---

## DELETE /zones/{zone}/records

Delete **all** records of one type at one owner name. To remove a single value
from a set (for example one of several A records), delete the set and add back
the values to keep, or use `PUT` to change a value.

### Request

```bash
curl -s -X DELETE http://127.0.0.1:8080/api/v1/zones/example.com./records \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "www", "type": "A"}'
```

### Request fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Owner name, relative or absolute |
| `type` | string | **Yes** | Record type (case-insensitive) |

### Response

**200 OK**
```json
{
  "message": "Record deleted"
}
```

### Error responses

| Status | Error | Cause |
|--------|-------|-------|
| `400` | `name and type are required` | Missing field |
| `404` | `zone example.com. not found` | Unknown zone |
| `404` | `no records found for www.example.com.` | No records at that name |
| `404` | `no A record found for www.example.com.` | No record of that type |
| `421` | `not the Raft leader; ...` | Raft follower |

---

## GET /zones/{zone}/export

Export a zone in BIND format.

### Request

```bash
curl -s http://127.0.0.1:8080/api/v1/zones/example.com./export \
  -H "Authorization: Bearer $TOKEN" -o example.com.zone
```

### Response

**200 OK**

Headers: `Content-Type: text/plain; charset=utf-8` and
`Content-Disposition: attachment; filename="example.com.zone"` (characters
other than `a-z`, `0-9`, `-` and `.` in the file name are replaced by `_`).

```
$ORIGIN apidoc.test.
$TTL 3600

@	3600	IN	SOA	ns1.apidoc.test. hostmaster.apidoc.test. (
		2026091604	; serial
		3600	; refresh
		600	; retry
		604800	; expire
		86400	; minimum
	)

@	3600	IN	NS	ns1.apidoc.test.

mail	600	IN	MX	10 mx.apidoc.test.
www	3600	IN	A	192.0.2.45
```

### Error responses

| Status | Error | Cause |
|--------|-------|-------|
| `404` | `zone example.com. not found` | Unknown zone |

---

## POST /zones/{zone}/ptr-bulk

Generate PTR records (and optionally forward A records) for every address in
an IPv4 range.

### Request (preview)

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/zones/2.0.192.in-addr.arpa./ptr-bulk \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "cidr": "192.0.2.0/30",
    "pattern": "host-[A]-[B]-[C]-[D].example.com.",
    "addA": true,
    "preview": true
  }'
```

### Request (apply)

Send the same body with `"preview": false` (or without `preview`).

### Path parameter

`{zone}` must be the exact name of an existing `in-addr.arpa.` zone, such as
`2.0.192.in-addr.arpa.` for a /24.

### Request fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cidr` | string | **Yes** | IPv4 CIDR, at most 65536 addresses (/16). The network must lie inside the reverse zone (for a /24 zone the prefix must be /24 or longer and match the zone's octets). Every address in the range is processed, including network and broadcast addresses. |
| `pattern` | string | **Yes** | Up to 255 characters; must contain `[A]`, `[B]`, `[C]` and `[D]`. The result is used as PTR target and, with `addA`, as the A record owner. End it with a dot to make it absolute. |
| `addA` | bool | No | Also create forward A records named by the pattern. The A records are added to **this reverse zone** (as absolute owner names), not to the forward zone. |
| `override` | bool | No | Replace existing PTR (and A) records instead of skipping them |
| `preview` | bool | No | Only report what would change |

For `192.0.2.1`, `[A]` = `192`, `[B]` = `0`, `[C]` = `2`, `[D]` = `1`.
Created records have TTL 3600.

### Preview response

**200 OK**
```json
{
  "preview": true,
  "total": 4,
  "willAdd": 4,
  "willAddA": 4,
  "willSkip": 0,
  "willOverride": 0,
  "changes": [
    {
      "ip": "192.0.2.1",
      "ptrName": "host-192-0-2-1.example.com.",
      "aName": "host-192-0-2-1.example.com.",
      "action": "add",
      "ptrExist": false,
      "revRecord": "1"
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `changes[].action` | `add`, `override` (existing PTR and `override: true`) or `skip` (existing PTR, no override) |
| `changes[].ptrName` | Generated name (PTR target) |
| `changes[].revRecord` | PTR owner name relative to the zone (`1` for `1.2.0.192.in-addr.arpa.`) |
| `changes[].oldPtr`, `oldA` | Existing values, when present |
| `changes[].aName`, `aExist` | Present only with `addA` |
| `willOverride` | Counts both PTR and A overrides |

### Apply response

**200 OK**
```json
{
  "added": 4,
  "addedA": 4,
  "exists": 0,
  "existsA": 0,
  "skipped": 0
}
```

| Field | Type | Description |
|-------|------|-------------|
| `added` | int | PTR records created |
| `addedA` | int | A records created |
| `exists` | int | PTR records that could not be added |
| `existsA` | int | A records that already existed (and were kept) or could not be added |
| `skipped` | int | Addresses skipped because a PTR existed and `override` was false (no PTR and no A written for them) |

### Error responses

| Status | Error | Cause |
|--------|-------|-------|
| `400` | `cidr and pattern are required` | Missing field |
| `400` | `pattern too long` | Pattern over 255 characters |
| `400` | `Invalid CIDR: ...` | Unparseable CIDR |
| `400` | `Only IPv4 CIDR is supported` | IPv6 range |
| `400` | `CIDR too large (max /16)` | More than 65536 addresses |
| `400` | `Pattern must contain [A], [B], [C], [D] placeholders` | Placeholder missing |
| `400` | `zone ... is not a reverse DNS zone (.in-addr.arpa)` | Not a reverse zone |
| `400` | `CIDR network 198.51.100.0 does not belong to reverse zone 2.0.192.in-addr.arpa.` | Range outside the zone |
| `400` | `CIDR prefix /16 is too small for zone ... (minimum /24)` | Range wider than the zone |
| `404` | `Zone 2.0.192.in-addr.arpa. not found` | Unknown zone (exact name required) |
| `500` | `Failed to delete existing PTR record: ...` | Override failed part-way; earlier changes stay applied |

---

## GET /zones/{zone}/ptr6-lookup

Find the PTR record of an IPv6 address in an `ip6.arpa.` zone. Read-only.

### Request

```bash
curl -s "http://127.0.0.1:8080/api/v1/zones/8.b.d.0.1.0.0.2.ip6.arpa./ptr6-lookup?ip=2001:db8::1" \
  -H "Authorization: Bearer $TOKEN"
```

### Query parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ip` | string | **Yes** | IPv6 address (IPv4 and IPv4-mapped addresses are rejected) |

### Response (found)

**200 OK**
```json
{
  "ip": "2001:db8::1",
  "ptr": "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
  "ptrFQDN": "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
  "target": "www.example.com.",
  "ttl": 3600,
  "found": true
}
```

### Response (not found)

**200 OK**
```json
{
  "ip": "2001:db8::2",
  "ptr": "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
  "ptrFQDN": "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
  "found": false
}
```

| Field | Type | Description |
|-------|------|-------------|
| `ip` | string | The address as sent |
| `ptr` | string | Nibble-reversed name without trailing dot |
| `ptrFQDN` | string | Same name with trailing dot |
| `target` | string | PTR target (only when found) |
| `ttl` | uint32 | TTL (only when found) |
| `found` | bool | Whether a PTR record exists |

### Error responses

| Status | Error | Cause |
|--------|-------|-------|
| `400` | `IP parameter is required` | Missing `ip` |
| `400` | `Invalid IPv6 address` | Not an IPv6 address |
| `400` | `Zone is not an IPv6 reverse zone (must end with ip6.arpa.)` | Wrong zone type |
| `404` | `Zone ... not found` | Unknown zone (exact name required) |

---

## POST /zones/reload

Re-read one zone from the file it was loaded from, without restarting.
**Admin only.** Zones created through the API without `zone_dir` have no file
and cannot be reloaded. To reload every zone and the rest of the configuration,
use `POST /api/v1/config/reload`.

### Request

```bash
curl -s -X POST "http://127.0.0.1:8080/api/v1/zones/reload?zone=example.com." \
  -H "Authorization: Bearer $TOKEN"
```

### Query parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `zone` | string | **Yes** | Exact zone name (lowercase, trailing dot) |

### Response

**200 OK**
```json
{
  "message": "Zone example.com. reloaded"
}
```

### Error responses

| Status | Error | Cause |
|--------|-------|-------|
| `400` | `Missing zone parameter` | No `zone` |
| `403` | `Admin role required` | Caller is not an admin |
| `500` | `zone example.com. not found` | Unknown zone, name not in exact form, or zone without a file |
| `500` | parse/validation error, or `Failed to reload zone` | Zone file invalid or unreadable |
| `503` | `Zone manager not available` | Subsystem unavailable |

---

## Common error format

All errors are JSON:

```json
{
  "error": "Error description"
}
```

| Status | Meaning |
|--------|---------|
| `200` | Success |
| `201` | Created |
| `400` | Bad request (validation error, malformed JSON, body over 64 KiB) |
| `401` | Missing or invalid token, or cookie-only authentication on a write |
| `403` | Role too low |
| `404` | Zone, record or sub-path not found |
| `405` | Method not allowed |
| `409` | Conflict (zone already exists, invalid zone name) |
| `421` | Write sent to a Raft follower |
| `429` | API rate limit (100 requests per minute per client IP) |
| `500` | Internal error (reload failure, partial bulk PTR failure) |
| `503` | Zone manager or Raft replication unavailable |

Error texts that contain `/` are replaced by a generic message such as
`Not found`.

---

## Security notes

- **Global RBAC.** Operators can change every zone; there is no per-zone
  isolation.
- **Input hygiene.** Owner names containing zone-file syntax characters and
  RDATA containing newlines or NUL are rejected, so a request cannot inject
  lines into a zone file. RDATA is otherwise not validated.
- **Export file names** are sanitised.
- **Body limit.** Request bodies are limited to 64 KiB.
- **Logging.** The API logs one line per request (method, path, status,
  latency). Bulk PTR runs also log a summary. There is no separate audit log of
  zone changes.

---

## Example: complete zone workflow

### 1. Create a zone

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/zones \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "name": "example.org.",
    "ttl": 3600,
    "admin_email": "hostmaster.example.org.",
    "nameservers": ["ns1.example.org.", "ns2.example.org."]
  }'
```

### 2. Add records

```bash
# A record (relative owner name)
curl -s -X POST http://127.0.0.1:8080/api/v1/zones/example.org./records \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "www", "type": "A", "ttl": 3600, "data": "192.0.2.1"}'

# MX record at the apex
curl -s -X POST http://127.0.0.1:8080/api/v1/zones/example.org./records \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "example.org.", "type": "MX", "ttl": 3600, "data": "10 mail.example.org."}'

# TXT record (no surrounding quotes)
curl -s -X POST http://127.0.0.1:8080/api/v1/zones/example.org./records \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "example.org.", "type": "TXT", "ttl": 3600, "data": "v=spf1 include:_spf.example.org -all"}'
```

### 3. List zones and records

```bash
curl -s http://127.0.0.1:8080/api/v1/zones -H "Authorization: Bearer $TOKEN"
curl -s http://127.0.0.1:8080/api/v1/zones/example.org. -H "Authorization: Bearer $TOKEN"
curl -s http://127.0.0.1:8080/api/v1/zones/example.org./records -H "Authorization: Bearer $TOKEN"
curl -s "http://127.0.0.1:8080/api/v1/zones/example.org./records?name=www" -H "Authorization: Bearer $TOKEN"
```

### 4. Change a record (always send `ttl`)

```bash
curl -s -X PUT http://127.0.0.1:8080/api/v1/zones/example.org./records \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "www", "type": "A", "old_data": "192.0.2.1", "data": "192.0.2.2", "ttl": 3600}'
```

### 5. Export the zone

```bash
curl -s http://127.0.0.1:8080/api/v1/zones/example.org./export \
  -H "Authorization: Bearer $TOKEN" -o example.org.zone
```

### 6. Delete records

```bash
curl -s -X DELETE http://127.0.0.1:8080/api/v1/zones/example.org./records \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "www", "type": "A"}'
```

### 7. Delete the zone

```bash
curl -s -X DELETE http://127.0.0.1:8080/api/v1/zones/example.org. -H "Authorization: Bearer $TOKEN"
```
