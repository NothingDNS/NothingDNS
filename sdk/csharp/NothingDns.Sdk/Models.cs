using System.Text.Json;
using System.Text.Json.Serialization;

namespace NothingDns.Sdk;

// Typed models for the NothingDNS management API.
//
// Every property carries an explicit JsonPropertyNameAttribute so the
// wire format stays exactly what the server sends — snake_case for the
// /api/v1 routes, and camelCase for the /api/dashboard, PTR bulk and PTR
// IPv6 lookup shapes — while the C# property names stay idiomatic
// PascalCase.
//
// Models are mutable classes whose properties have sensible defaults, so a field
// that a server build omits leaves its default in place rather than failing to
// deserialise. A newer server that adds fields never breaks an older client.
#pragma warning disable CS1591 // documented per-member below

/// <summary>Health, readiness and liveness probe result.</summary>
public sealed class HealthResponse
{
    /// <summary>Gets or sets the reported state: <c>healthy</c>, <c>ready</c>, <c>alive</c> or <c>unhealthy</c>.</summary>
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    /// <summary>Gets or sets the server timestamp of the probe.</summary>
    [JsonPropertyName("timestamp")]
    public string? Timestamp { get; set; }
}

/// <summary>DNS response cache counters.</summary>
public sealed class CacheStats
{
    /// <summary>Gets or sets the number of entries currently cached.</summary>
    [JsonPropertyName("size")]
    public long Size { get; set; }

    /// <summary>Gets or sets the maximum number of entries the cache holds.</summary>
    [JsonPropertyName("capacity")]
    public long Capacity { get; set; }

    /// <summary>Gets or sets the lifetime cache hit count.</summary>
    [JsonPropertyName("hits")]
    public long Hits { get; set; }

    /// <summary>Gets or sets the lifetime cache miss count.</summary>
    [JsonPropertyName("misses")]
    public long Misses { get; set; }

    /// <summary>Gets or sets the hit ratio, where 1.0 means every query was served from cache.</summary>
    [JsonPropertyName("hit_ratio")]
    public double HitRatio { get; set; }
}

/// <summary>Cluster summary embedded in <see cref="StatusResponse"/>.</summary>
public sealed class ClusterSummary
{
    /// <summary>Gets or sets a value indicating whether clustering is enabled.</summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    /// <summary>Gets or sets this node's identifier.</summary>
    [JsonPropertyName("node_id")]
    public string NodeId { get; set; } = string.Empty;

    /// <summary>Gets or sets the number of nodes known to the cluster.</summary>
    [JsonPropertyName("node_count")]
    public long NodeCount { get; set; }

    /// <summary>Gets or sets the number of nodes currently considered alive.</summary>
    [JsonPropertyName("alive_count")]
    public long AliveCount { get; set; }

    /// <summary>Gets or sets a value indicating whether the cluster is healthy.</summary>
    [JsonPropertyName("healthy")]
    public bool Healthy { get; set; }
}

/// <summary>Result of <c>GET /api/v1/status</c>.</summary>
public sealed class StatusResponse
{
    /// <summary>Gets or sets the server status string.</summary>
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    /// <summary>Gets or sets the server timestamp.</summary>
    [JsonPropertyName("timestamp")]
    public string? Timestamp { get; set; }

    /// <summary>Gets or sets the running NothingDNS version.</summary>
    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    /// <summary>Gets or sets the cache counters. Present for operators and admins only.</summary>
    [JsonPropertyName("cache")]
    public CacheStats? Cache { get; set; }

    /// <summary>Gets or sets the cluster summary, when clustering is configured.</summary>
    [JsonPropertyName("cluster")]
    public ClusterSummary? Cluster { get; set; }
}

/// <summary>DNS64/NAT64 synthesis settings (RFC 6147).</summary>
public sealed class Dns64Config
{
    /// <summary>Gets or sets a value indicating whether DNS64 synthesis is enabled.</summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    /// <summary>Gets or sets the well-known NAT64 prefix, normally <c>64:ff9b::/96</c>.</summary>
    [JsonPropertyName("prefix")]
    public string Prefix { get; set; } = string.Empty;

    /// <summary>Gets or sets the prefix length in bits.</summary>
    [JsonPropertyName("prefix_len")]
    public int PrefixLen { get; set; }

    /// <summary>Gets or sets networks excluded from synthesis, which already have native IPv6.</summary>
    [JsonPropertyName("exclude_nets")]
    public List<string> ExcludeNets { get; set; } = new();
}

/// <summary>DNS Cookies settings (RFC 7873).</summary>
public sealed class CookieConfig
{
    /// <summary>Gets or sets a value indicating whether DNS Cookies are enabled.</summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    /// <summary>Gets or sets the client cookie secret rotation policy.</summary>
    [JsonPropertyName("secret_rotation")]
    public string SecretRotation { get; set; } = string.Empty;
}

/// <summary>Result of <c>GET /api/v1/server/config</c>.</summary>
public sealed class ServerConfig
{
    /// <summary>Gets or sets the running NothingDNS version.</summary>
    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    /// <summary>Gets or sets the port the DNS listener is bound to.</summary>
    [JsonPropertyName("listen_port")]
    public int ListenPort { get; set; }

    /// <summary>Gets or sets the current log level.</summary>
    [JsonPropertyName("log_level")]
    public string LogLevel { get; set; } = string.Empty;

    /// <summary>Gets or sets the DNS64 synthesis configuration.</summary>
    [JsonPropertyName("dns64")]
    public Dns64Config? Dns64 { get; set; }

    /// <summary>Gets or sets the DNS Cookies configuration.</summary>
    [JsonPropertyName("cookie")]
    public CookieConfig? Cookie { get; set; }
}

/// <summary>A login or session result: the bearer token plus who it belongs to.</summary>
public sealed class Session
{
    /// <summary>Gets or sets the bearer token to send as <c>Authorization: Bearer</c>.</summary>
    [JsonPropertyName("token")]
    public string Token { get; set; } = string.Empty;

    /// <summary>Gets or sets the authenticated account name.</summary>
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    /// <summary>Gets or sets the account role: <c>admin</c>, <c>operator</c> or <c>viewer</c>.</summary>
    [JsonPropertyName("role")]
    public string Role { get; set; } = string.Empty;

    /// <summary>Gets or sets the RFC 3339 expiry timestamp. Absent on bootstrap responses.</summary>
    [JsonPropertyName("expires")]
    public string? Expires { get; set; }
}

/// <summary>A user account. The API never returns passwords.</summary>
public sealed class User
{
    /// <summary>Gets or sets the account name.</summary>
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    /// <summary>Gets or sets the account role: <c>admin</c>, <c>operator</c> or <c>viewer</c>.</summary>
    [JsonPropertyName("role")]
    public string Role { get; set; } = NothingDnsRoles.Viewer;

    /// <summary>Gets or sets when the account was created.</summary>
    [JsonPropertyName("created_at")]
    public string? CreatedAt { get; set; }

    /// <summary>Gets or sets when the account was last modified.</summary>
    [JsonPropertyName("updated_at")]
    public string? UpdatedAt { get; set; }
}

/// <summary>One entry of the server's role table.</summary>
public sealed class Role
{
    /// <summary>Gets or sets the role name.</summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the human-readable role description.</summary>
    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;
}

/// <summary>A zone's start-of-authority record.</summary>
public sealed class Soa
{
    /// <summary>Gets or sets the primary nameserver host name.</summary>
    [JsonPropertyName("mname")]
    public string Mname { get; set; } = string.Empty;

    /// <summary>Gets or sets the responsible party e-mail address in zone-file form.</summary>
    [JsonPropertyName("rname")]
    public string Rname { get; set; } = string.Empty;

    /// <summary>Gets or sets the zone serial number.</summary>
    [JsonPropertyName("serial")]
    public long Serial { get; set; }

    /// <summary>Gets or sets the secondary refresh interval in seconds.</summary>
    [JsonPropertyName("refresh")]
    public long Refresh { get; set; }

    /// <summary>Gets or sets the secondary retry interval in seconds.</summary>
    [JsonPropertyName("retry")]
    public long Retry { get; set; }

    /// <summary>Gets or sets the zone expiry interval in seconds.</summary>
    [JsonPropertyName("expire")]
    public long Expire { get; set; }

    /// <summary>Gets or sets the minimum TTL for negative answers in seconds.</summary>
    [JsonPropertyName("minimum")]
    public long Minimum { get; set; }
}

/// <summary>A zone summary, also used for the dashboard zone list.</summary>
public sealed class Zone
{
    /// <summary>Gets or sets the fully qualified zone name.</summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the current zone serial number.</summary>
    [JsonPropertyName("serial")]
    public long Serial { get; set; }

    /// <summary>Gets or sets the number of records in the zone.</summary>
    [JsonPropertyName("records")]
    public long Records { get; set; }
}

/// <summary>Result of <c>GET /api/v1/zones</c>.</summary>
public sealed class ZoneList
{
    /// <summary>Gets or sets the zones served by this node.</summary>
    [JsonPropertyName("zones")]
    public List<Zone> Zones { get; set; } = new();

    /// <summary>Gets or sets the total number of zones the server knows about.</summary>
    [JsonPropertyName("total")]
    public long Total { get; set; }

    /// <summary>Gets or sets a value indicating whether the server capped the returned list.</summary>
    [JsonPropertyName("truncated")]
    public bool Truncated { get; set; }
}

/// <summary>Result of <c>GET /api/v1/zones/{zone}</c>.</summary>
public sealed class ZoneDetail
{
    /// <summary>Gets or sets the fully qualified zone name.</summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the current zone serial number.</summary>
    [JsonPropertyName("serial")]
    public long Serial { get; set; }

    /// <summary>Gets or sets the number of records in the zone.</summary>
    [JsonPropertyName("records")]
    public long Records { get; set; }

    /// <summary>Gets or sets the zone's start-of-authority record.</summary>
    [JsonPropertyName("soa")]
    public Soa? Soa { get; set; }

    /// <summary>Gets or sets the zone's authoritative nameservers.</summary>
    [JsonPropertyName("nameservers")]
    public List<string> Nameservers { get; set; } = new();
}

/// <summary>A single DNS resource record.</summary>
public sealed class DnsRecord
{
    /// <summary>Gets or sets the owner name. <c>@</c> denotes the zone apex.</summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the record type, for example <c>A</c>, <c>MX</c> or <c>TXT</c>.</summary>
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    /// <summary>Gets or sets the record TTL in seconds.</summary>
    [JsonPropertyName("ttl")]
    public long Ttl { get; set; }

    /// <summary>Gets or sets the DNS class, normally <c>IN</c> for internet.</summary>
    [JsonPropertyName("class")]
    public string Class { get; set; } = string.Empty;

    /// <summary>Gets or sets the record data in zone-file presentation format.</summary>
    [JsonPropertyName("data")]
    public string Data { get; set; } = string.Empty;
}

/// <summary>Result of <c>GET /api/v1/zones/{zone}/records</c>.</summary>
public sealed class RecordList
{
    /// <summary>Gets or sets the returned records.</summary>
    [JsonPropertyName("records")]
    public List<DnsRecord> Records { get; set; } = new();

    /// <summary>Gets or sets the total number of records matching the query.</summary>
    [JsonPropertyName("total")]
    public long Total { get; set; }

    /// <summary>Gets or sets a value indicating whether the server capped the returned list.</summary>
    [JsonPropertyName("truncated")]
    public bool Truncated { get; set; }
}

/// <summary>A secondary (slave) zone and its transfer state.</summary>
public sealed class SlaveZone
{
    /// <summary>Gets or sets the zone name.</summary>
    [JsonPropertyName("zone")]
    public string Zone { get; set; } = string.Empty;

    /// <summary>Gets or sets the master server list, as configured.</summary>
    [JsonPropertyName("masters")]
    public string Masters { get; set; } = string.Empty;

    /// <summary>Gets or sets the last known serial.</summary>
    [JsonPropertyName("serial")]
    public long Serial { get; set; }

    /// <summary>Gets or sets when the last zone transfer completed.</summary>
    [JsonPropertyName("last_transfer")]
    public string? LastTransfer { get; set; }

    /// <summary>Gets or sets the transfer state: <c>pending</c> or <c>synced</c>.</summary>
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    /// <summary>Gets or sets the number of records held for the zone.</summary>
    [JsonPropertyName("records")]
    public long Records { get; set; }
}

/// <summary>One record the bulk PTR generator would create or change.</summary>
public sealed class PtrChange
{
    /// <summary>Gets or sets the owner name of the PTR record.</summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the record type.</summary>
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    /// <summary>Gets or sets the record TTL in seconds.</summary>
    [JsonPropertyName("ttl")]
    public long Ttl { get; set; }

    /// <summary>Gets or sets the record data.</summary>
    [JsonPropertyName("data")]
    public string Data { get; set; } = string.Empty;

    /// <summary>Gets or sets the action the generator would take: add, skip or override.</summary>
    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;
}

/// <summary>
/// Result of <c>POST /api/v1/zones/{zone}/ptr-bulk</c>.
/// </summary>
/// <remarks>
/// The endpoint answers with a different set of counters depending on the
/// <c>preview</c> flag that was sent. Check <see cref="Preview"/> to tell them
/// apart: when it is <see langword="true"/> the <c>Will*</c> counts and
/// <see cref="Changes"/> are populated; otherwise <see cref="Added"/>,
/// <see cref="Exists"/> and <see cref="Skipped"/> describe what was written.
/// </remarks>
public sealed class PtrBulkResult
{
    /// <summary>Gets or sets a value indicating whether the response describes a dry run.</summary>
    [JsonPropertyName("preview")]
    public bool Preview { get; set; }

    /// <summary>Gets or sets the total number of addresses covered by the range.</summary>
    [JsonPropertyName("total")]
    public long Total { get; set; }

    /// <summary>Gets or sets the number of PTR records that would be added.</summary>
    [JsonPropertyName("willAdd")]
    public long WillAdd { get; set; }

    /// <summary>Gets or sets the number of A records that would be added.</summary>
    [JsonPropertyName("willAddA")]
    public long WillAddA { get; set; }

    /// <summary>Gets or sets the number of existing records that would be left alone.</summary>
    [JsonPropertyName("willSkip")]
    public long WillSkip { get; set; }

    /// <summary>Gets or sets the number of existing records that would be replaced.</summary>
    [JsonPropertyName("willOverride")]
    public long WillOverride { get; set; }

    /// <summary>Gets or sets the per-record preview, populated only for a dry run.</summary>
    [JsonPropertyName("changes")]
    public List<PtrChange> Changes { get; set; } = new();

    /// <summary>Gets or sets the number of PTR records actually created.</summary>
    [JsonPropertyName("added")]
    public long Added { get; set; }

    /// <summary>Gets or sets the number of A records actually created.</summary>
    [JsonPropertyName("addedA")]
    public long AddedA { get; set; }

    /// <summary>Gets or sets the number of PTR records that already existed.</summary>
    [JsonPropertyName("exists")]
    public long Exists { get; set; }

    /// <summary>Gets or sets the number of A records that already existed.</summary>
    [JsonPropertyName("existsA")]
    public long ExistsA { get; set; }

    /// <summary>Gets or sets the number of records skipped.</summary>
    [JsonPropertyName("skipped")]
    public long Skipped { get; set; }
}

/// <summary>Result of <c>GET /api/v1/zones/{zone}/ptr6-lookup</c>.</summary>
public sealed class PtrLookup
{
    /// <summary>Gets or sets the IPv6 address that was looked up.</summary>
    [JsonPropertyName("ip")]
    public string Ip { get; set; } = string.Empty;

    /// <summary>Gets or sets the PTR owner name relative to the zone.</summary>
    [JsonPropertyName("ptr")]
    public string Ptr { get; set; } = string.Empty;

    /// <summary>Gets or sets the fully qualified PTR owner name.</summary>
    [JsonPropertyName("ptrFQDN")]
    public string PtrFqdn { get; set; } = string.Empty;

    /// <summary>Gets or sets the PTR target host name.</summary>
    [JsonPropertyName("target")]
    public string Target { get; set; } = string.Empty;

    /// <summary>Gets or sets the record TTL in seconds.</summary>
    [JsonPropertyName("ttl")]
    public long Ttl { get; set; }

    /// <summary>Gets or sets a value indicating whether a PTR record was found. Check this before reading the other fields.</summary>
    [JsonPropertyName("found")]
    public bool Found { get; set; }
}

/// <summary>An ACL rule. The same shape is used to read and to write the rule list.</summary>
public sealed class AclRule
{
    /// <summary>Gets or sets the rule name, used for identification in the dashboard.</summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the CIDR networks or addresses the rule matches.</summary>
    [JsonPropertyName("networks")]
    public List<string> Networks { get; set; } = new();

    /// <summary>Gets or sets the action: <c>allow</c>, <c>deny</c> or <c>redirect</c>.</summary>
    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;

    /// <summary>Gets or sets the query types the rule applies to. Empty means all types.</summary>
    [JsonPropertyName("types")]
    public List<string> Types { get; set; } = new();

    /// <summary>Gets or sets the redirect target for <c>redirect</c> rules, for example <c>127.0.0.1</c>.</summary>
    [JsonPropertyName("redirect")]
    public string Redirect { get; set; } = string.Empty;

    /// <summary>Convert the rule to the wire payload used by <c>PUT /api/v1/acl</c>.</summary>
    /// <returns>A dictionary keyed by the server's field names.</returns>
    public Dictionary<string, object?> ToPayload() => new(StringComparer.Ordinal)
    {
        ["name"] = Name,
        ["networks"] = Networks,
        ["action"] = Action,
        ["types"] = Types,
        ["redirect"] = Redirect,
    };
}

/// <summary>The list of clients permitted to use recursive resolution.</summary>
public sealed class RecursionAllowList
{
    /// <summary>Gets or sets a value indicating whether every client may recurse.</summary>
    [JsonPropertyName("allow_all")]
    public bool AllowAll { get; set; }

    /// <summary>Gets or sets the CIDR networks allowed to send recursive queries.</summary>
    [JsonPropertyName("networks")]
    public List<string> Networks { get; set; } = new();
}

/// <summary>Result of <c>GET /api/v1/acl</c>.</summary>
public sealed class AclConfig
{
    /// <summary>Gets or sets the ACL rules in evaluation order. The first match wins.</summary>
    [JsonPropertyName("rules")]
    public List<AclRule> Rules { get; set; } = new();

    /// <summary>Gets or sets the recursion allow list.</summary>
    [JsonPropertyName("allow_recursion")]
    public RecursionAllowList? AllowRecursion { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the list is served from
    /// <c>access_policy.json</c>, the dashboard-managed file that overrides the
    /// YAML configuration on reload.
    /// </summary>
    [JsonPropertyName("persistent")]
    public bool Persistent { get; set; }

    /// <summary>Gets or sets the path of the backing policy file.</summary>
    [JsonPropertyName("policy_file")]
    public string PolicyFile { get; set; } = string.Empty;
}

/// <summary>Blocklist filtering counters.</summary>
public sealed class BlocklistStats
{
    /// <summary>Gets or sets a value indicating whether blocklist filtering is active.</summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    /// <summary>Gets or sets the total number of loaded blocking rules.</summary>
    [JsonPropertyName("total_rules")]
    public long TotalRules { get; set; }

    /// <summary>Gets or sets the number of file-based sources.</summary>
    [JsonPropertyName("files_count")]
    public long FilesCount { get; set; }

    /// <summary>Gets or sets the number of URL-based sources.</summary>
    [JsonPropertyName("urls_count")]
    public long UrlsCount { get; set; }
}

/// <summary>One blocklist source.</summary>
public sealed class BlocklistSource
{
    /// <summary>Gets or sets the source identifier, used when removing or toggling it.</summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    /// <summary>Gets or sets the source type: <c>file</c> or <c>url</c>.</summary>
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    /// <summary>Gets or sets a value indicating whether this source is active.</summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    /// <summary>Gets or sets the number of domains loaded from this source.</summary>
    [JsonPropertyName("domains")]
    public long Domains { get; set; }
}

/// <summary>Response Policy Zone counters.</summary>
public sealed class RpzStats
{
    /// <summary>Gets or sets a value indicating whether RPZ filtering is active.</summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    /// <summary>Gets or sets the total number of loaded policy rules.</summary>
    [JsonPropertyName("total_rules")]
    public long TotalRules { get; set; }

    /// <summary>Gets or sets the number of QNAME rules.</summary>
    [JsonPropertyName("qname_rules")]
    public long QnameRules { get; set; }

    /// <summary>Gets or sets the number of client-IP rules.</summary>
    [JsonPropertyName("client_ip_rules")]
    public long ClientIpRules { get; set; }

    /// <summary>Gets or sets the number of response-IP rules.</summary>
    [JsonPropertyName("resp_ip_rules")]
    public long RespIpRules { get; set; }

    /// <summary>Gets or sets the number of policy files loaded.</summary>
    [JsonPropertyName("files_count")]
    public long FilesCount { get; set; }

    /// <summary>Gets or sets the lifetime number of enforced policy actions.</summary>
    [JsonPropertyName("total_matches")]
    public long TotalMatches { get; set; }

    /// <summary>Gets or sets the lifetime number of policy lookups.</summary>
    [JsonPropertyName("total_lookups")]
    public long TotalLookups { get; set; }

    /// <summary>Gets or sets when the policy zones were last reloaded.</summary>
    [JsonPropertyName("last_reload")]
    public string? LastReload { get; set; }
}

/// <summary>One QNAME policy rule.</summary>
public sealed class RpzRule
{
    /// <summary>Gets or sets the domain pattern the rule matches.</summary>
    [JsonPropertyName("pattern")]
    public string Pattern { get; set; } = string.Empty;

    /// <summary>Gets or sets the policy action.</summary>
    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;

    /// <summary>Gets or sets the RPZ trigger that activated the rule.</summary>
    [JsonPropertyName("trigger")]
    public string Trigger { get; set; } = string.Empty;

    /// <summary>Gets or sets the replacement data for rewriting actions.</summary>
    [JsonPropertyName("override_data")]
    public string OverrideData { get; set; } = string.Empty;

    /// <summary>Gets or sets the name of the policy zone the rule came from.</summary>
    [JsonPropertyName("policy_name")]
    public string PolicyName { get; set; } = string.Empty;

    /// <summary>Gets or sets the rule priority; lower values are evaluated first.</summary>
    [JsonPropertyName("priority")]
    public long Priority { get; set; }
}

/// <summary>Result of <c>GET /api/v1/rpz/rules</c>.</summary>
public sealed class RpzRuleList
{
    /// <summary>Gets or sets the QNAME rules.</summary>
    [JsonPropertyName("rules")]
    public List<RpzRule> Rules { get; set; } = new();

    /// <summary>Gets or sets the total number of rules the server knows about.</summary>
    [JsonPropertyName("total")]
    public long Total { get; set; }

    /// <summary>Gets or sets a value indicating whether the server capped the returned list.</summary>
    [JsonPropertyName("truncated")]
    public bool Truncated { get; set; }
}

/// <summary>DNSSEC validation status.</summary>
public sealed class DnssecStatus
{
    /// <summary>Gets or sets a value indicating whether DNSSEC validation is enabled.</summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    /// <summary>Gets or sets a value indicating whether validation is mandatory and unvalidated answers are refused.</summary>
    [JsonPropertyName("require_dnssec")]
    public bool RequireDnssec { get; set; }
}

/// <summary>Public metadata for one DNSSEC signing key.</summary>
public sealed class DnssecKey
{
    /// <summary>Gets or sets the key tag (RFC 4034 appendix B).</summary>
    [JsonPropertyName("keyTag")]
    public int KeyTag { get; set; }

    /// <summary>Gets or sets the DNSSEC algorithm number.</summary>
    [JsonPropertyName("algorithm")]
    public int Algorithm { get; set; }

    /// <summary>Gets or sets the DNSKEY flags.</summary>
    [JsonPropertyName("flags")]
    public int Flags { get; set; }

    /// <summary>Gets or sets a value indicating whether this is a key signing key.</summary>
    [JsonPropertyName("isKSK")]
    public bool IsKsk { get; set; }

    /// <summary>Gets or sets a value indicating whether this is a zone signing key.</summary>
    [JsonPropertyName("isZSK")]
    public bool IsZsk { get; set; }

    /// <summary>Gets or sets the zone the key belongs to.</summary>
    [JsonPropertyName("zone")]
    public string Zone { get; set; } = string.Empty;
}

/// <summary>Result of <c>GET /api/v1/dnssec/keys</c>.</summary>
public sealed class DnssecKeyList
{
    /// <summary>Gets or sets the published signing keys, grouped per zone.</summary>
    [JsonPropertyName("zones")]
    public List<DnssecKey> Zones { get; set; } = new();
}

/// <summary>Per-upstream counters inside the resolver pool.</summary>
public sealed class UpstreamHealth
{
    /// <summary>Gets or sets the upstream server address.</summary>
    [JsonPropertyName("address")]
    public string Address { get; set; } = string.Empty;

    /// <summary>Gets or sets a value indicating whether the upstream is considered healthy.</summary>
    [JsonPropertyName("healthy")]
    public bool Healthy { get; set; }

    /// <summary>Gets or sets the number of queries forwarded to this upstream.</summary>
    [JsonPropertyName("queries")]
    public long Queries { get; set; }

    /// <summary>Gets or sets the number of failed queries sent to this upstream.</summary>
    [JsonPropertyName("failed")]
    public long Failed { get; set; }

    /// <summary>Gets or sets the number of times traffic failed over away from this upstream.</summary>
    [JsonPropertyName("failovers")]
    public long Failovers { get; set; }
}

/// <summary>Health and latency for one configured upstream server.</summary>
public sealed class UpstreamServer
{
    /// <summary>Gets or sets the server address.</summary>
    [JsonPropertyName("address")]
    public string Address { get; set; } = string.Empty;

    /// <summary>Gets or sets a value indicating whether the server is considered healthy.</summary>
    [JsonPropertyName("healthy")]
    public bool Healthy { get; set; }

    /// <summary>Gets or sets the measured latency in milliseconds.</summary>
    [JsonPropertyName("latency_ms")]
    public double LatencyMs { get; set; }
}

/// <summary>Result of <c>GET /api/v1/upstreams</c>.</summary>
public sealed class Upstreams
{
    /// <summary>Gets or sets the per-upstream pool health counters.</summary>
    [JsonPropertyName("upstreams")]
    public List<UpstreamHealth> Health { get; set; } = new();

    /// <summary>Gets or sets the configured servers with their health.</summary>
    [JsonPropertyName("servers")]
    public List<UpstreamServer> Servers { get; set; } = new();
}

/// <summary>GeoDNS counters.</summary>
public sealed class GeoIpStats
{
    /// <summary>Gets or sets a value indicating whether GeoDNS is enabled.</summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    /// <summary>Gets or sets the number of configured geo rules.</summary>
    [JsonPropertyName("rules")]
    public long Rules { get; set; }

    /// <summary>Gets or sets a value indicating whether the MaxMind database is loaded.</summary>
    [JsonPropertyName("mmdb_loaded")]
    public bool MmdbLoaded { get; set; }

    /// <summary>Gets or sets the lifetime number of geo lookups.</summary>
    [JsonPropertyName("lookups")]
    public long Lookups { get; set; }

    /// <summary>Gets or sets the lifetime number of lookups that matched a rule.</summary>
    [JsonPropertyName("hits")]
    public long Hits { get; set; }

    /// <summary>Gets or sets the lifetime number of lookups that matched no rule.</summary>
    [JsonPropertyName("misses")]
    public long Misses { get; set; }
}

/// <summary>Gossip-layer message counters.</summary>
public sealed class GossipStats
{
    /// <summary>Gets or sets the number of gossip messages sent.</summary>
    [JsonPropertyName("messages_sent")]
    public long MessagesSent { get; set; }

    /// <summary>Gets or sets the number of gossip messages received.</summary>
    [JsonPropertyName("messages_received")]
    public long MessagesReceived { get; set; }

    /// <summary>Gets or sets the number of SWIM-style pings sent.</summary>
    [JsonPropertyName("ping_sent")]
    public long PingSent { get; set; }

    /// <summary>Gets or sets the number of SWIM-style pings received.</summary>
    [JsonPropertyName("ping_received")]
    public long PingReceived { get; set; }
}

/// <summary>Raft consensus state.</summary>
public sealed class RaftStats
{
    /// <summary>Gets or sets the Raft role state, for example <c>Follower</c> or <c>Leader</c>.</summary>
    [JsonPropertyName("state")]
    public string State { get; set; } = string.Empty;

    /// <summary>Gets or sets the current Raft term.</summary>
    [JsonPropertyName("term")]
    public long Term { get; set; }

    /// <summary>Gets or sets the index of the last committed log entry.</summary>
    [JsonPropertyName("commit_index")]
    public long CommitIndex { get; set; }

    /// <summary>Gets or sets the index of the last applied log entry.</summary>
    [JsonPropertyName("applied_index")]
    public long AppliedIndex { get; set; }

    /// <summary>Gets or sets a value indicating whether this node is the Raft leader.</summary>
    [JsonPropertyName("is_leader")]
    public bool IsLeader { get; set; }

    /// <summary>Gets or sets the identifier of the current leader.</summary>
    [JsonPropertyName("leader_id")]
    public string LeaderId { get; set; } = string.Empty;
}

/// <summary>Cluster-wide request and cache metrics.</summary>
public sealed class ClusterMetrics
{
    /// <summary>Gets or sets the lifetime query count.</summary>
    [JsonPropertyName("queries_total")]
    public long QueriesTotal { get; set; }

    /// <summary>Gets or sets the current query rate per second.</summary>
    [JsonPropertyName("queries_per_sec")]
    public double QueriesPerSec { get; set; }

    /// <summary>Gets or sets the lifetime cache hit count.</summary>
    [JsonPropertyName("cache_hits")]
    public long CacheHits { get; set; }

    /// <summary>Gets or sets the lifetime cache miss count.</summary>
    [JsonPropertyName("cache_misses")]
    public long CacheMisses { get; set; }

    /// <summary>Gets or sets the cache hit ratio.</summary>
    [JsonPropertyName("cache_hit_rate")]
    public double CacheHitRate { get; set; }

    /// <summary>Gets or sets the average query latency in milliseconds.</summary>
    [JsonPropertyName("latency_avg_ms")]
    public double LatencyAvgMs { get; set; }

    /// <summary>Gets or sets the 99th percentile query latency in milliseconds.</summary>
    [JsonPropertyName("latency_p99_ms")]
    public double LatencyP99Ms { get; set; }
}

/// <summary>Result of <c>GET /api/v1/cluster/status</c>.</summary>
public sealed class ClusterStatus
{
    /// <summary>Gets or sets this node's identifier.</summary>
    [JsonPropertyName("node_id")]
    public string NodeId { get; set; } = string.Empty;

    /// <summary>Gets or sets the consensus backend in use, for example <c>raft</c>.</summary>
    [JsonPropertyName("consensus")]
    public string Consensus { get; set; } = string.Empty;

    /// <summary>Gets or sets the number of nodes in the cluster.</summary>
    [JsonPropertyName("node_count")]
    public long NodeCount { get; set; }

    /// <summary>Gets or sets the number of nodes currently alive.</summary>
    [JsonPropertyName("alive_count")]
    public long AliveCount { get; set; }

    /// <summary>Gets or sets a value indicating whether the cluster is healthy.</summary>
    [JsonPropertyName("healthy")]
    public bool Healthy { get; set; }

    /// <summary>Gets or sets the gossip-layer counters.</summary>
    [JsonPropertyName("gossip")]
    public GossipStats? Gossip { get; set; }

    /// <summary>Gets or sets the Raft consensus state.</summary>
    [JsonPropertyName("raft")]
    public RaftStats? Raft { get; set; }

    /// <summary>Gets or sets the cluster-wide request and cache metrics.</summary>
    [JsonPropertyName("metrics")]
    public ClusterMetrics? Metrics { get; set; }
}

/// <summary>One node as seen by the cluster.</summary>
public sealed class ClusterNode
{
    /// <summary>Gets or sets the node identifier.</summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    /// <summary>Gets or sets the gossip address.</summary>
    [JsonPropertyName("addr")]
    public string Addr { get; set; } = string.Empty;

    /// <summary>Gets or sets the gossip port.</summary>
    [JsonPropertyName("port")]
    public int Port { get; set; }

    /// <summary>Gets or sets the membership state, for example <c>alive</c> or <c>suspect</c>.</summary>
    [JsonPropertyName("state")]
    public string State { get; set; } = string.Empty;

    /// <summary>Gets or sets the node's cluster role.</summary>
    [JsonPropertyName("role")]
    public string Role { get; set; } = string.Empty;

    /// <summary>Gets or sets the node's region label.</summary>
    [JsonPropertyName("region")]
    public string Region { get; set; } = string.Empty;

    /// <summary>Gets or sets the node's zone label.</summary>
    [JsonPropertyName("zone")]
    public string Zone { get; set; } = string.Empty;

    /// <summary>Gets or sets the node's load-balancing weight.</summary>
    [JsonPropertyName("weight")]
    public long Weight { get; set; }

    /// <summary>Gets or sets the node's HTTP management address.</summary>
    [JsonPropertyName("http_addr")]
    public string HttpAddr { get; set; } = string.Empty;

    /// <summary>Gets or sets the node's protocol version.</summary>
    [JsonPropertyName("version")]
    public long Version { get; set; }

    /// <summary>Gets or sets the node's health score.</summary>
    [JsonPropertyName("health_score")]
    public long HealthScore { get; set; }

    /// <summary>Gets or sets the node's current query rate per second.</summary>
    [JsonPropertyName("queries_per_second")]
    public double QueriesPerSecond { get; set; }

    /// <summary>Gets or sets the node's query latency in milliseconds.</summary>
    [JsonPropertyName("latency_ms")]
    public double LatencyMs { get; set; }

    /// <summary>Gets or sets the node's CPU utilisation percentage.</summary>
    [JsonPropertyName("cpu_percent")]
    public double CpuPercent { get; set; }

    /// <summary>Gets or sets the node's memory utilisation percentage.</summary>
    [JsonPropertyName("memory_percent")]
    public double MemoryPercent { get; set; }

    /// <summary>Gets or sets the node's number of active client connections.</summary>
    [JsonPropertyName("active_connections")]
    public long ActiveConnections { get; set; }
}

/// <summary>Result of <c>GET /api/dashboard/stats</c>.</summary>
public sealed class DashboardStats
{
    /// <summary>Gets or sets the server uptime in seconds.</summary>
    [JsonPropertyName("uptime")]
    public long Uptime { get; set; }

    /// <summary>Gets or sets the lifetime query count.</summary>
    [JsonPropertyName("queriesTotal")]
    public long QueriesTotal { get; set; }

    /// <summary>Gets or sets the current query rate per second.</summary>
    [JsonPropertyName("queriesPerSec")]
    public double QueriesPerSec { get; set; }

    /// <summary>Gets or sets the cache hit ratio.</summary>
    [JsonPropertyName("cacheHitRate")]
    public double CacheHitRate { get; set; }

    /// <summary>Gets or sets the lifetime count of blocked queries.</summary>
    [JsonPropertyName("blockedQueries")]
    public long BlockedQueries { get; set; }

    /// <summary>Gets or sets the number of currently active clients.</summary>
    [JsonPropertyName("activeClients")]
    public long ActiveClients { get; set; }

    /// <summary>Gets or sets the number of loaded zones.</summary>
    [JsonPropertyName("zoneCount")]
    public long ZoneCount { get; set; }

    /// <summary>Gets or sets the measured upstream latency in milliseconds.</summary>
    [JsonPropertyName("upstreamLatency")]
    public long UpstreamLatency { get; set; }
}

/// <summary>
/// One live query event from <c>GET /api/dashboard/queries</c>. This shape is
/// camelCase on the wire.
/// </summary>
public sealed class QueryEvent
{
    /// <summary>Gets or sets when the query was received.</summary>
    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = string.Empty;

    /// <summary>Gets or sets the client IP address.</summary>
    [JsonPropertyName("clientIp")]
    public string ClientIp { get; set; } = string.Empty;

    /// <summary>Gets or sets the client country code, when GeoIP data is available.</summary>
    [JsonPropertyName("countryCode")]
    public string CountryCode { get; set; } = string.Empty;

    /// <summary>Gets or sets the queried domain.</summary>
    [JsonPropertyName("domain")]
    public string Domain { get; set; } = string.Empty;

    /// <summary>Gets or sets the query type, for example <c>A</c> or <c>AAAA</c>.</summary>
    [JsonPropertyName("queryType")]
    public string QueryType { get; set; } = string.Empty;

    /// <summary>Gets or sets the response code, for example <c>NOERROR</c> or <c>NXDOMAIN</c>.</summary>
    [JsonPropertyName("responseCode")]
    public string ResponseCode { get; set; } = string.Empty;

    /// <summary>Gets or sets the answer section strings.</summary>
    [JsonPropertyName("answers")]
    public List<string> Answers { get; set; } = new();

    /// <summary>Gets or sets the handling time in milliseconds.</summary>
    [JsonPropertyName("duration")]
    public long Duration { get; set; }

    /// <summary>Gets or sets a value indicating whether the answer came from cache.</summary>
    [JsonPropertyName("cached")]
    public bool Cached { get; set; }

    /// <summary>Gets or sets a value indicating whether the query was blocked.</summary>
    [JsonPropertyName("blocked")]
    public bool Blocked { get; set; }

    /// <summary>Gets or sets the transport the query arrived on, for example <c>udp</c> or <c>dot</c>.</summary>
    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = string.Empty;
}

/// <summary>One row of the paginated query log. This shape is snake_case on the wire.</summary>
public sealed class QueryLogEntry
{
    /// <summary>Gets or sets when the query was received.</summary>
    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = string.Empty;

    /// <summary>Gets or sets the client IP address.</summary>
    [JsonPropertyName("client_ip")]
    public string ClientIp { get; set; } = string.Empty;

    /// <summary>Gets or sets the queried domain.</summary>
    [JsonPropertyName("domain")]
    public string Domain { get; set; } = string.Empty;

    /// <summary>Gets or sets the query type.</summary>
    [JsonPropertyName("query_type")]
    public string QueryType { get; set; } = string.Empty;

    /// <summary>Gets or sets the response code.</summary>
    [JsonPropertyName("response_code")]
    public string ResponseCode { get; set; } = string.Empty;

    /// <summary>Gets or sets the answer section strings.</summary>
    [JsonPropertyName("answers")]
    public List<string> Answers { get; set; } = new();

    /// <summary>Gets or sets the handling time in milliseconds.</summary>
    [JsonPropertyName("duration_ms")]
    public long DurationMs { get; set; }

    /// <summary>Gets or sets a value indicating whether the answer came from cache.</summary>
    [JsonPropertyName("cached")]
    public bool Cached { get; set; }

    /// <summary>Gets or sets a value indicating whether the query was blocked.</summary>
    [JsonPropertyName("blocked")]
    public bool Blocked { get; set; }

    /// <summary>Gets or sets the transport the query arrived on.</summary>
    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = string.Empty;
}

/// <summary>One page of the query log.</summary>
public sealed class QueryLogPage
{
    /// <summary>Gets or sets the rows in this page.</summary>
    [JsonPropertyName("queries")]
    public List<QueryLogEntry> Queries { get; set; } = new();

    /// <summary>Gets or sets the total number of matching rows.</summary>
    [JsonPropertyName("total")]
    public long Total { get; set; }

    /// <summary>Gets or sets the offset this page started at.</summary>
    [JsonPropertyName("offset")]
    public long Offset { get; set; }

    /// <summary>Gets or sets the page size the server applied.</summary>
    [JsonPropertyName("limit")]
    public long Limit { get; set; }
}

/// <summary>One entry of the most-queried domain list.</summary>
public sealed class TopDomain
{
    /// <summary>Gets or sets the domain name.</summary>
    [JsonPropertyName("domain")]
    public string Domain { get; set; } = string.Empty;

    /// <summary>Gets or sets how often the domain was queried.</summary>
    [JsonPropertyName("count")]
    public long Count { get; set; }
}

/// <summary>Result of <c>GET /api/v1/topdomains</c>.</summary>
public sealed class TopDomains
{
    /// <summary>Gets or sets the most-queried domains, most frequent first.</summary>
    [JsonPropertyName("domains")]
    public List<TopDomain> Domains { get; set; } = new();

    /// <summary>Gets or sets the limit the server applied.</summary>
    [JsonPropertyName("limit")]
    public long Limit { get; set; }
}

/// <summary>Ring buffer of recent metric samples.</summary>
public sealed class MetricsHistory
{
    /// <summary>Gets or sets the sample timestamps, as Unix seconds.</summary>
    [JsonPropertyName("timestamps")]
    public List<long> Timestamps { get; set; } = new();

    /// <summary>Gets or sets the per-sample query counts.</summary>
    [JsonPropertyName("queries")]
    public List<long> Queries { get; set; } = new();

    /// <summary>Gets or sets the per-sample cache hit counts.</summary>
    [JsonPropertyName("cache_hits")]
    public List<long> CacheHits { get; set; } = new();

    /// <summary>Gets or sets the per-sample cache miss counts.</summary>
    [JsonPropertyName("cache_misses")]
    public List<long> CacheMisses { get; set; } = new();

    /// <summary>Gets or sets the per-sample latency values in milliseconds.</summary>
    [JsonPropertyName("latency_ms")]
    public List<long> LatencyMs { get; set; } = new();

    /// <summary>Gets or sets the number of samples held in the buffer.</summary>
    [JsonPropertyName("count")]
    public long Count { get; set; }
}

#pragma warning restore CS1591
