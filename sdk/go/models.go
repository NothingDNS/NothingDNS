package nothingdns

// Typed models for the NothingDNS management API.
//
// Field names are intentionally identical to the server's JSON field names
// (snake_case, plus camelCase for the /api/dashboard and ptr6/ptr-bulk shapes)
// so that what you read in the API reference is exactly what you get on the
// model — there is no separate mapping layer to drift.
//
// Every model is a plain Go struct decoded with encoding/json, which tolerates
// both missing and unknown fields: a newer server never breaks an older
// client, and fields a given server version does not emit stay at their zero
// value. Optional request fields are pointers (or use `omitempty`) so that
// "leave unchanged" is distinguishable from "send zero".

// ---------------------------------------------------------------------------
// Health & status
// ---------------------------------------------------------------------------

// HealthResponse is the result of GET /health, /readyz or /livez.
type HealthResponse struct {
	// Status is "healthy", "ready", "alive" or "unhealthy".
	Status string `json:"status"`
	// Timestamp is the server's response time, RFC 3339.
	Timestamp string `json:"timestamp,omitempty"`
}

// CacheStats holds cache size, capacity, hit/miss counters and hit ratio. It
// is returned by Cache.Stats and embedded in StatusResponse.
type CacheStats struct {
	// Size is the number of entries currently cached.
	Size int `json:"size"`
	// Capacity is the maximum number of entries the cache holds.
	Capacity int `json:"capacity"`
	// Hits counts cache lookups served from the cache.
	Hits int `json:"hits"`
	// Misses counts cache lookups that had to go upstream.
	Misses int `json:"misses"`
	// HitRatio is hits/(hits+misses) as a fraction between 0 and 1.
	HitRatio float64 `json:"hit_ratio"`
}

// ClusterSummary is the cluster block embedded in StatusResponse.
type ClusterSummary struct {
	// Enabled reports whether clustering is configured on this node.
	Enabled bool `json:"enabled"`
	// NodeID is this node's cluster identity.
	NodeID string `json:"node_id"`
	// NodeCount is the number of known nodes.
	NodeCount int `json:"node_count"`
	// AliveCount is the number of currently alive nodes.
	AliveCount int `json:"alive_count"`
	// Healthy reports whether the cluster is considered healthy.
	Healthy bool `json:"healthy"`
}

// StatusResponse is the result of GET /api/v1/status.
type StatusResponse struct {
	// Status is the overall server status string.
	Status string `json:"status"`
	// Timestamp is the server's response time, RFC 3339.
	Timestamp string `json:"timestamp,omitempty"`
	// Version is the running server version.
	Version string `json:"version"`
	// Cache holds cache counters; present for operators and admins only.
	Cache *CacheStats `json:"cache,omitempty"`
	// Cluster holds the cluster summary when clustering is enabled.
	Cluster *ClusterSummary `json:"cluster,omitempty"`
}

// DNS64Config is the DNS64 block in the server configuration summary
// (RFC 6147).
type DNS64Config struct {
	// Enabled reports whether DNS64 synthesis is active.
	Enabled bool `json:"enabled"`
	// Prefix is the NAT64 well-known prefix, e.g. "64:ff9b::/96".
	Prefix string `json:"prefix"`
	// PrefixLen is the prefix length in bits.
	PrefixLen int `json:"prefix_len"`
	// ExcludeNets are IPv6 networks excluded from synthesis.
	ExcludeNets []string `json:"exclude_nets,omitempty"`
}

// CookieConfig is the DNS Cookies block in the server configuration summary
// (RFC 7873).
type CookieConfig struct {
	// Enabled reports whether DNS Cookies are active.
	Enabled bool `json:"enabled"`
	// SecretRotation is the configured cookie-secret rotation interval.
	SecretRotation string `json:"secret_rotation"`
}

// ServerConfig is the result of GET /api/v1/server/config.
type ServerConfig struct {
	// Version is the running server version.
	Version string `json:"version"`
	// ListenPort is the DNS listen port.
	ListenPort int `json:"listen_port"`
	// LogLevel is the current log level.
	LogLevel string `json:"log_level"`
	// DNS64 holds the DNS64 configuration when present.
	DNS64 *DNS64Config `json:"dns64,omitempty"`
	// Cookie holds the DNS Cookies configuration when present.
	Cookie *CookieConfig `json:"cookie,omitempty"`
}

// ---------------------------------------------------------------------------
// Authentication & users
// ---------------------------------------------------------------------------

// Session is a login/session result: the bearer token plus who it belongs to.
type Session struct {
	// Token is the bearer token to send with subsequent requests.
	Token string `json:"token"`
	// Username is the authenticated account.
	Username string `json:"username"`
	// Role is "admin", "operator" or "viewer".
	Role string `json:"role"`
	// Expires is the RFC 3339 expiry of the token; absent on bootstrap
	// responses.
	Expires string `json:"expires,omitempty"`
}

// User is a user account. Passwords are never returned by the API.
type User struct {
	// Username is the account name.
	Username string `json:"username"`
	// Role is "admin", "operator" or "viewer".
	Role string `json:"role"`
	// CreatedAt is when the account was created, RFC 3339.
	CreatedAt string `json:"created_at,omitempty"`
	// UpdatedAt is when the account was last modified, RFC 3339.
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Role describes one entry of the server's role table.
type Role struct {
	// Name is the role name.
	Name string `json:"name"`
	// Description is a human-readable summary of the role's powers.
	Description string `json:"description"`
}

// ---------------------------------------------------------------------------
// Zones
// ---------------------------------------------------------------------------

// SOA is a zone's start-of-authority record.
type SOA struct {
	// MName is the primary nameserver.
	MName string `json:"mname"`
	// RName is the zone administrator e-mail in DNS form.
	RName string `json:"rname"`
	// Serial is the zone serial number.
	Serial int `json:"serial"`
	// Refresh is the secondary refresh interval, in seconds.
	Refresh int `json:"refresh"`
	// Retry is the secondary retry interval, in seconds.
	Retry int `json:"retry"`
	// Expire is when a secondary should stop serving the zone, in seconds.
	Expire int `json:"expire"`
	// Minimum is the minimum TTL for negative answers, in seconds.
	Minimum int `json:"minimum"`
}

// Zone is a zone summary. It is also used for the dashboard zone list.
type Zone struct {
	// Name is the zone name.
	Name string `json:"name"`
	// Serial is the zone serial number.
	Serial int `json:"serial"`
	// Records is the number of records in the zone.
	Records int `json:"records"`
}

// ZoneList is the result of GET /api/v1/zones.
type ZoneList struct {
	// Zones are the zone summaries returned on this page.
	Zones []Zone `json:"zones"`
	// Total is the true number of zones; may exceed len(Zones) when
	// Truncated is true.
	Total int `json:"total"`
	// Truncated reports whether the server capped the list.
	Truncated bool `json:"truncated"`
}

// ZoneDetail is the result of GET /api/v1/zones/{zone}.
type ZoneDetail struct {
	// Name is the zone name.
	Name string `json:"name"`
	// Serial is the zone serial number.
	Serial int `json:"serial"`
	// Records is the number of records in the zone.
	Records int `json:"records"`
	// SOA is the zone's start-of-authority record.
	SOA *SOA `json:"soa,omitempty"`
	// NameServers is the zone's NS set.
	NameServers []string `json:"nameservers,omitempty"`
}

// Record is a single DNS resource record.
type Record struct {
	// Name is the owner name, relative to the zone.
	Name string `json:"name"`
	// Type is the record type, e.g. "A", "AAAA", "MX", "TXT".
	Type string `json:"type"`
	// TTL is the record's time to live, in seconds.
	TTL int `json:"ttl"`
	// Class is the DNS class, "IN" for internet.
	Class string `json:"class"`
	// Data is the record data in presentation format.
	Data string `json:"data"`
}

// RecordList is the result of GET /api/v1/zones/{zone}/records.
type RecordList struct {
	// Records are the records returned on this page.
	Records []Record `json:"records"`
	// Total is the true number of matching records; may exceed
	// len(Records) when Truncated is true.
	Total int `json:"total"`
	// Truncated reports whether the server capped the list.
	Truncated bool `json:"truncated"`
}

// SlaveZone describes a secondary (slave) zone and its transfer state.
type SlaveZone struct {
	// Zone is the secondary zone name.
	Zone string `json:"zone"`
	// Masters is the master server address list.
	Masters string `json:"masters"`
	// Serial is the last transferred serial.
	Serial int `json:"serial"`
	// LastTransfer is when the last transfer happened, RFC 3339.
	LastTransfer string `json:"last_transfer,omitempty"`
	// Status is "pending" or "synced".
	Status string `json:"status"`
	// Records is the number of records held for the zone.
	Records int `json:"records"`
}

// PTRChange is one record the bulk PTR generator would create.
type PTRChange struct {
	// Name is the owner name of the change.
	Name string `json:"name"`
	// Type is the record type, "PTR" or "A".
	Type string `json:"type"`
	// TTL is the record TTL, in seconds.
	TTL int `json:"ttl"`
	// Data is the record data.
	Data string `json:"data"`
	// Action is what the generator would do: "add", "skip" or "override".
	Action string `json:"action"`
}

// PTRBulkResponse is the result of Zones.PTRBulk. The fields present depend
// on the preview flag: a preview populates Preview, Total, the Will* counters
// and Changes, while an applied run populates the Added/Exists/Skipped
// counters. Both shapes decode into this one type.
type PTRBulkResponse struct {
	// Preview reports whether this is a dry run.
	Preview bool `json:"preview,omitempty"`
	// Total is the number of addresses covered by the range.
	Total int `json:"total"`
	// WillAdd counts PTR records that would be added.
	WillAdd int `json:"willAdd"`
	// WillAddA counts A records that would be added.
	WillAddA int `json:"willAddA"`
	// WillSkip counts records that would be skipped.
	WillSkip int `json:"willSkip"`
	// WillOverride counts records that would be replaced.
	WillOverride int `json:"willOverride"`
	// Changes lists the planned changes (preview only).
	Changes []PTRChange `json:"changes,omitempty"`
	// Added counts PTR records actually written.
	Added int `json:"added"`
	// AddedA counts A records actually written.
	AddedA int `json:"addedA"`
	// Exists counts PTR records that already existed.
	Exists int `json:"exists"`
	// ExistsA counts A records that already existed.
	ExistsA int `json:"existsA"`
	// Skipped counts records left untouched.
	Skipped int `json:"skipped"`
}

// PTRLookup is the result of Zones.PTR6Lookup.
type PTRLookup struct {
	// IP is the IPv6 address that was looked up.
	IP string `json:"ip"`
	// PTR is the PTR record's owner name.
	PTR string `json:"ptr"`
	// PTRFQDN is the fully-qualified PTR target.
	PTRFQDN string `json:"ptrFQDN"`
	// Target is the hostname the PTR points at.
	Target string `json:"target"`
	// TTL is the PTR record TTL, in seconds.
	TTL int `json:"ttl"`
	// Found reports whether a PTR record exists for the address.
	Found bool `json:"found"`
}

// ---------------------------------------------------------------------------
// ACL
// ---------------------------------------------------------------------------

// ACLRule is one access-control rule. It doubles as the request shape for
// ACL.Set: Name, Networks and Action are required; Types and Redirect are
// optional.
type ACLRule struct {
	// Name is the rule name shown in the dashboard.
	Name string `json:"name"`
	// Networks is the list of client networks the rule matches, in CIDR or
	// single-address form.
	Networks []string `json:"networks"`
	// Action is "allow", "deny" or "redirect".
	Action string `json:"action"`
	// Types optionally limits the rule to specific query types; empty means
	// all types.
	Types []string `json:"types,omitempty"`
	// Redirect is the redirect target for Action "redirect".
	Redirect string `json:"redirect,omitempty"`
}

// RecursionAllowList is the set of clients permitted to use recursive
// resolution.
type RecursionAllowList struct {
	// AllowAll permits recursion for every client.
	AllowAll bool `json:"allow_all"`
	// Networks is the explicit list of allowed client networks.
	Networks []string `json:"networks"`
}

// ACLConfig is the result of GET /api/v1/acl: the rules plus the recursion
// allow list.
type ACLConfig struct {
	// Rules are the ACL rules in evaluation order.
	Rules []ACLRule `json:"rules"`
	// AllowRecursion is the recursion allow list when present.
	AllowRecursion *RecursionAllowList `json:"allow_recursion,omitempty"`
	// Persistent reports whether the list is served from
	// access_policy.json (dashboard-managed) rather than the config file.
	Persistent bool `json:"persistent"`
	// PolicyFile is the path of the policy file when Persistent is true.
	PolicyFile string `json:"policy_file"`
}

// ---------------------------------------------------------------------------
// Blocklists
// ---------------------------------------------------------------------------

// BlocklistStats is the result of GET /api/v1/blocklists.
type BlocklistStats struct {
	// Enabled reports whether blocklist filtering is active.
	Enabled bool `json:"enabled"`
	// TotalRules is the total number of loaded blocklist rules.
	TotalRules int `json:"total_rules"`
	// FilesCount is the number of file-based sources.
	FilesCount int `json:"files_count"`
	// URLsCount is the number of URL-based sources.
	URLsCount int `json:"urls_count"`
}

// BlocklistSource is one configured blocklist source.
type BlocklistSource struct {
	// ID is the source identifier used to remove or toggle it.
	ID string `json:"id"`
	// Type is "file" or "url".
	Type string `json:"type"`
	// Enabled reports whether the source is active.
	Enabled bool `json:"enabled"`
	// Domains is the number of domains the source contributes.
	Domains int `json:"domains"`
}

// ---------------------------------------------------------------------------
// RPZ
// ---------------------------------------------------------------------------

// RPZStats is the result of GET /api/v1/rpz.
type RPZStats struct {
	// Enabled reports whether RPZ filtering is active.
	Enabled bool `json:"enabled"`
	// TotalRules is the number of loaded rules.
	TotalRules int `json:"total_rules"`
	// QNAMERules is the number of QNAME rules.
	QNAMERules int `json:"qname_rules"`
	// ClientIPRules is the number of client-IP rules.
	ClientIPRules int `json:"client_ip_rules"`
	// RespIPRules is the number of response-IP rules.
	RespIPRules int `json:"resp_ip_rules"`
	// FilesCount is the number of RPZ files loaded.
	FilesCount int `json:"files_count"`
	// TotalMatches counts queries that matched a rule.
	TotalMatches int `json:"total_matches"`
	// TotalLookups counts RPZ lookups.
	TotalLookups int `json:"total_lookups"`
	// LastReload is when the rules were last reloaded, RFC 3339.
	LastReload string `json:"last_reload,omitempty"`
}

// RPZRule is one QNAME policy rule.
type RPZRule struct {
	// Pattern is the domain pattern the rule matches.
	Pattern string `json:"pattern"`
	// Action is the policy action, e.g. "NXDOMAIN" or "DROP".
	Action string `json:"action"`
	// Trigger is the record type that triggered the match.
	Trigger string `json:"trigger"`
	// OverrideData is the replacement answer, when the action uses one.
	OverrideData string `json:"override_data"`
	// PolicyName is the originating policy zone.
	PolicyName string `json:"policy_name"`
	// Priority is the rule's evaluation priority.
	Priority int `json:"priority"`
}

// RPZRuleList is the result of GET /api/v1/rpz/rules.
type RPZRuleList struct {
	// Rules are the QNAME rules returned on this page.
	Rules []RPZRule `json:"rules"`
	// Total is the true number of rules; may exceed len(Rules) when
	// Truncated is true.
	Total int `json:"total"`
	// Truncated reports whether the server capped the list.
	Truncated bool `json:"truncated"`
}

// ---------------------------------------------------------------------------
// DNSSEC
// ---------------------------------------------------------------------------

// DNSSECStatus is the result of GET /api/v1/dnssec/status.
type DNSSECStatus struct {
	// Enabled reports whether DNSSEC validation runs at all.
	Enabled bool `json:"enabled"`
	// RequireDNSSEC reports whether bogus answers are refused rather than
	// served.
	RequireDNSSEC bool `json:"require_dnssec"`
}

// DNSSECKey is the public metadata of one DNSSEC signing key. Private key
// material is never exposed by the API.
type DNSSECKey struct {
	// KeyTag is the DNSSEC key tag.
	KeyTag int `json:"keyTag"`
	// Algorithm is the DNSSEC algorithm number.
	Algorithm int `json:"algorithm"`
	// Flags is the DNSKEY flags field.
	Flags int `json:"flags"`
	// IsKSK reports whether this is a key-signing key.
	IsKSK bool `json:"isKSK"`
	// IsZSK reports whether this is a zone-signing key.
	IsZSK bool `json:"isZSK"`
	// Zone is the zone the key signs.
	Zone string `json:"zone"`
}

// DNSSECKeyList is the result of GET /api/v1/dnssec/keys.
type DNSSECKeyList struct {
	// Zones are the signing keys, grouped by zone.
	Zones []DNSSECKey `json:"zones"`
}

// ---------------------------------------------------------------------------
// Upstreams & GeoDNS
// ---------------------------------------------------------------------------

// UpstreamHealth holds per-upstream counters inside the upstream pool.
type UpstreamHealth struct {
	// Address is the upstream "host:port".
	Address string `json:"address"`
	// Healthy reports the upstream's current health.
	Healthy bool `json:"healthy"`
	// Queries counts queries sent to this upstream.
	Queries int `json:"queries"`
	// Failed counts failed queries to this upstream.
	Failed int `json:"failed"`
	// Failovers counts failovers away from this upstream.
	Failovers int `json:"failovers"`
}

// UpstreamServer is one configured upstream server with its health.
type UpstreamServer struct {
	// Address is the server "host:port".
	Address string `json:"address"`
	// Healthy reports the server's current health.
	Healthy bool `json:"healthy"`
	// LatencyMS is the measured latency in milliseconds.
	LatencyMS float64 `json:"latency_ms"`
}

// Upstreams is the result of GET /api/v1/upstreams: pool counters and server
// health.
type Upstreams struct {
	// Upstreams are the pool-wide per-upstream counters.
	Upstreams []UpstreamHealth `json:"upstreams"`
	// Servers are the configured servers with latency and health.
	Servers []UpstreamServer `json:"servers"`
}

// GeoIPStats is the result of GET /api/v1/geoip/stats.
type GeoIPStats struct {
	// Enabled reports whether GeoDNS is active.
	Enabled bool `json:"enabled"`
	// Rules is the number of loaded GeoDNS rules.
	Rules int `json:"rules"`
	// MMDBLoaded reports whether a MaxMind database is loaded.
	MMDBLoaded bool `json:"mmdb_loaded"`
	// Lookups counts GeoDNS lookups.
	Lookups int `json:"lookups"`
	// Hits counts lookups that matched a rule.
	Hits int `json:"hits"`
	// Misses counts lookups that matched no rule.
	Misses int `json:"misses"`
}

// ---------------------------------------------------------------------------
// Cluster
// ---------------------------------------------------------------------------

// GossipStats holds gossip-layer message counters.
type GossipStats struct {
	// MessagesSent counts gossip messages sent.
	MessagesSent int `json:"messages_sent"`
	// MessagesReceived counts gossip messages received.
	MessagesReceived int `json:"messages_received"`
	// PingSent counts SWIM pings sent.
	PingSent int `json:"ping_sent"`
	// PingReceived counts SWIM pings received.
	PingReceived int `json:"ping_received"`
}

// RaftStats holds Raft consensus state.
type RaftStats struct {
	// State is the Raft state, e.g. "Leader" or "Follower".
	State string `json:"state"`
	// Term is the current Raft term.
	Term int `json:"term"`
	// CommitIndex is the highest committed log index.
	CommitIndex int `json:"commit_index"`
	// AppliedIndex is the highest applied log index.
	AppliedIndex int `json:"applied_index"`
	// IsLeader reports whether this node is the Raft leader.
	IsLeader bool `json:"is_leader"`
	// LeaderID is the current leader's node id.
	LeaderID string `json:"leader_id"`
}

// ClusterMetrics holds the query/latency metrics reported in cluster status.
type ClusterMetrics struct {
	// QueriesTotal is the total query count.
	QueriesTotal int `json:"queries_total"`
	// QueriesPerSec is the current query rate.
	QueriesPerSec float64 `json:"queries_per_sec"`
	// CacheHits counts cache hits.
	CacheHits int `json:"cache_hits"`
	// CacheMisses counts cache misses.
	CacheMisses int `json:"cache_misses"`
	// CacheHitRate is the cache hit fraction, 0..1.
	CacheHitRate float64 `json:"cache_hit_rate"`
	// LatencyAvgMS is the average query latency in milliseconds.
	LatencyAvgMS float64 `json:"latency_avg_ms"`
	// LatencyP99MS is the 99th-percentile query latency in milliseconds.
	LatencyP99MS float64 `json:"latency_p99_ms"`
}

// ClusterStatus is the result of GET /api/v1/cluster/status.
type ClusterStatus struct {
	// NodeID is this node's cluster identity.
	NodeID string `json:"node_id"`
	// Consensus is the consensus backend in use, e.g. "raft".
	Consensus string `json:"consensus"`
	// NodeCount is the number of known nodes.
	NodeCount int `json:"node_count"`
	// AliveCount is the number of currently alive nodes.
	AliveCount int `json:"alive_count"`
	// Healthy reports whether the cluster is considered healthy.
	Healthy bool `json:"healthy"`
	// Gossip holds gossip-layer counters when present.
	Gossip *GossipStats `json:"gossip,omitempty"`
	// Raft holds Raft state when present.
	Raft *RaftStats `json:"raft,omitempty"`
	// Metrics holds query/latency metrics when present.
	Metrics *ClusterMetrics `json:"metrics,omitempty"`
}

// ClusterNode is one node known to the gossip layer.
type ClusterNode struct {
	// ID is the node's cluster identity.
	ID string `json:"id"`
	// Addr is the node's gossip address.
	Addr string `json:"addr"`
	// Port is the node's gossip port.
	Port int `json:"port"`
	// State is the node's liveness state.
	State string `json:"state"`
	// Role is the node's role.
	Role string `json:"role"`
	// Region is the node's region label.
	Region string `json:"region"`
	// Zone is the node's zone label.
	Zone string `json:"zone"`
	// Weight is the node's load-balancing weight.
	Weight int `json:"weight"`
	// HTTPAddr is the node's management HTTP address.
	HTTPAddr string `json:"http_addr"`
	// Version is the node's software version number.
	Version int `json:"version"`
	// HealthScore is the node's health score.
	HealthScore int `json:"health_score"`
	// QueriesPerSecond is the node's current query rate.
	QueriesPerSecond float64 `json:"queries_per_second"`
	// LatencyMS is the node's average latency in milliseconds.
	LatencyMS float64 `json:"latency_ms"`
	// CPUPercent is the node's CPU utilisation.
	CPUPercent float64 `json:"cpu_percent"`
	// MemoryPercent is the node's memory utilisation.
	MemoryPercent float64 `json:"memory_percent"`
	// ActiveConnections is the node's current connection count.
	ActiveConnections int `json:"active_connections"`
}

// ---------------------------------------------------------------------------
// Dashboard & metrics
// ---------------------------------------------------------------------------

// DashboardStats is the result of GET /api/dashboard/stats. Note that this
// endpoint uses camelCase field names on the wire.
type DashboardStats struct {
	// Uptime is the server uptime in seconds.
	Uptime int `json:"uptime"`
	// QueriesTotal is the total query count.
	QueriesTotal int `json:"queriesTotal"`
	// QueriesPerSec is the current query rate.
	QueriesPerSec float64 `json:"queriesPerSec"`
	// CacheHitRate is the cache hit fraction, 0..1.
	CacheHitRate float64 `json:"cacheHitRate"`
	// BlockedQueries counts queries blocked by filtering.
	BlockedQueries int `json:"blockedQueries"`
	// ActiveClients is the number of distinct recent clients.
	ActiveClients int `json:"activeClients"`
	// ZoneCount is the number of hosted zones.
	ZoneCount int `json:"zoneCount"`
	// UpstreamLatency is the average upstream latency in milliseconds.
	UpstreamLatency int `json:"upstreamLatency"`
}

// QueryEvent is one live query event from GET /api/dashboard/queries. This
// endpoint uses camelCase field names on the wire, unlike the rest of the API.
type QueryEvent struct {
	// Timestamp is when the query was served, RFC 3339.
	Timestamp string `json:"timestamp"`
	// ClientIP is the querying client's address.
	ClientIP string `json:"clientIp"`
	// CountryCode is the client's GeoIP country code.
	CountryCode string `json:"countryCode"`
	// Domain is the queried name.
	Domain string `json:"domain"`
	// QueryType is the DNS query type.
	QueryType string `json:"queryType"`
	// ResponseCode is the DNS response code.
	ResponseCode string `json:"responseCode"`
	// Answers are the answer records returned.
	Answers []string `json:"answers,omitempty"`
	// Duration is the handling time in milliseconds.
	Duration int `json:"duration"`
	// Cached reports whether the answer came from the cache.
	Cached bool `json:"cached"`
	// Blocked reports whether the query was blocked.
	Blocked bool `json:"blocked"`
	// Protocol is the transport the query arrived on, e.g. "udp".
	Protocol string `json:"protocol"`
}

// QueryLogEntry is one row of the paginated query log (GET /api/v1/queries).
type QueryLogEntry struct {
	// Timestamp is when the query was served, RFC 3339.
	Timestamp string `json:"timestamp"`
	// ClientIP is the querying client's address.
	ClientIP string `json:"client_ip"`
	// Domain is the queried name.
	Domain string `json:"domain"`
	// QueryType is the DNS query type.
	QueryType string `json:"query_type"`
	// ResponseCode is the DNS response code.
	ResponseCode string `json:"response_code"`
	// Answers are the answer records returned.
	Answers []string `json:"answers,omitempty"`
	// DurationMS is the handling time in milliseconds.
	DurationMS int `json:"duration_ms"`
	// Cached reports whether the answer came from the cache.
	Cached bool `json:"cached"`
	// Blocked reports whether the query was blocked.
	Blocked bool `json:"blocked"`
	// Protocol is the transport the query arrived on.
	Protocol string `json:"protocol"`
}

// QueryLogPage is one page of the query log.
type QueryLogPage struct {
	// Queries are the log rows on this page.
	Queries []QueryLogEntry `json:"queries"`
	// Total is the total number of matching rows.
	Total int `json:"total"`
	// Offset is the index of the first row on this page.
	Offset int `json:"offset"`
	// Limit is the page size that was applied.
	Limit int `json:"limit"`
}

// TopDomain is one entry of the most-queried-domains list.
type TopDomain struct {
	// Domain is the queried name.
	Domain string `json:"domain"`
	// Count is how many times it was queried.
	Count int `json:"count"`
}

// TopDomains is the result of GET /api/v1/topdomains.
type TopDomains struct {
	// Domains are the most-queried domains, most frequent first.
	Domains []TopDomain `json:"domains"`
	// Limit is the page size that was applied.
	Limit int `json:"limit"`
}

// MetricsHistory is the ring buffer of recent metric samples returned by
// GET /api/v1/metrics/history. The series are parallel arrays: Queries[i] was
// recorded at Timestamps[i].
type MetricsHistory struct {
	// Timestamps are the sample times, Unix seconds.
	Timestamps []int64 `json:"timestamps"`
	// Queries are per-sample query counts.
	Queries []int64 `json:"queries"`
	// CacheHits are per-sample cache-hit counts.
	CacheHits []int64 `json:"cache_hits"`
	// CacheMisses are per-sample cache-miss counts.
	CacheMisses []int64 `json:"cache_misses"`
	// LatencyMS are per-sample latencies in milliseconds.
	LatencyMS []int64 `json:"latency_ms"`
	// Count is the number of samples held.
	Count int `json:"count"`
}
