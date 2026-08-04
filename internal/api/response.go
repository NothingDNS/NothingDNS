package api

import (
	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/dnssec"
)

// API response types — replaces map[string]interface{} usage per AGENT_DIRECTIVES §2.3.

// ErrorResponse is returned for all API errors.
type ErrorResponse struct {
	Error string `json:"error"`
}

// MessageResponse is returned for simple acknowledgement endpoints.
type MessageResponse struct {
	Message string `json:"message"`
}

// MessageNameResponse is returned for resource creation with a name.
type MessageNameResponse struct {
	Message string `json:"message"`
	Name    string `json:"name,omitempty"`
}

// HealthResponse is returned by GET /health.
type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

// DashboardStatsResponse is returned by GET /api/dashboard/stats.
type DashboardStatsResponse struct {
	Uptime          int     `json:"uptime"`
	QueriesTotal    uint64  `json:"queriesTotal"`
	QueriesPerSec   float64 `json:"queriesPerSec"`
	CacheHitRate    float64 `json:"cacheHitRate"`
	BlockedQueries  uint64  `json:"blockedQueries"`
	ActiveClients   int     `json:"activeClients"`
	ZoneCount       int     `json:"zoneCount"`
	UpstreamLatency int64   `json:"upstreamLatency"`
}

// CacheInfo is the cache sub-object in the status response.
type CacheInfo struct {
	Size     int     `json:"size"`
	Capacity int     `json:"capacity"`
	Hits     uint64  `json:"hits"`
	Misses   uint64  `json:"misses"`
	HitRatio float64 `json:"hit_ratio"`
}

// ClusterInfo is the cluster sub-object in the status response.
type ClusterInfo struct {
	Enabled    bool   `json:"enabled"`
	NodeID     string `json:"node_id,omitempty"`
	NodeCount  int    `json:"node_count,omitempty"`
	AliveCount int    `json:"alive_count,omitempty"`
	Healthy    bool   `json:"healthy,omitempty"`
}

// StatusResponse is returned by GET /api/v1/status.
type StatusResponse struct {
	Status    string      `json:"status"`
	Timestamp string      `json:"timestamp"`
	Version   string      `json:"version"`
	Cache     *CacheInfo  `json:"cache,omitempty"`
	Cluster   ClusterInfo `json:"cluster"`
}

// ZoneSummary represents a zone in the zone list.
type ZoneSummary struct {
	Name    string `json:"name"`
	Serial  uint32 `json:"serial"`
	Records int    `json:"records"`
}

// ZoneListResponse is returned by GET /api/v1/zones.
//
// Zones holds at most ZoneListMaxResults entries; Total is the
// unfiltered count, Truncated true when capped. L-N5 generalises
// the L-10 cap pattern to the sibling list endpoint.
type ZoneListResponse struct {
	Zones     []ZoneSummary `json:"zones"`
	Total     int           `json:"total"`
	Truncated bool          `json:"truncated,omitempty"`
}

// ZoneListMaxResults caps the zone list response. Same rationale as
// RecordListMaxResults.
const ZoneListMaxResults = 5000

// SOADetail represents SOA record details in a zone detail response.
type SOADetail struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

// ZoneDetailResponse is returned by GET /api/v1/zones/{name}.
type ZoneDetailResponse struct {
	Name        string     `json:"name"`
	Serial      uint32     `json:"serial,omitempty"`
	Records     int        `json:"records"`
	SOA         *SOADetail `json:"soa,omitempty"`
	Nameservers []string   `json:"nameservers"`
}

// RecordItem represents a DNS record in the records list.
type RecordItem struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Class string `json:"class"`
	Data  string `json:"data"`
}

// RecordListResponse is returned by GET /api/v1/zones/{name}/records.
//
// Records holds at most RecordListMaxResults entries; Total reflects
// the unfiltered count regardless of truncation, and Truncated is
// true when the response was capped. L-10 added the cap and the
// Total/Truncated companions; older clients ignore the new fields.
type RecordListResponse struct {
	Records   []RecordItem `json:"records"`
	Total     int          `json:"total"`
	Truncated bool         `json:"truncated,omitempty"`
}

// RecordListMaxResults caps the records-list endpoint so a request
// against a million-record reverse zone cannot allocate proportional
// JSON or freeze the operator's browser. Operator-gated, so this is
// defense-in-depth rather than a remote-DoS class.
const RecordListMaxResults = 5000

// CacheStatsResponse is returned by GET /api/v1/cache/stats.
type CacheStatsResponse struct {
	Size     int     `json:"size"`
	Capacity int     `json:"capacity"`
	Hits     uint64  `json:"hits"`
	Misses   uint64  `json:"misses"`
	HitRatio float64 `json:"hit_ratio"`
}

// GossipInfo is the gossip sub-object in the cluster status response.
type GossipInfo struct {
	MessagesSent     uint64 `json:"messages_sent"`
	MessagesReceived uint64 `json:"messages_received"`
	PingSent         uint64 `json:"ping_sent"`
	PingReceived     uint64 `json:"ping_received"`
}

// RaftInfo is the Raft-consensus sub-object in the cluster status response.
// Present only when the cluster runs in Raft mode.
type RaftInfo struct {
	State        string `json:"state"`         // Leader | Follower | Candidate
	Term         int64  `json:"term"`          // current Raft term
	CommitIndex  int64  `json:"commit_index"`  // highest committed log index
	AppliedIndex int64  `json:"applied_index"` // highest applied log index
	IsLeader     bool   `json:"is_leader"`     // whether this node is the leader
	LeaderID     string `json:"leader_id"`     // current leader, "" if unknown
}

// ClusterStatusResponse is returned by GET /api/v1/cluster/status.
type ClusterStatusResponse struct {
	NodeID     string     `json:"node_id"`
	Consensus  string     `json:"consensus"` // "raft" or "swim"
	NodeCount  int        `json:"node_count"`
	AliveCount int        `json:"alive_count"`
	Healthy    bool       `json:"healthy"`
	Gossip     GossipInfo `json:"gossip"`
	Raft       *RaftInfo  `json:"raft,omitempty"`
	// Aggregated cluster-wide metrics
	Metrics ClusterMetricsInfo `json:"metrics"`
}

// ClusterMetricsInfo holds aggregated cluster-wide operational metrics.
type ClusterMetricsInfo struct {
	QueriesTotal  uint64  `json:"queries_total"`   // Total queries across all nodes
	QueriesPerSec float64 `json:"queries_per_sec"` // Cluster-wide QPS
	CacheHits     uint64  `json:"cache_hits"`      // Total cache hits
	CacheMisses   uint64  `json:"cache_misses"`    // Total cache misses
	CacheHitRate  float64 `json:"cache_hit_rate"`  // Cache hit ratio (0-1)
	LatencyMsAvg  float64 `json:"latency_avg_ms"`  // Average latency across nodes
	LatencyMsP99  float64 `json:"latency_p99_ms"`  // P99 latency across nodes
}

// NodeDetail represents a cluster node in the nodes list.
type NodeDetail struct {
	ID       string `json:"id"`
	Addr     string `json:"addr"`
	Port     int    `json:"port"`
	State    string `json:"state"`
	Region   string `json:"region"`
	Zone     string `json:"zone"`
	Weight   int    `json:"weight"`
	HTTPAddr string `json:"http_addr"`
	Version  uint64 `json:"version"`
	// Health fields (0 values if unknown)
	HealthScore       int     `json:"health_score"`       // 0-100, higher is healthier
	QueriesPerSecond  float64 `json:"queries_per_second"` // Rolling average QPS
	LatencyMs         float64 `json:"latency_ms"`         // Rolling average latency
	CPUPercent        float64 `json:"cpu_percent"`        // Estimated CPU usage
	MemoryPercent     float64 `json:"memory_percent"`     // Estimated memory usage
	ActiveConnections int     `json:"active_connections"` // Current active connections
}

// ClusterNodesResponse is returned by GET /api/v1/cluster/nodes.
type ClusterNodesResponse struct {
	Nodes []NodeDetail `json:"nodes"`
}

// BlocklistResponse is returned by GET /api/v1/blocklists.
type BlocklistResponse struct {
	Enabled    bool `json:"enabled"`
	TotalRules int  `json:"total_rules"`
	FilesCount int  `json:"files_count"`
	URLsCount  int  `json:"urls_count"`
}

// BlocklistAddRequest is the request body for POST /api/v1/blocklists.
type BlocklistAddRequest struct {
	URL  string `json:"url,omitempty"`
	File string `json:"file,omitempty"`
}

// UpstreamStatus represents a single upstream server's status.
type UpstreamStatus struct {
	Address   string `json:"address"`
	Healthy   bool   `json:"healthy"`
	Queries   uint64 `json:"queries"`
	Failed    uint64 `json:"failed"`
	Failovers uint64 `json:"failovers"`
}

// UpstreamsResponse is returned by GET /api/v1/upstreams.
type UpstreamsResponse struct {
	Upstreams []UpstreamStatus `json:"upstreams"`
}

// UpstreamUpdateRequest is used to add/remove upstream servers.
type UpstreamUpdateRequest struct {
	Action string `json:"action"` // "add" or "remove"
	Server string `json:"server"` // server address (host:port)
}

// ACLRuleResponse represents a single ACL rule.
type ACLRuleResponse struct {
	Name     string   `json:"name"`
	Networks []string `json:"networks"`
	Action   string   `json:"action"`
	Types    []string `json:"types,omitempty"`
}

// ACLResponse is returned by GET /api/v1/acl.
type ACLResponse struct {
	Rules []ACLRuleResponse `json:"rules"`
}

// LoginRequest is the request body for POST /api/v1/auth/login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is returned by POST /api/v1/auth/login.
type LoginResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Expires  string `json:"expires"`
}

// UserResponse represents a user in API responses.
type UserResponse struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Created  string `json:"created_at,omitempty"`
	Updated  string `json:"updated_at,omitempty"`
}

// BootstrapRequest is the request body for POST /api/v1/auth/bootstrap.
type BootstrapRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	OldPassword string `json:"old_password,omitempty"`
}

// BootstrapResponse is returned by POST /api/v1/auth/bootstrap.
type BootstrapResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// CreateUserRequest is the request body for POST /api/v1/auth/users.
type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// RoleResponse represents a role in the roles endpoint.
type RoleResponse struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// RolesResponse is returned by GET /api/v1/auth/roles.
type RolesResponse struct {
	Roles []RoleResponse `json:"roles"`
}

// QueryLogEntry represents a single query in the log.
type QueryLogEntry struct {
	Timestamp    string `json:"timestamp"`
	ClientIP     string `json:"client_ip"`
	Domain       string `json:"domain"`
	QueryType    string `json:"query_type"`
	ResponseCode string `json:"response_code"`
	Duration     int64  `json:"duration_ms"`
	Cached       bool   `json:"cached"`
	Blocked      bool   `json:"blocked"`
	Protocol     string `json:"protocol"`
}

// QueryLogResponse is returned by GET /api/v1/queries.
type QueryLogResponse struct {
	Queries []QueryLogEntry `json:"queries"`
	Total   int             `json:"total"`
	Offset  int             `json:"offset"`
	Limit   int             `json:"limit"`
}

// TopDomainsEntry represents a domain with its query count.
type TopDomainsEntry = dashboard.TopDomainsEntry

// DNSSECStatusResponse is returned by GET /api/v1/dnssec/status.
type DNSSECStatusResponse = dnssec.DNSSECStatus

// DNSSECKeyInfo describes a single DNSSEC signing key.
type DNSSECKeyInfo struct {
	KeyTag    uint16 `json:"keyTag"`
	Algorithm uint8  `json:"algorithm"`
	Flags     uint16 `json:"flags"`
	IsKSK     bool   `json:"isKSK"`
	IsZSK     bool   `json:"isZSK"`
	Zone      string `json:"zone"`
}

// DNSSECKeysResponse is returned by GET /api/v1/dnssec/keys.
type DNSSECKeysResponse struct {
	Zones []DNSSECKeyInfo `json:"zones"`
}

// TopDomainsResponse is returned by GET /api/v1/topdomains.
type TopDomainsResponse struct {
	Domains []TopDomainsEntry `json:"domains"`
	Limit   int               `json:"limit"`
}

// RPZStatsResponse is returned by GET /api/v1/rpz.
type RPZStatsResponse struct {
	Enabled       bool   `json:"enabled"`
	TotalRules    int    `json:"total_rules"`
	QNAMERules    int    `json:"qname_rules"`
	ClientIPRules int    `json:"client_ip_rules"`
	RespIPRules   int    `json:"resp_ip_rules"`
	FilesCount    int    `json:"files_count"`
	TotalMatches  uint64 `json:"total_matches"`
	TotalLookups  uint64 `json:"total_lookups"`
	LastReload    string `json:"last_reload,omitempty"`
}

// RPZRuleResponse represents a single RPZ rule in API responses.
type RPZRuleResponse struct {
	Pattern      string `json:"pattern"`
	Action       string `json:"action"`
	Trigger      string `json:"trigger"`
	OverrideData string `json:"override_data,omitempty"`
	PolicyName   string `json:"policy_name"`
	Priority     int    `json:"priority"`
}

// RPZRulesResponse is returned by GET /api/v1/rpz/rules.
//
// Rules holds at most RPZRulesMaxResults entries; Total is the
// unfiltered count, Truncated true when capped. L-N5 generalises
// the L-10 cap pattern to the sibling list endpoint. Real-world
// malware feeds ship millions of rules; even an admin operator
// shouldn't accidentally fetch them all in one response.
type RPZRulesResponse struct {
	Rules     []RPZRuleResponse `json:"rules"`
	Total     int               `json:"total"`
	Truncated bool              `json:"truncated,omitempty"`
}

// RPZRulesMaxResults caps the rpz rules list response.
const RPZRulesMaxResults = 5000

// RPZAddRuleRequest is the request body for POST /api/v1/rpz/rules.
type RPZAddRuleRequest struct {
	Pattern      string `json:"pattern"`
	Action       string `json:"action"`
	OverrideData string `json:"override_data,omitempty"`
}

// ServerConfigResponse is returned by GET /api/v1/server/config.
type ServerConfigResponse struct {
	Version    string           `json:"version"`
	ListenPort int              `json:"listen_port"`
	LogLevel   string           `json:"log_level"`
	DNS64      DNS64ConfigInfo  `json:"dns64"`
	Cookie     CookieConfigInfo `json:"cookie"`
}

// DNS64ConfigInfo is the DNS64 sub-object in the server config response.
type DNS64ConfigInfo struct {
	Enabled     bool     `json:"enabled"`
	Prefix      string   `json:"prefix"`
	PrefixLen   int      `json:"prefix_len"`
	ExcludeNets []string `json:"exclude_nets,omitempty"`
}

// CookieConfigInfo is the DNS cookie sub-object in the server config response.
type CookieConfigInfo struct {
	Enabled        bool   `json:"enabled"`
	SecretRotation string `json:"secret_rotation,omitempty"`
}

// GeoDNSStatsResponse is returned by GET /api/v1/geoip/stats.
type GeoDNSStatsResponse struct {
	Enabled    bool   `json:"enabled"`
	Rules      int    `json:"rules"`
	MMDBLoaded bool   `json:"mmdb_loaded"`
	Lookups    uint64 `json:"lookups"`
	Hits       uint64 `json:"hits"`
	Misses     uint64 `json:"misses"`
}

// SlaveZoneResponse represents a slave zone in the transfer list.
type SlaveZoneResponse struct {
	Zone         string `json:"zone"`
	Masters      string `json:"masters"`
	Serial       uint32 `json:"serial"`
	LastTransfer string `json:"last_transfer,omitempty"`
	Status       string `json:"status"`
	Records      int    `json:"records"`
}

// SlaveZonesResponse is returned by GET /api/v1/zones/transfers.
type SlaveZonesResponse struct {
	SlaveZones []SlaveZoneResponse `json:"slave_zones"`
}

// ReverseDNSChange represents a single change in bulk PTR generation.
type ReverseDNSChange struct {
	IP        string `json:"ip"`
	PTRName   string `json:"ptrName"`
	AName     string `json:"aName,omitempty"`
	Action    string `json:"action"` // add, override, skip
	PTRExist  bool   `json:"ptrExist"`
	AExist    bool   `json:"aExist,omitempty"`
	OldPTR    string `json:"oldPtr,omitempty"`
	OldA      string `json:"oldA,omitempty"`
	RevRecord string `json:"revRecord"`
}

// ReverseDNSPreviewResponse is returned by bulk PTR preview.
type ReverseDNSPreviewResponse struct {
	Preview      bool               `json:"preview"`
	Total        int                `json:"total"`
	WillAdd      int                `json:"willAdd"`
	WillAddA     int                `json:"willAddA"`
	WillSkip     int                `json:"willSkip"`
	WillOverride int                `json:"willOverride"`
	Changes      []ReverseDNSChange `json:"changes"`
}

// BulkPTRResultResponse is returned after bulk PTR creation.
type BulkPTRResultResponse struct {
	Added   int `json:"added"`
	AddedA  int `json:"addedA"`
	Exists  int `json:"exists"`
	ExistsA int `json:"existsA"`
	Skipped int `json:"skipped"`
}

// PTRLookupResponse is returned by PTR lookup.
type PTRLookupResponse struct {
	IP      string `json:"ip"`
	PTR     string `json:"ptr"`
	PTRFQDN string `json:"ptrFQDN"`
	Target  string `json:"target,omitempty"`
	TTL     uint32 `json:"ttl,omitempty"`
	Found   bool   `json:"found"`
}

// CSPReportRequest is the payload POSTed by browsers when Content Security
// Policy is violated. Only the relevant fields are decoded; the full spec
// defines ~30 fields (see W3C CSP Level 2 §5).
type CSPReportRequest struct {
	DocumentURI       string `json:"document-uri"`
	Referrer          string `json:"referrer"`
	BlockedURI        string `json:"blocked-uri"`
	ViolatedDirective string `json:"violated-directive"`
	OriginalPolicy    string `json:"original-policy"`
	Disposition       string `json:"disposition"`
	ScriptSample      string `json:"script-sample"`
	StatusCode        int    `json:"status-code"`
	SourceFile        string `json:"source-file"`
	LineNumber        int    `json:"line-number"`
	ColumnNumber      int    `json:"column-number"`
}
