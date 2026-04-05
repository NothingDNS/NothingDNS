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
type ZoneListResponse struct {
	Zones []ZoneSummary `json:"zones"`
}

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
type RecordListResponse struct {
	Records []RecordItem `json:"records"`
}

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

// ClusterStatusResponse is returned by GET /api/v1/cluster/status.
type ClusterStatusResponse struct {
	NodeID     string     `json:"node_id"`
	NodeCount  int        `json:"node_count"`
	AliveCount int        `json:"alive_count"`
	Healthy    bool       `json:"healthy"`
	Gossip     GossipInfo `json:"gossip"`
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
}

// ClusterNodesResponse is returned by GET /api/v1/cluster/nodes.
type ClusterNodesResponse struct {
	Nodes []NodeDetail `json:"nodes"`
}

// BlocklistResponse is returned by GET /api/v1/blocklists.
type BlocklistResponse struct {
	Enabled     bool   `json:"enabled"`
	TotalRules  int    `json:"total_rules"`
	FilesCount  int    `json:"files_count"`
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
	Queries   uint64 `json:"queries,omitempty"`
	Failed    uint64 `json:"failed,omitempty"`
	Failovers uint64 `json:"failovers,omitempty"`
}

// UpstreamsResponse is returned by GET /api/v1/upstreams.
type UpstreamsResponse struct {
	Upstreams []UpstreamStatus `json:"upstreams"`
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

// TopDomainsResponse is returned by GET /api/v1/topdomains.
type TopDomainsResponse struct {
	Domains []TopDomainsEntry `json:"domains"`
	Limit   int              `json:"limit"`
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
type RPZRulesResponse struct {
	Rules []RPZRuleResponse `json:"rules"`
}

// RPZAddRuleRequest is the request body for POST /api/v1/rpz/rules.
type RPZAddRuleRequest struct {
	Pattern      string `json:"pattern"`
	Action       string `json:"action"`
	OverrideData string `json:"override_data,omitempty"`
}

// ServerConfigResponse is returned by GET /api/v1/server/config.
type ServerConfigResponse struct {
	Version    string `json:"version"`
	ListenPort int    `json:"listen_port"`
	LogLevel   string `json:"log_level"`
}
