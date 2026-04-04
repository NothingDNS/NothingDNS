package api

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
	Status    string     `json:"status"`
	Timestamp string     `json:"timestamp"`
	Version   string     `json:"version"`
	Cache     *CacheInfo   `json:"cache,omitempty"`
	Cluster   ClusterInfo  `json:"cluster"`
}

// ZoneSummary represents a zone in the zone list.
type ZoneSummary struct {
	Name    string  `json:"name"`
	Serial  uint32  `json:"serial"`
	Records int     `json:"records"`
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
