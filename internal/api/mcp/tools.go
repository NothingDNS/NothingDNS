package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DNSToolsHandler implements the Handler interface for DNS operations
type DNSToolsHandler struct {
	zoneManager   ZoneManager
	cache         CacheManager
	dnsResolver   DNSResolver
	blocklist     BlocklistManager
	statsProvider StatsProvider
}

// ZoneManager interface for zone operations
type ZoneManager interface {
	ListZones() ([]ZoneInfo, error)
	GetZone(name string) (*ZoneInfo, error)
	CreateZone(name string, opts ZoneOptions) error
	DeleteZone(name string) error
	AddRecord(zone, name, rtype, value string, ttl int) error
	DeleteRecord(zone, name, rtype string) error
	GetRecords(zone, name string) ([]RecordInfo, error)
	ImportZone(name string, data []byte) error
	ExportZone(name string) ([]byte, error)
}

// CacheManager interface for cache operations
type CacheManager interface {
	GetStats() CacheStats
	Flush() error
}

// DNSResolver interface for DNS resolution
type DNSResolver interface {
	Query(name, qtype string) (*QueryResult, error)
}

// BlocklistManager interface for blocklist operations
type BlocklistManager interface {
	IsBlocked(domain string) bool
	Lists() []string
}

// StatsProvider interface for statistics
type StatsProvider interface {
	GetStats() ServerStats
}

// ZoneInfo represents zone information
type ZoneInfo struct {
	Name        string   `json:"name"`
	Serial      uint32   `json:"serial"`
	RecordCount int      `json:"recordCount"`
	ZSK         bool     `json:"zsk"`
	KSK         bool     `json:"ksk"`
	Nameservers []string `json:"nameservers"`
}

// ZoneOptions represents zone creation options
type ZoneOptions struct {
	TTL        int      `json:"ttl"`
	AdminEmail string   `json:"adminEmail"`
	Masters    []string `json:"masters"`
}

// RecordInfo represents record information
type RecordInfo struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   int    `json:"ttl"`
	Value string `json:"value"`
}

// CacheStats represents cache statistics
type CacheStats struct {
	Size      int64   `json:"size"`
	HitRate   float64 `json:"hitRate"`
	MissRate  float64 `json:"missRate"`
	Evictions int64   `json:"evictions"`
}

// QueryResult represents a DNS query result
type QueryResult struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Answers []string `json:"answers"`
	RCode   string   `json:"rcode"`
	Time    int64    `json:"timeNs"`
}

// ServerStats represents server statistics
type ServerStats struct {
	Uptime         int64   `json:"uptime"`
	QueriesTotal   int64   `json:"queriesTotal"`
	QueriesPerSec  float64 `json:"queriesPerSec"`
	CacheHitRate   float64 `json:"cacheHitRate"`
	BlockedQueries int64   `json:"blockedQueries"`
	ZonesCount     int     `json:"zonesCount"`
}

// NewDNSToolsHandler creates a new DNS tools handler
func NewDNSToolsHandler(zm ZoneManager, cache CacheManager, resolver DNSResolver, bl BlocklistManager, stats StatsProvider) *DNSToolsHandler {
	return &DNSToolsHandler{
		zoneManager:   zm,
		cache:         cache,
		dnsResolver:   resolver,
		blocklist:     bl,
		statsProvider: stats,
	}
}

// ListTools returns the list of available tools
func (h *DNSToolsHandler) ListTools() ([]Tool, error) {
	return []Tool{
		{
			Name:        "dns_query",
			Description: "Query DNS records for a domain name",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"name": {Type: "string", Description: "The domain name to query"},
					"type": {Type: "string", Description: "The DNS record type (A, AAAA, MX, TXT, NS)", Default: "A"},
				},
				Required: []string{"name"},
			},
		},
		{
			Name:        "zone_list",
			Description: "List all configured DNS zones",
			InputSchema: InputSchema{Type: "object", Properties: map[string]Property{}},
		},
		{
			Name:        "zone_get",
			Description: "Get details of a specific DNS zone",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"name": {Type: "string", Description: "The zone name"},
				},
				Required: []string{"name"},
			},
		},
		{
			Name:        "zone_create",
			Description: "Create a new DNS zone",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"name":        {Type: "string", Description: "The zone name"},
					"ttl":         {Type: "integer", Description: "Default TTL", Default: 3600},
					"admin_email": {Type: "string", Description: "Admin email for SOA"},
				},
				Required: []string{"name"},
			},
		},
		{
			Name:        "zone_delete",
			Description: "Delete a DNS zone",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"name": {Type: "string", Description: "The zone name to delete"},
				},
				Required: []string{"name"},
			},
		},
		{
			Name:        "record_add",
			Description: "Add a DNS record to a zone",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"zone":  {Type: "string", Description: "The zone name"},
					"name":  {Type: "string", Description: "The record name"},
					"type":  {Type: "string", Description: "Record type (A, AAAA, MX, TXT, CNAME, NS)"},
					"value": {Type: "string", Description: "The record value"},
					"ttl":   {Type: "integer", Description: "TTL in seconds", Default: 3600},
				},
				Required: []string{"zone", "name", "type", "value"},
			},
		},
		{
			Name:        "record_delete",
			Description: "Delete a DNS record from a zone",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"zone": {Type: "string", Description: "The zone name"},
					"name": {Type: "string", Description: "The record name"},
					"type": {Type: "string", Description: "The record type"},
				},
				Required: []string{"zone", "name", "type"},
			},
		},
		{
			Name:        "record_list",
			Description: "List records in a zone",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"zone": {Type: "string", Description: "The zone name"},
					"name": {Type: "string", Description: "Filter by record name (optional)"},
				},
				Required: []string{"zone"},
			},
		},
		{
			Name:        "cache_stats",
			Description: "Get cache statistics",
			InputSchema: InputSchema{Type: "object", Properties: map[string]Property{}},
		},
		{
			Name:        "cache_flush",
			Description: "Flush the DNS cache",
			InputSchema: InputSchema{Type: "object", Properties: map[string]Property{}},
		},
		{
			Name:        "blocklist_check",
			Description: "Check if a domain is blocked",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"domain": {Type: "string", Description: "The domain to check"},
				},
				Required: []string{"domain"},
			},
		},
		{
			Name:        "server_stats",
			Description: "Get server statistics",
			InputSchema: InputSchema{Type: "object", Properties: map[string]Property{}},
		},
	}, nil
}

// CallTool executes a tool by name
func (h *DNSToolsHandler) CallTool(name string, args map[string]interface{}) (*ToolResult, error) {
	switch name {
	case "dns_query":
		return h.callDNSQuery(args)
	case "zone_list":
		return h.callZoneList()
	case "zone_get":
		return h.callZoneGet(args)
	case "zone_create":
		return h.callZoneCreate(args)
	case "zone_delete":
		return h.callZoneDelete(args)
	case "record_add":
		return h.callRecordAdd(args)
	case "record_delete":
		return h.callRecordDelete(args)
	case "record_list":
		return h.callRecordList(args)
	case "cache_stats":
		return h.callCacheStats()
	case "cache_flush":
		return h.callCacheFlush()
	case "blocklist_check":
		return h.callBlocklistCheck(args)
	case "server_stats":
		return h.callServerStats()
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

func (h *DNSToolsHandler) callDNSQuery(args map[string]interface{}) (*ToolResult, error) {
	name := getString(args, "name")
	qtype := getStringDefault(args, "type", "A")

	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	if h.dnsResolver == nil {
		return errorResult("DNS resolver not configured"), nil
	}

	result, err := h.dnsResolver.Query(name, qtype)
	if err != nil {
		return errorResult(fmt.Sprintf("Query failed: %v", err)), nil
	}

	return jsonResult(result), nil
}

func (h *DNSToolsHandler) callZoneList() (*ToolResult, error) {
	if h.zoneManager == nil {
		return errorResult("Zone manager not configured"), nil
	}

	zones, err := h.zoneManager.ListZones()
	if err != nil {
		return nil, err
	}

	return jsonResult(zones), nil
}

func (h *DNSToolsHandler) callZoneGet(args map[string]interface{}) (*ToolResult, error) {
	name := getString(args, "name")
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	if h.zoneManager == nil {
		return errorResult("Zone manager not configured"), nil
	}

	zone, err := h.zoneManager.GetZone(name)
	if err != nil {
		return errorResult(fmt.Sprintf("Zone not found: %v", err)), nil
	}

	return jsonResult(zone), nil
}

func (h *DNSToolsHandler) callZoneCreate(args map[string]interface{}) (*ToolResult, error) {
	name := getString(args, "name")
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	if h.zoneManager == nil {
		return errorResult("Zone manager not configured"), nil
	}

	opts := ZoneOptions{
		TTL:        getIntDefault(args, "ttl", 3600),
		AdminEmail: getString(args, "admin_email"),
	}

	if err := h.zoneManager.CreateZone(name, opts); err != nil {
		return errorResult(fmt.Sprintf("Failed to create zone: %v", err)), nil
	}

	return textResult(fmt.Sprintf("Zone '%s' created successfully", name)), nil
}

func (h *DNSToolsHandler) callZoneDelete(args map[string]interface{}) (*ToolResult, error) {
	name := getString(args, "name")
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	if h.zoneManager == nil {
		return errorResult("Zone manager not configured"), nil
	}

	if err := h.zoneManager.DeleteZone(name); err != nil {
		return errorResult(fmt.Sprintf("Failed to delete zone: %v", err)), nil
	}

	return textResult(fmt.Sprintf("Zone '%s' deleted successfully", name)), nil
}

func (h *DNSToolsHandler) callRecordAdd(args map[string]interface{}) (*ToolResult, error) {
	zone := getString(args, "zone")
	name := getString(args, "name")
	rtype := getString(args, "type")
	value := getString(args, "value")
	ttl := getIntDefault(args, "ttl", 3600)

	if zone == "" || name == "" || rtype == "" || value == "" {
		return nil, fmt.Errorf("zone, name, type, and value are required")
	}

	if h.zoneManager == nil {
		return errorResult("Zone manager not configured"), nil
	}

	if err := h.zoneManager.AddRecord(zone, name, rtype, value, ttl); err != nil {
		return errorResult(fmt.Sprintf("Failed to add record: %v", err)), nil
	}

	return textResult(fmt.Sprintf("Record %s %s added to zone '%s'", name, rtype, zone)), nil
}

func (h *DNSToolsHandler) callRecordDelete(args map[string]interface{}) (*ToolResult, error) {
	zone := getString(args, "zone")
	name := getString(args, "name")
	rtype := getString(args, "type")

	if zone == "" || name == "" || rtype == "" {
		return nil, fmt.Errorf("zone, name, and type are required")
	}

	if h.zoneManager == nil {
		return errorResult("Zone manager not configured"), nil
	}

	if err := h.zoneManager.DeleteRecord(zone, name, rtype); err != nil {
		return errorResult(fmt.Sprintf("Failed to delete record: %v", err)), nil
	}

	return textResult(fmt.Sprintf("Record %s %s deleted from zone '%s'", name, rtype, zone)), nil
}

func (h *DNSToolsHandler) callRecordList(args map[string]interface{}) (*ToolResult, error) {
	zone := getString(args, "zone")
	name := getString(args, "name")

	if zone == "" {
		return nil, fmt.Errorf("zone is required")
	}

	if h.zoneManager == nil {
		return errorResult("Zone manager not configured"), nil
	}

	records, err := h.zoneManager.GetRecords(zone, name)
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to list records: %v", err)), nil
	}

	return jsonResult(records), nil
}

func (h *DNSToolsHandler) callCacheStats() (*ToolResult, error) {
	if h.cache == nil {
		return errorResult("Cache not configured"), nil
	}

	stats := h.cache.GetStats()
	return jsonResult(stats), nil
}

func (h *DNSToolsHandler) callCacheFlush() (*ToolResult, error) {
	if h.cache == nil {
		return errorResult("Cache not configured"), nil
	}

	if err := h.cache.Flush(); err != nil {
		return errorResult(fmt.Sprintf("Failed to flush cache: %v", err)), nil
	}

	return textResult("Cache flushed successfully"), nil
}

func (h *DNSToolsHandler) callBlocklistCheck(args map[string]interface{}) (*ToolResult, error) {
	domain := getString(args, "domain")
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	if h.blocklist == nil {
		return errorResult("Blocklist not configured"), nil
	}

	blocked := h.blocklist.IsBlocked(domain)
	result := &BlocklistCheckResult{
		Domain:  domain,
		Blocked: blocked,
	}

	return jsonResult(result), nil
}

func (h *DNSToolsHandler) callServerStats() (*ToolResult, error) {
	if h.statsProvider == nil {
		return errorResult("Stats provider not configured"), nil
	}

	stats := h.statsProvider.GetStats()
	return jsonResult(stats), nil
}

// ListResources implements Handler
func (h *DNSToolsHandler) ListResources() ([]Resource, error) {
	var resources []Resource

	if h.zoneManager != nil {
		zones, err := h.zoneManager.ListZones()
		if err == nil {
			for _, z := range zones {
				resources = append(resources, Resource{
					URI:         fmt.Sprintf("dns://zone/%s", z.Name),
					Name:        fmt.Sprintf("Zone: %s", z.Name),
					Description: fmt.Sprintf("DNS zone with %d records", z.RecordCount),
					MimeType:    "application/json",
				})
			}
		}
	}

	resources = append(resources,
		Resource{
			URI:         "dns://server/status",
			Name:        "Server Status",
			Description: "Current server status and statistics",
			MimeType:    "application/json",
		},
		Resource{
			URI:         "dns://cache/stats",
			Name:        "Cache Statistics",
			Description: "Current DNS cache statistics",
			MimeType:    "application/json",
		},
	)

	return resources, nil
}

// ReadResource implements Handler
func (h *DNSToolsHandler) ReadResource(uri string) (*ResourceContents, error) {
	if !strings.HasPrefix(uri, "dns://") {
		return nil, fmt.Errorf("invalid URI scheme")
	}

	path := strings.TrimPrefix(uri, "dns://")

	switch {
	case strings.HasPrefix(path, "zone/"):
		zoneName := strings.TrimPrefix(path, "zone/")
		if h.zoneManager == nil {
			return nil, fmt.Errorf("zone manager not configured")
		}
		zone, err := h.zoneManager.GetZone(zoneName)
		if err != nil {
			return nil, err
		}
		data, err := json.MarshalIndent(zone, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshaling zone data: %w", err)
		}
		return &ResourceContents{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(data),
		}, nil

	case path == "server/status":
		if h.statsProvider == nil {
			return nil, fmt.Errorf("stats provider not configured")
		}
		stats := h.statsProvider.GetStats()
		data, err := json.MarshalIndent(stats, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshaling server stats: %w", err)
		}
		return &ResourceContents{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(data),
		}, nil

	case path == "cache/stats":
		if h.cache == nil {
			return nil, fmt.Errorf("cache not configured")
		}
		stats := h.cache.GetStats()
		data, err := json.MarshalIndent(stats, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshaling cache stats: %w", err)
		}
		return &ResourceContents{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(data),
		}, nil

	default:
		return nil, fmt.Errorf("resource not found: %s", uri)
	}
}

// ListPrompts implements Handler
func (h *DNSToolsHandler) ListPrompts() ([]Prompt, error) {
	return []Prompt{
		{
			Name:        "troubleshoot_dns",
			Description: "Troubleshoot DNS resolution issues for a domain",
			Arguments: []PromptArg{
				{Name: "domain", Description: "The domain to troubleshoot", Required: true},
			},
		},
		{
			Name:        "zone_setup",
			Description: "Guide for setting up a new DNS zone",
			Arguments: []PromptArg{
				{Name: "zone_name", Description: "The zone name to set up", Required: true},
			},
		},
	}, nil
}

// GetPrompt implements Handler
func (h *DNSToolsHandler) GetPrompt(name string, args map[string]string) (*PromptResult, error) {
	switch name {
	case "troubleshoot_dns":
		domain := args["domain"]
		return &PromptResult{
			Description: "DNS troubleshooting guide",
			Messages: []PromptMessage{
				{
					Role:    "user",
					Content: Content{Type: "text", Text: fmt.Sprintf("Help me troubleshoot DNS issues for %s", domain)},
				},
				{
					Role: "assistant",
					Content: Content{Type: "text", Text: fmt.Sprintf(`I'll help troubleshoot DNS issues for %s:

1. Check A record: dns_query(name="%s", type="A")
2. Check AAAA record: dns_query(name="%s", type="AAAA")
3. Check MX record: dns_query(name="%s", type="MX")
4. Check NS record: dns_query(name="%s", type="NS")
5. Check SOA record: dns_query(name="%s", type="SOA")

Would you like me to run these queries?`, domain, domain, domain, domain, domain, domain)},
				},
			},
		}, nil

	case "zone_setup":
		zoneName := args["zone_name"]
		return &PromptResult{
			Description: "Zone setup guide",
			Messages: []PromptMessage{
				{
					Role: "assistant",
					Content: Content{Type: "text", Text: fmt.Sprintf(`To set up zone %s:

1. Create zone: zone_create(name="%s")
2. Add NS records
3. Add A record for @
4. Add A record for www
5. Add MX record

Use record_add to add each record.`, zoneName, zoneName)},
				},
			},
		}, nil

	default:
		return nil, fmt.Errorf("unknown prompt: %s", name)
	}
}

// BlocklistCheckResult holds the result of a blocklist domain check.
type BlocklistCheckResult struct {
	Domain  string `json:"domain"`
	Blocked bool   `json:"blocked"`
}

// Helper functions

func getString(args map[string]interface{}, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getStringDefault(args map[string]interface{}, key, def string) string {
	if v := getString(args, key); v != "" {
		return v
	}
	return def
}

func getIntDefault(args map[string]interface{}, key string, def int) int {
	if v, ok := args[key]; ok {
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return def
}

func textResult(text string) *ToolResult {
	return &ToolResult{
		Content: []Content{{Type: "text", Text: text}},
	}
}

func errorResult(text string) *ToolResult {
	return &ToolResult{
		Content: []Content{{Type: "text", Text: text}},
		IsError: true,
	}
}

func jsonResult(data interface{}) *ToolResult {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return &ToolResult{
			Content: []Content{{Type: "text", Text: fmt.Sprintf("error: %v", err)}},
			IsError: true,
		}
	}
	return &ToolResult{
		Content: []Content{{Type: "text", Text: string(b)}},
	}
}
