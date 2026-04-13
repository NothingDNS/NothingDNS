// Package blocklist provides domain blocking functionality for NothingDNS.
package blocklist

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Entry represents a blocked domain entry.
type Entry struct {
	Domain  string
	Comment string
}

// Blocklist manages blocked domains.
type Blocklist struct {
	mu              sync.RWMutex
	entries         map[string]Entry
	files           []string
	urls            []string
	enabled         bool
	httpClient      *http.Client
	sourceEntries   map[string]map[string]Entry // source → domain → Entry
	disabledSources map[string]bool             // source → disabled
	manualEntries   map[string]Entry            // manually added domains (no source)
}

// Config holds blocklist configuration.
type Config struct {
	Enabled bool
	Files   []string
	URLs    []string // URLs to download blocklists from
}

// New creates a new blocklist manager.
func New(cfg Config) *Blocklist {
	bl := &Blocklist{
		entries:         make(map[string]Entry),
		sourceEntries:   make(map[string]map[string]Entry),
		disabledSources: make(map[string]bool),
		manualEntries:   make(map[string]Entry),
		files:           cfg.Files,
		urls:            cfg.URLs,
		enabled:         cfg.Enabled,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	return bl
}

// Close releases resources held by the blocklist.
func (bl *Blocklist) Close() error {
	if bl.httpClient != nil {
		bl.httpClient.CloseIdleConnections()
	}
	return nil
}

// Load loads all configured blocklist files and URLs.
func (bl *Blocklist) Load() error {
	if !bl.enabled {
		return nil
	}

	bl.mu.Lock()
	defer bl.mu.Unlock()

	bl.entries = make(map[string]Entry)
	bl.sourceEntries = make(map[string]map[string]Entry)

	// Load from files
	for _, file := range bl.files {
		if err := bl.loadFile(file); err != nil {
			return fmt.Errorf("loading blocklist %s: %w", file, err)
		}
	}

	// Load from URLs
	for _, url := range bl.urls {
		if err := bl.loadURL(url); err != nil {
			return fmt.Errorf("loading blocklist from %s: %w", url, err)
		}
	}

	return nil
}

// validateBlocklistURL checks that a blocklist URL is safe to fetch.
// It blocks private/reserved IPs, cloud metadata endpoints, and non-HTTPS schemes.
func validateBlocklistURL(rawURL string) error {
	u, err := parseURL(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow HTTPS
	if u.Scheme != "https" {
		return fmt.Errorf("only HTTPS URLs are allowed, got scheme %q", u.Scheme)
	}

	host := u.Host

	// Block known cloud metadata and internal hostnames
	host = strings.ToLower(host)
	switch host {
	case "169.254.169.254", "metadata.google.internal", "metadata.azure.com",
		"metadata.googleusercontent.com":
		return fmt.Errorf("cloud metadata host not allowed: %s", host)
	}

	// Resolve hostname and check for private/reserved IPs
	ip := net.ParseIP(host)
	if ip == nil {
		// Not an IP — resolve hostname
		addrs, err := net.LookupHost(host)
		if err != nil {
			return fmt.Errorf("cannot resolve host %q: %w", host, err)
		}
		for _, addr := range addrs {
			if ip = net.ParseIP(addr); ip != nil && isPrivateOrReservedIP(ip) {
				return fmt.Errorf("private/reserved IP not allowed: %s", addr)
			}
		}
	} else if isPrivateOrReservedIP(ip) {
		return fmt.Errorf("private/reserved IP not allowed: %s", ip)
	}

	return nil
}

// isPrivateOrReservedIP returns true if the IP is in a private, reserved, or link-local range.
func isPrivateOrReservedIP(ip net.IP) bool {
	// RFC 1918 private addresses
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 127.0.0.0/8
		if ip4[0] == 127 {
			return true
		}
		// 169.254.0.0/16 (link-local)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		return false
	}
	// IPv6
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	// RFC 4193 unique local (fc00::/7)
	if ip[0]&0xfe == 0xfc {
		return true
	}
	return false
}

// parseURL parses a URL and returns scheme/host using stdlib net/url.
func parseURL(rawURL string) (*urlInfo, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("URL must have scheme and host")
	}
	return &urlInfo{Scheme: u.Scheme, Host: u.Hostname()}, nil
}

type urlInfo struct {
	Scheme string
	Host   string
}

// loadURL downloads and parses a blocklist from a URL.
func (bl *Blocklist) loadURL(url string) error {
	if err := validateBlocklistURL(url); err != nil {
		return fmt.Errorf("invalid blocklist URL: %w", err)
	}
	resp, err := bl.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	scanner := bufio.NewScanner(resp.Body)
	// Increase buffer for long lines (some blocklist entries can be very long)
	const maxLineLength = 4096
	buf := make([]byte, maxLineLength)
	scanner.Buffer(buf, maxLineLength)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse hosts file format: IP domain [comment]
		fields := strings.Fields(line)
		if len(fields) < 2 {
			// Also accept just domain per line (no IP)
			if len(fields) == 1 {
				domain := strings.ToLower(fields[0])
				bl.entries[domain] = Entry{
					Domain:  domain,
					Comment: "url:" + url,
				}
				if bl.sourceEntries[url] == nil {
					bl.sourceEntries[url] = make(map[string]Entry)
				}
				bl.sourceEntries[url][domain] = Entry{Domain: domain, Comment: "url:" + url}
			}
			continue
		}

		// fields[0] is IP (127.0.0.1, 0.0.0.0, etc.)
		// fields[1] is the domain to block
		domain := strings.ToLower(fields[1])

		// Extract comment if present
		comment := ""
		if idx := strings.Index(line, "#"); idx != -1 {
			comment = strings.TrimSpace(line[idx+1:])
		}
		if comment == "" {
			comment = "url:" + url
		}

		bl.entries[domain] = Entry{
			Domain:  domain,
			Comment: comment,
		}
		if bl.sourceEntries[url] == nil {
			bl.sourceEntries[url] = make(map[string]Entry)
		}
		bl.sourceEntries[url][domain] = Entry{Domain: domain, Comment: comment}
	}

	return scanner.Err()
}

// loadFile loads a single blocklist file.
func (bl *Blocklist) loadFile(path string) error {
	// SECURITY: Check for path traversal sequences
	if strings.Contains(path, "..") {
		return fmt.Errorf("blocklist path traversal attempt blocked: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse hosts file format: IP domain [comment]
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// fields[0] is IP (127.0.0.1, 0.0.0.0, etc.)
		// fields[1] is the domain to block
		domain := strings.ToLower(fields[1])

		// Extract comment if present
		comment := ""
		if idx := strings.Index(line, "#"); idx != -1 {
			comment = strings.TrimSpace(line[idx+1:])
		}

		bl.entries[domain] = Entry{
			Domain:  domain,
			Comment: comment,
		}
		if bl.sourceEntries[path] == nil {
			bl.sourceEntries[path] = make(map[string]Entry)
		}
		bl.sourceEntries[path][domain] = Entry{Domain: domain, Comment: comment}
	}

	return scanner.Err()
}

// IsBlocked checks if a domain is blocked.
// Uses efficient suffix matching without repeated string allocations.
func (bl *Blocklist) IsBlocked(domain string) bool {
	if !bl.enabled {
		return false
	}

	bl.mu.RLock()
	defer bl.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Check each enabled source
	for source, entries := range bl.sourceEntries {
		if bl.disabledSources[source] {
			continue
		}
		// Check exact match
		if _, blocked := entries[domain]; blocked {
			return true
		}
		// Check parent domains by finding dots and checking substrings
		// For "sub.ads.example.com", check "ads.example.com", then "example.com"
		for i := 0; i < len(domain); i++ {
			if domain[i] == '.' && i < len(domain)-1 {
				parent := domain[i+1:]
				if _, blocked := entries[parent]; blocked {
					return true
				}
			}
		}
	}

	// Check manually added domains
	if _, blocked := bl.manualEntries[domain]; blocked {
		return true
	}
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' && i < len(domain)-1 {
			parent := domain[i+1:]
			if _, blocked := bl.manualEntries[parent]; blocked {
				return true
			}
		}
	}

	return false
}

// Reload reloads all blocklist files.
func (bl *Blocklist) Reload() error {
	return bl.Load()
}

// Stats returns blocklist statistics.
func (bl *Blocklist) Stats() Stats {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	return Stats{
		Enabled:     bl.enabled,
		TotalBlocks: len(bl.entries),
		Files:       len(bl.files),
		URLs:        len(bl.urls),
	}
}

// Stats holds blocklist statistics.
type Stats struct {
	Enabled     bool
	TotalBlocks int
	Files       int
	URLs        int
}

// GetEntries returns all blocked domains (for debugging/monitoring).
func (bl *Blocklist) GetEntries() []Entry {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	entries := make([]Entry, 0, len(bl.entries))
	for _, entry := range bl.entries {
		entries = append(entries, entry)
	}
	return entries
}

// AddFile loads a new blocklist file and merges its entries.
func (bl *Blocklist) AddFile(path string) error {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	if err := bl.loadFile(path); err != nil {
		return err
	}
	bl.files = append(bl.files, path)
	return nil
}

// AddURL downloads and loads a blocklist from a URL.
func (bl *Blocklist) AddURL(url string) error {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	if err := bl.loadURL(url); err != nil {
		return err
	}
	bl.urls = append(bl.urls, url)
	return nil
}

// ListURLs returns the list of configured blocklist URLs.
func (bl *Blocklist) ListURLs() []string {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	urls := make([]string, len(bl.urls))
	copy(urls, bl.urls)
	return urls
}

// RemoveFile removes all entries that originated from a given file path.
func (bl *Blocklist) RemoveFile(path string) error {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	// Reload without the target file
	newFiles := make([]string, 0, len(bl.files))
	for _, f := range bl.files {
		if f != path {
			newFiles = append(newFiles, f)
		}
	}
	bl.files = newFiles

	// Clean up source tracking
	delete(bl.sourceEntries, path)
	delete(bl.disabledSources, path)

	// Rebuild entries from remaining files
	bl.entries = make(map[string]Entry)
	for _, f := range bl.files {
		if err := bl.loadFile(f); err != nil {
			return err
		}
	}
	return nil
}

// SetEnabled enables or disables the blocklist.
func (bl *Blocklist) SetEnabled(enabled bool) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.enabled = enabled
}

// SourceInfo describes a blocklist source (file or URL).
type SourceInfo struct {
	ID      string `json:"id"`
	Type    string `json:"type"` // "file" or "url"
	Enabled bool   `json:"enabled"`
	Domains int    `json:"domains"`
}

// GetSources returns status for all blocklist sources.
func (bl *Blocklist) GetSources() []SourceInfo {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	var sources []SourceInfo
	for _, f := range bl.files {
		sources = append(sources, SourceInfo{
			ID:      f,
			Type:    "file",
			Enabled: !bl.disabledSources[f],
			Domains: len(bl.sourceEntries[f]),
		})
	}
	for _, u := range bl.urls {
		sources = append(sources, SourceInfo{
			ID:      u,
			Type:    "url",
			Enabled: !bl.disabledSources[u],
			Domains: len(bl.sourceEntries[u]),
		})
	}
	return sources
}

// ToggleSource enables or disables a blocklist source.
// Returns the new enabled state and an error if the source is not found.
func (bl *Blocklist) ToggleSource(id string) (bool, error) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	// Check if source exists
	found := false
	for _, f := range bl.files {
		if f == id {
			found = true
			break
		}
	}
	if !found {
		for _, u := range bl.urls {
			if u == id {
				found = true
				break
			}
		}
	}
	if !found {
		return false, fmt.Errorf("source not found: %s", id)
	}

	bl.disabledSources[id] = !bl.disabledSources[id]
	return !bl.disabledSources[id], nil
}

// RemoveSource removes a source by ID (file path or URL).
func (bl *Blocklist) RemoveSource(id string) error {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	// Try as file
	for i, f := range bl.files {
		if f == id {
			bl.files = append(bl.files[:i], bl.files[i+1:]...)
			delete(bl.sourceEntries, id)
			delete(bl.disabledSources, id)
			// Rebuild entries
			bl.entries = make(map[string]Entry)
			for _, f := range bl.files {
				if err := bl.loadFile(f); err != nil {
					return err
				}
			}
			return nil
		}
	}
	// Try as URL
	for i, u := range bl.urls {
		if u == id {
			bl.urls = append(bl.urls[:i], bl.urls[i+1:]...)
			delete(bl.sourceEntries, id)
			delete(bl.disabledSources, id)
			// Rebuild entries
			bl.entries = make(map[string]Entry)
			for _, u := range bl.urls {
				if err := bl.loadURL(u); err != nil {
					return err
				}
			}
			return nil
		}
	}
	return fmt.Errorf("source not found: %s", id)
}

// AddDomain adds a single domain to the blocklist in-memory.
func (bl *Blocklist) AddDomain(domain string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	bl.entries[d] = Entry{Domain: d}
	bl.manualEntries[d] = Entry{Domain: d}
}

// RemoveDomain removes a single domain from the blocklist in-memory.
func (bl *Blocklist) RemoveDomain(domain string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	delete(bl.entries, d)
	delete(bl.manualEntries, d)
}

// ListFiles returns the list of configured blocklist file paths.
func (bl *Blocklist) ListFiles() []string {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	files := make([]string, len(bl.files))
	copy(files, bl.files)
	return files
}
