// Package blocklist provides domain blocking functionality for NothingDNS.
package blocklist

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Entry represents a blocked domain entry.
type Entry struct {
	Domain  string
	Comment string
}

// Blocklist manages blocked domains.
//
// enabled is atomic.Bool because IsBlocked reads it on the hot request
// path without taking bl.mu, while SetEnabled used to write it under
// the lock — a textbook data race. atomic.Bool is wait-free for
// readers and gives visibility guarantees on writes.
type Blocklist struct {
	mu              sync.RWMutex
	entries         map[string]Entry
	files           []string
	urls            []string
	enabled         atomic.Bool
	httpClient      *http.Client
	sourceEntries   map[string]map[string]Entry // source → domain → Entry
	disabledSources map[string]bool             // source → disabled
	manualEntries   map[string]Entry            // manually added domains (no source)
	// baseDir confines file sources to prevent arbitrary file reads (VULN-067)
	baseDir string
}

// Config holds blocklist configuration.
type Config struct {
	Enabled bool
	Files   []string
	URLs    []string // URLs to download blocklists from
	// BaseDir confines file sources to this directory to prevent
	// arbitrary file reads (VULN-067). Paths outside BaseDir are rejected.
	BaseDir string
}

// maxBlocklistRedirects caps the number of HTTP redirects followed when fetching
// a blocklist. Kept small to bound attacker-controlled hopping through the
// validator and to limit request-goroutine hold time.
const maxBlocklistRedirects = 5

var (
	errBlocklistBodyTooLarge = errors.New("blocklist response body exceeds maximum size")
	maxRemoteBlocklistBody   = int64(100 * 1024 * 1024)
)

type maxBytesReader struct {
	r         io.Reader
	remaining int64
}

func newMaxBytesReader(r io.Reader, n int64) *maxBytesReader {
	return &maxBytesReader{r: r, remaining: n}
}

func (r *maxBytesReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		var b [1]byte
		n, err := r.r.Read(b[:])
		if n > 0 {
			return 0, errBlocklistBodyTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:int(r.remaining)]
	}
	n, err := r.r.Read(p)
	r.remaining -= int64(n)
	return n, err
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
		baseDir:         cfg.BaseDir,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			// SECURITY: Re-validate every redirect hop. Without this, Go's default
			// policy follows up to 10 redirects with no per-hop check, so a
			// compliant 302 to http://169.254.169.254/ or RFC1918 bypasses
			// validateBlocklistURL (which runs only on the initial URL).
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxBlocklistRedirects {
					return fmt.Errorf("blocklist fetch: redirect limit (%d) exceeded", maxBlocklistRedirects)
				}
				if err := validateBlocklistURL(req.URL.String()); err != nil {
					return fmt.Errorf("blocklist redirect blocked: %w", err)
				}
				return nil
			},
		},
	}
	bl.enabled.Store(cfg.Enabled)
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
	if !bl.enabled.Load() {
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
// SECURITY (LOW-006): Validates IP at config time to block private/reserved
// ranges. DNS rebinding is mitigated by requiring IP literals and HTTPS.
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

	// Only allow IP literals to prevent DNS rebinding attacks.
	// DNS lookups can be manipulated by attackers to first return public IPs
	// then later resolve to private IPs.
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("only IP addresses are allowed in blocklist URLs, not hostnames: %s", host)
	}
	if isPrivateOrReservedIP(ip) {
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

	// SECURITY: Limit total response body size to prevent memory exhaustion.
	scanner := bufio.NewScanner(newMaxBytesReader(resp.Body, maxRemoteBlocklistBody))
	// Increase buffer for long lines (some blocklist entries can be very long)
	const maxLineLength = 4096
	buf := make([]byte, maxLineLength)
	scanner.Buffer(buf, maxLineLength)

	// SECURITY: Limit total number of entries to prevent memory exhaustion
	const maxEntries = 10_000_000 // 10 million
	entryCount := 0
	sourceEntries := make(map[string]Entry)

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
				entryCount++
				if entryCount > maxEntries {
					return fmt.Errorf("blocklist %s exceeds maximum entry count of %d", url, maxEntries)
				}
				domain := normalizeDomain(fields[0])
				sourceEntries[domain] = Entry{Domain: domain, Comment: "url:" + url}
			}
			continue
		}

		// fields[0] is IP (127.0.0.1, 0.0.0.0, etc.)
		// fields[1] is the domain to block
		entryCount++
		if entryCount > maxEntries {
			return fmt.Errorf("blocklist %s exceeds maximum entry count of %d", url, maxEntries)
		}
		domain := normalizeDomain(fields[1])

		// Extract comment if present
		comment := ""
		if idx := strings.Index(line, "#"); idx != -1 {
			comment = strings.TrimSpace(line[idx+1:])
		}
		if comment == "" {
			comment = "url:" + url
		}

		sourceEntries[domain] = Entry{Domain: domain, Comment: comment}
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, errBlocklistBodyTooLarge) {
			return fmt.Errorf("blocklist %s exceeds maximum response body size of %d bytes", url, maxRemoteBlocklistBody)
		}
		return err
	}

	bl.sourceEntries[url] = sourceEntries
	for domain, entry := range sourceEntries {
		bl.entries[domain] = entry
	}
	return nil
}

// loadFile loads a single blocklist file.
func (bl *Blocklist) loadFile(path string) error {
	cleanPath := filepath.Clean(path)
	// Ensure the path is absolute
	if !filepath.IsAbs(cleanPath) {
		return fmt.Errorf("blocklist path must be absolute: %s", path)
	}
	if bl.baseDir != "" {
		if err := ensureBlocklistPathInBaseDir(cleanPath, bl.baseDir); err != nil {
			return err
		}
	}
	f, err := os.Open(cleanPath)
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

		// Parse hosts file format ("IP domain [comment]") or plain
		// domain-per-line format — the URL loader accepts both, and
		// plain domain lists (oisd, hagezi, …) are at least as common
		// as hosts files. Silently skipping single-field lines loaded
		// such files as 0 entries with no error.
		fields := strings.Fields(line)
		var domain string
		switch {
		case len(fields) == 1:
			domain = normalizeDomain(fields[0])
		case len(fields) >= 2:
			// fields[0] is IP (127.0.0.1, 0.0.0.0, etc.)
			// fields[1] is the domain to block
			domain = normalizeDomain(fields[1])
		default:
			continue
		}

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

func ensureBlocklistPathInBaseDir(path, baseDir string) error {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("blocklist path: %w", err)
	}
	realBaseDir, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return fmt.Errorf("blocklist basedir: %w", err)
	}
	rel, err := filepath.Rel(realBaseDir, realPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("blocklist path %q is outside BaseDir %q", path, baseDir)
	}
	return nil
}

// IsBlocked checks if a domain is blocked.
// Uses efficient suffix matching with minimal allocations.
func (bl *Blocklist) IsBlocked(domain string) bool {
	if !bl.enabled.Load() {
		return false
	}

	bl.mu.RLock()
	defer bl.mu.RUnlock()

	domain = normalizeDomain(domain)

	// Check each enabled source
	for source, entries := range bl.sourceEntries {
		if bl.disabledSources[source] {
			continue
		}
		if isDomainBlockedIn(entries, domain) {
			return true
		}
	}

	// Check manually added domains (including parent-domain matches)
	return isDomainBlockedIn(bl.manualEntries, domain)
}

func isDomainBlockedIn(entries map[string]Entry, domain string) bool {
	if _, blocked := entries[domain]; blocked {
		return true
	}

	// Check parent domains by finding dots and checking substrings.
	// For "sub.ads.example.com", check "ads.example.com", then "example.com".
	// Use index-based checking to minimize allocations.
	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] == '.' && i < len(domain)-1 {
			parent := domain[i+1:]
			if _, blocked := entries[parent]; blocked {
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
		Enabled:     bl.enabled.Load(),
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

// SetEnabled enables or disables the blocklist. Wait-free for readers.
func (bl *Blocklist) SetEnabled(enabled bool) {
	bl.enabled.Store(enabled)
}

// Toggle atomically flips the enabled state and returns the new value.
// Replaces the TOCTOU-prone Stats()+SetEnabled(!Stats.Enabled) pattern:
// two concurrent toggles racing on the latter both observed the same
// Stats().Enabled and both wrote the same !value — one of the toggles
// was silently lost. CompareAndSwap loop guarantees exactly N flips
// for N callers.
func (bl *Blocklist) Toggle() bool {
	for {
		cur := bl.enabled.Load()
		if bl.enabled.CompareAndSwap(cur, !cur) {
			return !cur
		}
	}
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

	d := normalizeDomain(domain)
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

// normalizeDomain lowercases and strips the trailing root-zone dot
// from a domain name. This is the on-load companion to the on-lookup
// `strings.ToLower(strings.TrimSuffix(domain, "."))` pattern; without
// it (L-7) a BIND-style source line ("example.com.") loaded as
// "example.com." would never match a lookup for "example.com" — the
// entry silently never blocked anything.
func normalizeDomain(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}
