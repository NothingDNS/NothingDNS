// Package blocklist provides domain blocking functionality for NothingDNS.
package blocklist

import (
	"bufio"
	"fmt"
	"net/http"
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
	mu       sync.RWMutex
	entries  map[string]Entry
	suffixes map[string]struct{} // Pre-computed suffixes for O(1) longest-match lookup
	files    []string
	urls     []string
	enabled  bool
	httpClient *http.Client
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
		entries: make(map[string]Entry),
		files:   cfg.Files,
		urls:    cfg.URLs,
		enabled: cfg.Enabled,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	return bl
}

// Load loads all configured blocklist files and URLs.
func (bl *Blocklist) Load() error {
	if !bl.enabled {
		return nil
	}

	bl.mu.Lock()
	defer bl.mu.Unlock()

	bl.entries = make(map[string]Entry)

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

// loadURL downloads and parses a blocklist from a URL.
func (bl *Blocklist) loadURL(url string) error {
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
	}

	return scanner.Err()
}

// loadFile loads a single blocklist file.
func (bl *Blocklist) loadFile(path string) error {
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

	// Check exact match
	if _, blocked := bl.entries[domain]; blocked {
		return true
	}

	// Check parent domains by finding dots and checking substrings
	// For "sub.ads.example.com", check "ads.example.com", then "example.com"
	// This avoids O(n²) string split+join operations
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' && i < len(domain)-1 {
			parent := domain[i+1:] // Everything after this dot
			if _, blocked := bl.entries[parent]; blocked {
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

// AddDomain adds a single domain to the blocklist in-memory.
func (bl *Blocklist) AddDomain(domain string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	bl.entries[d] = Entry{Domain: d}
}

// RemoveDomain removes a single domain from the blocklist in-memory.
func (bl *Blocklist) RemoveDomain(domain string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	delete(bl.entries, d)
}

// ListFiles returns the list of configured blocklist file paths.
func (bl *Blocklist) ListFiles() []string {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	files := make([]string, len(bl.files))
	copy(files, bl.files)
	return files
}
