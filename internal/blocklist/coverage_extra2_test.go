package blocklist

import (
	"testing"
)

// ---------------------------------------------------------------------------
// parseURL edge cases (supplement ssrf_test.go)
// ---------------------------------------------------------------------------

func TestParseURL_InvalidURL2(t *testing.T) {
	_, err := parseURL("://missing-scheme")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestParseURL_NoHost2(t *testing.T) {
	_, err := parseURL("https:///list.txt")
	if err == nil {
		t.Error("expected error for URL without host")
	}
}

// ---------------------------------------------------------------------------
// ToggleSource — URL source toggle
// ---------------------------------------------------------------------------

func TestToggleSource_URLSource(t *testing.T) {
	bl := New(Config{})
	bl.urls = []string{"https://example.com/list.txt"}
	bl.sourceEntries = map[string]map[string]Entry{
		"https://example.com/list.txt": {"evil.com": {Domain: "evil.com"}},
	}

	// Toggle disable
	enabled, err := bl.ToggleSource("https://example.com/list.txt")
	if err != nil {
		t.Fatalf("ToggleSource: %v", err)
	}
	if enabled {
		t.Error("expected enabled=false after first toggle")
	}

	// Toggle back to enabled
	enabled, err = bl.ToggleSource("https://example.com/list.txt")
	if err != nil {
		t.Fatalf("ToggleSource (second): %v", err)
	}
	if !enabled {
		t.Error("expected enabled=true after second toggle")
	}
}

// ---------------------------------------------------------------------------
// GetSources — mixed types with disabled state
// ---------------------------------------------------------------------------

func TestGetSources_MixedSources(t *testing.T) {
	bl := New(Config{})
	bl.files = []string{"/etc/block.txt"}
	bl.urls = []string{"https://example.com/list.txt"}
	bl.disabledSources = map[string]bool{
		"https://example.com/list.txt": true,
	}
	bl.sourceEntries = map[string]map[string]Entry{
		"/etc/block.txt":               {"evil.com": {Domain: "evil.com"}, "bad.com": {Domain: "bad.com"}},
		"https://example.com/list.txt": {"spam.com": {Domain: "spam.com"}},
	}

	sources := bl.GetSources()
	if len(sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(sources))
	}

	// Find each source
	var fileSource, urlSource *SourceInfo
	for i := range sources {
		if sources[i].Type == "file" {
			fileSource = &sources[i]
		}
		if sources[i].Type == "url" {
			urlSource = &sources[i]
		}
	}

	if fileSource == nil {
		t.Fatal("expected file source")
	}
	if fileSource.Domains != 2 {
		t.Errorf("file source Domains = %d, want 2", fileSource.Domains)
	}
	if !fileSource.Enabled {
		t.Error("expected file source to be enabled")
	}

	if urlSource == nil {
		t.Fatal("expected url source")
	}
	if urlSource.Enabled {
		t.Error("expected url source to be disabled")
	}
	if urlSource.Domains != 1 {
		t.Errorf("url source Domains = %d, want 1", urlSource.Domains)
	}
}
