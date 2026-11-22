package blocklist

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
)

// Lines in a syntax the blocklist does not support (Adblock, wildcard,
// regex; SPECIFICATION §9.1.1) are not entries: they are skipped and the
// source is reported, instead of loading as entries that never match (F873).
const unsupportedSyntaxList = "||ads.example.com^\n*.tracker.example.net\n/regex.*/\n@@||allowed.example.org^\nreal.example.com\n"

func TestUnsupportedSyntaxLinesAreSkippedAndReported(t *testing.T) {
	var logs bytes.Buffer
	prev := util.GetDefaultLogger()
	util.SetDefaultLogger(util.NewLogger(util.INFO, util.TextFormat, &logs))
	defer util.SetDefaultLogger(prev)

	file := filepath.Join(t.TempDir(), "list")
	if err := os.WriteFile(file, []byte(unsupportedSyntaxList), 0o600); err != nil {
		t.Fatal(err)
	}
	bl := New(Config{Enabled: true, Files: []string{file}})
	if err := bl.Load(); err != nil {
		t.Fatal(err)
	}
	if n := bl.Stats().TotalBlocks; n != 1 || !bl.IsBlocked("real.example.com") {
		t.Fatalf("file: TotalBlocks %d, want 1 (real.example.com)", n)
	}
	if !strings.Contains(logs.String(), "skipped 4") {
		t.Fatalf("file: no warning about the skipped lines: %q", logs.String())
	}

	logs.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(unsupportedSyntaxList))
	}))
	defer srv.Close()
	ub := New(Config{Enabled: true})
	ub.httpClient = newRedirectClient(srv)
	if err := ub.loadURL("https://8.8.8.8/list"); err != nil {
		t.Fatal(err)
	}
	if n := ub.Stats().TotalBlocks; n != 1 {
		t.Fatalf("url: TotalBlocks %d, want 1", n)
	}
	if !strings.Contains(logs.String(), "skipped 4") {
		t.Fatalf("url: no warning about the skipped lines: %q", logs.String())
	}
}
