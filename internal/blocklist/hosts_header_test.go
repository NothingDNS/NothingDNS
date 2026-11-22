package blocklist

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The header of a standard hosts-file blocklist (verbatim from
// StevenBlack/hosts) maps the host's own names; it is not a list of names to
// block. Loaded as entries, "localhost" overrode the RFC 6761 local answer
// and "local" blocked every *.local name (F872).
const hostsHeaderList = `127.0.0.1 localhost
127.0.0.1 localhost.localdomain
127.0.0.1 local
255.255.255.255 broadcasthost
::1 localhost
::1 ip6-localhost
::1 ip6-loopback
fe80::1%lo0 localhost
ff00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
0.0.0.0 0.0.0.0
0.0.0.0 ads.example.com
`

func assertHostsHeaderSkipped(t *testing.T, bl *Blocklist) {
	t.Helper()
	if !bl.IsBlocked("ads.example.com") {
		t.Fatal("ads.example.com should be blocked")
	}
	for _, name := range []string{"localhost", "www.localhost", "localhost.localdomain", "local", "dc1.corp.local",
		"broadcasthost", "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes",
		"ip6-allrouters", "ip6-allhosts", "0.0.0.0"} {
		if bl.IsBlocked(name) {
			t.Errorf("%s blocked by a hosts-file header line", name)
		}
	}
}

func TestHostsFileHeaderIsNotBlocked(t *testing.T) {
	file := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(file, []byte(hostsHeaderList), 0o600); err != nil {
		t.Fatal(err)
	}
	bl := New(Config{Enabled: true, Files: []string{file}})
	if err := bl.Load(); err != nil {
		t.Fatal(err)
	}
	assertHostsHeaderSkipped(t, bl)
}

func TestHostsURLHeaderIsNotBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(hostsHeaderList))
	}))
	defer srv.Close()
	bl := New(Config{Enabled: true})
	bl.httpClient = newRedirectClient(srv)
	if err := bl.loadURL("https://8.8.8.8/hosts"); err != nil {
		t.Fatal(err)
	}
	assertHostsHeaderSkipped(t, bl)
}
