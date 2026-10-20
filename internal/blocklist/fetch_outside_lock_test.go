package blocklist

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// gatedTransport holds every request until release is closed, then serves a
// one-domain hosts list.
type gatedTransport struct {
	started chan struct{}
	release chan struct{}
}

func (g *gatedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	select {
	case g.started <- struct{}{}:
	default:
	}
	<-g.release
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("0.0.0.0 fetched.example\n")),
		Header:     make(http.Header),
	}, nil
}

// isBlockedWithin runs IsBlocked on another goroutine and reports whether it
// returned within d.
func isBlockedWithin(bl *Blocklist, domain string, d time.Duration) (blocked, returned bool) {
	res := make(chan bool, 1)
	go func() { res <- bl.IsBlocked(domain) }()
	select {
	case b := <-res:
		return b, true
	case <-time.After(d):
		return false, false
	}
}

// IsBlocked sits in front of every query. A slow remote blocklist fetch must
// not hold the lock it takes: while AddURL or a reload downloads a list, the
// current rules have to keep answering.
func TestRemoteFetchDoesNotBlockLookups(t *testing.T) {
	const url = "https://8.8.8.8/list.txt"

	for _, tc := range []struct {
		name  string
		start func(bl *Blocklist) <-chan error
	}{
		{"AddURL", func(bl *Blocklist) <-chan error {
			done := make(chan error, 1)
			go func() { done <- bl.AddURL(url) }()
			return done
		}},
		{"Reload", func(bl *Blocklist) <-chan error {
			bl.urls = []string{url}
			done := make(chan error, 1)
			go func() { done <- bl.Reload() }()
			return done
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bl := New(Config{Enabled: true})
			bl.AddDomain("manual.example")
			gate := &gatedTransport{started: make(chan struct{}, 1), release: make(chan struct{})}
			bl.httpClient.Transport = gate

			// Control: lookups are immediate while nothing is being fetched.
			if blocked, returned := isBlockedWithin(bl, "manual.example", time.Second); !returned || !blocked {
				t.Fatalf("control: blocked=%v returned=%v", blocked, returned)
			}

			done := tc.start(bl)
			select {
			case <-gate.started:
			case <-time.After(5 * time.Second):
				t.Fatal("fetch never started")
			}

			blocked, returned := isBlockedWithin(bl, "manual.example", 500*time.Millisecond)
			close(gate.release)
			if err := <-done; err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if !returned {
				t.Fatal("FAIL: IsBlocked stalled for the whole remote fetch")
			}
			if !blocked {
				t.Fatal("manual.example stopped being blocked during the fetch")
			}
			if !bl.IsBlocked("fetched.example") {
				t.Fatal("fetched list was not installed")
			}
		})
	}
}
