package nothingdns

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type closeProbeTransport struct {
	started chan struct{}
	release chan struct{}
	closed  atomic.Int32
}

func (p *closeProbeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	close(p.started)
	<-p.release
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"status":"healthy"}`)), Request: r}, nil
}

func (p *closeProbeTransport) CloseIdleConnections() { p.closed.Add(1) }

func TestClientCloseIdleConnections(t *testing.T) {
	for _, mode := range []string{"default client", "custom client default transport", "explicit transport"} {
		t.Run(mode, func(t *testing.T) {
			probe := &closeProbeTransport{started: make(chan struct{}), release: make(chan struct{})}
			previous := http.DefaultTransport
			http.DefaultTransport = probe
			t.Cleanup(func() { http.DefaultTransport = previous })
			var hc *http.Client
			if mode == "custom client default transport" {
				hc = &http.Client{}
			} else if mode == "explicit transport" {
				hc = &http.Client{Transport: probe}
			}
			c := NewClient("http://audit.invalid", "", 0, hc, nil)
			done := make(chan error, 1)
			go func() { _, err := c.Health(context.Background()); done <- err }()
			<-probe.started
			close(probe.release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			c.Close()
			if got := probe.closed.Load(); got != 1 {
				t.Fatalf("CloseIdleConnections calls = %d, want 1", got)
			}
			c.Close()
			if got := probe.closed.Load(); got != 2 {
				t.Fatalf("repeated Close calls = %d, want 2", got)
			}
		})
	}
}
