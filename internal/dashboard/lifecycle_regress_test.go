package dashboard

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// DoH/DoWS queries still reach RecordQuery after main has stopped the
// dashboard; recording must not send on the closed broadcast channel (F632).
func TestRecordQueryAfterStopDoesNotPanic(t *testing.T) {
	s := NewServer()
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			s.RecordQuery(&QueryEvent{Domain: "example.com", QueryType: "A"})
		}()
	}
	s.Stop()
	close(gate)
	wg.Wait()
	s.RecordQuery(&QueryEvent{Domain: "example.com", QueryType: "A"})
	if got := s.GetStats().QueriesTotal; got != 9 {
		t.Errorf("QueriesTotal = %d, want 9", got)
	}
}

// At MaxWebSocketClients the upgrade is refused instead of parking an
// unregistered connection in ClientLoop (F633).
func TestWebSocketConnectionLimitEnforced(t *testing.T) {
	upgrade := func(prefill int) string {
		s := NewServer()
		defer s.Stop()
		s.SetAuthToken("tok")
		s.mu.Lock()
		for i := 0; i < prefill; i++ {
			s.clients[&Client{conn: &MockWebSocketConn{}, send: make(chan []byte, 1)}] = struct{}{}
		}
		s.mu.Unlock()

		ts := httptest.NewServer(s)
		defer ts.Close()
		c, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		req := "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
			"Authorization: Bearer tok\r\n\r\n"
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		return resp.Status
	}
	if got := upgrade(MaxWebSocketClients - 1); !strings.HasPrefix(got, "101") {
		t.Errorf("below limit: status %q, want 101", got)
	}
	if got := upgrade(MaxWebSocketClients); !strings.HasPrefix(got, "503") {
		t.Errorf("at limit: status %q, want 503", got)
	}
}
