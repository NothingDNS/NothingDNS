package dashboard

import (
	"encoding/json"
	"testing"
	"time"
)

// Live query events streamed to non-admin viewers must carry masked client
// IPs, like the query log API; admins see the full address.
func TestBroadcastRedactsClientIPForNonAdmins(t *testing.T) {
	server := NewServer()
	defer server.Stop()

	admin := &Client{conn: &MockWebSocketConn{}, send: make(chan []byte, 4)}
	viewer := &Client{conn: &MockWebSocketConn{}, send: make(chan []byte, 4), redactIPs: true}
	server.AddClient(admin)
	server.AddClient(viewer)

	server.RecordQuery(&QueryEvent{ClientIP: "192.0.2.77", Domain: "example.com", QueryType: "A"})

	read := func(c *Client) string {
		t.Helper()
		select {
		case data := <-c.send:
			var msg BroadcastMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				t.Fatal(err)
			}
			return msg.Event.ClientIP
		case <-time.After(2 * time.Second):
			t.Fatal("no broadcast received")
			return ""
		}
	}
	if got := read(admin); got != "192.0.2.77" {
		t.Errorf("admin client IP = %q, want the full address", got)
	}
	if got := read(viewer); got != "192.0.2.xxx" {
		t.Errorf("viewer client IP = %q, want 192.0.2.xxx", got)
	}

	// The stored event (shared with the query log) must stay unmasked.
	recent, _ := server.GetStats().GetRecentQueries(0, 10)
	if len(recent) != 1 || recent[0].ClientIP != "192.0.2.77" {
		t.Errorf("stored events changed by redaction: %+v", recent)
	}
}

func TestRedactQueryEventsCopies(t *testing.T) {
	in := []*QueryEvent{{ClientIP: "2001:db8::1"}, nil}
	out := RedactQueryEvents(in)
	if out[0].ClientIP != "2001:db8::xxxx" || in[0].ClientIP != "2001:db8::1" || out[1] != nil {
		t.Errorf("RedactQueryEvents = %+v (input %+v)", out[0], in[0])
	}
}
