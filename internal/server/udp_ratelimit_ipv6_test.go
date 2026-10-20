package server

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// The transport's per-source UDP cap counts an IPv6 client by its /64: one
// line owns 2^64 addresses, so a per-address count never limits it (F709 did
// the same for connection caps).
func TestUDPRateLimitCountsIPv6PerSlash64(t *testing.T) {
	name, err := protocol.ParseName("example.com.")
	if err != nil {
		t.Fatal(err)
	}
	query := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewQueryFlags(), QDCount: 1},
		Questions: []*protocol.Question{{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
	wire := make([]byte, 512)
	n, err := query.Pack(wire)
	if err != nil {
		t.Fatal(err)
	}
	wire = wire[:n]

	run := func(sources []string, limit int) int64 {
		var handled int64
		server := NewUDPServerWithWorkers("127.0.0.1:0", HandlerFunc(func(ResponseWriter, *protocol.Message) {
			atomic.AddInt64(&handled, 1)
		}), 2)
		server.SetRateLimit(limit)

		next := int32(-1)
		stop := make(chan struct{})
		server.ListenWithConn(&mockUDPConnWithControl{readFn: func(buf []byte) (int, *net.UDPAddr, error) {
			i := int(atomic.AddInt32(&next, 1))
			if i >= len(sources) {
				<-stop
				return 0, nil, net.ErrClosed
			}
			return copy(buf, wire), &net.UDPAddr{IP: net.ParseIP(sources[i]), Port: 5353}, nil
		}})
		done := make(chan error, 1)
		go func() { done <- server.Serve() }()

		deadline := time.Now().Add(2 * time.Second)
		for atomic.LoadInt32(&next) < int32(len(sources)) && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond) // let the workers drain
		close(stop)
		server.Stop()
		<-done
		return atomic.LoadInt64(&handled)
	}

	// Control: one source over the limit is capped.
	same := make([]string, 10)
	for i := range same {
		same[i] = "2001:db8:1:1::1"
	}
	if got := run(same, 3); got != 3 {
		t.Fatalf("control: single source handled %d, want 3", got)
	}

	// Ten addresses of one /64 share the budget.
	rotating := make([]string, 10)
	for i := range rotating {
		rotating[i] = fmt.Sprintf("2001:db8:1:1::%x", i+1)
	}
	if got := run(rotating, 3); got != 3 {
		t.Fatalf("FAIL: %d queries from one /64 handled with a limit of 3", got)
	}

	// Different /64s are independent.
	apart := make([]string, 4)
	for i := range apart {
		apart[i] = fmt.Sprintf("2001:db8:1:%x::1", i+1)
	}
	if got := run(apart, 1); got != 4 {
		t.Fatalf("control: four /64s handled %d, want 4", got)
	}
}
