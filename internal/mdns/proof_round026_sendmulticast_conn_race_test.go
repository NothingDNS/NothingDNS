// Round-026 proof: sendMulticast reads Responder.conn with NO lock, while
// Stop() writes the same field (r.conn = nil) under r.lifecycleMu. The read
// and the write are ordered by no common mutex, so the pair is a data race
// on a pointer field (go test -race flags it).
//
// READER  (sendMulticast, mdns.go:691 and :706):
//
//	if r.conn == nil { return }        // read #1, no lock
//	... writeUDPPacket(r.conn, ...)    // read #2, no lock
//
// WRITER  (Stop, mdso.go:222):
//
//	r.conn = nil                        // write, under r.lifecycleMu only
//
// Both are reachable concurrently in production: sendMulticast runs on the
// receiveLoop / maintenanceLoop goroutines (via handleQuery / announceAll),
// while Stop runs on the caller's goroutine, and Stop only reaches
// r.wg.Wait() AFTER it has already nil'd the field — so the WaitGroup does
// not order the two accesses either.
//
// WHY THIS HARNESS IS DETERMINISTIC (the earlier attempt was flaky): driving
// the race through Start() needs net.ListenMulticastUDP, which is unreliable
// in a container. This test builds the Responder DIRECTLY (same package) with
// a plain loopback *net.UDPConn — no multicast join — so the unsynchronized
// access pair is exercised every run and the race detector reports it
// deterministically.
//
// CLAIM  (Concurrent): sendMulticast loop racing Stop() -> data race on r.conn.
// CONTROL (Sequential): the same send-then-Stop on one goroutine is correctly
//
//	synchronized (no concurrent access), proving the harness itself is valid
//	and the failure is specifically the missing synchronization, not an
//	artifact of constructing the Responder or packing the message.
package mdns

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// newRaceResponder builds a started-enough Responder around a plain loopback
// UDP socket. running=true + a real stopCh let the production Stop() run its
// full body (including r.conn = nil) without needing a multicast group.
func newRaceResponder(t *testing.T) (*Responder, *net.UDPConn) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	r := &Responder{
		conn:    conn,
		running: true,
		stopCh:  make(chan struct{}),
	}
	return r, conn
}

func raceMsg(t *testing.T) *protocol.Message {
	t.Helper()
	name, err := protocol.ParseName("probe.local.")
	if err != nil {
		t.Fatalf("parse name: %v", err)
	}
	return &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Questions: []*protocol.Question{{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
}

var raceDst = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// CONTROL: sequential access is not a race. Same Responder construction and
// message as the claim; only the concurrency differs.
func TestSendMulticastConnRace_Control_Sequential(t *testing.T) {
	r, _ := newRaceResponder(t)
	r.sendMulticast(raceMsg(t), raceDst)
	r.Stop()
}

// CLAIM: sendMulticast (reader, inside a wg-tracked loop as in production)
// races with Stop() (writer, r.conn = nil) on the Responder.conn field.
func TestSendMulticastConnRace_Concurrent(t *testing.T) {
	r, conn := newRaceResponder(t)
	defer conn.Close()

	msg := raceMsg(t)
	started := make(chan struct{})

	// Model the ONLY real caller of sendMulticast: it runs inside a
	// wg-tracked loop goroutine (receiveLoop / maintenanceLoop via
	// handleQuery / announceAll), exactly as in production. A reader OUTSIDE
	// the WaitGroup would not be ordered by wg.Wait() and is unfaithful.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		// Signal that the send loop is now running. Every read below happens
		// AFTER this signal, so none of them is ordered-before Stop()'s write
		// of r.conn — which is exactly the unsynchronized window in the
		// original code. The loop models a burst of in-flight mDNS responses
		// (an in-flight handleQuery keeps sending and does not re-check
		// stopCh between sends).
		close(started)
		for i := 0; i < 200000; i++ {
			r.sendMulticast(msg, raceDst) // reads r.conn
		}
	}()

	<-started
	// With the fix, Stop() runs r.wg.Wait() BEFORE writing r.conn = nil, so
	// the writer is ordered after every reader and the race is gone. Without
	// the fix, the write races the still-running reader above.
	r.Stop()
}
