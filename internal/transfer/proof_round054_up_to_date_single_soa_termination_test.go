package transfer

// Regression test (round 054, resolving a round-053 gap): the up-to-date
// single-SOA answer terminates at the end of the stream, and a master that
// closes after writing it can surface that close at EITHER read site. On a
// net.Pipe the peer's Close makes the next SetReadDeadline fail with
// "read/write on closed pipe" instead of letting the next Read return EOF,
// so the round-053 EOF-only leg raced the writer goroutine and intermittently
// dropped a complete up-to-date answer (observed in the 2026-10-19 full-suite
// run: F198's control failed with "got 0 records err=setting read deadline:
// io: read/write on closed pipe"). The stub here makes that deterministic.

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// connFailingDeadlineAfterN delegates to a real pipe but fails
// SetReadDeadline from the Nth call on, as a peer-closed pipe does.
type connFailingDeadlineAfterN struct {
	net.Conn
	calls int
}

func (c *connFailingDeadlineAfterN) SetReadDeadline(t time.Time) error {
	c.calls++
	if c.calls >= 2 {
		return net.ErrClosed
	}
	return c.Conn.SetReadDeadline(t)
}

func frameSingleSOA(t *testing.T, id uint16, serial uint32) []byte {
	t.Helper()
	msg := &protocol.Message{
		Header:  protocol.Header{ID: id, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{mkSOARR(t, serial)},
	}
	return frameMessage(t, msg)
}

func TestIXFRClient_UpToDateSingleSOATerminatesOnClosedPipe(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	stub := &connFailingDeadlineAfterN{Conn: clientConn}
	go func() {
		defer serverConn.Close()
		frame := frameSingleSOA(t, 0x4242, 42)
		if _, err := serverConn.Write(frame); err != nil {
			return
		}
	}()

	recs, err := NewIXFRClient("unused:53").receiveIXFRResponseForRequest(stub, 0x4242, nil, 42, nil)
	if err != nil {
		t.Fatalf("FAIL: complete up-to-date single SOA dropped when the peer's close beat the next SetReadDeadline: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("FAIL: got %d records, want the single up-to-date SOA", len(recs))
	}
	_ = io.EOF // keep the io import tied to the truncation semantics documented above
}

// Controls: the same closed-pipe failure mode must stay an error whenever the
// single received record is not an up-to-date candidate (F199), and a
// non-candidate stream still errors.
func TestIXFRClient_ClosedPipeNonCandidateStillErrors(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	stub := &connFailingDeadlineAfterN{Conn: clientConn}
	go func() {
		defer serverConn.Close()
		msg := &protocol.Message{
			Header:  protocol.Header{ID: 0x4242, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Answers: []*protocol.ResourceRecord{mkSOARR(t, 3)},
		}
		if _, err := serverConn.Write(frameMessage(t, msg)); err != nil {
			return
		}
	}()

	// Client serial 2: SOA(3) is strictly newer, so a lone leading SOA is NOT
	// an up-to-date answer; the closed pipe must surface as an error (truncated
	// stream), never as a completed transfer.
	if _, err := NewIXFRClient("unused:53").receiveIXFRResponseForRequest(stub, 0x4242, nil, 2, nil); err == nil {
		t.Fatal("FAIL: closed-pipe error swallowed for a non-candidate single SOA (serial newer than client)")
	}
}
