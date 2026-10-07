package transfer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// F547: the primary-side NOTIFY sender gained cancellation (so the server's
// notifier stops cleanly on shutdown) and optional TSIG signing.

// TestNOTIFYSender_ContextCancelEndsWait: gated — ctx is cancelled only after
// the secondary has received the first datagram; the long per-attempt timeout
// would otherwise keep the sender waiting for minutes.
func TestNOTIFYSender_ContextCancelEndsWait(t *testing.T) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got := make(chan struct{}, 8)
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, _, err := c.ReadFromUDP(buf); err != nil {
				return
			}
			got <- struct{}{}
		}
	}()

	s := NewNOTIFYSender("")
	s.SetTimeout(10 * time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.SendNOTIFYContext(ctx, "example.com.", 5, c.LocalAddr().String()) }()

	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("NOTIFY datagram never arrived")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SendNOTIFYContext did not return after cancel")
	}

	// Already-cancelled context: nothing is sent.
	if err := s.SendNOTIFYContext(ctx, "example.com.", 6, c.LocalAddr().String()); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled ctx: err = %v, want context.Canceled", err)
	}
}

// TestNOTIFYSender_TSIGSigned: with a key set, the NOTIFY carries a TSIG the
// secondary can verify; without one (control) it carries none.
func TestNOTIFYSender_TSIGSigned(t *testing.T) {
	key := &TSIGKey{Name: "notify-key.example.", Algorithm: HmacSHA256, Secret: []byte("f547-notify-secret-0123456789abc")}
	for _, signed := range []bool{false, true} {
		verdict := make(chan error, 1)
		c, seen := r32Slave(t, func(_ int, req *protocol.Message) [][]byte {
			var v error
			if signed {
				v = VerifyMessage(req, key, nil)
			} else if _, err := findTSIGRecord(req); err == nil {
				v = errors.New("unsigned sender produced a TSIG record")
			}
			if req.Header.Flags.Opcode != protocol.OpcodeNotify || len(req.Answers) != 1 {
				v = errors.New("not a NOTIFY with an SOA hint")
			}
			select {
			case verdict <- v:
			default:
			}
			return [][]byte{r32Reply(req, req.Header.ID, protocol.RcodeSuccess)}
		})
		s := NewNOTIFYSender("")
		s.SetTimeout(5 * time.Second)
		if signed {
			s.SetTSIGKey(key)
		}
		err := s.SendNOTIFYContext(context.Background(), "example.com.", 9, c.LocalAddr().String())
		c.Close()
		<-seen
		if err != nil {
			t.Fatalf("signed=%v: SendNOTIFYContext: %v", signed, err)
		}
		if v := <-verdict; v != nil {
			t.Fatalf("signed=%v: %v", signed, v)
		}
	}
}
