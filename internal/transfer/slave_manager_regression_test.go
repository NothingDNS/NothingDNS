package transfer

import (
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// r31Master is a loopback fake master. Every accepted connection is handed to
// the test through accepted; Close returns how many were accepted in total.
type r31Master struct {
	ln       net.Listener
	accepted chan net.Conn
	total    chan int
}

func newR31Master(t *testing.T) *r31Master {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	m := &r31Master{ln: ln, accepted: make(chan net.Conn, 64), total: make(chan int, 1)}
	go func() {
		n := 0
		for {
			c, err := ln.Accept()
			if err != nil {
				m.total <- n
				return
			}
			n++
			m.accepted <- c
		}
	}()
	return m
}

// serve handles every further connection with h; the returned func closes the
// listener and reports the total number of accepted connections.
func (m *r31Master) serve(h func(net.Conn)) func() int {
	done, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		for {
			select {
			case c := <-m.accepted:
				h(c)
			case <-done:
				return
			}
		}
	}()
	return func() int {
		m.ln.Close()
		n := <-m.total
		close(done)
		<-finished
		return n
	}
}

func r31ReadRequest(c net.Conn) *protocol.Message {
	lb := make([]byte, 2)
	if _, err := io.ReadFull(c, lb); err != nil {
		return nil
	}
	buf := make([]byte, int(lb[0])<<8|int(lb[1]))
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil
	}
	m, err := protocol.UnpackMessage(buf)
	if err != nil {
		return nil
	}
	return m
}

// r31Refuse reads the request and hangs up: the transfer fails.
func r31Refuse(c net.Conn) { _ = r31ReadRequest(c); c.Close() }

// r31ServeAXFR answers with a complete AXFR (SOA serial, one A, SOA).
func r31ServeAXFR(serial uint32) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		req := r31ReadRequest(c)
		if req == nil {
			return
		}
		origin, _ := protocol.ParseName("example.com.")
		www, _ := protocol.ParseName("www.example.com.")
		soa := &protocol.ResourceRecord{Name: origin, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataSOA{MName: origin, RName: origin, Serial: serial, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 60}}
		a := &protocol.ResourceRecord{Name: www, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}}
		resp := &protocol.Message{
			Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess), QDCount: 1},
			Questions: req.Questions,
			Answers:   []*protocol.ResourceRecord{soa, a, soa},
		}
		buf := make([]byte, 2+65535)
		n, err := resp.Pack(buf[2:])
		if err != nil {
			return
		}
		buf[0], buf[1] = byte(n>>8), byte(n)
		_, _ = c.Write(buf[:2+n])
	}
}

func r31Config(masters ...string) SlaveZoneConfig {
	return SlaveZoneConfig{ZoneName: "example.com.", Masters: masters, TransferType: "axfr",
		Timeout: 5 * time.Second, RetryInterval: time.Hour}
}

// TestSlaveManager_TSIGSecretSignsTransfers pins F202: the production wiring
// hands SlaveManager an empty KeyStore plus tsig_key_name/tsig_secret. The
// secret used to be read nowhere, so every keyed transfer failed with
// "TSIG key not found" before dialing and the zone never loaded.
func TestSlaveManager_TSIGSecretSignsTransfers(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789ABCDEF")
	key := &TSIGKey{Name: "xfer-key.", Algorithm: HmacSHA256, Secret: secret}

	m := newR31Master(t)
	var req *protocol.Message
	stop := m.serve(func(c net.Conn) { req = r31ReadRequest(c); c.Close() })
	sm := NewSlaveManager(NewKeyStore())
	cfg := r31Config(m.ln.Addr().String())
	cfg.TSIGKeyName, cfg.TSIGSecret = "xfer-key.", base64.StdEncoding.EncodeToString(secret)
	if err := sm.AddSlaveZone(cfg); err != nil {
		t.Fatalf("AddSlaveZone: %v", err)
	}
	sm.Stop() // barrier: the initial transfer has finished
	if n := stop(); n != 1 {
		t.Fatalf("keyed slave zone sent %d transfer requests, want 1", n)
	}
	if req == nil || VerifyMessage(req, key, nil) != nil {
		t.Fatal("transfer request is not signed with the configured tsig_secret")
	}

	bad := r31Config("127.0.0.1:1")
	bad.TSIGKeyName, bad.TSIGSecret = "xfer-key.", "not base64!!"
	sm2 := NewSlaveManager(NewKeyStore())
	if err := sm2.AddSlaveZone(bad); err == nil {
		t.Fatal("invalid base64 tsig_secret was accepted")
	}
	if sm2.GetSlaveZone("example.com.") != nil {
		t.Fatal("rejected slave zone was still registered")
	}
	sm2.Stop()
}

// TestSlaveManager_FailsOverToNextMaster pins F203: Masters is a redundancy
// list, but only Masters[0] was ever contacted.
func TestSlaveManager_FailsOverToNextMaster(t *testing.T) {
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := deadLn.Addr().String()
	deadLn.Close()

	good := newR31Master(t)
	stop := good.serve(r31ServeAXFR(42))
	sm := NewSlaveManager(NewKeyStore())
	if err := sm.AddSlaveZone(r31Config(dead, good.ln.Addr().String())); err != nil {
		t.Fatalf("AddSlaveZone: %v", err)
	}
	sm.Stop()
	if n := stop(); n != 1 {
		t.Fatalf("second master served %d transfers, want 1", n)
	}
	if got := sm.GetSlaveZone("example.com.").GetLastSerial(); got != 42 {
		t.Fatalf("serial after failover = %d, want 42", got)
	}
}

// TestSlaveManager_NotifyStormCoalesced pins F204: each NOTIFY used to spawn
// its own concurrent transfer and, on failure, its own retry chain. NOTIFYs
// arriving during a transfer must fold into one follow-up run, and at most
// one retry chain may exist per zone. Ordering is gated on the fake master's
// accepted connections; Stop is the completion barrier.
func TestSlaveManager_NotifyStormCoalesced(t *testing.T) {
	m := newR31Master(t)
	sm := NewSlaveManager(nil)
	sz, err := NewSlaveZone(r31Config(m.ln.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	sz.LastSerial = 1
	sm.slaveZones["example.com."] = sz
	sm.clients["example.com."] = NewIXFRClient(sz.Config.Masters[0])

	notify := func() { sm.handleNotify(&NOTIFYRequest{ZoneName: "example.com.", Serial: 2}) }
	notify()
	first := <-m.accepted // first transfer is in flight
	for i := 0; i < 10; i++ {
		notify()
	}
	r31Refuse(first)
	r31Refuse(<-m.accepted) // the single coalesced follow-up run
	stop := m.serve(r31Refuse)
	sm.Stop()
	if n := stop(); n != 2 {
		t.Fatalf("11 NOTIFYs produced %d transfers, want 2 (one + one coalesced re-run)", n)
	}
	sz.mu.RLock()
	retries := sz.retries
	sz.mu.RUnlock()
	if retries != 1 {
		t.Fatalf("retries=%d, want one retry chain", retries)
	}

	// A transfer failing while a retry wait is pending must not fork a
	// second retry chain.
	m2 := newR31Master(t)
	stop2 := m2.serve(r31Refuse)
	sm2 := NewSlaveManager(nil)
	sz2, _ := NewSlaveZone(r31Config(m2.ln.Addr().String()))
	sz2.LastSerial = 1
	sm2.slaveZones["example.com."] = sz2
	sm2.clients["example.com."] = NewIXFRClient(sz2.Config.Masters[0])
	sm2.performZoneTransfer("example.com.")
	sm2.performZoneTransfer("example.com.")
	sm2.Stop()
	stop2()
	sz2.mu.RLock()
	retries = sz2.retries
	sz2.mu.RUnlock()
	if retries != 1 {
		t.Fatalf("two failures during one retry wait started %d retry chains, want 1", retries)
	}
}
