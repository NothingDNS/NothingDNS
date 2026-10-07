package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dnscookie"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// R53 regressions: TSIG-signed AXFR/IXFR between this server and this
// repository's transfer clients (F312, F313) and signing after the pipeline's
// response-writer rewrites (F315).

func xfrTSIGKey() *transfer.TSIGKey {
	return &transfer.TSIGKey{Name: "r53-xfr-key.example.", Algorithm: transfer.HmacSHA256, Secret: []byte("0123456789abcdef0123456789abcdef")}
}

type xfrTSIGMasterOpts struct {
	keyed, authOnly, cookies bool
	extraHosts               int // additional A records, for long streams
}

// xfrTSIGZone is example.com serial 2 with NS, ns1 A, www A (+ extraHosts).
func xfrTSIGZone(extraHosts int) *zone.Zone {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", TTL: 300, MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 2, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}
	z.Records["example.com."] = []zone.Record{{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."}}
	z.Records["ns1.example.com."] = []zone.Record{{Name: "ns1.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.53"}}
	z.Records["www.example.com."] = []zone.Record{{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.2"}}
	for i := 0; i < extraHosts; i++ {
		name := fmt.Sprintf("h%d.example.com.", i)
		z.Records[name] = []zone.Record{{Name: name, TTL: 300, Class: "IN", Type: "A", RData: fmt.Sprintf("198.51.100.%d", i%250+1)}}
	}
	return z
}

// xfrTSIGMaster serves the full query pipeline (ServeDNS) over loopback TCP.
func xfrTSIGMaster(t *testing.T, o xfrTSIGMasterOpts) string {
	t.Helper()
	h := newTestHandler()
	h.config.Resolution.AuthoritativeOnly = o.authOnly
	if o.cookies {
		jar, err := dnscookie.NewCookieJar(time.Hour)
		if err != nil {
			t.Fatalf("NewCookieJar: %v", err)
		}
		h.cookieJar = jar
	}
	zones := map[string]*zone.Zone{"example.com.": xfrTSIGZone(o.extraHosts)}
	opts := []transfer.AXFRServerOption{transfer.WithAllowList([]string{"127.0.0.0/8"})}
	if o.keyed {
		ks := transfer.NewKeyStore()
		ks.AddKey(xfrTSIGKey())
		opts = append(opts, transfer.WithKeyStore(ks))
	}
	h.transfer.AXFRServer = transfer.NewAXFRServer(zones, opts...)
	h.transfer.IXFRServer = transfer.NewIXFRServer(h.transfer.AXFRServer)
	h.transfer.IXFRServer.RecordChange("example.com.", 1, 2,
		[]zone.RecordChange{{Name: "www.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.2"}},
		[]zone.RecordChange{{Name: "www.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.1"}})
	srv := server.NewTCPServerWithWorkers("127.0.0.1:0", h, 1)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Stop() })
	return srv.Addr().String()
}

// xfrRawAXFR sends a signed AXFR request (optionally with EDNS and a client
// cookie) and returns the request MAC and every response message up to the
// closing SOA, as received.
func xfrRawAXFR(t *testing.T, addr string, key *transfer.TSIGKey, edns, cookie bool) ([]byte, []*protocol.Message) {
	t.Helper()
	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{Header: protocol.Header{ID: 0x5353, QDCount: 1},
		Questions: []*protocol.Question{{Name: name, QType: protocol.TypeAXFR, QClass: protocol.ClassIN}}}
	if edns {
		req.SetEDNS0(1232, false)
		if cookie {
			req.GetOPT().Data.(*protocol.RDataOPT).AddOption(protocol.OptionCodeCookie, []byte("r53cooki"))
		}
	}
	tsigRR, err := transfer.SignMessage(req, key, 300)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req.Additionals = append(req.Additionals, tsigRR)
	reqMAC, err := transfer.TSIGRequestMAC(req)
	if err != nil {
		t.Fatalf("request MAC: %v", err)
	}
	buf := make([]byte, 2+65535)
	n, err := req.Pack(buf[2:])
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	binary.BigEndian.PutUint16(buf, uint16(n))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(buf[:2+n]); err != nil {
		t.Fatalf("write: %v", err)
	}
	var msgs []*protocol.Message
	soas := 0
	for soas < 2 {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			t.Fatalf("read len after %d messages: %v", len(msgs), err)
		}
		body := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(conn, body); err != nil {
			t.Fatalf("read body: %v", err)
		}
		msg, err := protocol.UnpackMessage(body)
		if err != nil {
			t.Fatalf("unpack: %v", err)
		}
		if msg.Header.Flags.RCODE != protocol.RcodeSuccess {
			t.Fatalf("AXFR rcode %d", msg.Header.Flags.RCODE)
		}
		for _, rr := range msg.Answers {
			if rr.Type == protocol.TypeSOA {
				soas++
			}
		}
		msgs = append(msgs, msg)
	}
	return reqMAC, msgs
}

// F312, F313: a TSIG-keyed transfer from this server must verify in this
// repository's AXFR/IXFR clients (one RFC 8945 §5.3.1 chain bound to the
// request MAC). Before R53 the AXFR client rejected the last message's MAC and
// the IXFR response carried no TSIG at all.
func TestTransferTSIG_KeyedRoundTripWithOwnClients(t *testing.T) {
	key := xfrTSIGKey()
	addr := xfrTSIGMaster(t, xfrTSIGMasterOpts{keyed: true})

	if recs, err := transfer.NewAXFRClient(addr, transfer.WithAXFRTimeout(5*time.Second)).Transfer("example.com.", key); err != nil || len(recs) != 5 {
		t.Fatalf("keyed AXFR: records=%d err=%v, want 5 records", len(recs), err)
	}
	if recs, err := transfer.NewIXFRClient(addr, transfer.WithIXFRTimeout(5*time.Second)).Transfer("example.com.", 1, key); err != nil || len(recs) != 6 {
		t.Fatalf("keyed incremental IXFR: records=%d err=%v, want 6 records", len(recs), err)
	}
	if recs, err := transfer.NewIXFRClient(addr, transfer.WithIXFRTimeout(5*time.Second)).Transfer("example.com.", 2, key); err != nil || len(recs) != 1 {
		t.Fatalf("keyed up-to-date IXFR: records=%d err=%v, want the lone SOA", len(recs), err)
	}
	// Serial not covered by the journal: HandleIXFR answers with the full zone.
	if recs, err := transfer.NewIXFRClient(addr, transfer.WithIXFRTimeout(5*time.Second)).Transfer("example.com.", 0, key); err != nil || len(recs) != 5 {
		t.Fatalf("keyed AXFR-style IXFR: records=%d err=%v, want 5 records", len(recs), err)
	}

	// A long stream: every message stays in the chain.
	long := xfrTSIGMaster(t, xfrTSIGMasterOpts{keyed: true, extraHosts: 250})
	if recs, err := transfer.NewAXFRClient(long, transfer.WithAXFRTimeout(5*time.Second)).Transfer("example.com.", key); err != nil || len(recs) != 255 {
		t.Fatalf("keyed 255-record AXFR: records=%d err=%v", len(recs), err)
	}

	// A different secret under the same key name must still fail.
	wrong := &transfer.TSIGKey{Name: key.Name, Algorithm: key.Algorithm, Secret: []byte("ffffffffffffffffffffffffffffffff")}
	if _, err := transfer.NewAXFRClient(addr, transfer.WithAXFRTimeout(5*time.Second)).Transfer("example.com.", wrong); err == nil {
		t.Fatal("AXFR with a wrong secret accepted")
	}

	// Unkeyed transfers are unchanged and carry no TSIG.
	plain := xfrTSIGMaster(t, xfrTSIGMasterOpts{})
	if recs, err := transfer.NewAXFRClient(plain, transfer.WithAXFRTimeout(5*time.Second)).Transfer("example.com.", nil); err != nil || len(recs) != 5 {
		t.Fatalf("unkeyed AXFR: records=%d err=%v", len(recs), err)
	}
	if recs, err := transfer.NewIXFRClient(plain, transfer.WithIXFRTimeout(5*time.Second)).Transfer("example.com.", 1, nil); err != nil || len(recs) != 6 {
		t.Fatalf("unkeyed IXFR: records=%d err=%v", len(recs), err)
	}
}

// F315: the pipeline's response writers (header policy: RA/OPCODE/RD/CD and
// OPT normalization; DNS cookies) must not change a transfer message after it
// was signed, and the TSIG RR must stay last.
func TestTransferTSIG_SignedAfterResponseWriterRewrites(t *testing.T) {
	key := xfrTSIGKey()
	cases := []struct {
		name               string
		opts               xfrTSIGMasterOpts
		edns, cookie, noRA bool
	}{
		{name: "plain request", opts: xfrTSIGMasterOpts{keyed: true}},
		{name: "authoritative_only clears RA", opts: xfrTSIGMasterOpts{keyed: true, authOnly: true}, noRA: true},
		{name: "EDNS request gets OPT", opts: xfrTSIGMasterOpts{keyed: true}, edns: true},
		{name: "cookie request gets server cookie", opts: xfrTSIGMasterOpts{keyed: true, cookies: true}, edns: true, cookie: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := xfrTSIGMaster(t, tc.opts)
			reqMAC, msgs := xfrRawAXFR(t, addr, key, tc.edns, tc.cookie)
			for i, m := range msgs {
				if n := len(m.Additionals); n == 0 || m.Additionals[n-1].Type != protocol.TypeTSIG {
					t.Fatalf("message %d: TSIG is not the last additional record", i)
				}
				if tc.edns && m.GetOPT() == nil {
					t.Fatalf("message %d: EDNS request answered without OPT", i)
				}
				if tc.noRA && m.Header.Flags.RA {
					t.Fatalf("message %d: RA set on an authoritative-only server", i)
				}
			}
			if err := transfer.VerifyMessage(msgs[0], key, reqMAC); err != nil {
				t.Fatalf("first message does not verify against the request MAC: %v", err)
			}
		})
	}
}
