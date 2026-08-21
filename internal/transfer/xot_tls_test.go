// NothingDNS - end-to-end TLS transport tests for the XoT server side
// (RFC 9103). The pre-existing xot_request_validation_test.go covers the
// request-validation branches with fake connections; this suite drives the
// real AcceptLoop → handleConnection → handleMessage → handle{AXFR,IXFR}
// path over genuine TLS with a self-signed certificate fixture, closing
// the AcceptLoop (13.3%), handleIXFRRequest (16.7%), and handleAXFRRequest
// (26.1%) coverage gaps.

package transfer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// newXoTCertFiles writes a fresh self-signed RSA-2048 certificate and key
// to dir (buildXoTTLSConfig loads from files) and returns the paths plus
// the parsed pair for the client's trust pool.
func newXoTCertFiles(t *testing.T, dir string) (certFile, keyFile string, pair tls.Certificate) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509 cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	certFile = filepath.Join(dir, "xot-cert.pem")
	keyFile = filepath.Join(dir, "xot-key.pem")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	pair, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	return certFile, keyFile, pair
}

// newXoTTestZone builds a zone with a SOA and n extra A records.
func newXoTTestZone(origin string, serial uint32, extraRecords int) *zone.Zone {
	z := zone.NewZone(origin)
	z.SOA = &zone.SOARecord{
		Name: origin, TTL: 300,
		MName: "ns1." + origin, RName: "admin." + origin,
		Serial: serial, Refresh: 7200, Retry: 900, Expire: 1209600, Minimum: 300,
	}
	for i := 0; i < extraRecords; i++ {
		name := fmt.Sprintf("host%d.%s", i, origin)
		z.Records[name] = append(z.Records[name], zone.Record{
			Name: name, Type: "A", TTL: 300, Class: "IN", RData: "192.0.2.1",
		})
	}
	return z
}

// startXoTTestServer builds a deny-by-default-safe XoT server (allowlist
// grants 127.0.0.1/32), binds an ephemeral TLS listener on the server's own
// tls.Config (port 853 is privileged and can't be used in tests), and runs
// AcceptLoop. Returns the server and the certificate for client trust.
func startXoTTestServer(t *testing.T, zones map[string]*zone.Zone, allowedCIDR string) (*XoTServer, tls.Certificate) {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, pair := newXoTCertFiles(t, dir)
	srv, err := NewXoTServer(zones, &XoTConfig{
		CertFile:        certFile,
		KeyFile:         keyFile,
		AllowedNetworks: []string{allowedCIDR},
	}, nil)
	if err != nil {
		t.Fatalf("NewXoTServer: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.tlsConfig)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	srv.mu.Lock()
	srv.listener = ln
	srv.address = "127.0.0.1"
	// Addr() formats address:port — reflect the ephemeral listener's real
	// port, not the default 853 the config path never reached.
	srv.port = ln.Addr().(*net.TCPAddr).Port
	srv.mu.Unlock()

	go srv.AcceptLoop()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, pair
}

// xotDial connects a TLS client that trusts only the fixture certificate.
func xotDial(t *testing.T, addr string, pair tls.Certificate) *tls.Conn {
	t.Helper()
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}
	return conn
}

// xotSendFrame writes one length-prefixed DNS message (RFC 9103 framing).
func xotSendFrame(t *testing.T, conn net.Conn, msg *protocol.Message) {
	t.Helper()
	buf := make([]byte, 2+65535)
	n, err := msg.Pack(buf[2:])
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	binary.BigEndian.PutUint16(buf[:2], uint16(n))
	if _, err := conn.Write(buf[:2+n]); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

// xotReadFrame reads one length-prefixed DNS message and unpacks it.
func xotReadFrame(t *testing.T, conn net.Conn) *protocol.Message {
	t.Helper()
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatalf("read prefix: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read body (%d bytes): %v", len(body), err)
	}
	msg, err := protocol.UnpackMessage(body)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return msg
}

func xotTransferQuery(id uint16, qname string, qtype uint16) *protocol.Message {
	q, _ := protocol.NewQuestion(qname, qtype, protocol.ClassIN)
	return &protocol.Message{
		Header:    protocol.Header{ID: id, Flags: protocol.NewQueryFlags(), QDCount: 1},
		Questions: []*protocol.Question{q},
	}
}

// TestXoT_AXFROverTLS_FullTransfer drives the complete path: TLS accept,
// length-prefixed read, dispatch, ACL pass, zone lookup, and a chunked
// full-zone AXFR (60 records forces sendAXFRResponse's 50-record chunking
// into multiple messages; RFC 5936 SOA-first/SOA-last framing).
func TestXoT_AXFROverTLS_FullTransfer(t *testing.T) {
	const extra = 60
	zones := map[string]*zone.Zone{"example.com.": newXoTTestZone("example.com.", 2026082101, extra)}
	srv, pair := startXoTTestServer(t, zones, "127.0.0.1/32")

	conn := xotDial(t, srv.Addr(), pair)
	xotSendFrame(t, conn, xotTransferQuery(0x4142, "example.com.", protocol.TypeAXFR))

	// SOA + 60 records + SOA = 62 answers → chunked into 2 frames (50 max).
	var answers []*protocol.ResourceRecord
	for range 2 {
		resp := xotReadFrame(t, conn)
		answers = append(answers, resp.Answers...)
	}
	if len(answers) != extra+2 {
		t.Fatalf("total answers = %d, want %d (SOA + records + SOA)", len(answers), extra+2)
	}
	if answers[0].Type != protocol.TypeSOA {
		t.Errorf("first answer type = %d, want SOA", answers[0].Type)
	}
	if answers[len(answers)-1].Type != protocol.TypeSOA {
		t.Errorf("last answer type = %d, want SOA (RFC 5936 closing SOA)", answers[len(answers)-1].Type)
	}
}

// TestXoT_IXFROverTLS_CurrentSerialSOAOnly: a client presenting the
// current serial gets the SOA-only "no changes needed" response (RFC 1995).
func TestXoT_IXFROverTLS_CurrentSerialSOAOnly(t *testing.T) {
	const serial = uint32(2026082101)
	zones := map[string]*zone.Zone{"example.com.": newXoTTestZone("example.com.", serial, 5)}
	srv, pair := startXoTTestServer(t, zones, "127.0.0.1/32")

	conn := xotDial(t, srv.Addr(), pair)
	req := xotTransferQuery(0x4344, "example.com.", protocol.TypeIXFR)
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")
	origin, _ := protocol.ParseName("example.com.")
	req.Authorities = []*protocol.ResourceRecord{{
		Name: origin, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataSOA{MName: mname, RName: rname, Serial: serial},
	}}
	xotSendFrame(t, conn, req)

	resp := xotReadFrame(t, conn)
	if len(resp.Answers) != 1 || resp.Answers[0].Type != protocol.TypeSOA {
		t.Fatalf("IXFR with current serial: answers = %d, want exactly one SOA", len(resp.Answers))
	}
	if soa, ok := resp.Answers[0].Data.(*protocol.RDataSOA); !ok || soa.Serial != serial {
		t.Errorf("SOA serial = %+v, want %d", resp.Answers[0].Data, serial)
	}
}

// TestXoT_IXFROverTLS_FallbackToAXFR: an older client serial with no
// journal store falls back to a full-zone transfer.
func TestXoT_IXFROverTLS_FallbackToAXFR(t *testing.T) {
	const extra = 5
	zones := map[string]*zone.Zone{"example.com.": newXoTTestZone("example.com.", 2026082101, extra)}
	srv, pair := startXoTTestServer(t, zones, "127.0.0.1/32")

	conn := xotDial(t, srv.Addr(), pair)
	req := xotTransferQuery(0x4546, "example.com.", protocol.TypeIXFR)
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")
	origin, _ := protocol.ParseName("example.com.")
	req.Authorities = []*protocol.ResourceRecord{{
		Name: origin, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataSOA{MName: mname, RName: rname, Serial: 2026082001},
	}}
	xotSendFrame(t, conn, req)

	resp := xotReadFrame(t, conn)
	if len(resp.Answers) != extra+2 {
		t.Fatalf("IXFR fallback answers = %d, want %d (full AXFR)", len(resp.Answers), extra+2)
	}
	if resp.Answers[0].Type != protocol.TypeSOA {
		t.Errorf("first answer type = %d, want SOA", resp.Answers[0].Type)
	}
}

// TestXoT_UnknownZoneNXDOMAIN: AXFR and IXFR for a zone the server does
// not host both answer NXDOMAIN.
func TestXoT_UnknownZoneNXDOMAIN(t *testing.T) {
	zones := map[string]*zone.Zone{"example.com.": newXoTTestZone("example.com.", 1, 1)}
	srv, pair := startXoTTestServer(t, zones, "127.0.0.1/32")

	conn := xotDial(t, srv.Addr(), pair)
	for i, qtype := range []uint16{protocol.TypeAXFR, protocol.TypeIXFR} {
		xotSendFrame(t, conn, xotTransferQuery(uint16(0x5000+i), "absent.test.", qtype))
		resp := xotReadFrame(t, conn)
		if resp.Header.Flags.RCODE != protocol.RcodeNameError {
			t.Errorf("qtype %d: RCODE = %d, want NXDOMAIN", qtype, resp.Header.Flags.RCODE)
		}
	}
}

// TestXoT_ZoneWithoutSOAServfail: a hosted zone lacking a SOA cannot be
// transferred; both handlers must answer SERVFAIL, not hang or crash.
func TestXoT_ZoneWithoutSOAServfail(t *testing.T) {
	broken := zone.NewZone("broken.test.")
	zones := map[string]*zone.Zone{"broken.test.": broken}
	srv, pair := startXoTTestServer(t, zones, "127.0.0.1/32")

	conn := xotDial(t, srv.Addr(), pair)
	for i, qtype := range []uint16{protocol.TypeAXFR, protocol.TypeIXFR} {
		xotSendFrame(t, conn, xotTransferQuery(uint16(0x6000+i), "broken.test.", qtype))
		resp := xotReadFrame(t, conn)
		if resp.Header.Flags.RCODE != protocol.RcodeServerFailure {
			t.Errorf("qtype %d: RCODE = %d, want SERVFAIL", qtype, resp.Header.Flags.RCODE)
		}
	}
}

// TestXoT_RefusedWhenNotAllowlisted: deny-by-default — a client outside
// the configured network is REFUSED for both AXFR and IXFR, over real TLS.
func TestXoT_RefusedWhenNotAllowlisted(t *testing.T) {
	zones := map[string]*zone.Zone{"example.com.": newXoTTestZone("example.com.", 1, 1)}
	// Allowlist excludes loopback: the test client (127.0.0.1) must be denied.
	srv, pair := startXoTTestServer(t, zones, "10.0.0.0/8")

	conn := xotDial(t, srv.Addr(), pair)
	for i, qtype := range []uint16{protocol.TypeAXFR, protocol.TypeIXFR} {
		xotSendFrame(t, conn, xotTransferQuery(uint16(0x7000+i), "example.com.", qtype))
		resp := xotReadFrame(t, conn)
		if resp.Header.Flags.RCODE != protocol.RcodeRefused {
			t.Errorf("qtype %d: RCODE = %d, want REFUSED", qtype, resp.Header.Flags.RCODE)
		}
	}
}

// TestXoT_UnsupportedQueryTypeNotImplemented: a plain A query over XoT is
// answered NOTIMP by handleMessage's default branch.
func TestXoT_UnsupportedQueryTypeNotImplemented(t *testing.T) {
	zones := map[string]*zone.Zone{"example.com.": newXoTTestZone("example.com.", 1, 1)}
	srv, pair := startXoTTestServer(t, zones, "127.0.0.1/32")

	conn := xotDial(t, srv.Addr(), pair)
	xotSendFrame(t, conn, xotTransferQuery(0x8001, "www.example.com.", protocol.TypeA))
	resp := xotReadFrame(t, conn)
	if resp.Header.Flags.RCODE != protocol.RcodeNotImplemented {
		t.Errorf("A-over-XoT RCODE = %d, want NOTIMP", resp.Header.Flags.RCODE)
	}
}

// TestXoT_MalformedMessageFormerr: undecodable wire bytes answer FORMERR
// without killing the connection loop.
func TestXoT_MalformedMessageFormerr(t *testing.T) {
	zones := map[string]*zone.Zone{"example.com.": newXoTTestZone("example.com.", 1, 1)}
	srv, pair := startXoTTestServer(t, zones, "127.0.0.1/32")

	conn := xotDial(t, srv.Addr(), pair)
	frame := make([]byte, 2+8)
	binary.BigEndian.PutUint16(frame[:2], 8)
	copy(frame[2:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write garbage frame: %v", err)
	}
	resp := xotReadFrame(t, conn)
	if resp.Header.Flags.RCODE != protocol.RcodeFormatError {
		t.Errorf("garbage RCODE = %d, want FORMERR", resp.Header.Flags.RCODE)
	}

	// The connection must still be usable afterwards.
	xotSendFrame(t, conn, xotTransferQuery(0x8002, "example.com.", protocol.TypeAXFR))
	resp = xotReadFrame(t, conn)
	if len(resp.Answers) == 0 {
		t.Error("connection unusable after FORMERR; expected AXFR answers on reuse")
	}
}

// TestXoT_AcceptLoopWithoutListenerReturns: AcceptLoop on a server that
// never served must return immediately (guard branch), not block.
func TestXoT_AcceptLoopWithoutListenerReturns(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := newXoTCertFiles(t, dir)
	srv, err := NewXoTServer(map[string]*zone.Zone{}, &XoTConfig{
		CertFile:        certFile,
		KeyFile:         keyFile,
		AllowedNetworks: []string{"127.0.0.1/32"},
	}, nil)
	if err != nil {
		t.Fatalf("NewXoTServer: %v", err)
	}
	done := make(chan struct{})
	go func() { srv.AcceptLoop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("AcceptLoop without listener did not return")
	}
}
