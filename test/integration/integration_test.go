package integration

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const (
	testAddr = "127.0.0.1"
)

// testEnv holds a running test server environment.
type testEnv struct {
	udpPort   int
	udpServer *server.UDPServer
	tcpServer *server.TCPServer
	handler   *testHandler
	tmpDir    string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	udpPort := findFreePort(t)
	tmpDir := t.TempDir()

	// Create a test zone file
	zoneContent := `
$ORIGIN test.local.
$TTL 3600
@       IN  SOA  ns1.test.local. admin.test.local. (
            2024010101 ; serial
            3600       ; refresh
            900        ; retry
            604800     ; expire
            86400      ; minimum
            )
        IN  NS   ns1.test.local.
ns1     IN  A    127.0.0.1
www     IN  A    192.168.1.1
mail    IN  A    192.168.1.2
        IN  MX   10 mail.test.local.
alias   IN  CNAME www.test.local.
dual    IN  A    10.0.0.1
dual    IN  A    10.0.0.2
txt     IN  TXT  "v=spf1 include:_spf.example.com ~all"
`
	zoneFile := filepath.Join(tmpDir, "test.local.zone")
	if err := os.WriteFile(zoneFile, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("write zone file: %v", err)
	}

	f, err := os.Open(zoneFile)
	if err != nil {
		t.Fatalf("open zone file: %v", err)
	}
	defer f.Close()

	z, err := zone.ParseFile(zoneFile, f)
	if err != nil {
		t.Fatalf("parse zone file: %v", err)
	}
	if err := z.Validate(); err != nil {
		t.Fatalf("validate zone: %v", err)
	}

	handler := &testHandler{
		zones: map[string]*zone.Zone{
			"test.local.": z,
		},
		cache: cache.New(cache.Config{
			Capacity:    1000,
			MinTTL:      5 * time.Second,
			MaxTTL:      86400 * time.Second,
			DefaultTTL:  300 * time.Second,
			NegativeTTL: 60 * time.Second,
		}),
	}

	addr := fmt.Sprintf("%s:%d", testAddr, udpPort)

	udpServer := server.NewUDPServer(addr, handler)
	if err := udpServer.Listen(); err != nil {
		t.Fatalf("UDP listen: %v", err)
	}

	tcpServer := server.NewTCPServer(addr, handler)
	if err := tcpServer.Listen(); err != nil {
		t.Fatalf("TCP listen: %v", err)
	}

	env := &testEnv{
		udpPort:   udpPort,
		udpServer: udpServer,
		tcpServer: tcpServer,
		handler:   handler,
		tmpDir:    tmpDir,
	}

	go func() {
		if err := udpServer.Serve(); err != nil {
			t.Logf("UDP serve ended: %v", err)
		}
	}()
	go func() {
		if err := tcpServer.Serve(); err != nil {
			t.Logf("TCP serve ended: %v", err)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	t.Cleanup(func() {
		udpServer.Stop()
		tcpServer.Stop()
	})

	return env
}

func (e *testEnv) addr() string {
	return fmt.Sprintf("%s:%d", testAddr, e.udpPort)
}

func findFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// testHandler is a minimal DNS handler that serves authoritative zones.
type testHandler struct {
	zones map[string]*zone.Zone
	cache *cache.Cache
}

func (h *testHandler) ServeDNS(w server.ResponseWriter, r *protocol.Message) {
	if len(r.Questions) == 0 {
		sendTestError(w, r, protocol.RcodeFormatError)
		return
	}

	q := r.Questions[0]
	qname := q.Name.String()
	qtype := q.QType
	qtypeStr := protocol.TypeString(qtype)

	for _, z := range h.zones {
		records := z.Lookup(qname, qtypeStr)
		if len(records) > 0 {
			resp := buildTestResponse(r, records)
			w.Write(resp)
			return
		}

		// Try CNAME
		cnames := z.Lookup(qname, "CNAME")
		if len(cnames) > 0 {
			target := cnames[0].RData
			targetRecs := z.Lookup(target, qtypeStr)
			if len(targetRecs) > 0 {
				allRecs := append(cnames, targetRecs...)
				resp := buildTestResponse(r, allRecs)
				w.Write(resp)
				return
			}
			resp := buildTestResponse(r, cnames)
			w.Write(resp)
			return
		}
	}

	sendTestError(w, r, protocol.RcodeNameError)
}

func buildTestResponse(query *protocol.Message, records []zone.Record) *protocol.Message {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: query.Questions,
	}
	for _, rec := range records {
		data := parseTestRData(rec.Type, rec.RData)
		if data == nil {
			continue
		}
		rr := &protocol.ResourceRecord{
			Name:  query.Questions[0].Name,
			Type:  strType(rec.Type),
			Class: protocol.ClassIN,
			TTL:   rec.TTL,
			Data:  data,
		}
		resp.AddAnswer(rr)
	}
	return resp
}

func sendTestError(w server.ResponseWriter, query *protocol.Message, rcode uint8) {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(rcode),
		},
		Questions: query.Questions,
	}
	w.Write(resp)
}

func strType(s string) uint16 {
	if t, ok := protocol.StringToType[s]; ok {
		return t
	}
	return 0
}

func parseTestRData(rtype, rdata string) protocol.RData {
	switch rtype {
	case "A":
		ip := net.ParseIP(rdata)
		if ip == nil {
			return nil
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil
		}
		var addr [4]byte
		copy(addr[:], ipv4)
		return &protocol.RDataA{Address: addr}
	case "AAAA":
		ip := net.ParseIP(rdata)
		if ip == nil {
			return nil
		}
		var addr [16]byte
		copy(addr[:], ip.To16())
		return &protocol.RDataAAAA{Address: addr}
	case "CNAME", "NS", "PTR":
		name, err := protocol.ParseName(rdata)
		if err == nil {
			return &protocol.RDataCNAME{CName: name}
		}
	case "TXT":
		return &protocol.RDataTXT{Strings: []string{rdata}}
	}
	return nil
}

// rawDNSQuery sends a raw DNS query over UDP and returns the response.
func rawDNSQuery(t *testing.T, addr string, query *protocol.Message) *protocol.Message {
	t.Helper()

	buf := make([]byte, 4096)
	n, err := query.Pack(buf)
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := conn.Write(buf[:n]); err != nil {
		t.Fatalf("write query: %v", err)
	}

	respBuf := make([]byte, 4096)
	rn, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	resp, err := protocol.UnpackMessage(respBuf[:rn])
	if err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return resp
}

// rawTCPQuery sends a raw DNS query over TCP.
func rawTCPQuery(t *testing.T, addr string, query *protocol.Message) *protocol.Message {
	t.Helper()

	buf := make([]byte, 65535)
	n, err := query.Pack(buf)
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial tcp %s: %v", addr, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	length := uint16(n)
	conn.Write([]byte{byte(length >> 8), byte(length)})
	conn.Write(buf[:n])

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		t.Fatalf("read length: %v", err)
	}
	respLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1])

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.Fatalf("read response: %v", err)
	}

	resp, err := protocol.UnpackMessage(respBuf)
	if err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return resp
}

func makeQuery(name string, qtype uint16) *protocol.Message {
	parsedName, _ := protocol.ParseName(name)
	return &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   parsedName,
				QType:  qtype,
				QClass: protocol.ClassIN,
			},
		},
	}
}

// ===================== TESTS =====================

func TestUDP_A_RecordLookup(t *testing.T) {
	env := newTestEnv(t)

	resp := rawDNSQuery(t, env.addr(), makeQuery("www.test.local.", protocol.TypeA))

	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("RCODE = %d, want Success", resp.Header.Flags.RCODE)
	}
	if len(resp.Answers) == 0 {
		t.Fatal("expected answers")
	}
	a, ok := resp.Answers[0].Data.(*protocol.RDataA)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answers[0].Data)
	}
	expected := net.IPv4(192, 168, 1, 1).To4()
	if !net.IP(a.Address[:]).Equal(expected) {
		t.Errorf("A address = %v, want %v", net.IP(a.Address[:]), expected)
	}
}

func TestUDP_CNAME_RecordLookup(t *testing.T) {
	env := newTestEnv(t)

	resp := rawDNSQuery(t, env.addr(), makeQuery("alias.test.local.", protocol.TypeA))

	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("RCODE = %d, want Success", resp.Header.Flags.RCODE)
	}
	if len(resp.Answers) == 0 {
		t.Fatal("expected answers for CNAME chase")
	}
}

func TestUDP_NXDOMAIN(t *testing.T) {
	env := newTestEnv(t)

	resp := rawDNSQuery(t, env.addr(), makeQuery("nonexistent.test.local.", protocol.TypeA))

	if resp.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Fatalf("RCODE = %d, want NXDOMAIN", resp.Header.Flags.RCODE)
	}
}

func TestUDP_TXT_RecordLookup(t *testing.T) {
	env := newTestEnv(t)

	resp := rawDNSQuery(t, env.addr(), makeQuery("txt.test.local.", protocol.TypeTXT))

	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("RCODE = %d, want Success", resp.Header.Flags.RCODE)
	}
	if len(resp.Answers) == 0 {
		t.Fatal("expected TXT answer")
	}
	txt, ok := resp.Answers[0].Data.(*protocol.RDataTXT)
	if !ok {
		t.Fatalf("expected TXT record, got %T", resp.Answers[0].Data)
	}
	if len(txt.Strings) == 0 || txt.Strings[0] == "" {
		t.Error("expected non-empty TXT data")
	}
}

func TestUDP_MultipleA_Records(t *testing.T) {
	env := newTestEnv(t)

	resp := rawDNSQuery(t, env.addr(), makeQuery("dual.test.local.", protocol.TypeA))

	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("RCODE = %d, want Success", resp.Header.Flags.RCODE)
	}
	if len(resp.Answers) < 2 {
		t.Fatalf("expected 2 A records, got %d", len(resp.Answers))
	}
}

func TestTCP_A_RecordLookup(t *testing.T) {
	env := newTestEnv(t)

	resp := rawTCPQuery(t, env.addr(), makeQuery("www.test.local.", protocol.TypeA))

	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("RCODE = %d, want Success", resp.Header.Flags.RCODE)
	}
	if len(resp.Answers) == 0 {
		t.Fatal("expected answers over TCP")
	}
	a, ok := resp.Answers[0].Data.(*protocol.RDataA)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answers[0].Data)
	}
	expected := net.IPv4(192, 168, 1, 1).To4()
	if !net.IP(a.Address[:]).Equal(expected) {
		t.Errorf("A address = %v, want %v", net.IP(a.Address[:]), expected)
	}
}

func TestTCP_NXDOMAIN(t *testing.T) {
	env := newTestEnv(t)

	resp := rawTCPQuery(t, env.addr(), makeQuery("nonexistent.test.local.", protocol.TypeA))

	if resp.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Fatalf("RCODE = %d, want NXDOMAIN", resp.Header.Flags.RCODE)
	}
}

func TestUDP_EmptyQuery(t *testing.T) {
	env := newTestEnv(t)

	query := &protocol.Message{
		Header: protocol.Header{
			ID:    0x5678,
			Flags: protocol.NewQueryFlags(),
		},
	}
	resp := rawDNSQuery(t, env.addr(), query)

	if resp.Header.Flags.RCODE != protocol.RcodeFormatError {
		t.Fatalf("RCODE = %d, want FormatError for empty query", resp.Header.Flags.RCODE)
	}
}

func TestUDP_ResponseHasQR(t *testing.T) {
	env := newTestEnv(t)

	resp := rawDNSQuery(t, env.addr(), makeQuery("www.test.local.", protocol.TypeA))

	if !resp.Header.Flags.QR {
		t.Error("response QR bit not set")
	}
}

func TestUDP_ResponseMatchesQueryID(t *testing.T) {
	env := newTestEnv(t)

	query := makeQuery("www.test.local.", protocol.TypeA)
	query.Header.ID = 0xABCD

	resp := rawDNSQuery(t, env.addr(), query)

	if resp.Header.ID != 0xABCD {
		t.Errorf("response ID = 0x%04X, want 0xABCD", resp.Header.ID)
	}
}

func TestMultipleQueries(t *testing.T) {
	env := newTestEnv(t)

	names := []string{
		"www.test.local.",
		"mail.test.local.",
		"ns1.test.local.",
		"dual.test.local.",
	}

	for _, name := range names {
		resp := rawDNSQuery(t, env.addr(), makeQuery(name, protocol.TypeA))
		if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
			t.Errorf("query %s: RCODE = %d, want Success", name, resp.Header.Flags.RCODE)
		}
		if len(resp.Answers) == 0 {
			t.Errorf("query %s: expected answers", name)
		}
	}
}

func TestUDP_ConcurrentQueries(t *testing.T) {
	env := newTestEnv(t)

	const numQueries = 50
	results := make(chan error, numQueries)

	for i := 0; i < numQueries; i++ {
		go func(id int) {
			query := makeQuery("www.test.local.", protocol.TypeA)
			query.Header.ID = uint16(id)

			buf := make([]byte, 4096)
			n, err := query.Pack(buf)
			if err != nil {
				results <- fmt.Errorf("pack: %w", err)
				return
			}

			conn, err := net.DialTimeout("udp", env.addr(), 2*time.Second)
			if err != nil {
				results <- fmt.Errorf("dial: %w", err)
				return
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(2 * time.Second))
			conn.Write(buf[:n])

			respBuf := make([]byte, 4096)
			rn, err := conn.Read(respBuf)
			if err != nil {
				results <- fmt.Errorf("read: %w", err)
				return
			}

			resp, err := protocol.UnpackMessage(respBuf[:rn])
			if err != nil {
				results <- fmt.Errorf("unpack: %w", err)
				return
			}
			if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
				results <- fmt.Errorf("RCODE=%d", resp.Header.Flags.RCODE)
				return
			}
			results <- nil
		}(i)
	}

	for i := 0; i < numQueries; i++ {
		if err := <-results; err != nil {
			t.Errorf("concurrent query %d: %v", i, err)
		}
	}
}
