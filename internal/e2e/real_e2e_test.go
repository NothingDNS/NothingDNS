package e2e

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// TestRealUDPServer tests a real UDP DNS server from query to response.
func TestRealUDPServer(t *testing.T) {
	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}

		if len(req.Questions) > 0 {
			q := req.Questions[0]
			if q.QType == protocol.TypeA {
				resp.AddAnswer(&protocol.ResourceRecord{
					Name:  q.Name,
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
				})
			} else if q.QType == protocol.TypeAAAA {
				resp.AddAnswer(&protocol.ResourceRecord{
					Name:  q.Name,
					Type:  protocol.TypeAAAA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataAAAA{Address: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
				})
			} else if q.QType == protocol.TypeMX {
				resp.AddAnswer(&protocol.ResourceRecord{
					Name:  q.Name,
					Type:  protocol.TypeMX,
					Class: protocol.ClassIN,
					TTL:   300,
					Data: &protocol.RDataMX{
						Preference: 10,
						Exchange:   &protocol.Name{Labels: []string{"mail", "example", "com"}, FQDN: true},
					},
				})
			} else if q.QType == protocol.TypeTXT {
				resp.AddAnswer(&protocol.ResourceRecord{
					Name:  q.Name,
					Type:  protocol.TypeTXT,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataTXT{Strings: []string{"v=spf1 mx ~all"}},
				})
			} else if q.QType == protocol.TypeNS {
				resp.AddAnswer(&protocol.ResourceRecord{
					Name:  q.Name,
					Type:  protocol.TypeNS,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataNS{NSDName: &protocol.Name{Labels: []string{"ns1", "example", "com"}, FQDN: true}},
				})
			} else if q.QType == protocol.TypeCNAME {
				resp.AddAnswer(&protocol.ResourceRecord{
					Name:  q.Name,
					Type:  protocol.TypeCNAME,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataCNAME{CName: &protocol.Name{Labels: []string{"www", "example", "com"}, FQDN: true}},
				})
			}
		}

		w.Write(resp)
	})

	srv := server.NewUDPServer("127.0.0.1:0", handler)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer srv.Stop()

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := srv.Addr()
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("Expected UDPAddr, got %T", addr)
	}

	testCases := []struct {
		name  string
		qtype uint16
		check func(t *testing.T, resp *protocol.Message)
	}{
		{
			name:  "A query",
			qtype: protocol.TypeA,
			check: func(t *testing.T, resp *protocol.Message) {
				if len(resp.Answers) != 1 {
					t.Errorf("Expected 1 answer, got %d", len(resp.Answers))
				}
				if rr, ok := resp.Answers[0].Data.(*protocol.RDataA); ok {
					if rr.Address != [4]byte{1, 2, 3, 4} {
						t.Errorf("Expected A record 1.2.3.4, got %v", rr.Address)
					}
				}
			},
		},
		{
			name:  "AAAA query",
			qtype: protocol.TypeAAAA,
			check: func(t *testing.T, resp *protocol.Message) {
				if len(resp.Answers) != 1 {
					t.Errorf("Expected 1 answer, got %d", len(resp.Answers))
				}
			},
		},
		{
			name:  "MX query",
			qtype: protocol.TypeMX,
			check: func(t *testing.T, resp *protocol.Message) {
				if len(resp.Answers) != 1 {
					t.Errorf("Expected 1 answer, got %d", len(resp.Answers))
				}
			},
		},
		{
			name:  "TXT query",
			qtype: protocol.TypeTXT,
			check: func(t *testing.T, resp *protocol.Message) {
				if len(resp.Answers) != 1 {
					t.Errorf("Expected 1 answer, got %d", len(resp.Answers))
				}
			},
		},
		{
			name:  "NS query",
			qtype: protocol.TypeNS,
			check: func(t *testing.T, resp *protocol.Message) {
				if len(resp.Answers) != 1 {
					t.Errorf("Expected 1 answer, got %d", len(resp.Answers))
				}
			},
		},
		{
			name:  "CNAME query",
			qtype: protocol.TypeCNAME,
			check: func(t *testing.T, resp *protocol.Message) {
				if len(resp.Answers) != 1 {
					t.Errorf("Expected 1 answer, got %d", len(resp.Answers))
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			query, err := protocol.NewQuery(0x1234, "www.example.com.", tc.qtype)
			if err != nil {
				t.Fatalf("Failed to create query: %v", err)
			}

			buf := make([]byte, 512)
			n, err := query.Pack(buf)
			if err != nil {
				t.Fatalf("Failed to pack query: %v", err)
			}

			conn, err := net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				t.Fatalf("Failed to dial: %v", err)
			}
			defer conn.Close()

			_, err = conn.Write(buf[:n])
			if err != nil {
				t.Fatalf("Failed to send: %v", err)
			}

			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			respBuf := make([]byte, 512)
			n, err = conn.Read(respBuf)
			if err != nil {
				t.Fatalf("Failed to read: %v", err)
			}

			resp, err := protocol.UnpackMessage(respBuf[:n])
			if err != nil {
				t.Fatalf("Failed to unpack: %v", err)
			}

			if resp.Header.ID != query.Header.ID {
				t.Errorf("ID mismatch: got %x, want %x", resp.Header.ID, query.Header.ID)
			}

			if !resp.Header.Flags.QR {
				t.Error("Expected QR flag to be set")
			}

			tc.check(t, resp)
		})
	}
}

// TestRealTCPServer tests a real TCP DNS server.
func TestRealTCPServer(t *testing.T) {
	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header:  protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		if len(req.Questions) > 0 && req.Questions[0].QType == protocol.TypeA {
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  req.Questions[0].Name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{5, 6, 7, 8}},
			})
		}
		w.Write(resp)
	})

	srv := server.NewTCPServer("127.0.0.1:0", handler)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer srv.Stop()

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := srv.Addr()
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("Expected TCPAddr, got %T", addr)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	query, _ := protocol.NewQuery(0x5678, "example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	lenBuf := [2]byte{byte(n >> 8), byte(n & 0xff)}
	conn.Write(lenBuf[:])
	conn.Write(buf[:n])

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	var respLen [2]byte
	conn.Read(respLen[:])

	msgLen := int(respLen[0])<<8 | int(respLen[1])
	if msgLen > 65535 {
		t.Fatalf("Invalid message length: %d", msgLen)
	}

	respBuf := make([]byte, msgLen)
	conn.Read(respBuf)

	resp, err := protocol.UnpackMessage(respBuf)
	if err != nil {
		t.Fatalf("Failed to unpack: %v", err)
	}

	if resp.Header.ID != query.Header.ID {
		t.Errorf("ID mismatch: got %x, want %x", resp.Header.ID, query.Header.ID)
	}
}

// TestRealTCPServerMultipleQueries tests multiple queries on single TCP connection.
func TestRealTCPServerMultipleQueries(t *testing.T) {
	var requestCount int
	var mu sync.Mutex

	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		mu.Lock()
		requestCount++
		mu.Unlock()

		resp := &protocol.Message{
			Header:  protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		w.Write(resp)
	})

	srv := server.NewTCPServer("127.0.0.1:0", handler)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer srv.Stop()

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := srv.Addr().(*net.TCPAddr)

	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	domains := []string{"a.example.com.", "b.example.com.", "c.example.com.", "d.example.com.", "e.example.com."}

	for i, domain := range domains {
		query, _ := protocol.NewQuery(uint16(i), domain, protocol.TypeA)
		buf := make([]byte, 512)
		n, _ := query.Pack(buf)

		lenBuf := [2]byte{byte(n >> 8), byte(n & 0xff)}
		conn.Write(lenBuf[:])
		conn.Write(buf[:n])
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	for i := 0; i < len(domains); i++ {
		var respLen [2]byte
		conn.Read(respLen[:])
		msgLen := int(respLen[0])<<8 | int(respLen[1])
		respBuf := make([]byte, msgLen)
		conn.Read(respBuf)
	}

	mu.Lock()
	defer mu.Unlock()
	if requestCount != len(domains) {
		t.Errorf("Expected %d requests, got %d", len(domains), requestCount)
	}
}

// TestConcurrentUDPServer tests UDP server under concurrent query load.
func TestConcurrentUDPServer(t *testing.T) {
	var requestCount int
	var mu sync.Mutex

	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		mu.Lock()
		requestCount++
		mu.Unlock()

		resp := &protocol.Message{
			Header:  protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		w.Write(resp)
	})

	srv := server.NewUDPServer("127.0.0.1:0", handler)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer srv.Stop()

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := srv.Addr().(*net.UDPAddr)

	var wg sync.WaitGroup
	concurrency := 10
	queriesPerClient := 20

	for c := 0; c < concurrency; c++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				t.Errorf("Client %d: failed to dial: %v", clientID, err)
				return
			}
			defer conn.Close()

			for q := 0; q < queriesPerClient; q++ {
				id := uint16(clientID*1000 + q)
				query, _ := protocol.NewQuery(id, fmt.Sprintf("www%d%d.example.com.", clientID, q), protocol.TypeA)
				buf := make([]byte, 512)
				n, _ := query.Pack(buf)

				conn.Write(buf[:n])

				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				respBuf := make([]byte, 512)
				conn.Read(respBuf)
			}
		}(c)
	}

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	expected := concurrency * queriesPerClient
	if requestCount != expected {
		t.Errorf("Expected %d requests, got %d", expected, requestCount)
	}
}

// TestServerGracefulShutdown tests that server shuts down gracefully.
func TestServerGracefulShutdown(t *testing.T) {
	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header:  protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		w.Write(resp)
	})

	srv := server.NewUDPServer("127.0.0.1:0", handler)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	srv.Stop()

	// Verify server is stopped by sending a query - should not receive response
	addr := srv.Addr().(*net.UDPAddr)
	query, _ := protocol.NewQuery(0x1234, "test.example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	conn, err := net.DialUDP("udp", nil, addr)
	if err == nil {
		defer conn.Close()
		conn.Write(buf[:n])
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		respBuf := make([]byte, 512)
		_, err = conn.Read(respBuf)
		if err == nil {
			t.Error("Server should not respond after Stop")
		}
		// err != nil means no response received - this is expected after Stop
	}
}

// TestServerHandlerPanicRecovery tests that handler panics are recovered.
func TestServerHandlerPanicRecovery(t *testing.T) {
	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		panic("intentional panic for testing")
	})

	srv := server.NewUDPServer("127.0.0.1:0", handler)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer srv.Stop()

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := srv.Addr().(*net.UDPAddr)

	query, _ := protocol.NewQuery(0x9999, "test.example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	conn.Write(buf[:n])

	time.Sleep(50 * time.Millisecond)
	stats := srv.Stats()
	if stats.PacketsReceived == 0 {
		t.Error("Server did not receive packet")
	}
}

// TestServerInvalidQueryHandling tests that invalid queries are handled gracefully.
// Note: UDP server calls handler even for invalid queries - this test verifies
// the server doesn't crash when receiving garbage.
func TestServerInvalidQueryHandling(t *testing.T) {
	var callCount int
	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		callCount++
		resp := &protocol.Message{
			Header:  protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		w.Write(resp)
	})

	srv := server.NewUDPServer("127.0.0.1:0", handler)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer srv.Stop()

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := srv.Addr().(*net.UDPAddr)

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// Send garbage - server should not crash
	conn.Write([]byte{0xFF, 0xFF, 0xFF})
	time.Sleep(50 * time.Millisecond)

	// Server should still be alive
	stats := srv.Stats()
	if stats.PacketsReceived == 0 {
		t.Error("Server did not receive any packets")
	}
	t.Logf("Call count: %d, packets received: %d", callCount, stats.PacketsReceived)
}

// TestDoHWithRealHTTPServer tests DoH with a real HTTP server.
func TestDoHWithRealHTTPServer(t *testing.T) {
	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		resp := &protocol.Message{
			Header:  protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: req.Questions,
		}
		if len(req.Questions) > 0 && req.Questions[0].QType == protocol.TypeA {
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  req.Questions[0].Name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{9, 9, 9, 9}},
			})
		}
		w.Write(resp)
	})

	dohHandler := newTestDoHHandler(handler)

	srv := &http.Server{
		Addr:    "127.0.0.1:0",
		Handler: dohHandler,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	go srv.Serve(ln)
	time.Sleep(10 * time.Millisecond)

	defer srv.Close()

	query, _ := protocol.NewQuery(0xabcd, "test.example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	resp, err := http.Post(fmt.Sprintf("http://%s/dns-query", ln.Addr().String()),
		"application/dns-message", bytes.NewReader(buf[:n]))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	respBuf := make([]byte, 65535)
	n, _ = resp.Body.Read(respBuf)
	dnsResp, err := protocol.UnpackMessage(respBuf[:n])
	if err != nil {
		t.Fatalf("Failed to unpack: %v", err)
	}

	if dnsResp.Header.ID != query.Header.ID {
		t.Errorf("ID mismatch: got %x, want %x", dnsResp.Header.ID, query.Header.ID)
	}

	encoded := base64.RawURLEncoding.EncodeToString(buf[:n])
	resp, err = http.Get(fmt.Sprintf("http://%s/dns-query?dns=%s", ln.Addr().String(), encoded))
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

type testDoHHandler struct {
	dnsHandler server.Handler
}

func newTestDoHHandler(h server.Handler) *testDoHHandler {
	return &testDoHHandler{dnsHandler: h}
}

func (h *testDoHHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var queryData []byte
	var err error

	if r.Method == http.MethodGet {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		queryData, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "invalid base64", http.StatusBadRequest)
			return
		}
	} else {
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/dns-message" {
			http.Error(w, "wrong content type", http.StatusBadRequest)
			return
		}
		queryData, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
	}

	query, err := protocol.UnpackMessage(queryData)
	if err != nil {
		http.Error(w, "invalid dns message", http.StatusBadRequest)
		return
	}

	if len(query.Questions) == 0 {
		http.Error(w, "no questions", http.StatusBadRequest)
		return
	}

	rw := &testDoHResponseWriter{w: w, query: query}
	h.dnsHandler.ServeDNS(rw, query)
}

type testDoHResponseWriter struct {
	w       http.ResponseWriter
	query   *protocol.Message
	written bool
}

func (rw *testDoHResponseWriter) Write(msg *protocol.Message) (int, error) {
	if rw.written {
		return 0, fmt.Errorf("already written")
	}
	rw.written = true

	msg.Header.ID = rw.query.Header.ID
	msg.Header.Flags.QR = true

	buf := make([]byte, msg.WireLength())
	n, err := msg.Pack(buf)
	if err != nil {
		return 0, err
	}

	rw.w.Header().Set("Content-Type", "application/dns-message")
	rw.w.WriteHeader(http.StatusOK)
	return rw.w.Write(buf[:n])
}

func (rw *testDoHResponseWriter) ClientInfo() *server.ClientInfo {
	return &server.ClientInfo{Protocol: "https"}
}

func (rw *testDoHResponseWriter) MaxSize() int {
	return 65535
}
