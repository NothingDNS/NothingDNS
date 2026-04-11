package e2e

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// TestAXFRServer tests AXFR server with a real TCP connection.
func TestAXFRServer(t *testing.T) {
	// Create a zone with some records (same pattern as transfer_test.go)
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}
	z.Records["example.com."] = []zone.Record{
		{Type: "A", TTL: 3600, RData: "192.0.2.1"},
		{Type: "NS", TTL: 3600, RData: "ns1.example.com."},
	}
	z.Records["www.example.com."] = []zone.Record{
		{Type: "A", TTL: 3600, RData: "192.0.2.2"},
	}

	// Use the same pattern as transfer_test.go
	axfrServer := transfer.NewAXFRServer(make(map[string]*zone.Zone), transfer.WithAllowList([]string{"127.0.0.0/8"}))
	axfrServer.AddZone(z)

	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		if len(req.Questions) > 0 && req.Questions[0].QType == protocol.TypeAXFR {
			clientIP := net.ParseIP("127.0.0.1")
			if cip := w.ClientInfo().IP(); cip != nil {
				clientIP = cip
			}
			records, _, err := axfrServer.HandleAXFR(req, clientIP)
			if err != nil {
				return
			}
			// Stream each record as a separate DNS message
			for _, rr := range records {
				resp := &protocol.Message{
					Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
					Questions: req.Questions,
					Answers:   []*protocol.ResourceRecord{rr},
				}
				w.Write(resp)
			}
		}
	})

	srv := server.NewTCPServer("127.0.0.1:0", handler)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer srv.Stop()

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := srv.Addr().(*net.TCPAddr)

	// Connect and request AXFR
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// Send AXFR query
	qname, _ := protocol.ParseName("example.com.")
	query := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: qname, QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
		},
	}

	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	// Write length-prefixed
	lenBuf := [2]byte{byte(n >> 8), byte(n & 0xff)}
	conn.Write(lenBuf[:])
	conn.Write(buf[:n])

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read multiple responses (AXFR streams records)
	recordCount := 0
	for {
		var msgLenBuf [2]byte
		_, err := conn.Read(msgLenBuf[:])
		if err != nil {
			break // End of stream
		}

		msgLen := int(msgLenBuf[0])<<8 | int(msgLenBuf[1])
		if msgLen > 65535 {
			t.Fatalf("Invalid message length: %d", msgLen)
		}

		respBuf := make([]byte, msgLen)
		_, err = conn.Read(respBuf)
		if err != nil {
			break
		}

		resp, err := protocol.UnpackMessage(respBuf)
		if err != nil {
			continue
		}

		// Count all records in response
		recordCount += len(resp.Answers)
		recordCount += len(resp.Authorities)
	}

	t.Logf("AXFR received %d records", recordCount)
	if recordCount == 0 {
		t.Error("Expected some records from AXFR")
	}

	// Verify we got SOA at start and end
	// (AXFR format: SOA, [records...], SOA)
}

// TestAXFRServerACL tests AXFR access control.
func TestAXFRServerACL(t *testing.T) {
	z := zone.NewZone("test.com.")
	z.SOA = &zone.SOARecord{
		MName:   "ns1.test.com.",
		RName:   "admin.test.com.",
		Serial:  1,
		Refresh: 3600,
		Retry:   3600,
		Expire:  3600 * 7,
		Minimum: 3600,
	}
	z.Records["test.com."] = []zone.Record{
		{Type: "NS", TTL: 3600, RData: "ns1.test.com."},
	}
	z.Records["ns1.test.com."] = []zone.Record{
		{Type: "A", TTL: 3600, RData: "192.0.2.1"},
	}

	zones := map[string]*zone.Zone{"test.com.": z}

	// Test with allow list
	server := transfer.NewAXFRServer(zones, transfer.WithAllowList([]string{"127.0.0.0/8"}))

	if !server.IsAllowed(net.ParseIP("127.0.0.1")) {
		t.Error("127.0.0.1 should be allowed in 127.0.0.0/8")
	}

	if server.IsAllowed(net.ParseIP("10.0.0.1")) {
		t.Error("10.0.0.1 should not be allowed")
	}
}

// TestIXFRServerWithTCPServer tests IXFR via the actual TCP server.
func TestIXFRServerWithTCPServer(t *testing.T) {
	// Create zone with records and SOA
	z := zone.NewZone("ixfr.test.")
	z.SOA = &zone.SOARecord{
		MName:   "ns.ixfr.test.",
		RName:   "admin.ixfr.test.",
		Serial:  100,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minimum: 3600,
	}
	z.Records["ixfr.test."] = []zone.Record{
		{Type: "NS", TTL: 3600, RData: "ns.ixfr.test."},
	}
	z.Records["ns.ixfr.test."] = []zone.Record{
		{Type: "A", TTL: 3600, RData: "10.0.0.1"},
	}
	z.Records["www.ixfr.test."] = []zone.Record{
		{Type: "A", TTL: 300, RData: "10.0.0.2"},
	}

	zones := map[string]*zone.Zone{"ixfr.test.": z}
	axfrServer := transfer.NewAXFRServer(zones)
	ixfrHandler := transfer.NewIXFRServer(axfrServer)

	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		if len(req.Questions) == 0 {
			return
		}
		q := req.Questions[0]
		if q.QType == protocol.TypeIXFR {
			clientIP := net.ParseIP("127.0.0.1")
			if cip := w.ClientInfo().IP(); cip != nil {
				clientIP = cip
			}
			records, err := ixfrHandler.HandleIXFR(req, clientIP)
			if err != nil {
				return
			}
			// Stream records
			for _, rr := range records {
				resp := &protocol.Message{
					Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
					Questions: req.Questions,
					Answers:   []*protocol.ResourceRecord{rr},
				}
				w.Write(resp)
			}
		} else if q.QType == protocol.TypeAXFR {
			clientIP := net.ParseIP("127.0.0.1")
			if cip := w.ClientInfo().IP(); cip != nil {
				clientIP = cip
			}
			records, _, err := axfrServer.HandleAXFR(req, clientIP)
			if err != nil {
				return
			}
			for _, rr := range records {
				resp := &protocol.Message{
					Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
					Questions: req.Questions,
					Answers:   []*protocol.ResourceRecord{rr},
				}
				w.Write(resp)
			}
		} else {
			// Regular query
			resp := &protocol.Message{
				Header:  protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
				Questions: req.Questions,
			}
			w.Write(resp)
		}
	})

	srv := server.NewTCPServer("127.0.0.1:0", handler)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer srv.Stop()

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := srv.Addr().(*net.TCPAddr)

	// Test IXFR request with current serial (should return single SOA)
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	qname, _ := protocol.ParseName("ixfr.test.")
	query := &protocol.Message{
		Header: protocol.Header{
			ID:      0xABCD,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
			NSCount: 1, // IXFR requires SOA in authority section
		},
		Questions: []*protocol.Question{
			{Name: qname, QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  qname,
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				TTL:   3600,
				Data: &protocol.RDataSOA{
					MName:   &protocol.Name{Labels: []string{"ns", "ixfr", "test"}, FQDN: true},
					RName:   &protocol.Name{Labels: []string{"admin", "ixfr", "test"}, FQDN: true},
					Serial:  100, // Same as server serial
					Refresh: 3600,
					Retry:   600,
					Expire:  86400,
					Minimum: 3600,
				},
			},
		},
	}

	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	lenBuf := [2]byte{byte(n >> 8), byte(n & 0xff)}
	conn.Write(lenBuf[:])
	conn.Write(buf[:n])

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read response - when client serial equals server serial, returns single SOA
	var msgLenBuf [2]byte
	_, err = conn.Read(msgLenBuf[:])
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}
	msgLen := int(msgLenBuf[0])<<8 | int(msgLenBuf[1])
	if msgLen > 65535 || msgLen == 0 {
		t.Fatalf("Invalid message length: %d", msgLen)
	}
	respBuf := make([]byte, msgLen)
	_, err = conn.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	resp, err := protocol.UnpackMessage(respBuf)
	if err != nil {
		t.Fatalf("Failed to unpack: %v", err)
	}

	// When client is up to date, IXFR returns single SOA
	if len(resp.Answers) != 1 || resp.Answers[0].Type != protocol.TypeSOA {
		t.Errorf("Expected single SOA response, got %d answers", len(resp.Answers))
	}
}

// TestAXFRServerWithTCPServer tests AXFR via the actual TCP server.
func TestAXFRServerWithTCPServer(t *testing.T) {
	// Create zone with records
	z := zone.NewZone("axfr.test.")
	z.SOA = &zone.SOARecord{
		MName:   "ns.axfr.test.",
		RName:   "admin.axfr.test.",
		Serial:  100,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minimum: 3600,
	}
	z.Records["axfr.test."] = []zone.Record{
		{Type: "NS", TTL: 3600, RData: "ns.axfr.test."},
	}
	z.Records["ns.axfr.test."] = []zone.Record{
		{Type: "A", TTL: 3600, RData: "10.0.0.1"},
	}
	z.Records["www.axfr.test."] = []zone.Record{
		{Type: "A", TTL: 300, RData: "10.0.0.2"},
		{Type: "AAAA", TTL: 300, RData: "2001:db8::2"},
	}

	axfrServer := transfer.NewAXFRServer(make(map[string]*zone.Zone), transfer.WithAllowList([]string{"127.0.0.0/8"}))
	axfrServer.AddZone(z)

	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		if len(req.Questions) == 0 {
			return
		}
		q := req.Questions[0]
		if q.QType == protocol.TypeAXFR {
			clientIP := net.ParseIP("127.0.0.1")
			if cip := w.ClientInfo().IP(); cip != nil {
				clientIP = cip
			}
			records, _, err := axfrServer.HandleAXFR(req, clientIP)
			if err != nil {
				return
			}
			// Stream records
			for _, rr := range records {
				resp := &protocol.Message{
					Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
					Questions: req.Questions,
					Answers:   []*protocol.ResourceRecord{rr},
				}
				w.Write(resp)
			}
		} else {
			// Regular query
			resp := &protocol.Message{
				Header:  protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
				Questions: req.Questions,
			}
			w.Write(resp)
		}
	})

	srv := server.NewTCPServer("127.0.0.1:0", handler)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer srv.Stop()

	go srv.Serve()
	time.Sleep(10 * time.Millisecond)

	addr := srv.Addr().(*net.TCPAddr)

	// Test AXFR request
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	qname, _ := protocol.ParseName("axfr.test.")
	query := &protocol.Message{
		Header: protocol.Header{
			ID:      0xABCD,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: qname, QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
		},
	}

	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	lenBuf := [2]byte{byte(n >> 8), byte(n & 0xff)}
	conn.Write(lenBuf[:])
	conn.Write(buf[:n])

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read streamed responses
	soaCount := 0
	recordCount := 0
	for {
		var msgLenBuf [2]byte
		_, err := conn.Read(msgLenBuf[:])
		if err != nil {
			break
		}
		msgLen := int(msgLenBuf[0])<<8 | int(msgLenBuf[1])
		if msgLen > 65535 || msgLen == 0 {
			break
		}
		respBuf := make([]byte, msgLen)
		_, err = conn.Read(respBuf)
		if err != nil {
			break
		}
		resp, err := protocol.UnpackMessage(respBuf)
		if err != nil || len(resp.Answers) == 0 {
			continue
		}
		for _, rr := range resp.Answers {
			recordCount++
			if rr.Type == protocol.TypeSOA {
				soaCount++
			}
		}
	}

	if recordCount == 0 {
		t.Error("Expected records from AXFR")
	}
	if soaCount < 2 {
		t.Errorf("Expected at least 2 SOA records (start and end), got %d", soaCount)
	}
	t.Logf("AXFR test: received %d records including %d SOAs", recordCount, soaCount)
}

// TestAXFRMultipleMessageStreaming tests that AXFR correctly streams multiple DNS messages.
func TestAXFRMultipleMessageStreaming(t *testing.T) {
	z := zone.NewZone("stream.test.")
	z.SOA = &zone.SOARecord{
		MName:   "ns.stream.test.",
		RName:   "admin.stream.test.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minimum: 3600,
	}
	// Add many records
	for i := 0; i < 20; i++ {
		z.Records[fmt.Sprintf("host%d.stream.test.", i)] = []zone.Record{
			{Type: "A", TTL: 300, RData: fmt.Sprintf("192.0.2.%d", i+1)},
		}
	}

	axfrServer := transfer.NewAXFRServer(make(map[string]*zone.Zone), transfer.WithAllowList([]string{"127.0.0.0/8"}))
	axfrServer.AddZone(z)

	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		if len(req.Questions) > 0 && req.Questions[0].QType == protocol.TypeAXFR {
			clientIP := net.ParseIP("127.0.0.1")
			if cip := w.ClientInfo().IP(); cip != nil {
				clientIP = cip
			}
			records, _, err := axfrServer.HandleAXFR(req, clientIP)
			if err != nil {
				return
			}
			for _, rr := range records {
				resp := &protocol.Message{
					Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
					Questions: req.Questions,
					Answers:   []*protocol.ResourceRecord{rr},
				}
				w.Write(resp)
			}
		}
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

	qname, _ := protocol.ParseName("stream.test.")
	query := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: qname, QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
		},
	}

	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	lenBuf := [2]byte{byte(n >> 8), byte(n & 0xff)}
	conn.Write(lenBuf[:])
	conn.Write(buf[:n])

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read all streamed messages
	messageCount := 0
	for {
		var msgLenBuf [2]byte
		_, err := conn.Read(msgLenBuf[:])
		if err != nil {
			break
		}
		msgLen := int(msgLenBuf[0])<<8 | int(msgLenBuf[1])
		if msgLen == 0 || msgLen > 65535 {
			break
		}
		respBuf := make([]byte, msgLen)
		_, err = conn.Read(respBuf)
		if err != nil {
			break
		}
		messageCount++
	}

	// Should have multiple messages (SOA + records + SOA)
	if messageCount < 3 {
		t.Errorf("Expected at least 3 messages, got %d", messageCount)
	}
	t.Logf("AXFR streaming test: received %d messages for 20+ records", messageCount)
}

// TestAXFRDenied tests that AXFR is denied for non-allowed IPs.
func TestAXFRDenied(t *testing.T) {
	z := zone.NewZone("denied.test.")
	z.SOA = &zone.SOARecord{
		MName:   "ns.denied.test.",
		RName:   "admin.denied.test.",
		Serial:  1,
	}
	z.Records["denied.test."] = []zone.Record{
		{Type: "NS", TTL: 3600, RData: "ns.denied.test."},
	}

	// Create AXFR server that only allows 192.168.0.0/24
	axfrServer := transfer.NewAXFRServer(make(map[string]*zone.Zone), transfer.WithAllowList([]string{"192.168.0.0/24"}))
	axfrServer.AddZone(z)

	handler := server.HandlerFunc(func(w server.ResponseWriter, req *protocol.Message) {
		if len(req.Questions) > 0 && req.Questions[0].QType == protocol.TypeAXFR {
			// Client is 127.0.0.1 but allow list only allows 192.168.0.0/24
			clientIP := net.ParseIP("127.0.0.1")
			if cip := w.ClientInfo().IP(); cip != nil {
				clientIP = cip
			}
			records, _, err := axfrServer.HandleAXFR(req, clientIP)
			if err != nil {
				// Access denied - this is expected
				return
			}
			// If no error, client was allowed - stream records
			for _, rr := range records {
				resp := &protocol.Message{
					Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
					Questions: req.Questions,
					Answers:   []*protocol.ResourceRecord{rr},
				}
				w.Write(resp)
			}
		}
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

	qname, _ := protocol.ParseName("denied.test.")
	query := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: qname, QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
		},
	}

	buf := make([]byte, 512)
	n, _ := query.Pack(buf)

	lenBuf := [2]byte{byte(n >> 8), byte(n & 0xff)}
	conn.Write(lenBuf[:])
	conn.Write(buf[:n])

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Set a short read deadline - should get no data since request is denied
	var msgLenBuf [2]byte
	_, err = conn.Read(msgLenBuf[:])
	if err == nil {
		// If we read something, it means AXFR was processed (which is wrong for ACL)
		t.Error("Expected AXFR to be denied, but got response")
	}
}

// TestIXFRRecordChange tests that IXFR can record changes without panic.
func TestIXFRRecordChange(t *testing.T) {
	axfrServer := transfer.NewAXFRServer(make(map[string]*zone.Zone))
	ixfrServer := transfer.NewIXFRServer(axfrServer)

	zoneName := "example.com."

	// Record changes - should not panic
	ixfrServer.RecordChange(zoneName, 1, 2,
		[]zone.RecordChange{
			{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "192.0.2.1"},
		},
		nil,
	)

	ixfrServer.RecordChange(zoneName, 2, 3,
		nil,
		[]zone.RecordChange{
			{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "192.0.2.1"},
		},
	)

	ixfrServer.SetMaxJournalSize(5)

	// Add many changes
	for i := 0; i < 10; i++ {
		ixfrServer.RecordChange(zoneName, uint32(i), uint32(i+1), nil, nil)
	}
	// Should not panic and should handle gracefully
}
