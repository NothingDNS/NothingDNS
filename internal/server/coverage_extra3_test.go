package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ==============================================================================
// TCP handleMessage - EDNS0 with valid ECS through pack/unpack cycle
// Tests the full ECS extraction path now that TypeOPT is registered in createRData.
// Lines 224-234: optData type assertion succeeds, ECS option found and unpacked.
// ==============================================================================

func TestTCPServerHandleMessageEDNS0ECSExtractViaNetwork(t *testing.T) {
	infoCh := make(chan *ClientInfo, 1)

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		infoCh <- w.ClientInfo()
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewTCPServerWithWorkers("127.0.0.1:0", handler, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Build a query with EDNS0 OPT record containing a valid Client Subnet option
	query, _ := protocol.NewQuery(0xEC51, "ecs-network.example.com.", protocol.TypeA)
	query.SetEDNS0(4096, false)

	opt := &protocol.RDataOPT{Options: []protocol.EDNS0Option{
		{
			Code: protocol.OptionCodeClientSubnet,
			Data: []byte{0x00, 0x01, 0x18, 0x00, 10, 0, 0, 0}, // IPv4 /24
		},
	}}
	query.Additionals = []*protocol.ResourceRecord{
		{
			Name:  mustParseName("."),
			Type:  protocol.TypeOPT,
			Class: 4096,
			Data:   opt,
		},
	}

	buf := make([]byte, 512)
	n, _ := query.Pack(buf[2:])
	binary.BigEndian.PutUint16(buf[0:], uint16(n))
	client.Write(buf[:n+2])

	// Read response
	var lengthBuf [2]byte
	io.ReadFull(client, lengthBuf[:])
	respLen := binary.BigEndian.Uint16(lengthBuf[:])
	respBuf := make([]byte, respLen)
	io.ReadFull(client, respBuf)

	var receivedClientInfo *ClientInfo
	select {
	case receivedClientInfo = <-infoCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for handler")
	}

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if !receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be true")
	}
	if receivedClientInfo.EDNS0UDPSize != 4096 {
		t.Errorf("EDNS0UDPSize = %d, want 4096", receivedClientInfo.EDNS0UDPSize)
	}
	// With TypeOPT registered, ECS should be properly extracted
	if receivedClientInfo.ClientSubnet == nil {
		t.Error("ClientSubnet should not be nil for valid ECS data")
	} else {
		if receivedClientInfo.ClientSubnet.Family != 1 {
			t.Errorf("ClientSubnet.Family = %d, want 1 (IPv4)", receivedClientInfo.ClientSubnet.Family)
		}
		if receivedClientInfo.ClientSubnet.SourcePrefixLength != 24 {
			t.Errorf("ClientSubnet.SourcePrefixLength = %d, want 24", receivedClientInfo.ClientSubnet.SourcePrefixLength)
		}
	}
}

// ==============================================================================
// TCP handleMessage - EDNS0 with non-ECS option through pack/unpack cycle
// Lines 224-230: optData type assertion succeeds, but option code is not ECS
// ==============================================================================

func TestTCPServerHandleMessageEDNS0NonECSViaNetwork(t *testing.T) {
	infoCh := make(chan *ClientInfo, 1)

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		infoCh <- w.ClientInfo()
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewTCPServerWithWorkers("127.0.0.1:0", handler, 1)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Build query with EDNS0 OPT record containing a non-ECS option
	query, _ := protocol.NewQuery(0xEC52, "non-ecs-network.example.com.", protocol.TypeA)
	query.SetEDNS0(4096, false)

	opt := &protocol.RDataOPT{Options: []protocol.EDNS0Option{
		{
			Code: 10, // Not OptionCodeClientSubnet
			Data: []byte{0x00, 0x01},
		},
	}}
	query.Additionals = []*protocol.ResourceRecord{
		{
			Name:  mustParseName("."),
			Type:  protocol.TypeOPT,
			Class: 4096,
			Data:   opt,
		},
	}

	buf := make([]byte, 512)
	n, _ := query.Pack(buf[2:])
	binary.BigEndian.PutUint16(buf[0:], uint16(n))
	client.Write(buf[:n+2])

	var lengthBuf [2]byte
	io.ReadFull(client, lengthBuf[:])
	respLen := binary.BigEndian.Uint16(lengthBuf[:])
	respBuf := make([]byte, respLen)
	io.ReadFull(client, respBuf)

	var receivedClientInfo *ClientInfo
	select {
	case receivedClientInfo = <-infoCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for handler")
	}

	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if !receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be true")
	}
	if receivedClientInfo.EDNS0UDPSize != 4096 {
		t.Errorf("EDNS0UDPSize = %d, want 4096", receivedClientInfo.EDNS0UDPSize)
	}
	// No ECS option present, so ClientSubnet should be nil
	if receivedClientInfo.ClientSubnet != nil {
		t.Error("ClientSubnet should be nil when no ECS option present")
	}
}

// ==============================================================================
// UDP handleRequest - EDNS0 with valid ECS through pack/unpack cycle
// Lines 225-231: optData type assertion succeeds, ECS option found and unpacked.
// ==============================================================================

func TestUDPServerHandleRequestEDNS0ECSViaNetwork(t *testing.T) {
	infoCh := make(chan *ClientInfo, 1)

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		infoCh <- w.ClientInfo()
		w.Write(&protocol.Message{
			Header: protocol.Header{
				ID:    req.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	server := NewUDPServer("127.0.0.1:0", handler)
	if err := server.Listen(); err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer server.Stop()

	go server.Serve()
	time.Sleep(20 * time.Millisecond)

	client, err := net.DialUDP("udp", nil, server.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Build query with EDNS0 OPT containing a valid ECS option
	query, _ := protocol.NewQuery(0xEC53, "ecs-udp.example.com.", protocol.TypeA)
	query.SetEDNS0(4096, false)

	opt := &protocol.RDataOPT{Options: []protocol.EDNS0Option{
		{
			Code: protocol.OptionCodeClientSubnet,
			Data: []byte{0x00, 0x01, 0x10, 0x00, 172, 16, 0, 0}, // IPv4 /16
		},
	}}
	query.Additionals = []*protocol.ResourceRecord{
		{
			Name:  mustParseName("."),
			Type:  protocol.TypeOPT,
			Class: 4096,
			Data:   opt,
		},
	}

	buf := make([]byte, 512)
	n, _ := query.Pack(buf)
	client.Write(buf[:n])

	client.SetReadDeadline(time.Now().Add(time.Second))
	respBuf := make([]byte, 512)
	n, err = client.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	var receivedClientInfo *ClientInfo
	select {
	case receivedClientInfo = <-infoCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for handler")
	}
	if receivedClientInfo == nil {
		t.Fatal("ClientInfo should not be nil")
	}
	if !receivedClientInfo.HasEDNS0 {
		t.Error("HasEDNS0 should be true")
	}
	if receivedClientInfo.EDNS0UDPSize != 4096 {
		t.Errorf("EDNS0UDPSize = %d, want 4096", receivedClientInfo.EDNS0UDPSize)
	}
	if receivedClientInfo.ClientSubnet == nil {
		t.Error("ClientSubnet should not be nil for valid ECS data")
	} else {
		if receivedClientInfo.ClientSubnet.Family != 1 {
			t.Errorf("ClientSubnet.Family = %d, want 1 (IPv4)", receivedClientInfo.ClientSubnet.Family)
		}
		if receivedClientInfo.ClientSubnet.SourcePrefixLength != 16 {
			t.Errorf("ClientSubnet.SourcePrefixLength = %d, want 16", receivedClientInfo.ClientSubnet.SourcePrefixLength)
		}
	}
}

// ==============================================================================
// TCP Write - truncation with small maxSize to exercise truncation path
// Lines 273-279: message exceeds maxSize, triggers truncation
// ==============================================================================

func TestTCPResponseWriterTruncationSmallMaxSize3(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go io.Copy(io.Discard, clientConn)

	rw := &tcpResponseWriter{
		conn:    serverConn,
		client:  &ClientInfo{Protocol: "tcp"},
		maxSize: 50, // Small to trigger truncation
	}

	name := mustParseName("tcp-trunc3.example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0xDED7,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
			},
		},
	}

	_, err := rw.Write(msg)
	_ = err
}

// ==============================================================================
// TLS Write - truncation with small maxSize to exercise truncation path
// Lines 297-303: message exceeds maxSize, triggers truncation
// ==============================================================================

func TestTLSResponseWriterTruncationSmallMaxSize3(t *testing.T) {
	cert := generateTestTLSCert3(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
	}()

	tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
	clientConn, err := tls.Dial("tcp", ln.Addr().String(), tlsClientConfig)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	rw := &tlsResponseWriter{
		conn:    clientConn,
		client:  &ClientInfo{Protocol: "dot"},
		maxSize: 50, // Small to trigger truncation
	}

	name := mustParseName("tls-trunc3.example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0xDED8,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
			},
		},
	}

	_, err = rw.Write(msg)
	_ = err
}

// ==============================================================================
// generateTestTLSCert3 generates a TLS certificate for testing.
// ==============================================================================

func generateTestTLSCert3(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to load certificate: %v", err)
	}

	return cert
}
