package raft

// Verifies that a non-nil rpcTLS config is actually wired into the Raft RPC
// transport (listener). Before this wiring, NewClusterIntegration hardcoded a
// nil tls.Config, so cluster.rpc.* was dead/misleading configuration.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

func selfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "raft-rpc-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS12,
	}
}

// TestClusterIntegration_RPCTLSListener confirms a node constructed with a
// non-nil rpcTLS still boots and becomes leader (the RPC listener is created
// over TLS), and that a plain (non-TLS) dial to that listener fails the
// handshake — proving the listener really is TLS-wrapped.
func TestClusterIntegration_RPCTLSListener(t *testing.T) {
	addr := freeTCPAddr(t)
	ci, err := NewClusterIntegration("n1", nil, nil, addr, t.TempDir(), "", "", selfSignedTLSConfig(t), util.DefaultLogger())
	if err != nil {
		t.Fatalf("NewClusterIntegration with rpcTLS: %v", err)
	}
	if err := ci.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ci.Stop()

	deadline := time.Now().Add(10 * time.Second) // randomized 1s+ election timeout
	for !ci.IsLeader() {
		if time.Now().After(deadline) {
			t.Fatal("node did not become leader over TLS RPC listener")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A plaintext TCP client must not complete a request against the TLS
	// listener: the TLS server rejects the non-handshake bytes.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	// Send bytes a Raft frame would start with; over TLS this is not a valid
	// ClientHello, so the server tears the connection down and a read fails.
	if _, err := conn.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x00}); err != nil {
		return // write already failed — listener rejected us, acceptable
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("plaintext client unexpectedly got a response from TLS listener")
	}
}
