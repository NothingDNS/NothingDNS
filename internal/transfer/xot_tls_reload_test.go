package transfer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/zone"
)

type xotReloadCert struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

// xotReloadIssue creates a certificate with subject cn, signed by parent
// (self-signed when parent is nil).
func xotReloadIssue(t *testing.T, cn string, parent *xotReloadCert, isCA bool, usage x509.ExtKeyUsage) *xotReloadCert {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{"xot.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
	}
	signer, signerKey := tmpl, k
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &k.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return &xotReloadCert{cert: c, key: k,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})}
}

func (c *xotReloadCert) pair(t *testing.T) tls.Certificate {
	t.Helper()
	p, err := tls.X509KeyPair(c.certPEM, c.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func xotReloadWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// xotReloadDial handshakes against cfg over loopback TCP (net.Pipe has no
// buffering, so a server alert can deadlock against the client's Finished)
// and reads one byte so post-handshake session tickets are processed. It
// returns the served certificate's CN, whether the session was resumed, and
// the error.
func xotReloadDial(t *testing.T, cfg *tls.Config, client *tls.Config) (string, bool, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		s := tls.Server(conn, cfg)
		if s.Handshake() == nil {
			_, _ = s.Write([]byte{1})
		}
		_ = s.Close()
	}()
	defer func() { <-done }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(conn, client)
	defer c.Close()
	if err := c.Handshake(); err != nil {
		return "", false, err
	}
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return "", false, err // TLS 1.3 reports a rejected client cert here
	}
	st := c.ConnectionState()
	return st.PeerCertificates[0].Subject.CommonName, st.DidResume, nil
}

// TestXoTReloadTLS_CertAndCA (F609): ReloadTLS swaps the server
// certificate for handshakes without SNI, swaps the mTLS client-CA pool
// (a client of the removed CA is refused, also on session resumption), and
// a failed reload keeps the previous certificate and pool.
func TestXoTReloadTLS_CertAndCA(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), filepath.Join(dir, "ca.pem")
	srvA := xotReloadIssue(t, "A", nil, false, x509.ExtKeyUsageServerAuth)
	srvB := xotReloadIssue(t, "B", nil, false, x509.ExtKeyUsageServerAuth)
	ca1 := xotReloadIssue(t, "CA1", nil, true, x509.ExtKeyUsageClientAuth)
	ca2 := xotReloadIssue(t, "CA2", nil, true, x509.ExtKeyUsageClientAuth)
	cli1 := xotReloadIssue(t, "client1", ca1, false, x509.ExtKeyUsageClientAuth)
	cli2 := xotReloadIssue(t, "client2", ca2, false, x509.ExtKeyUsageClientAuth)
	xotReloadWrite(t, certFile, srvA.certPEM)
	xotReloadWrite(t, keyFile, srvA.keyPEM)
	xotReloadWrite(t, caFile, ca1.certPEM)

	srv, err := NewXoTServer(map[string]*zone.Zone{}, &XoTConfig{CertFile: certFile, KeyFile: keyFile, CAFile: caFile}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := srv.tlsConfig
	cache := tls.NewLRUClientSessionCache(4)
	client := func(c *xotReloadCert) *tls.Config {
		return &tls.Config{InsecureSkipVerify: true, ServerName: "xot.test", MinVersion: tls.VersionTLS13, NextProtos: []string{xotALPN}, // #nosec G402 -- test reads the presented certificate
			Certificates: []tls.Certificate{c.pair(t)}, ClientSessionCache: cache}
	}

	if cn, _, err := xotReloadDial(t, cfg, client(cli1)); err != nil || cn != "A" {
		t.Fatalf("initial: cn=%q err=%v", cn, err)
	}
	if _, resumed, err := xotReloadDial(t, cfg, client(cli1)); err != nil || !resumed {
		t.Fatalf("control: second CA1 handshake did not resume (resumed=%v err=%v)", resumed, err)
	}
	if _, _, err := xotReloadDial(t, cfg, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cli2.pair(t)}}); err == nil { // #nosec G402
		t.Fatal("CA2 client accepted before reload")
	}

	xotReloadWrite(t, certFile, srvB.certPEM)
	xotReloadWrite(t, keyFile, srvB.keyPEM)
	xotReloadWrite(t, caFile, ca2.certPEM)
	if err := srv.ReloadTLS(); err != nil {
		t.Fatal(err)
	}

	if _, _, err := xotReloadDial(t, cfg, client(cli1)); err == nil {
		t.Fatal("CA1 client (with a resumable session) accepted after its CA was removed")
	}
	if cn, _, err := xotReloadDial(t, cfg, client(cli2)); err != nil || cn != "B" {
		t.Fatalf("after reload: cn=%q err=%v, want B", cn, err)
	}

	// Failure keeps the previous certificate and pool.
	xotReloadWrite(t, certFile, srvA.certPEM) // A cert with B key: mismatch
	xotReloadWrite(t, caFile, []byte("not a certificate"))
	if err := srv.ReloadTLS(); err == nil {
		t.Fatal("ReloadTLS with bad files succeeded")
	}
	if cn, _, err := xotReloadDial(t, cfg, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cli2.pair(t)}}); err != nil || cn != "B" { // #nosec G402
		t.Fatalf("after failed reload: cn=%q err=%v, want B with CA2 still trusted", cn, err)
	}
}
