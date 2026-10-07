package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// certReloadPEM returns a self-signed certificate and key whose subject CN
// is cn.
func certReloadPEM(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{"dns.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

func certReloadWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// certReloadHandshake runs one in-memory TLS handshake against cfg and
// returns the CN of the certificate the server presented.
func certReloadHandshake(t *testing.T, cfg *tls.Config, sni string) string {
	t.Helper()
	sc, cc := net.Pipe()
	defer sc.Close()
	defer cc.Close()
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- tls.Server(sc, cfg).Handshake()
	}()
	c := tls.Client(cc, &tls.Config{InsecureSkipVerify: true, ServerName: sni, MinVersion: tls.VersionTLS13}) // #nosec G402 -- test reads the presented certificate
	if err := c.Handshake(); err != nil {
		t.Errorf("client handshake: %v", err)
		return ""
	}
	if err := <-srvErr; err != nil {
		t.Errorf("server handshake: %v", err)
		return ""
	}
	return c.ConnectionState().PeerCertificates[0].Subject.CommonName
}

// TestCertReloader_ReloadSwapsForAllHandshakes: after Reload, handshakes
// with and without SNI get the new certificate (F607).
func TestCertReloader_ReloadSwapsForAllHandshakes(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	aCert, aKey := certReloadPEM(t, "A")
	bCert, bKey := certReloadPEM(t, "B")
	certReloadWrite(t, certFile, aCert)
	certReloadWrite(t, keyFile, aKey)

	r, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS13}
	for _, sni := range []string{"", "dns.test"} {
		if got := certReloadHandshake(t, cfg, sni); got != "A" {
			t.Fatalf("before reload (sni=%q): got %q, want A", sni, got)
		}
	}

	certReloadWrite(t, certFile, bCert)
	certReloadWrite(t, keyFile, bKey)
	// Files changed but no reload yet: still A (no per-handshake disk read).
	if got := certReloadHandshake(t, cfg, "dns.test"); got != "A" {
		t.Fatalf("before reload, files swapped: got %q, want A", got)
	}
	if err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	for _, sni := range []string{"", "dns.test"} {
		if got := certReloadHandshake(t, cfg, sni); got != "B" {
			t.Fatalf("after reload (sni=%q): got %q, want B", sni, got)
		}
	}
}

// TestCertReloader_FailedReloadKeepsOld: a missing file or a key that does
// not match keeps the current certificate.
func TestCertReloader_FailedReloadKeepsOld(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	aCert, aKey := certReloadPEM(t, "A")
	bCert, _ := certReloadPEM(t, "B")
	certReloadWrite(t, certFile, aCert)
	certReloadWrite(t, keyFile, aKey)
	r, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS13}

	certReloadWrite(t, certFile, bCert) // B certificate, A key: mismatch
	if err := r.Reload(); err == nil {
		t.Fatal("Reload with a mismatched key succeeded")
	}
	if got := certReloadHandshake(t, cfg, ""); got != "A" {
		t.Fatalf("after mismatched reload: got %q, want A", got)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	if err := r.Reload(); err == nil {
		t.Fatal("Reload with a missing key file succeeded")
	}
	if got := certReloadHandshake(t, cfg, "dns.test"); got != "A" {
		t.Fatalf("after missing-file reload: got %q, want A", got)
	}
}

func TestNewCertReloader_Errors(t *testing.T) {
	if _, err := NewCertReloader("", ""); err == nil {
		t.Error("empty paths accepted")
	}
	if _, err := NewCertReloader("/nonexistent/c.pem", "/nonexistent/k.pem"); err == nil {
		t.Error("missing files accepted")
	}
	var r CertReloader
	if _, err := r.GetCertificate(nil); err == nil {
		t.Error("empty holder returned a certificate")
	}
}

// TestCertReloader_ConcurrentHandshakesDuringReload: handshakes racing a
// reload each get a complete certificate (A or B, never an error), and
// every handshake that starts after Reload returns gets B. Run with -race.
func TestCertReloader_ConcurrentHandshakesDuringReload(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	aCert, aKey := certReloadPEM(t, "A")
	bCert, bKey := certReloadPEM(t, "B")
	certReloadWrite(t, certFile, aCert)
	certReloadWrite(t, keyFile, aKey)
	r, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS13}
	certReloadWrite(t, certFile, bCert)
	certReloadWrite(t, keyFile, bKey)

	const workers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 5; j++ {
				if got := certReloadHandshake(t, cfg, ""); got != "A" && got != "B" {
					t.Errorf("concurrent handshake got %q", got)
				}
			}
		}()
	}
	close(start)
	if err := r.Reload(); err != nil {
		t.Error(err)
	}
	wg.Wait()
	for i := 0; i < 3; i++ {
		if got := certReloadHandshake(t, cfg, ""); got != "B" {
			t.Fatalf("handshake after reload: got %q, want B", got)
		}
	}
}
