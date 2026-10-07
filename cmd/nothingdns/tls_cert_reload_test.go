package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"github.com/nothingdns/nothingdns/internal/api"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func tlsReloadGenCert(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		DNSNames: []string{"dns.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

func tlsReloadWrite(t *testing.T, path string, b []byte) {
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func tlsReloadCN(st tls.ConnectionState) string {
	if len(st.PeerCertificates) == 0 {
		return "<none>"
	}
	return st.PeerCertificates[0].Subject.CommonName
}

func tlsReloadTLS(t *testing.T, addr, sni string, alpn []string) string {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: sni, NextProtos: alpn}) // #nosec
	if err != nil {
		t.Errorf("dial %s: %v", addr, err)
		return ""
	}
	defer c.Close()
	return tlsReloadCN(c.ConnectionState())
}

func tlsReloadQUIC(t *testing.T, addr string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := quicgo.DialAddr(ctx, addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}}, nil) // #nosec
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	defer c.CloseWithError(0, "")
	return tlsReloadCN(c.ConnectionState().TLS)
}

func tlsReloadFreeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

type tlsReloadRig struct {
	certFile, keyFile string
	srvs              *servers
	apiSrv            *api.Server
	apiAddr           string
	state             *reloadableState
}

// startTLSReloadRig starts DoT, DoQ, XoT and the HTTPS API with the
// production start code, all serving certFile/keyFile (cert "A").
func startTLSReloadRig(t *testing.T) *tlsReloadRig {
	t.Helper()
	dir := t.TempDir()
	r := &tlsReloadRig{certFile: filepath.Join(dir, "c.pem"), keyFile: filepath.Join(dir, "k.pem")}
	aC, aK := tlsReloadGenCert(t, "A")
	tlsReloadWrite(t, r.certFile, aC)
	tlsReloadWrite(t, r.keyFile, aK)
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)

	cfg := &config.Config{}
	cfg.Server.TLS = config.TLSConfig{Enabled: true, Bind: "127.0.0.1:0", CertFile: r.certFile, KeyFile: r.keyFile}
	cfg.Server.QUIC.Enabled = true
	cfg.Server.QUIC.Bind = "127.0.0.1:0"
	cfg.Server.XoT.Enabled = true
	cfg.Server.XoT.Bind = "127.0.0.1:0"
	cfg.Server.XoT.AllowedNetworks = []string{"127.0.0.0/8"}

	r.srvs = &servers{}
	t.Cleanup(func() { r.srvs.stopAll(logger) })
	if err := r.srvs.startTLS(cfg, nil, nil, logger); err != nil {
		t.Fatal(err)
	}
	if err := r.srvs.startDoQ(cfg, nil, logger); err != nil {
		t.Fatal(err)
	}
	if err := r.srvs.startXoT(cfg, map[string]*zone.Zone{}, &sync.RWMutex{}, &TransferManager{}, logger); err != nil {
		t.Fatal(err)
	}
	r.apiAddr = tlsReloadFreeAddr(t)
	r.apiSrv = api.NewServer(config.HTTPConfig{Enabled: true, Bind: r.apiAddr, TLSCertFile: r.certFile, TLSKeyFile: r.keyFile}, nil, nil, nil, nil, nil, nil)
	if err := r.apiSrv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.apiSrv.Stop() })
	r.state = &reloadableState{apiServer: r.apiSrv, logger: logger}
	r.state.setTransports(r.srvs)
	return r
}

func (r *tlsReloadRig) served(t *testing.T) map[string]string {
	t.Helper()
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- test reads the presented certificate
	defer cl.CloseIdleConnections()
	resp, err := cl.Get("https://" + r.apiAddr + "/api/v1/health")
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	_ = resp.Body.Close()
	dot := r.srvs.tls.Addr().String()
	return map[string]string{
		"DoT":     tlsReloadTLS(t, dot, "", nil),
		"DoT+SNI": tlsReloadTLS(t, dot, "dns.test", nil),
		"DoQ":     tlsReloadQUIC(t, r.srvs.doq.Addr().String()),
		"XoT":     tlsReloadTLS(t, r.srvs.xot.Addr(), "", []string{"dot"}),
		"API":     tlsReloadCN(*resp.TLS),
	}
}

func tlsReloadExpect(t *testing.T, stage string, got map[string]string, want string) {
	t.Helper()
	for name, cn := range got {
		if cn != want {
			t.Errorf("%s: %s served %q, want %q", stage, name, cn, want)
		}
	}
}

// TestReloadConfig_ReloadsTLSCertificates (F607–F611): a reload re-reads
// the certificate files of DoT (with and without SNI), DoQ, XoT and the
// HTTPS API — even when the config file itself fails to load — and a
// reload whose files are broken keeps every listener on its previous
// certificate.
func TestReloadConfig_ReloadsTLSCertificates(t *testing.T) {
	r := startTLSReloadRig(t)
	tlsReloadExpect(t, "start", r.served(t), "A")

	bC, bK := tlsReloadGenCert(t, "B")
	tlsReloadWrite(t, r.certFile, bC)
	tlsReloadWrite(t, r.keyFile, bK)
	// Files replaced but no reload yet: nothing re-reads them per handshake.
	tlsReloadExpect(t, "files swapped, no reload", r.served(t), "A")

	if _, err := reloadConfig(filepath.Join(t.TempDir(), "missing.yaml"), r.state); err == nil {
		t.Fatal("reloadConfig with a missing config file succeeded")
	}
	tlsReloadExpect(t, "after reload", r.served(t), "B")

	// Broken files (certificate C with key B; then a missing key) keep B.
	cC, _ := tlsReloadGenCert(t, "C")
	tlsReloadWrite(t, r.certFile, cC)
	reloadTLSCertificates(r.state)
	tlsReloadExpect(t, "after mismatched-key reload", r.served(t), "B")
	if err := os.Remove(r.keyFile); err != nil {
		t.Fatal(err)
	}
	reloadTLSCertificates(r.state)
	tlsReloadExpect(t, "after missing-key reload", r.served(t), "B")
}

// TestReloadTLSCertificates_ConcurrentHandshakes: DoT handshakes racing a
// reload all succeed with A or B; handshakes after it get B. Run with -race.
func TestReloadTLSCertificates_ConcurrentHandshakes(t *testing.T) {
	r := startTLSReloadRig(t)
	bC, bK := tlsReloadGenCert(t, "B")
	tlsReloadWrite(t, r.certFile, bC)
	tlsReloadWrite(t, r.keyFile, bK)
	dot := r.srvs.tls.Addr().String()

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 4; j++ {
				if cn := tlsReloadTLS(t, dot, "", nil); cn != "A" && cn != "B" {
					t.Errorf("concurrent handshake served %q", cn)
				}
			}
		}()
	}
	close(start)
	reloadTLSCertificates(r.state)
	wg.Wait()
	if cn := tlsReloadTLS(t, dot, "", nil); cn != "B" {
		t.Fatalf("after reload: %q, want B", cn)
	}
}
