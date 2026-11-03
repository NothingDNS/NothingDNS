package server

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestBuildTLSConfigForProfileUsesTrustedRootCAs(t *testing.T) {
	pool := x509.NewCertPool()
	cfg, err := BuildTLSConfigForProfile(StrictTLSProfileConfig("dns.example", pool), "", "")
	if err != nil {
		t.Fatalf("BuildTLSConfigForProfile: %v", err)
	}
	if cfg.RootCAs != pool {
		t.Fatal("trusted CA pool was not assigned to RootCAs")
	}
	if cfg.ClientCAs != nil || cfg.ClientAuth != tls.NoClientCert {
		t.Fatal("upstream trust pool unexpectedly enabled server-side client authentication")
	}

	withoutPool, err := BuildTLSConfigForProfile(StrictTLSProfileConfig("dns.example", nil), "", "")
	if err != nil {
		t.Fatalf("BuildTLSConfigForProfile without pool: %v", err)
	}
	if withoutPool.RootCAs != nil {
		t.Fatal("nil profile pool should preserve the system-root default")
	}
}
