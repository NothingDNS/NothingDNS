// NothingDNS — reloadable TLS certificate holder.

package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sync/atomic"
)

// CertReloader holds one listener's certificate/key pair and hands it to
// every TLS handshake through tls.Config.GetCertificate. Reload re-reads the
// files and swaps the certificate atomically: handshakes that start after a
// successful Reload get the new certificate, connections already established
// keep theirs, and a failed Reload (missing file, key that does not match)
// keeps the previous certificate. It is safe for concurrent use.
type CertReloader struct {
	certFile string
	keyFile  string
	cert     atomic.Pointer[tls.Certificate]
}

// NewCertReloader loads certFile/keyFile once and returns a holder serving
// that pair. It fails when the pair cannot be loaded, so a listener never
// starts without a certificate.
func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("certificate and key file are required")
	}
	r := &CertReloader{certFile: certFile, keyFile: keyFile}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload re-reads the certificate and key files. On error the current
// certificate stays in use and the error is returned.
func (r *CertReloader) Reload() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("loading certificate %s / key %s: %w", r.certFile, r.keyFile, err)
	}
	r.cert.Store(&cert)
	return nil
}

// Files returns the certificate and key paths the holder reads.
func (r *CertReloader) Files() (certFile, keyFile string) {
	return r.certFile, r.keyFile
}

// Certificate returns the certificate currently served.
func (r *CertReloader) Certificate() *tls.Certificate {
	return r.cert.Load()
}

// GetCertificate implements tls.Config.GetCertificate. Leave
// tls.Config.Certificates empty so it is consulted for every handshake,
// with or without SNI.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := r.cert.Load(); c != nil {
		return c, nil
	}
	return nil, errors.New("no TLS certificate loaded")
}
