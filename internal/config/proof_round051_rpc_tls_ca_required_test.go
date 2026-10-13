package config

import "testing"

// Round 051: cluster.rpc.tls.enabled without tls_ca_cert_file must be a load
// error, never a silently-accepted half-authenticated Raft RPC listener.
//
// Pre-fix: validateCluster's RPC TLS block (validation.go) required
// cert_file/key_file and constrained min_tls_version, but nothing required
// tls_ca_cert_file. RPCConfig.NewTLSConfig (cluster_config.go:241) then
// returned a tls.Config with ClientAuth unset (NoClientCert) and RootCAs nil:
// inbound Raft RPC accepted any unauthenticated client (RequestVote /
// AppendEntries / InstallSnapshot are then reachable by any host that can
// dial the RPC port), and outbound peer dials verified servers against the
// host's system trust store — the exact peer-impersonation vector the
// NewTLSConfig comment itself documents for the CA-less case.
//
// Contract basis (expected behaviour): the same file's XoT surface is
// documented deny-by-default ("will refuse all transfers otherwise" without
// its CA/allowlist), and the runtime-consistency convention this package
// already enforces (F602 encryption_key, F569 forward_updates) turns a
// dangerous-but-parseable config into a load error. cluster_manager.go:42
// feeds NewTLSConfig's result straight into the Raft RPC transport.
//
// Pre-fix expectation: the CA-less case FAILS (Validate returns no error);
// post-fix it is rejected with an error naming cluster.rpc and
// tls_ca_cert_file. Control: the same config with the CA file set keeps
// validating cleanly both before and after.

func TestRound051RPCTLSCARequired(t *testing.T) {
	caLess := `
cluster:
  enabled: true
  rpc:
    enabled: true
    tls_cert_file: "/etc/nothingdns/pki/node.pem"
    tls_key_file: "/etc/nothingdns/pki/node-key.pem"
`
	cfg, err := UnmarshalYAML(caLess)
	if err != nil {
		t.Fatalf("control parse failed: %v", err)
	}
	if errs := cfg.Validate(); len(errs) == 0 {
		t.Fatalf("FAIL: CA-less cluster.rpc TLS accepted silently (want a load error requiring tls_ca_cert_file, per XoT deny-by-default and the F602/F569 runtime-consistency contract)")
	}

	withCA := `
cluster:
  enabled: true
  rpc:
    enabled: true
    tls_cert_file: "/etc/nothingdns/pki/node.pem"
    tls_key_file: "/etc/nothingdns/pki/node-key.pem"
    tls_ca_cert_file: "/etc/nothingdns/pki/cluster-ca.pem"
`
	cfg, err = UnmarshalYAML(withCA)
	if err != nil {
		t.Fatalf("control parse failed: %v", err)
	}
	if errs := cfg.Validate(); len(errs) != 0 {
		t.Fatalf("FAIL: control with tls_ca_cert_file set must validate cleanly, got: %v", errs)
	}
}
