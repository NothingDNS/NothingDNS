package rpz

import (
	"net"
	"os"
	"testing"
)

func precedenceZone(t *testing.T, body string) string {
	t.Helper()
	f := t.TempDir() + "/z.rpz"
	if err := os.WriteFile(f, []byte("$TTL 60\n@ IN SOA ns.rpz. admin.rpz. 1 3600 600 86400 60\n@ IN NS ns.rpz.\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// draft-vixie-dnsop-dns-rpz-00 §5.6: the longest IP prefix wins within a
// zone, so a /32 PASSTHRU exception holds against a /24 block (F887); §5.2:
// the earlier of the plain rpz.files wins (F886).
func TestRPZPrecedence(t *testing.T) {
	e := NewEngine(Config{Enabled: true, Files: []string{precedenceZone(t,
		"24.0.2.0.192.rpz-ip CNAME .\n32.5.2.0.192.rpz-ip CNAME rpz-passthru.\n"+
			"24.0.2.0.192.rpz-client-ip CNAME .\n32.5.2.0.192.rpz-client-ip CNAME rpz-passthru.\n")}})
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if r := e.ResponseIPPolicy([]net.IP{net.ParseIP("192.0.2.5")}); r == nil || r.Action != ActionPassThrough {
		t.Errorf("rpz-ip /32 passthru vs /24 block: %+v", r)
	}
	if r := e.ClientIPPolicy(net.ParseIP("192.0.2.5")); r == nil || r.Action != ActionPassThrough {
		t.Errorf("rpz-client-ip /32 passthru vs /24 block: %+v", r)
	}
	allow := precedenceZone(t, "*.example.com CNAME rpz-passthru.\n")
	block := precedenceZone(t, "bad.example.com CNAME .\n")
	e = NewEngine(Config{Enabled: true, Files: []string{allow, block}})
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if r := e.QNAMEPolicy("bad.example.com."); r == nil || r.Action != ActionPassThrough {
		t.Errorf("files [allow, block]: %+v, want the earlier zone's PASSTHRU", r)
	}
}
