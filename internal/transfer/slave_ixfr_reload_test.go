package transfer

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// After a restart the slave zone is the persisted file, whose RDATA text can
// differ from the wire form's (TXT with ';', HTTPS alpn quoting); IXFR
// deletions must still remove those records (RFC 1995 §4, F871).

func slaveReloadRR(t *testing.T, name, typ, rdata string) *protocol.ResourceRecord {
	d := protocol.ParseRDataText(typ, rdata)
	if d == nil {
		t.Fatalf("rdata %s %s", typ, rdata)
	}
	n, _ := protocol.ParseName(name)
	return &protocol.ResourceRecord{Name: n, Type: protocol.RecordTypeFromText(typ), Class: protocol.ClassIN, TTL: 300, Data: d}
}

func slaveReloadSOA(t *testing.T, serial string) *protocol.ResourceRecord {
	return slaveReloadRR(t, "example.com.", "SOA", "ns1.example.com. admin.example.com. "+serial+" 3600 600 86400 300")
}

func slaveReloadHas(sz *SlaveZone, name, typ, rdataContains string) bool {
	z := sz.GetZone()
	z.RLock()
	defer z.RUnlock()
	for _, r := range z.Records[name] {
		if strings.EqualFold(r.Type, typ) && strings.Contains(r.RData, rdataContains) {
			return true
		}
	}
	return false
}

func TestSlaveIXFRDeletesAfterPersistedReload(t *testing.T) {
	dir := t.TempDir()
	cfg := SlaveZoneConfig{ZoneName: "example.com.", Masters: []string{"192.0.2.53:53"}}
	sm1 := NewSlaveManager(nil)
	sm1.SetPersistDir(dir)
	sz1, err := NewSlaveZone(cfg)
	if err != nil {
		t.Fatal(err)
	}
	axfr := []*protocol.ResourceRecord{
		slaveReloadSOA(t, "1"),
		slaveReloadRR(t, "example.com.", "NS", "ns1.example.com."),
		slaveReloadRR(t, "ns1.example.com.", "A", "192.0.2.53"),
		slaveReloadRR(t, "www.example.com.", "A", "192.0.2.1"),
		slaveReloadRR(t, "svc.example.com.", "HTTPS", `1 . alpn="h2,h3" port=443`),
		slaveReloadRR(t, "txt.example.com.", "TXT", `"v=1;old"`),
		slaveReloadSOA(t, "1"),
	}
	if err := sm1.applyTransferredZone(sz1, axfr); err != nil {
		t.Fatal(err)
	}
	sm1.persistSlaveZone("example.com.", sz1)

	// Restart: a new manager preloads the persisted file.
	sm2 := NewSlaveManager(nil)
	sm2.SetPersistDir(dir)
	sz2, _ := NewSlaveZone(cfg)
	sm2.mu.Lock()
	sm2.loadPersistedZone("example.com.", sz2)
	sm2.mu.Unlock()
	if sz2.GetZone() == nil || sz2.GetLastSerial() != 1 {
		t.Fatalf("persisted zone not loaded (serial %d)", sz2.GetLastSerial())
	}
	ixfr := []*protocol.ResourceRecord{
		slaveReloadSOA(t, "2"),
		slaveReloadSOA(t, "1"),
		slaveReloadRR(t, "www.example.com.", "A", "192.0.2.1"),
		slaveReloadRR(t, "svc.example.com.", "HTTPS", `1 . alpn="h2,h3" port=443`),
		slaveReloadRR(t, "txt.example.com.", "TXT", `"v=1;old"`),
		slaveReloadSOA(t, "2"),
		slaveReloadRR(t, "www.example.com.", "A", "192.0.2.2"),
		slaveReloadRR(t, "svc.example.com.", "HTTPS", `1 . alpn="h3" port=8443`),
		slaveReloadRR(t, "txt.example.com.", "TXT", `"v=1;new"`),
		slaveReloadSOA(t, "2"),
	}
	if err := sm2.applyTransferredZone(sz2, ixfr); err != nil {
		t.Fatal(err)
	}
	if slaveReloadHas(sz2, "www.example.com.", "A", "192.0.2.1") || !slaveReloadHas(sz2, "www.example.com.", "A", "192.0.2.2") {
		t.Fatal("A record replacement failed")
	}
	oldHTTPS := slaveReloadHas(sz2, "svc.example.com.", "HTTPS", "8443") && slaveReloadHas(sz2, "svc.example.com.", "HTTPS", "port=443")
	oldTXT := slaveReloadHas(sz2, "txt.example.com.", "TXT", "old")
	if oldHTTPS || oldTXT {
		t.Fatalf("IXFR deletions missed after reload: old HTTPS kept=%v, old TXT kept=%v", oldHTTPS, oldTXT)
	}
}
