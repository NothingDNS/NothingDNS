package main

// F583/F584 (P2-G5) regression: SIGHUP applies transfer.tsig_keys (added,
// removed and rotated keys, allowed_cidrs, allow_update grants) to AXFR/IXFR
// and Dynamic DNS, and slave_zones TSIG secrets to slave transfers. Before
// P2-G5 the key stores were built once at startup: a removed key kept
// authenticating until restart. Built from
// .temp_files/verify_F583_F584_tsig_key_reload.

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

var (
	keyReloadRemoved = []byte("F583-removed-key-0123456789abcd!")
	keyReloadRotOld  = []byte("F583-rotated-old-0123456789abcd!")
	keyReloadRotNew  = []byte("F583-rotated-new-0123456789abcd!")
	keyReloadKeep    = []byte("F583-unchanged-0123456789abcdef!")
	keyReloadCIDR    = []byte("F583-cidr-key-0123456789abcdefg!")
)

func keyReloadKey(name string, secret []byte) *transfer.TSIGKey {
	return &transfer.TSIGKey{Name: name, Algorithm: transfer.HmacSHA256, Secret: secret}
}

func keyReloadKeyYAML(name string, secret []byte, extra string) string {
	return fmt.Sprintf("    - name: %s\n      algorithm: hmac-sha256\n      secret: \"%s\"\n%s", name, base64.StdEncoding.EncodeToString(secret), extra)
}

const keyReloadGrant = "      allow_update:\n        - example.com.\n"

func keyReloadCfg(dnsPort int, dir, zoneFile, keys, slaves string) string {
	return fmt.Sprintf("server:\n  udp_bind:\n    - 127.0.0.1:%d\n  tcp_bind:\n    - 127.0.0.1:%d\nlogging:\n  level: error\nmetrics:\n  enabled: false\nstorage:\n  data_dir: %s\nzones:\n  - %s\ntransfer:\n  allow_list:\n    - 127.0.0.0/8\n  require_tsig: true\n  tsig_keys:\n%s%s",
		dnsPort, dnsPort, filepath.Join(dir, "data"), zoneFile, keys, slaves)
}

func keyReloadAXFR(addr string, key *transfer.TSIGKey) bool {
	_, err := transfer.NewAXFRClient(addr, transfer.WithAXFRTimeout(5*time.Second)).Transfer("example.com.", key)
	return err == nil
}

func keyReloadIXFR(addr string, key *transfer.TSIGKey) bool {
	_, err := transfer.NewIXFRClient(addr, transfer.WithIXFRTimeout(5*time.Second)).Transfer("example.com.", 0, key)
	return err == nil
}

func keyReloadUpdate(t *testing.T, addr string, key *transfer.TSIGKey, host string) string {
	t.Helper()
	r := ddnsPolUpdate(t, addr, key, ddnsPolAdd(t, host, "192.0.2.77"))
	if r.err != nil {
		return "error: " + r.err.Error()
	}
	return protocol.RcodeString(int(r.rcode))
}

// keyReloadSOASerial returns name's SOA serial from the answer or the
// authority section (a transferred slave zone answers its apex SOA query
// with NODATA + SOA in the authority section).
func keyReloadSOASerial(addr, name string) (uint32, error) {
	q, _ := protocol.NewQuery(9, name, protocol.TypeSOA)
	buf := make([]byte, 512)
	n, err := q.Pack(buf)
	if err != nil {
		return 0, err
	}
	c, err := net.Dial("udp", addr)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Write(buf[:n]); err != nil {
		return 0, err
	}
	rb := make([]byte, 4096)
	rn, err := c.Read(rb)
	if err != nil {
		return 0, err
	}
	m, err := protocol.UnpackMessage(rb[:rn])
	if err != nil {
		return 0, err
	}
	for _, rr := range append(m.Answers, m.Authorities...) {
		if soa, ok := rr.Data.(*protocol.RDataSOA); ok {
			return soa.Serial, nil
		}
	}
	return 0, fmt.Errorf("no SOA (rcode %d)", m.Header.Flags.RCODE)
}

func keyReloadWaitSOA(addr, name string, want uint32, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if s, err := keyReloadSOASerial(addr, name); err == nil && s == want {
			return true
		}
		time.Sleep(50 * time.Millisecond) // polling for a state, not ordering
	}
	return false
}

// F583 e2e: a real server, SIGHUP after the tsig_keys section changed.
func TestF583_ReloadAppliesTSIGKeys(t *testing.T) {
	dir := t.TempDir()
	zoneFile := filepath.Join(dir, "example.com.zone")
	if err := os.WriteFile(zoneFile, []byte(fmt.Sprintf(notifyE2EZone, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	dnsPort := bootRestoreFreePort(t, "udp")
	before := keyReloadKeyYAML("removed-key.", keyReloadRemoved, keyReloadGrant) +
		keyReloadKeyYAML("rotated-key.", keyReloadRotOld, "") +
		keyReloadKeyYAML("keep-key.", keyReloadKeep, keyReloadGrant) +
		keyReloadKeyYAML("cidr-key.", keyReloadCIDR, "")
	sigCh, cfgPath := notifyReloadBoot(t, keyReloadCfg(dnsPort, dir, zoneFile, before, ""), dir)
	addr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	if !notifyReloadWaitSerial(addr, 1) {
		t.Fatal("setup: server never served serial 1")
	}
	removed, rotOld, rotNew := keyReloadKey("removed-key.", keyReloadRemoved), keyReloadKey("rotated-key.", keyReloadRotOld), keyReloadKey("rotated-key.", keyReloadRotNew)
	keep, cidr := keyReloadKey("keep-key.", keyReloadKeep), keyReloadKey("cidr-key.", keyReloadCIDR)
	if !keyReloadAXFR(addr, removed) || !keyReloadIXFR(addr, removed) || !keyReloadAXFR(addr, rotOld) || !keyReloadAXFR(addr, cidr) {
		t.Fatal("setup: configured keys do not authenticate transfers before the reload")
	}
	if got := keyReloadUpdate(t, addr, keep, "pre.example.com."); got != "NOERROR" {
		t.Fatalf("setup: keep-key UPDATE before reload = %s", got)
	}
	if got := keyReloadUpdate(t, addr, rotOld, "pre2.example.com."); got != "REFUSED" {
		t.Fatalf("setup: rotated-key (no grant) UPDATE before reload = %s, want REFUSED", got)
	}

	// Remove removed-key; rotate rotated-key and grant it example.com.;
	// revoke keep-key's grant; restrict cidr-key to 10.0.0.0/8.
	after := keyReloadKeyYAML("rotated-key.", keyReloadRotNew, keyReloadGrant) +
		keyReloadKeyYAML("keep-key.", keyReloadKeep, "") +
		keyReloadKeyYAML("cidr-key.", keyReloadCIDR, "      allowed_cidrs:\n        - 10.0.0.0/8\n")
	if err := os.WriteFile(cfgPath, []byte(keyReloadCfg(dnsPort, dir, zoneFile, after, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zoneFile, []byte(fmt.Sprintf(notifyE2EZone, 2026100799)), 0o644); err != nil {
		t.Fatal(err)
	}
	sigCh <- syscall.SIGHUP
	if !notifyReloadWaitSerial(addr, 2026100799) {
		t.Fatal("setup: SIGHUP reload did not take effect")
	}

	if !keyReloadAXFR(addr, keep) {
		t.Error("unchanged key no longer authenticates AXFR after reload")
	}
	if keyReloadAXFR(addr, removed) || keyReloadIXFR(addr, removed) {
		t.Error("removed key still authenticates AXFR/IXFR after reload")
	}
	if got := keyReloadUpdate(t, addr, removed, "post.example.com."); got != "NOTAUTH" {
		t.Errorf("removed key UPDATE = %s, want NOTAUTH", got)
	}
	if keyReloadAXFR(addr, rotOld) {
		t.Error("rotated key's old secret still authenticates AXFR")
	}
	if !keyReloadAXFR(addr, rotNew) || !keyReloadIXFR(addr, rotNew) {
		t.Error("rotated key's new secret does not authenticate AXFR/IXFR")
	}
	if got := keyReloadUpdate(t, addr, rotNew, "rot.example.com."); got != "NOERROR" {
		t.Errorf("newly granted key UPDATE = %s, want NOERROR", got)
	}
	if got := keyReloadUpdate(t, addr, keep, "revoked.example.com."); got != "REFUSED" {
		t.Errorf("revoked grant UPDATE = %s, want REFUSED", got)
	}
	if keyReloadAXFR(addr, cidr) {
		t.Error("key restricted to 10.0.0.0/8 by the reload still authenticates from 127.0.0.1")
	}
}

// keyReloadMaster serves slave.test. over loopback TCP, TSIG required with ks.
func keyReloadMaster(t *testing.T, ks *transfer.KeyStore) (string, *zone.Zone) {
	t.Helper()
	z := zone.NewZone("slave.test.")
	z.SOA = &zone.SOARecord{Name: "slave.test.", TTL: 300, MName: "ns1.slave.test.", RName: "admin.slave.test.", Serial: 2, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}
	z.Records["slave.test."] = []zone.Record{{Name: "slave.test.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.slave.test."}}
	z.Records["ns1.slave.test."] = []zone.Record{{Name: "ns1.slave.test.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.53"}}
	mh := newTestHandler()
	mh.transfer.AXFRServer = transfer.NewAXFRServer(map[string]*zone.Zone{"slave.test.": z},
		transfer.WithAllowList([]string{"127.0.0.0/8"}), transfer.WithKeyStore(ks), transfer.WithRequireTSIG())
	mh.transfer.IXFRServer = transfer.NewIXFRServer(mh.transfer.AXFRServer)
	srv := server.NewTCPServerWithWorkers("127.0.0.1:0", mh, 1)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Stop() })
	return srv.Addr().String(), z
}

func keyReloadNotify(t *testing.T, addr, zoneName string, id uint16) {
	t.Helper()
	msg := &protocol.Message{
		Header:    protocol.Header{ID: id, Flags: protocol.Flags{Opcode: protocol.OpcodeNotify, AA: true}},
		Questions: []*protocol.Question{{Name: ddnsPolName(t, zoneName), QType: protocol.TypeSOA, QClass: protocol.ClassIN}},
	}
	if _, err := ddnsPolExchange(addr, msg); err != nil {
		t.Fatalf("NOTIFY exchange: %v", err)
	}
}

// F584 e2e: a keyed slave zone signs its transfers with the secret a SIGHUP
// loaded. Control: before the key rotation, a NOTIFY-triggered transfer with
// the unchanged secret succeeds.
func TestF584_ReloadAppliesSlaveKey(t *testing.T) {
	dir := t.TempDir()
	zoneFile := filepath.Join(dir, "example.com.zone")
	if err := os.WriteFile(zoneFile, []byte(fmt.Sprintf(notifyE2EZone, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	mks := transfer.NewKeyStore()
	mks.AddKey(keyReloadKey("slave-key.", keyReloadRotOld))
	maddr, mz := keyReloadMaster(t, mks)
	slaves := func(secret []byte) string {
		return fmt.Sprintf("slave_zones:\n  - zone_name: slave.test.\n    transfer_type: axfr\n    masters:\n      - %s\n    tsig_key_name: slave-key.\n    tsig_secret: \"%s\"\n", maddr, base64.StdEncoding.EncodeToString(secret))
	}
	keys := keyReloadKeyYAML("keep-key.", keyReloadKeep, "")
	dnsPort := bootRestoreFreePort(t, "udp")
	sigCh, cfgPath := notifyReloadBoot(t, keyReloadCfg(dnsPort, dir, zoneFile, keys, slaves(keyReloadRotOld)), dir)
	addr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	if !notifyReloadWaitSerial(addr, 1) {
		t.Fatal("setup: server never served serial 1")
	}
	if !keyReloadWaitSOA(addr, "slave.test.", 2, 15*time.Second) {
		t.Fatal("setup: keyed slave zone never transferred serial 2")
	}
	// Control: same secret, master serial 3 → NOTIFY → transfer.
	mz.Lock()
	mz.SOA.Serial = 3
	mz.Unlock()
	keyReloadNotify(t, addr, "slave.test.", 101)
	if !keyReloadWaitSOA(addr, "slave.test.", 3, 10*time.Second) {
		t.Fatal("control: NOTIFY-triggered keyed transfer did not fetch serial 3")
	}

	// Rotate the master's key and the slave's secret, reload, NOTIFY.
	mks.ReplaceKey("slave-key.", keyReloadKey("slave-key.", keyReloadRotNew))
	mz.Lock()
	mz.SOA.Serial = 4
	mz.Unlock()
	if err := os.WriteFile(cfgPath, []byte(keyReloadCfg(dnsPort, dir, zoneFile, keys, slaves(keyReloadRotNew))), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zoneFile, []byte(fmt.Sprintf(notifyE2EZone, 2)), 0o644); err != nil {
		t.Fatal(err)
	}
	sigCh <- syscall.SIGHUP
	if !notifyReloadWaitSerial(addr, 2) {
		t.Fatal("setup: SIGHUP reload did not take effect")
	}
	keyReloadNotify(t, addr, "slave.test.", 102)
	if !keyReloadWaitSOA(addr, "slave.test.", 4, 10*time.Second) {
		s, _ := keyReloadSOASerial(addr, "slave.test.")
		t.Fatalf("slave.test. serial = %d after reload with the rotated secret, want 4", s)
	}
}

// keyReloadHandler serves a handler wired like main (NewTransferManager
// result incl. the reloadable key stores) over loopback TCP.
func keyReloadHandler(t *testing.T, yaml string) (*integratedHandler, string) {
	t.Helper()
	zones := map[string]*zone.Zone{"example.com.": xfrTSIGZone(0)}
	mgr := tmNewManager(t, yaml, zones)
	t.Cleanup(mgr.Stop)
	h := newTestHandler()
	h.zones = zones
	h.zoneManager = zone.NewManager()
	h.zoneManager.LoadZone(zones["example.com."], "")
	mgr.SetZonesMu(&h.zonesMu)
	r := mgr.Result()
	h.transfer = TransferComponents{AXFRServer: r.AXFRServer, IXFRServer: r.IXFRServer, NotifyHandler: r.NotifyHandler, DDNSHandler: r.DDNSHandler, SlaveManager: r.SlaveManager, AXFRKeys: r.AXFRKeys, SlaveKeys: r.SlaveKeys}
	srv := server.NewTCPServerWithWorkers("127.0.0.1:0", h, 2)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Stop() })
	return h, srv.Addr().String()
}

func keyReloadPlan(t *testing.T, yaml string) *transferKeyPlan {
	t.Helper()
	cfg, err := config.UnmarshalYAML(yaml)
	if err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	plan, err := prepareTransferKeys(cfg, nil)
	if err != nil {
		t.Fatalf("prepareTransferKeys: %v", err)
	}
	return plan
}

func keyReloadYAML(dir, keys string) string {
	return fmt.Sprintf("storage:\n  data_dir: %s\ntransfer:\n  allow_list:\n    - 127.0.0.0/8\n  require_tsig: true\n  tsig_keys:\n%s", dir, keys)
}

func keyReloadWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(time.Millisecond) // polling a lock state, not ordering
	}
}

// F583 gated: a transfer that started before the reload is authenticated
// entirely against the old key set (it finishes first; the reload waits),
// and every request after the reload sees only the new set.
func TestF583_InFlightTransferFinishesWithOldKeys(t *testing.T) {
	dir := t.TempDir()
	removed := keyReloadKey("removed-key.", keyReloadRemoved)
	keep := keyReloadKey("keep-key.", keyReloadKeep)
	h, addr := keyReloadHandler(t, keyReloadYAML(dir, keyReloadKeyYAML("removed-key.", keyReloadRemoved, "")+keyReloadKeyYAML("keep-key.", keyReloadKeep, "")))
	plan := keyReloadPlan(t, keyReloadYAML(dir, keyReloadKeyYAML("keep-key.", keyReloadKeep, "")))

	// Park an AXFR signed with the soon-removed key inside HandleAXFR: it
	// holds xferKeysMu (read) and blocks on the zones lock before verifying.
	h.zonesMu.Lock()
	inFlight := make(chan bool, 1)
	go func() { inFlight <- keyReloadAXFR(addr, removed) }()
	keyReloadWaitFor(t, "the AXFR to hold the key lock", func() bool {
		if h.xferKeysMu.TryLock() {
			h.xferKeysMu.Unlock()
			return false
		}
		return true
	})
	reloaded := make(chan struct{})
	go func() { applyTransferKeys(h, plan, nil); close(reloaded) }()
	keyReloadWaitFor(t, "the reload to wait for the in-flight AXFR", func() bool {
		if h.xferKeysMu.TryRLock() {
			h.xferKeysMu.RUnlock()
			return false
		}
		return true
	})
	select {
	case <-reloaded:
		t.Fatal("reload completed while an AXFR was authenticating")
	default:
	}
	h.zonesMu.Unlock()
	if ok := ddnsBatchWait(t, inFlight, "in-flight AXFR"); !ok {
		t.Error("AXFR that started before the reload was not authenticated with the old key set")
	}
	ddnsBatchWait(t, reloaded, "reload")
	if keyReloadAXFR(addr, removed) {
		t.Error("removed key authenticates an AXFR that started after the reload")
	}
	if !keyReloadAXFR(addr, keep) {
		t.Error("unchanged key stopped authenticating after the reload")
	}
}

// F583 unit: the DDNS handler is replaced (grants cannot be revoked in
// place), the old one is closed, a consumer is started per handler, and the
// managed key stores are synced exactly.
func TestApplyTransferKeys_F583(t *testing.T) {
	applyTransferKeys(nil, nil, nil)
	h0 := newTestHandler()
	applyTransferKeys(h0, &transferKeyPlan{}, nil) // no stores, no DDNS: no-op
	if h0.transfer.DDNSHandler != nil {
		t.Fatal("reload created a DDNS handler where none was configured")
	}

	dir := t.TempDir()
	h, addr := keyReloadHandler(t, keyReloadYAML(dir, keyReloadKeyYAML("keep-key.", keyReloadKeep, keyReloadGrant)))
	keep := keyReloadKey("keep-key.", keyReloadKeep)
	if got := keyReloadUpdate(t, addr, keep, "a.example.com."); got != "NOERROR" {
		t.Fatalf("setup UPDATE = %s", got)
	}
	old := h.currentDDNSHandler()
	h.ddnsConsumerMu.Lock()
	if h.ddnsConsumer != old {
		t.Error("no consumer started for the startup DDNS handler")
	}
	h.ddnsConsumerMu.Unlock()

	newKey := keyReloadKey("new-key.", keyReloadRotNew)
	applyTransferKeys(h, keyReloadPlan(t, keyReloadYAML(dir, keyReloadKeyYAML("keep-key.", keyReloadKeep, "")+keyReloadKeyYAML("new-key.", keyReloadRotNew, keyReloadGrant))), util.NewLogger(util.ERROR, util.TextFormat, nil))
	if h.currentDDNSHandler() == old {
		t.Fatal("DDNS handler not replaced by the reload")
	}
	if _, open := <-old.GetUpdateChannel(); open {
		// The startup UPDATE's event may still be buffered; the channel
		// must be closed after it.
		if _, open = <-old.GetUpdateChannel(); open {
			t.Error("replaced DDNS handler was not closed")
		}
	}
	if got := keyReloadUpdate(t, addr, keep, "b.example.com."); got != "REFUSED" {
		t.Errorf("revoked grant UPDATE = %s, want REFUSED", got)
	}
	if got := keyReloadUpdate(t, addr, newKey, "c.example.com."); got != "NOERROR" {
		t.Errorf("added key UPDATE = %s, want NOERROR", got)
	}
	h.ddnsConsumerMu.Lock()
	if h.ddnsConsumer != h.transfer.DDNSHandler {
		t.Error("no consumer started for the reloaded DDNS handler")
	}
	h.ddnsConsumerMu.Unlock()
	if !keyReloadAXFR(addr, newKey) || !keyReloadAXFR(addr, keep) {
		t.Error("reloaded keys do not authenticate AXFR")
	}

	// managedKeyStore.sync: exact set, replacement and removal.
	m := newManagedKeyStore()
	m.sync([]*transfer.TSIGKey{keyReloadKey("A.example.", keyReloadRotOld), keyReloadKey("b.example.", keyReloadKeep)})
	m.sync([]*transfer.TSIGKey{keyReloadKey("a.example.", keyReloadRotNew)})
	if k, ok := m.store.GetKey("a.example."); !ok || string(k.Secret) != string(keyReloadRotNew) {
		t.Errorf("rotated key not replaced: %v %v", ok, k)
	}
	if _, ok := m.store.GetKey("b.example."); ok {
		t.Error("removed key still in the store")
	}
	m.sync(nil)
	if m.store.HasKeys() {
		t.Error("store not empty after syncing an empty key set")
	}
	var nilStore *managedKeyStore
	nilStore.sync(nil)

	// An unparsable key aborts the reload's preparation.
	bad := &config.Config{Transfer: config.TransferConfig{TSIGKeys: []config.TransferTSIGKeyConfig{{Name: "x.", Algorithm: "hmac-sha256", Secret: "!!!"}}}}
	if _, err := prepareTransferKeys(bad, nil); err == nil || !strings.Contains(err.Error(), "tsig_keys") {
		t.Errorf("prepareTransferKeys(bad secret) err = %v", err)
	}
}
