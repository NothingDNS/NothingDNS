package main

// F452 (P2-C2) regression: DDNS UPDATE authorization from transfer.tsig_keys
// allow_update, TSIG-signed responses, and Raft replication in cluster mode.
// Built from .temp_files/verify_F452_ddns_update_policy (identifiers renamed).

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const ddnsPolZone = "example.com."

var (
	ddnsPolSecret      = []byte("F452-ddns-update-key-0123456789!") // 32 raw bytes
	ddnsPolOtherSecret = []byte("F452-other-transfer-key-abcdefgh") // 32 raw bytes
)

func ddnsPolKey(name string, secret []byte) *transfer.TSIGKey {
	return &transfer.TSIGKey{Name: name, Algorithm: transfer.HmacSHA256, Secret: secret}
}

type ddnsPolServer struct {
	addr    string
	zone    *zone.Zone
	manager *zone.Manager
	cluster *cluster.Cluster
	prodErr []string
	valErr  []string
}

// ddnsPolServe builds the master from yaml. raft starts a single-node Raft
// cluster sharing the zone manager (as main does) before serving.
func ddnsPolServe(t *testing.T, yaml string, raft bool) *ddnsPolServer {
	t.Helper()
	cfg, err := config.UnmarshalYAML(yaml)
	if err != nil {
		t.Fatalf("setup: UnmarshalYAML: %v", err)
	}
	s := &ddnsPolServer{valErr: cfg.Validate()}
	for _, e := range cfg.ValidateProduction() {
		if strings.Contains(e, "transfer") {
			s.prodErr = append(s.prodErr, e)
		}
	}
	z := xfrTSIGZone(0)
	zm := zone.NewManager()
	zm.LoadZone(z, "")
	zones := map[string]*zone.Zone{ddnsPolZone: z}
	h := newTestHandler()
	h.zones = zones
	h.zoneManager = zm
	mgr, err := NewTransferManager(cfg, zones, nil, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("setup: NewTransferManager: %v", err)
	}
	t.Cleanup(mgr.Stop)
	mgr.SetZonesMu(&h.zonesMu)
	r := mgr.Result()
	h.transfer = TransferComponents{AXFRServer: r.AXFRServer, IXFRServer: r.IXFRServer, NotifyHandler: r.NotifyHandler, DDNSHandler: r.DDNSHandler, SlaveManager: r.SlaveManager}
	if raft {
		c, err := cluster.New(cluster.Config{
			Enabled:              true,
			AllowInsecureCluster: true,
			NodeID:               "ddnsPol-node",
			BindAddr:             "127.0.0.1",
			GossipPort:           0,
			ConsensusMode:        cluster.ConsensusRaft,
			DataDir:              t.TempDir(),
			Peers:                []cluster.PeerConfig{{NodeID: "ddnsPol-node", Addr: "127.0.0.1:0"}},
			ZoneManager:          zm,
		}, util.NewLogger(util.ERROR, util.TextFormat, nil), nil)
		if err != nil {
			t.Fatalf("setup: cluster.New: %v", err)
		}
		if err := c.Start(); err != nil {
			t.Fatalf("setup: cluster.Start: %v", err)
		}
		t.Cleanup(func() { _ = c.Stop() })
		deadline := time.Now().Add(10 * time.Second)
		for c.RaftLeaderID() != "ddnsPol-node" || !c.IsLeader() {
			if time.Now().After(deadline) {
				t.Fatalf("setup: single-node Raft never elected itself")
			}
			time.Sleep(10 * time.Millisecond) // waiting for election, not ordering
		}
		h.cluster = c
		s.cluster = c
	}
	srv := server.NewTCPServerWithWorkers("127.0.0.1:0", h, 1)
	if err := srv.Listen(); err != nil {
		t.Fatalf("setup: listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Stop() })
	s.addr = srv.Addr().String()
	s.zone = z
	s.manager = zm
	return s
}

func ddnsPolName(t *testing.T, s string) *protocol.Name {
	t.Helper()
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatalf("setup: ParseName(%q): %v", s, err)
	}
	return n
}

// ddnsPolAdd is an RFC 2136 §2.5.1 "add to an RRset" RR (class IN).
func ddnsPolAdd(t *testing.T, name, ip string) *protocol.ResourceRecord {
	var a [4]byte
	copy(a[:], net.ParseIP(ip).To4())
	return &protocol.ResourceRecord{Name: ddnsPolName(t, name), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: a}}
}

// ddnsPolDelRRset is §2.5.2 "delete an RRset" (class ANY, TTL 0, RDLENGTH 0).
func ddnsPolDelRRset(t *testing.T, name string, typ uint16) *protocol.ResourceRecord {
	return &protocol.ResourceRecord{Name: ddnsPolName(t, name), Type: typ, Class: protocol.ClassANY, TTL: 0, Data: &protocol.RDataRaw{TypeVal: typ}}
}

// ddnsPolDelRR is §2.5.4 "delete an RR from an RRset" (class NONE, TTL 0).
func ddnsPolDelRR(t *testing.T, name, ip string) *protocol.ResourceRecord {
	rr := ddnsPolAdd(t, name, ip)
	rr.Class, rr.TTL = protocol.ClassNONE, 0
	return rr
}

type ddnsPolResult struct {
	rcode     uint8
	signed    bool
	verifyErr error
	err       error
}

func (r ddnsPolResult) String() string {
	if r.err != nil {
		return "error=" + r.err.Error()
	}
	v := "unsigned"
	if r.signed {
		v = "signed,verify=ok"
		if r.verifyErr != nil {
			v = "signed,verify=" + r.verifyErr.Error()
		}
	}
	return protocol.RcodeString(int(r.rcode)) + "(" + v + ")"
}

var ddnsPolNextID uint16 = 0x4520

// ddnsPolUpdate sends an UPDATE for ddnsPolZone over TCP, TSIG-signed with key
// when key != nil, and verifies a signed response against the request MAC.
func ddnsPolUpdate(t *testing.T, addr string, key *transfer.TSIGKey, rrs ...*protocol.ResourceRecord) ddnsPolResult {
	t.Helper()
	return ddnsPolUpdateWithPrereq(t, addr, key, nil, rrs...)
}

// ddnsPolUpdateWithPrereq is ddnsPolUpdate with an RFC 2136 prerequisite RR.
func ddnsPolUpdateWithPrereq(t *testing.T, addr string, key *transfer.TSIGKey, pre *protocol.ResourceRecord, rrs ...*protocol.ResourceRecord) ddnsPolResult {
	t.Helper()
	ddnsPolNextID++
	msg := &protocol.Message{
		Header:      protocol.Header{ID: ddnsPolNextID, Flags: protocol.Flags{Opcode: protocol.OpcodeUpdate}},
		Questions:   []*protocol.Question{{Name: ddnsPolName(t, ddnsPolZone), QType: protocol.TypeSOA, QClass: protocol.ClassIN}},
		Authorities: rrs,
	}
	if pre != nil {
		msg.Answers = []*protocol.ResourceRecord{pre}
	}
	var reqMAC []byte
	if key != nil {
		tsigRR, err := transfer.SignMessage(msg, key, 300)
		if err != nil {
			t.Fatalf("setup: SignMessage: %v", err)
		}
		msg.Additionals = append(msg.Additionals, tsigRR)
		if reqMAC, err = transfer.TSIGRequestMAC(msg); err != nil {
			t.Fatalf("setup: TSIGRequestMAC: %v", err)
		}
	}
	resp, err := ddnsPolExchange(addr, msg)
	if err != nil {
		return ddnsPolResult{err: err}
	}
	res := ddnsPolResult{rcode: resp.Header.Flags.RCODE}
	for _, rr := range resp.Additionals {
		if rr.Type == protocol.TypeTSIG {
			res.signed = true
		}
	}
	if res.signed && key != nil {
		res.verifyErr = transfer.VerifyMessage(resp, key, reqMAC)
	}
	return res
}

func ddnsPolExchange(addr string, msg *protocol.Message) (*protocol.Message, error) {
	buf := make([]byte, 65535)
	n, err := msg.Pack(buf)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	out := make([]byte, 2+n)
	binary.BigEndian.PutUint16(out, uint16(n))
	copy(out[2:], buf[:n])
	if _, err := conn.Write(out); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	rb := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(conn, rb); err != nil {
		return nil, err
	}
	return protocol.UnpackMessage(rb)
}

// ddnsPolA returns the sorted-as-stored A RDATA at name.
func ddnsPolA(z *zone.Zone, name string) []string {
	z.RLock()
	defer z.RUnlock()
	var out []string
	for _, r := range z.Records[name] {
		if strings.EqualFold(r.Type, "A") {
			out = append(out, r.RData)
		}
	}
	return out
}

func ddnsPolCommit(c *cluster.Cluster) int64 {
	if c == nil {
		return 0
	}
	return c.Stats().RaftStats.CommitIndex
}

func ddnsPolVYAML(dir, keys string) string {
	return fmt.Sprintf("storage:\n  data_dir: %s\ntransfer:\n  allow_list:\n    - 127.0.0.0/8\n  require_tsig: true\n%s", dir, keys)
}

func ddnsPolVKey(name string, secret []byte, extra string) string {
	return fmt.Sprintf("    - name: %s\n      algorithm: hmac-sha256\n      secret: \"%s\"\n%s", name, base64.StdEncoding.EncodeToString(secret), extra)
}

func ddnsPolExpect(t *testing.T, label string, r ddnsPolResult, rcode uint8, signed bool) {
	t.Helper()
	ok := r.err == nil && r.rcode == rcode && r.signed == signed && (!signed || r.verifyErr == nil)
	t.Logf("%-46s EXPECTED %s signed=%v ACTUAL %s", label, protocol.RcodeString(int(rcode)), signed, r)
	if !ok {
		t.Errorf("%s: unexpected result %s", label, r)
	}
}

func ddnsPolExpectA(t *testing.T, label string, z *zone.Zone, name string, want ...string) {
	t.Helper()
	got := ddnsPolA(z, name)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s: %s A = %v, want %v", label, name, got, want)
	}
}

// F452 (P2-C2): a Dynamic DNS UPDATE is accepted only when TSIG-signed with a
// transfer.tsig_keys key whose allow_update lists the zone (and, if set, whose
// allowed_cidrs contains the client); responses to signed UPDATEs are signed.
func TestDDNSUpdatePolicy_TSIGKeyAllowUpdate(t *testing.T) {
	upd := ddnsPolKey("ddns-key.example.", ddnsPolSecret)
	other := ddnsPolKey("other-key.example.", ddnsPolOtherSecret)
	keys := "  tsig_keys:\n" +
		ddnsPolVKey("ddns-key.example.", ddnsPolSecret, "      allow_update:\n        - Example.COM\n") + // case + relative form
		ddnsPolVKey("other-key.example.", ddnsPolOtherSecret, "") // transfer-only key

	for rep := 0; rep < 3; rep++ {
		s := ddnsPolServe(t, ddnsPolVYAML(t.TempDir(), keys), false)
		if len(s.valErr) != 0 {
			t.Fatalf("Validate: %v", s.valErr)
		}
		ddnsPolExpect(t, "unsigned add", ddnsPolUpdate(t, s.addr, nil, ddnsPolAdd(t, "u.example.com.", "192.0.2.1")), protocol.RcodeRefused, false)
		ddnsPolExpect(t, "signed add x2", ddnsPolUpdate(t, s.addr, upd, ddnsPolAdd(t, "new.example.com.", "192.0.2.77"), ddnsPolAdd(t, "new.example.com.", "192.0.2.78")), protocol.RcodeSuccess, true)
		ddnsPolExpectA(t, "after add", s.zone, "new.example.com.", "192.0.2.77", "192.0.2.78")
		ddnsPolExpect(t, "replayed add (idempotent)", ddnsPolUpdate(t, s.addr, upd, ddnsPolAdd(t, "new.example.com.", "192.0.2.77")), protocol.RcodeSuccess, true)
		ddnsPolExpectA(t, "after replay", s.zone, "new.example.com.", "192.0.2.77", "192.0.2.78")
		ddnsPolExpect(t, "delete one RR", ddnsPolUpdate(t, s.addr, upd, ddnsPolDelRR(t, "new.example.com.", "192.0.2.77")), protocol.RcodeSuccess, true)
		ddnsPolExpectA(t, "after delete RR", s.zone, "new.example.com.", "192.0.2.78")
		ddnsPolExpect(t, "delete RRset", ddnsPolUpdate(t, s.addr, upd, ddnsPolDelRRset(t, "www.example.com.", protocol.TypeA)), protocol.RcodeSuccess, true)
		ddnsPolExpectA(t, "after delete RRset", s.zone, "www.example.com.")
		ddnsPolExpect(t, "transfer-only key (no allow_update)", ddnsPolUpdate(t, s.addr, other, ddnsPolAdd(t, "o.example.com.", "192.0.2.9")), protocol.RcodeRefused, true)
		ddnsPolExpectA(t, "after refused", s.zone, "o.example.com.")
		wrong := ddnsPolKey("ddns-key.example.", ddnsPolOtherSecret)
		ddnsPolExpect(t, "wrong secret", ddnsPolUpdate(t, s.addr, wrong, ddnsPolAdd(t, "w.example.com.", "192.0.2.9")), protocol.RcodeNotAuth, false)
		ddnsPolExpectA(t, "after bad MAC", s.zone, "w.example.com.")
		unknown := ddnsPolKey("nobody.example.", ddnsPolSecret)
		ddnsPolExpect(t, "unknown key", ddnsPolUpdate(t, s.addr, unknown, ddnsPolAdd(t, "k.example.com.", "192.0.2.9")), protocol.RcodeNotAuth, false)
		// Prerequisite failure (NXRRSET) is answered signed.
		pre := ddnsPolAdd(t, "missing.example.com.", "192.0.2.1")
		pre.Class, pre.TTL, pre.Data = protocol.ClassANY, 0, &protocol.RDataRaw{TypeVal: protocol.TypeA}
		msgRR := ddnsPolAdd(t, "p.example.com.", "192.0.2.5")
		r := ddnsPolUpdateWithPrereq(t, s.addr, upd, pre, msgRR)
		ddnsPolExpect(t, "yxrrset prereq fails", r, protocol.RcodeNXRRSet, true)
		ddnsPolExpectA(t, "after prereq fail", s.zone, "p.example.com.")
	}

	// allowed_cidrs: a key restricted to another network is not usable from
	// loopback; one including loopback is.
	cidrKeys := "  tsig_keys:\n" +
		ddnsPolVKey("ddns-key.example.", ddnsPolSecret, "      allowed_cidrs:\n        - 198.51.100.0/24\n      allow_update:\n        - example.com.\n") +
		ddnsPolVKey("other-key.example.", ddnsPolOtherSecret, "      allowed_cidrs:\n        - 127.0.0.0/8\n      allow_update:\n        - example.com.\n")
	s := ddnsPolServe(t, ddnsPolVYAML(t.TempDir(), cidrKeys), false)
	ddnsPolExpect(t, "key outside allowed_cidrs", ddnsPolUpdate(t, s.addr, upd, ddnsPolAdd(t, "c.example.com.", "192.0.2.3")), protocol.RcodeNotAuth, false)
	ddnsPolExpectA(t, "after cidr refusal", s.zone, "c.example.com.")
	ddnsPolExpect(t, "key inside allowed_cidrs", ddnsPolUpdate(t, s.addr, other, ddnsPolAdd(t, "c.example.com.", "192.0.2.3")), protocol.RcodeSuccess, true)
	ddnsPolExpectA(t, "after cidr accept", s.zone, "c.example.com.", "192.0.2.3")

	// No keys at all: every UPDATE refused.
	s = ddnsPolServe(t, fmt.Sprintf("storage:\n  data_dir: %s\n", t.TempDir()), false)
	ddnsPolExpect(t, "no tsig_keys, signed", ddnsPolUpdate(t, s.addr, upd, ddnsPolAdd(t, "n.example.com.", "192.0.2.4")), protocol.RcodeNotAuth, false)
	ddnsPolExpect(t, "no tsig_keys, unsigned", ddnsPolUpdate(t, s.addr, nil, ddnsPolAdd(t, "n.example.com.", "192.0.2.4")), protocol.RcodeRefused, false)
	ddnsPolExpectA(t, "no keys", s.zone, "n.example.com.")

	// Config validation of allow_update.
	bad, err := config.UnmarshalYAML(ddnsPolVYAML(t.TempDir(), "  tsig_keys:\n"+ddnsPolVKey("k.example.", ddnsPolSecret, "      allow_update:\n        - \"*.example.com.\"\n        - bad..name\n        - example.com.\n        - EXAMPLE.com\n")))
	if err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	errs := strings.Join(bad.Validate(), "\n")
	t.Logf("invalid allow_update validation:\n%s", errs)
	for _, want := range []string{"not a wildcard", "invalid zone name 'bad..name'", "duplicate zone 'EXAMPLE.com'"} {
		if !strings.Contains(errs, want) {
			t.Errorf("validation missing %q", want)
		}
	}

}

// TestDDNSUpdatePolicy_RaftReplicated: in Raft cluster mode an accepted
// UPDATE reaches the zone only through committed Raft entries.
func TestDDNSUpdatePolicy_RaftReplicated(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a single-node Raft cluster")
	}
	upd := ddnsPolKey("ddns-key.example.", ddnsPolSecret)
	other := ddnsPolKey("other-key.example.", ddnsPolOtherSecret)
	keys := "  tsig_keys:\n" +
		ddnsPolVKey("ddns-key.example.", ddnsPolSecret, "      allow_update:\n        - Example.COM\n") + // case + relative form
		ddnsPolVKey("other-key.example.", ddnsPolOtherSecret, "") // transfer-only key

	// Raft mode: every accepted UPDATE is ONE committed Raft entry (an atomic
	// zone batch, F532), however many records it changes.
	rs := ddnsPolServe(t, ddnsPolVYAML(t.TempDir(), keys), true)
	step := func(label string, wantDelta int64, rcode uint8, rrs ...*protocol.ResourceRecord) {
		before := ddnsPolCommit(rs.cluster)
		r := ddnsPolUpdate(t, rs.addr, upd, rrs...)
		after := ddnsPolCommit(rs.cluster)
		ddnsPolExpect(t, "raft "+label, r, rcode, true)
		t.Logf("%-46s commitIndex %d -> %d (want +%d)", "raft "+label, before, after, wantDelta)
		if after-before != wantDelta {
			t.Errorf("raft %s: commit index advanced by %d, want %d", label, after-before, wantDelta)
		}
	}
	step("add x2", 1, protocol.RcodeSuccess, ddnsPolAdd(t, "r.example.com.", "192.0.2.80"), ddnsPolAdd(t, "r.example.com.", "192.0.2.81"))
	ddnsPolExpectA(t, "raft after add", rs.zone, "r.example.com.", "192.0.2.80", "192.0.2.81")
	step("replayed add is a no-op", 0, protocol.RcodeSuccess, ddnsPolAdd(t, "r.example.com.", "192.0.2.80"))
	step("delete one RR", 1, protocol.RcodeSuccess, ddnsPolDelRR(t, "r.example.com.", "192.0.2.80"))
	ddnsPolExpectA(t, "raft after delete RR", rs.zone, "r.example.com.", "192.0.2.81")
	step("delete RRset", 1, protocol.RcodeSuccess, ddnsPolDelRRset(t, "www.example.com.", protocol.TypeA))
	ddnsPolExpectA(t, "raft after delete RRset", rs.zone, "www.example.com.")
	step("apex NS RRset delete ignored (F82)", 0, protocol.RcodeSuccess, ddnsPolDelRRset(t, "example.com.", protocol.TypeNS))
	if rs.zone.Records["example.com."] == nil {
		t.Errorf("raft: apex NS removed")
	}
	step("delete name (ANY/ANY)", 1, protocol.RcodeSuccess, ddnsPolDelRRset(t, "r.example.com.", protocol.TypeANY))
	ddnsPolExpectA(t, "raft after delete name", rs.zone, "r.example.com.")
	before := ddnsPolCommit(rs.cluster)
	ddnsPolExpect(t, "raft transfer-only key", ddnsPolUpdate(t, rs.addr, other, ddnsPolAdd(t, "o.example.com.", "192.0.2.9")), protocol.RcodeRefused, true)
	pre := ddnsPolAdd(t, "missing.example.com.", "192.0.2.1")
	pre.Class, pre.TTL, pre.Data = protocol.ClassANY, 0, &protocol.RDataRaw{TypeVal: protocol.TypeA}
	ddnsPolExpect(t, "raft prereq fails", ddnsPolUpdateWithPrereq(t, rs.addr, upd, pre, ddnsPolAdd(t, "p.example.com.", "192.0.2.5")), protocol.RcodeNXRRSet, true)
	soa := &protocol.ResourceRecord{Name: ddnsPolName(t, ddnsPolZone), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataSOA{MName: ddnsPolName(t, "ns1.example.com."), RName: ddnsPolName(t, "admin.example.com."), Serial: 4000000000, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}}
	ddnsPolExpect(t, "raft SOA replacement refused", ddnsPolUpdate(t, rs.addr, upd, soa), protocol.RcodeRefused, true)
	if after := ddnsPolCommit(rs.cluster); after != before {
		t.Errorf("raft: refused/failed updates advanced commit index %d -> %d", before, after)
	}
	ddnsPolExpectA(t, "raft refusals", rs.zone, "o.example.com.")
	ddnsPolExpectA(t, "raft refusals", rs.zone, "p.example.com.")

}
