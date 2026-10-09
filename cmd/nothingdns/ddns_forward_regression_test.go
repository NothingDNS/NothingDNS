package main

// F562 (P2-G1) regression: RFC 2136 §6 forwarding of UPDATE from a Raft
// follower to the leader. Built from .temp_files/prove_F562_ddns_follower_forward
// and .temp_files/verify_F562_ddns_follower_forward.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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

type ddnsFwdNode struct {
	id   string
	dns  string
	zone *zone.Zone
	mgr  *ClusterManager
}

func ddnsFwdFreeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("setup: probe listen: %v", err)
	}
	a := l.Addr().String()
	_ = l.Close()
	return a
}

// fwdMode selects cluster.forward_updates for a test node (F569).
type fwdMode int

const (
	fwdOff           fwdMode = iota // default config: followers answer REFUSED
	fwdOn                           // forward_updates: true in the YAML (validated)
	fwdOnUnvalidated                // set after Validate: models a node whose leader advertises no address
)

// ddnsFwdStartMode serves the full pipeline for one Raft node on dnsAddr.
// bind is the configured server.bind host ("127.0.0.1", or "0.0.0.0" to test
// the wildcard case; the listener itself is always dnsAddr), advertise the
// optional cluster.dns_advertise_addr, mode the cluster.forward_updates
// setting (F569).
func ddnsFwdStartMode(t *testing.T, id, dnsAddr, bind, advertise, raftAddr, peerID, peerAddr, keys string, mode fwdMode) *ddnsFwdNode {
	t.Helper()
	node, err := ddnsFwdStartModeErr(t, id, dnsAddr, bind, advertise, raftAddr, peerID, peerAddr, keys, mode)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return node
}

// ddnsFwdStartModeErr is ddnsFwdStartMode returning the environmental boot
// errors (transfer manager, listener and cluster binds) so ddnsFwdPairMode
// can retry when one of the four probe-released addresses was stolen between
// ddnsFwdFreeAddr and the bind — the same close-then-rebind race hardened for
// the NOTIFY tests (F568). Yaml/validate mistakes stay Fatalf: they are
// deterministic input bugs, not races.
func ddnsFwdStartModeErr(t *testing.T, id, dnsAddr, bind, advertise, raftAddr, peerID, peerAddr, keys string, mode fwdMode) (*ddnsFwdNode, error) {
	t.Helper()
	_, port, _ := net.SplitHostPort(dnsAddr)
	_, rport, _ := net.SplitHostPort(raftAddr)
	adv := ""
	if advertise != "" {
		adv = "  dns_advertise_addr: " + advertise + "\n"
	}
	if mode == fwdOn {
		adv += "  forward_updates: true\n"
	}
	y := fmt.Sprintf("server:\n  bind:\n    - %s\n  port: %s\n%s"+
		"cluster:\n  enabled: true\n  node_id: %s\n  bind_addr: 127.0.0.1\n  gossip_port: %s\n  consensus_mode: raft\n  allow_insecure: true\n  data_dir: %s\n%s  peers:\n    - node_id: %s\n      addr: %s\n",
		bind, port, ddnsPolVYAML(t.TempDir(), keys), id, rport, t.TempDir(), adv, peerID, peerAddr)
	cfg, err := config.UnmarshalYAML(y)
	if err != nil {
		t.Fatalf("setup: yaml: %v\n%s", err, y)
	}
	if errs := cfg.Validate(); len(errs) != 0 {
		t.Fatalf("setup: Validate: %v", errs)
	}
	if mode == fwdOnUnvalidated {
		cfg.Cluster.ForwardUpdates = true
	}
	z := xfrTSIGZone(0)
	zm := zone.NewManager()
	zm.LoadZone(z, "")
	zones := map[string]*zone.Zone{ddnsPolZone: z}
	h := newTestHandler()
	h.config = cfg
	h.zones = zones
	h.zoneManager = zm
	lg := util.NewLogger(util.ERROR, util.TextFormat, nil)
	tm, err := NewTransferManager(cfg, zones, nil, lg)
	if err != nil {
		return nil, fmt.Errorf("setup: NewTransferManager: %w", err)
	}
	t.Cleanup(tm.Stop)
	tm.SetZonesMu(&h.zonesMu)
	r := tm.Result()
	h.transfer = TransferComponents{AXFRServer: r.AXFRServer, IXFRServer: r.IXFRServer, NotifyHandler: r.NotifyHandler, DDNSHandler: r.DDNSHandler, SlaveManager: r.SlaveManager}
	srv := server.NewTCPServerWithWorkers(dnsAddr, h, 2)
	if err := srv.Listen(); err != nil {
		return nil, fmt.Errorf("setup: listen: %w", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Stop() })
	mgr, err := NewClusterManager(cfg, lg, nil, nil, zm)
	if err != nil {
		return nil, fmt.Errorf("setup: NewClusterManager: %w", err)
	}
	t.Cleanup(mgr.Stop)
	h.cluster = mgr.Cluster
	return &ddnsFwdNode{id: id, dns: dnsAddr, zone: z, mgr: mgr}, nil
}

// ddnsFwdPair starts a two-node Raft cluster and returns (leader, follower)
// once the follower has learned the leader from its AppendEntries.
func ddnsFwdPair(t *testing.T, keys, bind, advA, advB string) (*ddnsFwdNode, *ddnsFwdNode) {
	t.Helper()
	return ddnsFwdPairMode(t, keys, bind, advA, advB, fwdOff)
}

// ddnsFwdPairMode is ddnsFwdPair with cluster.forward_updates per mode on
// both nodes (F569). A boot that fails because one of the four probe-
// released addresses was stolen before the bind (EADDRINUSE — the same
// close-then-rebind race hardened for the NOTIFY tests) retries with fresh
// addresses; any other boot error fails with its real cause.
func ddnsFwdPairMode(t *testing.T, keys, bind, advA, advB string, mode fwdMode) (*ddnsFwdNode, *ddnsFwdNode) {
	t.Helper()
	const bootAttempts = 3
	for attempt := 1; ; attempt++ {
		dA, dB, rA, rB := ddnsFwdFreeAddr(t), ddnsFwdFreeAddr(t), ddnsFwdFreeAddr(t), ddnsFwdFreeAddr(t)
		a, err := ddnsFwdStartModeErr(t, "fwd-a", dA, bind, advA, rA, "fwd-b", rB, keys, mode)
		if err != nil {
			if attempt < bootAttempts && errors.Is(err, syscall.EADDRINUSE) {
				continue
			}
			t.Fatalf("%v", err)
		}
		b, err := ddnsFwdStartModeErr(t, "fwd-b", dB, bind, advB, rB, "fwd-a", rA, keys, mode)
		if err != nil {
			if attempt < bootAttempts && errors.Is(err, syscall.EADDRINUSE) {
				// Node A of the failed attempt stays up until its test-end
				// cleanup; the retry only needs fresh addresses.
				continue
			}
			t.Fatalf("%v", err)
		}
		return ddnsFwdAwaitLeader(t, a, b)
	}
}

// ddnsFwdAwaitLeader waits until one node leads, the other has learned it,
// and the leader's term-start no-op entry is committed and applied on both
// (so later commit-index deltas count only UPDATEs).
func ddnsFwdAwaitLeader(t *testing.T, a, b *ddnsFwdNode) (*ddnsFwdNode, *ddnsFwdNode) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var leader, follower *ddnsFwdNode
		switch {
		case a.mgr.Cluster.IsLeader() && b.mgr.Cluster.RaftLeaderID() == a.id:
			leader, follower = a, b
		case b.mgr.Cluster.IsLeader() && a.mgr.Cluster.RaftLeaderID() == b.id:
			leader, follower = b, a
		}
		if leader != nil {
			if c := ddnsPolCommit(leader.mgr.Cluster); c >= 1 {
				ddnsFwdWaitApplied(t, leader, c)
				ddnsFwdWaitApplied(t, follower, c)
				return leader, follower
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("setup: no Raft leader elected and learned")
		}
		time.Sleep(10 * time.Millisecond) // waiting for election, not ordering
	}
}

// ddnsFwdWaitApplied waits until n has applied index idx (replication
// convergence, not ordering).
func ddnsFwdWaitApplied(t *testing.T, n *ddnsFwdNode, idx int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for n.mgr.Cluster.Stats().RaftStats.AppliedIndex < idx {
		if time.Now().After(deadline) {
			t.Fatalf("%s never reached commit index %d", n.id, idx)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var ddnsFwdKeys = "  tsig_keys:\n" +
	ddnsPolVKey("ddns-key.example.", ddnsPolSecret, "      allow_update:\n        - example.com.\n") +
	ddnsPolVKey("other-key.example.", ddnsPolOtherSecret, "")

// F562: a TSIG-signed UPDATE sent to a follower is forwarded to the leader,
// committed through Raft, and the leader's signed response verifies at the
// client. The leader (not the follower) enforces TSIG and allow_update.
func TestDDNSForward_F562_FollowerForwardsToLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a two-node Raft cluster")
	}
	upd := ddnsPolKey("ddns-key.example.", ddnsPolSecret)
	other := ddnsPolKey("other-key.example.", ddnsPolOtherSecret)
	leader, follower := ddnsFwdPairMode(t, ddnsFwdKeys, "127.0.0.1", "", "", fwdOn)

	before := ddnsPolCommit(leader.mgr.Cluster)
	ddnsPolExpect(t, "signed add via follower", ddnsPolUpdate(t, follower.dns, upd, ddnsPolAdd(t, "fwd.example.com.", "192.0.2.20")), protocol.RcodeSuccess, true)
	if got := ddnsPolCommit(leader.mgr.Cluster); got != before+1 {
		t.Errorf("leader commit index %d -> %d, want +1", before, got)
	}
	ddnsPolExpectA(t, "leader after forwarded add", leader.zone, "fwd.example.com.", "192.0.2.20")
	ddnsFwdWaitApplied(t, follower, ddnsPolCommit(leader.mgr.Cluster))
	ddnsPolExpectA(t, "follower after forwarded add", follower.zone, "fwd.example.com.", "192.0.2.20")

	// Prerequisite failure is decided by the leader and relayed signed.
	pre := ddnsPolAdd(t, "missing.example.com.", "192.0.2.1")
	pre.Class, pre.TTL, pre.Data = protocol.ClassANY, 0, &protocol.RDataRaw{TypeVal: protocol.TypeA}
	ddnsPolExpect(t, "prereq fails via follower", ddnsPolUpdateWithPrereq(t, follower.dns, upd, pre, ddnsPolAdd(t, "p.example.com.", "192.0.2.5")), protocol.RcodeNXRRSet, true)

	// Policy is the leader's: the follower forwards without authorizing.
	mark := ddnsPolCommit(leader.mgr.Cluster)
	ddnsPolExpect(t, "key without allow_update via follower", ddnsPolUpdate(t, follower.dns, other, ddnsPolAdd(t, "o.example.com.", "192.0.2.9")), protocol.RcodeRefused, true)
	wrong := ddnsPolKey("ddns-key.example.", ddnsPolOtherSecret)
	ddnsPolExpect(t, "bad MAC via follower", ddnsPolUpdate(t, follower.dns, wrong, ddnsPolAdd(t, "w.example.com.", "192.0.2.9")), protocol.RcodeNotAuth, false)
	// Unsigned UPDATEs are not forwarded; they stay REFUSED.
	ddnsPolExpect(t, "unsigned via follower", ddnsPolUpdate(t, follower.dns, nil, ddnsPolAdd(t, "u.example.com.", "192.0.2.9")), protocol.RcodeRefused, false)
	ddnsPolExpect(t, "unsigned at leader", ddnsPolUpdate(t, leader.dns, nil, ddnsPolAdd(t, "u.example.com.", "192.0.2.9")), protocol.RcodeRefused, false)
	if got := ddnsPolCommit(leader.mgr.Cluster); got != mark {
		t.Errorf("refused updates advanced the leader commit index %d -> %d", mark, got)
	}
	for _, n := range []string{"o.example.com.", "w.example.com.", "u.example.com.", "p.example.com."} {
		ddnsPolExpectA(t, "leader after refusals", leader.zone, n)
	}

	// The leader itself still commits directly (no forwarding loop).
	ddnsPolExpect(t, "signed add at leader", ddnsPolUpdate(t, leader.dns, upd, ddnsPolAdd(t, "ldr.example.com.", "192.0.2.30")), protocol.RcodeSuccess, true)
	ddnsPolExpectA(t, "leader after direct add", leader.zone, "ldr.example.com.", "192.0.2.30")
}

// F562: no leader known, or a leader that advertises no DNS address
// (wildcard bind, no cluster.dns_advertise_addr) → SERVFAIL, not REFUSED.
func TestDDNSForward_F562_NoLeaderOrAddressServfail(t *testing.T) {
	if testing.Short() {
		t.Skip("starts Raft clusters")
	}
	upd := ddnsPolKey("ddns-key.example.", ddnsPolSecret)

	// One node of a two-node cluster: no quorum, no leader.
	lone := ddnsFwdStartMode(t, "lone-a", ddnsFwdFreeAddr(t), "127.0.0.1", "", ddnsFwdFreeAddr(t), "lone-b", ddnsFwdFreeAddr(t), ddnsFwdKeys, fwdOn)
	ddnsPolExpect(t, "no leader", ddnsPolUpdate(t, lone.dns, upd, ddnsPolAdd(t, "n.example.com.", "192.0.2.40")), protocol.RcodeServerFailure, false)
	ddnsPolExpectA(t, "no leader", lone.zone, "n.example.com.")

	// Wildcard bind and no advertise address: nothing is advertised. With
	// forward_updates such a config fails validation (F569), so the flag is
	// set past Validate to model a leader that advertises no address (e.g.
	// an older-version leader during a rolling upgrade).
	leader, follower := ddnsFwdPairMode(t, ddnsFwdKeys, "0.0.0.0", "", "", fwdOnUnvalidated)
	if got := leader.mgr.Cluster.AdvertisedDNSAddr(); got != "" {
		t.Fatalf("wildcard bind advertised %q, want none", got)
	}
	ddnsPolExpect(t, "leader advertises no address", ddnsPolUpdate(t, follower.dns, upd, ddnsPolAdd(t, "x.example.com.", "192.0.2.41")), protocol.RcodeServerFailure, false)
	ddnsPolExpectA(t, "no address", leader.zone, "x.example.com.")
}

// F562: with a wildcard bind, cluster.dns_advertise_addr supplies the
// address followers forward to.
func TestDDNSForward_F562_ExplicitAdvertiseAddr(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a two-node Raft cluster")
	}
	upd := ddnsPolKey("ddns-key.example.", ddnsPolSecret)
	dA, dB, rA, rB := ddnsFwdFreeAddr(t), ddnsFwdFreeAddr(t), ddnsFwdFreeAddr(t), ddnsFwdFreeAddr(t)
	a := ddnsFwdStartMode(t, "adv-a", dA, "0.0.0.0", dA, rA, "adv-b", rB, ddnsFwdKeys, fwdOn)
	b := ddnsFwdStartMode(t, "adv-b", dB, "0.0.0.0", dB, rB, "adv-a", rA, ddnsFwdKeys, fwdOn)
	leader, follower := ddnsFwdAwaitLeader(t, a, b)
	if id, addr, ok := follower.mgr.Cluster.LeaderDNSAddr(); !ok || id != leader.id || addr != leader.dns {
		t.Fatalf("follower LeaderDNSAddr = (%q, %q, %v), want (%q, %q, true)", id, addr, ok, leader.id, leader.dns)
	}
	ddnsPolExpect(t, "signed add via follower (advertised)", ddnsPolUpdate(t, follower.dns, upd, ddnsPolAdd(t, "adv.example.com.", "192.0.2.50")), protocol.RcodeSuccess, true)
	ddnsPolExpectA(t, "leader after add", leader.zone, "adv.example.com.", "192.0.2.50")
}

// fakeFwdCluster is a ddnsForwardCluster with fixed answers.
type fakeFwdCluster struct {
	self, leader, addr, own string
	isLeader, known         bool
}

func (f fakeFwdCluster) IsLeader() bool            { return f.isLeader }
func (f fakeFwdCluster) GetNodeID() string         { return f.self }
func (f fakeFwdCluster) AdvertisedDNSAddr() string { return f.own }
func (f fakeFwdCluster) LeaderDNSAddr() (string, string, bool) {
	return f.leader, f.addr, f.known
}

// ddnsFwdFakeLeader accepts one TCP DNS exchange, hands the request bytes to
// got, and answers with reply(req) unless reply is nil (then it never answers
// and closes the connection when the test ends).
func ddnsFwdFakeLeader(t *testing.T, reply func([]byte) []byte) (addr string, got <-chan []byte) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ch := make(chan []byte, 1)
	done := make(chan struct{})
	t.Cleanup(func() { close(done); _ = l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		req := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		ch <- req
		if reply == nil {
			<-done
			return
		}
		out := reply(req)
		frame := make([]byte, 2+len(out))
		binary.BigEndian.PutUint16(frame, uint16(len(out)))
		copy(frame[2:], out)
		_, _ = c.Write(frame)
	}()
	return l.Addr().String(), ch
}

func ddnsFwdSignedUpdate(t *testing.T, key *transfer.TSIGKey, withOPT bool) (*protocol.Message, []byte) {
	t.Helper()
	msg := &protocol.Message{
		Header:      protocol.Header{ID: 0x5620, Flags: protocol.Flags{Opcode: protocol.OpcodeUpdate}},
		Questions:   []*protocol.Question{{Name: ddnsPolName(t, ddnsPolZone), QType: protocol.TypeSOA, QClass: protocol.ClassIN}},
		Authorities: []*protocol.ResourceRecord{ddnsPolAdd(t, "u.example.com.", "192.0.2.1")},
	}
	if withOPT {
		msg.SetEDNS0(1232, false)
	}
	tsigRR, err := transfer.SignMessage(msg, key, 300)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	msg.Additionals = append(msg.Additionals, tsigRR)
	buf := make([]byte, 65535)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	parsed, err := protocol.UnpackMessage(buf[:n])
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	return parsed, append([]byte(nil), buf[:n]...)
}

// F562: the forwarded request is the client's message (ID and TSIG intact),
// and the leader's response is written back byte-for-byte, past the cookie
// and header-policy rewrites that would break its TSIG MAC.
func TestDDNSForward_F562_RelaysBytesUnchanged(t *testing.T) {
	key := ddnsPolKey("ddns-key.example.", ddnsPolSecret)
	req, reqWire := ddnsFwdSignedUpdate(t, key, true)
	reqMAC, err := transfer.TSIGRequestMAC(req)
	if err != nil {
		t.Fatalf("TSIGRequestMAC: %v", err)
	}
	var leaderWire []byte
	addr, got := ddnsFwdFakeLeader(t, func([]byte) []byte {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: req.Header.ID, Flags: protocol.Flags{QR: true, Opcode: protocol.OpcodeUpdate, RA: true}},
			Questions: req.Questions,
		}
		resp.SetEDNS0(512, false) // differs from what the follower's policy writer would emit
		rr, err := transfer.NewTSIGStreamSigner(key, reqMAC, 300).Sign(resp)
		if err != nil {
			t.Errorf("leader sign: %v", err)
			return nil
		}
		resp.Additionals = append(resp.Additionals, rr)
		buf := make([]byte, 65535)
		n, err := resp.Pack(buf)
		if err != nil {
			t.Errorf("leader pack: %v", err)
			return nil
		}
		leaderWire = append([]byte(nil), buf[:n]...)
		return leaderWire
	})
	c := fakeFwdCluster{self: "f", leader: "l", addr: addr, own: "127.0.0.1:1", known: true}
	resp, leaderID, err := forwardUpdate(c, req, 5*time.Second)
	if err != nil || leaderID != "l" {
		t.Fatalf("forwardUpdate = (%v, %q), want success via l", err, leaderID)
	}
	if fwd := <-got; !bytes.Equal(fwd, reqWire) {
		t.Errorf("forwarded request differs from the client's message:\n got %x\nwant %x", fwd, reqWire)
	}

	h := newTestHandler()
	h.config.Server.Port = 53
	capture := newCaptureWriter("192.0.2.99", "tcp")
	w := &cookieResponseWriter{inner: newHeaderPolicyWriter(h, capture, req), cookieData: bytes.Repeat([]byte{7}, 24)}
	if _, err := writeRelayedResponse(w, resp); err != nil {
		t.Fatalf("writeRelayedResponse: %v", err)
	}
	buf := make([]byte, 65535)
	n, err := capture.msg.Pack(buf)
	if err != nil {
		t.Fatalf("pack relayed: %v", err)
	}
	if !bytes.Equal(buf[:n], leaderWire) {
		t.Errorf("relayed response differs from the leader's bytes:\n got %x\nwant %x", buf[:n], leaderWire)
	}
	if err := transfer.VerifyMessage(capture.msg, key, reqMAC); err != nil {
		t.Errorf("relayed response TSIG does not verify: %v", err)
	}
	if hw := w.inner.(*headerPolicyResponseWriter); !hw.wrote || hw.rcode != protocol.RcodeSuccess {
		t.Errorf("header policy writer not told about the relayed rcode: wrote=%v rcode=%d", hw.wrote, hw.rcode)
	}

	// Control: the normal write path rewrites the same response (which is
	// why the relay must bypass it).
	capture2 := newCaptureWriter("192.0.2.99", "tcp")
	w2 := &cookieResponseWriter{inner: newHeaderPolicyWriter(h, capture2, req), cookieData: bytes.Repeat([]byte{7}, 24)}
	resp2, _ := protocol.UnpackMessage(leaderWire)
	if _, err := w2.Write(resp2); err != nil {
		t.Fatalf("control write: %v", err)
	}
	n2, _ := capture2.msg.Pack(buf)
	if bytes.Equal(buf[:n2], leaderWire) {
		t.Errorf("control: rewriting writers left the bytes unchanged; the bypass is untested")
	}
}

// F562 loop protection and failure modes: no forward when this node leads
// (or believes it does), to its own address, with no leader or no address;
// a silent leader times out; a reply that does not answer the UPDATE fails.
func TestDDNSForward_F562_ForwardRefusals(t *testing.T) {
	key := ddnsPolKey("ddns-key.example.", ddnsPolSecret)
	req, _ := ddnsFwdSignedUpdate(t, key, false)
	cases := []struct {
		name string
		c    fakeFwdCluster
		want string
	}{
		{"no leader", fakeFwdCluster{self: "f", known: false}, "no Raft leader"},
		{"leader is self", fakeFwdCluster{self: "f", leader: "f", addr: "127.0.0.1:9", known: true}, "is the leader"},
		{"node believes it leads", fakeFwdCluster{self: "f", leader: "l", addr: "127.0.0.1:9", known: true, isLeader: true}, "is the leader"},
		{"leader advertises nothing", fakeFwdCluster{self: "f", leader: "l", known: true}, "no DNS address"},
		{"leader address is own address", fakeFwdCluster{self: "f", leader: "l", addr: "127.0.0.1:9", own: "127.0.0.1:9", known: true}, "own address"},
	}
	for _, tc := range cases {
		_, _, err := forwardUpdate(tc.c, req, time.Second)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", tc.name, err, tc.want)
		}
	}

	silent, got := ddnsFwdFakeLeader(t, nil)
	start := time.Now()
	_, _, err := forwardUpdate(fakeFwdCluster{self: "f", leader: "l", addr: silent, known: true}, req, 200*time.Millisecond)
	<-got
	if err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("silent leader: err = %v after %v, want a timeout error", err, time.Since(start))
	}

	wrongID, _ := ddnsFwdFakeLeader(t, func([]byte) []byte {
		m := &protocol.Message{Header: protocol.Header{ID: req.Header.ID + 1, Flags: protocol.Flags{QR: true, Opcode: protocol.OpcodeUpdate}}}
		buf := make([]byte, 512)
		n, _ := m.Pack(buf)
		return buf[:n]
	})
	if _, _, err := forwardUpdate(fakeFwdCluster{self: "f", leader: "l", addr: wrongID, known: true}, req, 5*time.Second); err == nil || !strings.Contains(err.Error(), "does not answer") {
		t.Errorf("mismatched reply: err = %v, want rejection", err)
	}
}

// F562: the advertised DNS address is cluster.dns_advertise_addr, else the
// first concrete DNS TCP bind, else none.
func TestClusterDNSAdvertiseAddr_F562(t *testing.T) {
	cases := []struct {
		name      string
		bind, tcp []string
		port      int
		advertise string
		want      string
	}{
		{"explicit wins", []string{"192.0.2.1"}, nil, 53, "198.51.100.7:5300", "198.51.100.7:5300"},
		{"concrete bind", []string{"192.0.2.1"}, nil, 5354, "", "192.0.2.1:5354"},
		{"tcp_bind preferred", []string{"192.0.2.1"}, []string{"192.0.2.2"}, 53, "", "192.0.2.2:53"},
		{"wildcard v4", []string{"0.0.0.0"}, nil, 53, "", ""},
		{"wildcard v6", []string{"::"}, nil, 53, "", ""},
		{"no bind", nil, nil, 53, "", ""},
		{"wildcard then concrete", []string{"0.0.0.0", "192.0.2.3"}, nil, 53, "", ""},
		{"ipv6 concrete", []string{"2001:db8::1"}, nil, 53, "", "[2001:db8::1]:53"},
	}
	for _, tc := range cases {
		cfg := config.DefaultConfig()
		cfg.Server.Bind, cfg.Server.TCPBind, cfg.Server.Port = tc.bind, tc.tcp, tc.port
		cfg.Cluster.DNSAdvertiseAddr = tc.advertise
		if got := clusterDNSAdvertiseAddr(cfg); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
