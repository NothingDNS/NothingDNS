package main

// F569 regressions (P2-G2): RFC 2136 §6 follower forwarding (F562) is opt-in
// via cluster.forward_updates (default false).

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

// A default-config follower answers a signed UPDATE REFUSED (signed) and the
// leader commits nothing; the leader itself still accepts it.
func TestDDNSForward_F569_DefaultFollowerRefuses(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a two-node Raft cluster")
	}
	upd := ddnsPolKey("ddns-key.example.", ddnsPolSecret)
	leader, follower := ddnsFwdPair(t, ddnsFwdKeys, "127.0.0.1", "", "")

	before := ddnsPolCommit(leader.mgr.Cluster)
	ddnsPolExpect(t, "signed add via default follower", ddnsPolUpdate(t, follower.dns, upd, ddnsPolAdd(t, "off.example.com.", "192.0.2.70")), protocol.RcodeRefused, true)
	if got := ddnsPolCommit(leader.mgr.Cluster); got != before {
		t.Errorf("leader commit index %d -> %d; a non-forwarding follower must not reach the leader", before, got)
	}
	ddnsPolExpectA(t, "leader after refused follower add", leader.zone, "off.example.com.")
	ddnsPolExpect(t, "signed add at leader", ddnsPolUpdate(t, leader.dns, upd, ddnsPolAdd(t, "on.example.com.", "192.0.2.71")), protocol.RcodeSuccess, true)
	ddnsPolExpectA(t, "leader after direct add", leader.zone, "on.example.com.", "192.0.2.71")
}

// updateNeedsForward is false without forward_updates even when every other
// condition holds; true once enabled.
func TestUpdateNeedsForward_F569_OptIn(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a two-node Raft cluster")
	}
	_, follower := ddnsFwdPair(t, ddnsFwdKeys, "127.0.0.1", "", "")
	h := newTestHandler()
	h.zones[ddnsPolZone] = follower.zone
	h.cluster = follower.mgr.Cluster
	key := ddnsPolKey("ddns-key.example.", ddnsPolSecret)
	req, _ := ddnsFwdSignedUpdate(t, key, false)
	h.config = config.DefaultConfig()
	if h.updateNeedsForward(req, ddnsPolZone) {
		t.Fatal("default config must not forward UPDATEs")
	}
	cfg := config.DefaultConfig()
	cfg.Cluster.ForwardUpdates = true
	h.config = cfg
	if !h.updateNeedsForward(req, ddnsPolZone) {
		t.Fatal("forward_updates: true must forward a signed UPDATE on a follower")
	}
}

// Validation's advertised-address check agrees with the address the server
// actually advertises (clusterDNSAdvertiseAddr).
func TestForwardUpdatesValidation_F569_MatchesAdvertiseDerivation(t *testing.T) {
	cases := []struct {
		bind, tcp []string
		port      int
		advertise string
	}{
		{[]string{"192.0.2.1"}, nil, 53, "198.51.100.7:5300"},
		{[]string{"192.0.2.1"}, nil, 5354, ""},
		{[]string{"192.0.2.1:5354"}, nil, 53, ""},
		{[]string{"192.0.2.1:0"}, nil, 53, ""},
		{[]string{"192.0.2.1"}, []string{"192.0.2.2"}, 53, ""},
		{[]string{"192.0.2.1"}, []string{"0.0.0.0"}, 53, ""},
		{[]string{"0.0.0.0"}, nil, 53, ""},
		{[]string{"::"}, nil, 53, ""},
		{[]string{"[::]"}, nil, 53, ""},
		{nil, nil, 53, ""},
		{[]string{"0.0.0.0", "192.0.2.3"}, nil, 53, ""},
		{[]string{"0.0.0.0:53", "192.0.2.3:5300"}, nil, 53, ""},
		{[]string{"2001:db8::1"}, nil, 53, ""},
		{[]string{"[2001:db8::1]"}, nil, 53, ""},
	}
	for _, tc := range cases {
		cfg := config.DefaultConfig()
		cfg.Cluster.Enabled = true
		cfg.Cluster.ConsensusMode = "raft"
		cfg.Cluster.ForwardUpdates = true
		cfg.Server.Bind, cfg.Server.TCPBind, cfg.Server.Port = tc.bind, tc.tcp, tc.port
		cfg.Cluster.DNSAdvertiseAddr = tc.advertise
		validationErr := false
		for _, e := range cfg.Validate() {
			if strings.Contains(e, "forward_updates") {
				validationErr = true
			}
		}
		advertises := clusterDNSAdvertiseAddr(cfg) != ""
		if validationErr == advertises {
			t.Errorf("%+v: validation error=%v but advertised address=%q", tc, validationErr, clusterDNSAdvertiseAddr(cfg))
		}
	}
}
