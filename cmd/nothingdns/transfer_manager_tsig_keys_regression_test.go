package main

import (
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// X6 regressions: TSIG keys from the YAML config must reach the key stores
// NewTransferManager builds — transfer.tsig_keys for the AXFR/IXFR server
// (F367) and slave_zones tsig_key_name/tsig_secret for the slave manager
// (F368). Before X6 both stores stayed empty: a production master
// (allow_list forces require_tsig) refused every transfer, and every keyed
// slave zone failed with "TSIG key not found".

var tmTSIGSecret = []byte("X6-master-key-0123456789-abcdef!")

func tmTSIGKey() *transfer.TSIGKey {
	return &transfer.TSIGKey{Name: "x6-xfr-key.example.", Algorithm: transfer.HmacSHA256, Secret: tmTSIGSecret}
}

func tmNewManager(t *testing.T, yaml string, zones map[string]*zone.Zone) *TransferManager {
	t.Helper()
	cfg, err := config.UnmarshalYAML(yaml)
	if err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	if errs := cfg.ValidateProduction(); len(errs) > 0 {
		for _, e := range errs {
			if e == "production: transfer.require_tsig needs at least one transfer.tsig_keys entry, otherwise every zone transfer is refused" {
				t.Fatalf("production validation: %s", e)
			}
		}
	}
	mgr, err := NewTransferManager(cfg, zones, &sync.RWMutex{}, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("NewTransferManager: %v", err)
	}
	return mgr
}

func TestTransferManager_TSIGKeysFromConfig(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(tmTSIGSecret)
	dir := t.TempDir()

	// F367: production master configured from YAML.
	mgr := tmNewManager(t, fmt.Sprintf(`storage:
  data_dir: %s/m
transfer:
  allow_list:
    - 127.0.0.0/8
  require_tsig: true
  tsig_keys:
    - name: x6-xfr-key.example.
      secret: "%s"
`, dir, b64), map[string]*zone.Zone{"example.com.": xfrTSIGZone(0)})
	t.Cleanup(mgr.Stop)
	h := newTestHandler()
	r := mgr.Result()
	h.transfer = TransferComponents{AXFRServer: r.AXFRServer, IXFRServer: r.IXFRServer, NotifyHandler: r.NotifyHandler, DDNSHandler: r.DDNSHandler, SlaveManager: r.SlaveManager}
	srv := server.NewTCPServerWithWorkers("127.0.0.1:0", h, 1)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Stop() })
	addr := srv.Addr().String()

	if recs, err := transfer.NewAXFRClient(addr, transfer.WithAXFRTimeout(5*time.Second)).Transfer("example.com.", tmTSIGKey()); err != nil || len(recs) != 5 {
		t.Fatalf("signed AXFR from a configured key: records=%d err=%v, want 5", len(recs), err)
	}
	if recs, err := transfer.NewIXFRClient(addr, transfer.WithIXFRTimeout(5*time.Second)).Transfer("example.com.", 0, tmTSIGKey()); err != nil || len(recs) != 5 {
		t.Fatalf("signed IXFR from a configured key: records=%d err=%v, want 5", len(recs), err)
	}
	if _, err := transfer.NewAXFRClient(addr, transfer.WithAXFRTimeout(5*time.Second)).Transfer("example.com.", nil); err == nil {
		t.Fatal("unsigned AXFR accepted by a require_tsig master")
	}

	// F368: keyed slave zone against a keyed master.
	mh := newTestHandler()
	ks := transfer.NewKeyStore()
	ks.AddKey(tmTSIGKey())
	mh.transfer.AXFRServer = transfer.NewAXFRServer(map[string]*zone.Zone{"example.com.": xfrTSIGZone(0)},
		transfer.WithAllowList([]string{"127.0.0.0/8"}), transfer.WithKeyStore(ks))
	mh.transfer.IXFRServer = transfer.NewIXFRServer(mh.transfer.AXFRServer)
	msrv := server.NewTCPServerWithWorkers("127.0.0.1:0", mh, 1)
	if err := msrv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = msrv.Serve() }()
	t.Cleanup(func() { _ = msrv.Stop() })

	slave := tmNewManager(t, fmt.Sprintf(`storage:
  data_dir: %s/s
slave_zones:
  - zone_name: example.com.
    transfer_type: axfr
    masters:
      - %s
    tsig_key_name: x6-xfr-key.example.
    tsig_secret: "%s"
`, dir, msrv.Addr().String(), b64), map[string]*zone.Zone{})
	slave.Stop() // waits for the initial transfer
	sz := slave.Result().SlaveManager.GetSlaveZone("example.com.")
	if sz == nil || sz.GetLastSerial() != 2 {
		var got uint32
		if sz != nil {
			got = sz.GetLastSerial()
		}
		t.Fatalf("keyed slave zone serial=%d after initial transfer, want 2", got)
	}
}
