package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

// An emptied cache must overwrite the snapshot; otherwise entries an operator
// flushed come back from the stale cache.json on the next start (F637).
func TestCacheManagerFlushedEntriesNotRestored(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ZoneDir = t.TempDir()
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	const key = "flushed.example.:1"

	m := NewCacheManager(cfg, logger)
	msg := newTestQuery(t, "flushed.example.", protocol.TypeA)
	msg.Header.Flags.QR = true
	m.Cache.Set(key, msg, 3600)
	m.saveToFile()
	m.Cache.Flush()
	m.Stop()

	next := NewCacheManager(cfg, logger)
	defer next.Stop()
	next.LoadCache()
	if next.Cache.Get(key) != nil {
		t.Fatal("flushed entry restored from a stale cache snapshot")
	}
}
