package transfer

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// A slave reports each transfer's outcome, and says once per EXPIRE window
// that the zone expired; before, a slave without its master went quiet and
// then silently stopped answering (F767).
func TestSlaveLogsTransferOutcomeAndExpiry(t *testing.T) {
	var buf bytes.Buffer
	prev := util.GetDefaultLogger()
	util.SetDefaultLogger(util.NewLogger(util.DEBUG, util.TextFormat, &buf))
	defer util.SetDefaultLogger(prev)

	sm := &SlaveManager{}
	sz := &SlaveZone{LastSerial: 7, expireAt: time.Now().Add(-time.Second)}

	sm.logTransferOutcome("c.example.", sz, nil)
	if !strings.Contains(buf.String(), "zone c.example. transferred (serial 7)") {
		t.Errorf("success not logged:\n%s", buf.String())
	}
	buf.Reset()

	boom := errors.New("connection refused")
	sm.logTransferOutcome("c.example.", sz, boom)
	sm.logTransferOutcome("c.example.", sz, boom)
	out := buf.String()
	if strings.Count(out, "transfer of c.example. failed: connection refused") != 2 {
		t.Errorf("failures not logged:\n%s", out)
	}
	if strings.Count(out, "has expired") != 1 {
		t.Errorf("expiry must be logged exactly once per window:\n%s", out)
	}

	buf.Reset()
	sm.logTransferOutcome("c.example.", sz, nil)
	sm.logTransferOutcome("c.example.", sz, boom)
	if strings.Count(buf.String(), "has expired") != 1 {
		t.Errorf("expiry must be logged again after a successful transfer:\n%s", buf.String())
	}

	buf.Reset()
	fresh := &SlaveZone{expireAt: time.Now().Add(time.Hour)}
	sm.logTransferOutcome("d.example.", fresh, boom)
	if strings.Contains(buf.String(), "has expired") {
		t.Errorf("expiry reported for a zone inside its window:\n%s", buf.String())
	}
}
