// NothingDNS - outgoing NOTIFY (RFC 1996) for zones this server is primary for

package main

import (
	"context"
	"strings"
	"sync"

	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// notifySendFunc sends one NOTIFY (with retransmissions) and returns when it
// is answered, exhausted, or ctx is cancelled.
type notifySendFunc func(ctx context.Context, zoneName string, serial uint32, target string) error

// zoneNotifier sends NOTIFY to the configured transfer.also_notify targets
// whenever the SOA serial of a transferable zone changes (F547), and once for
// every zone after startup (NotifyAll, F568).
//
// Observe is called after every zone-tree rebuild (API/Raft/gossip
// mutations, DDNS, SIGHUP reload); it never blocks on the network. Each
// (zone, target) pair has at most one sender goroutine in flight; a serial
// change that arrives while one is running replaces the pending serial
// (latest wins) and cancels the in-flight, now superseded, send so the
// latest serial goes out without waiting for the old one's retransmissions.
//
// SetTargets (SIGHUP reload, F567) swaps the target list and send function:
// removed targets' in-flight sends are cancelled and their pending serials
// dropped; added targets are notified from the next change on.
type zoneNotifier struct {
	targets []string
	send    notifySendFunc
	logger  *util.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	stopped bool
	primed  bool
	serials map[string]uint32       // last observed serial per zone origin
	flights map[notifyKey]*notifyFl // per zone+target sender state
}

type notifyKey struct{ zone, target string }

type notifyFl struct {
	running bool
	pending uint32
	dirty   bool
	removed bool               // target dropped by SetTargets; sender exits
	cancel  context.CancelFunc // cancels the in-flight send; nil when idle
}

// newZoneNotifier returns a notifier sending with send to targets. With no
// targets it only tracks serials and sends nothing until SetTargets adds
// some (SIGHUP). It returns nil only when send is nil.
func newZoneNotifier(targets []string, send notifySendFunc, logger *util.Logger) *zoneNotifier {
	if send == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &zoneNotifier{
		targets: append([]string(nil), targets...),
		send:    send,
		logger:  logger,
		ctx:     ctx,
		cancel:  cancel,
		serials: make(map[string]uint32),
		flights: make(map[notifyKey]*notifyFl),
	}
}

// newTransferNOTIFYSend adapts transfer.NOTIFYSender (RFC 1996 §3.6
// retransmission, stray-reply rejection) to notifySendFunc.
func newTransferNOTIFYSend(key *transfer.TSIGKey) notifySendFunc {
	sender := transfer.NewNOTIFYSender("")
	sender.SetTSIGKey(key)
	return sender.SendNOTIFYContext
}

func zoneSerial(z *zone.Zone) (uint32, bool) {
	if z == nil {
		return 0, false
	}
	z.RLock()
	defer z.RUnlock()
	if z.SOA == nil {
		return 0, false
	}
	return z.SOA.Serial, true
}

// Observe compares the zones' current serials with the last observed ones
// and schedules a NOTIFY for each zone whose serial changed. The first call
// only records the startup baseline. Zones absent from zones are forgotten.
// Callers must not hold any zone lock.
func (n *zoneNotifier) Observe(zones map[string]*zone.Zone) {
	if n == nil {
		return
	}
	current := make(map[string]uint32, len(zones))
	for origin, z := range zones {
		if serial, ok := zoneSerial(z); ok {
			current[strings.ToLower(origin)] = serial
		}
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.stopped {
		return
	}
	first := !n.primed
	n.primed = true
	for origin, serial := range current {
		prev, seen := n.serials[origin]
		n.serials[origin] = serial
		if first || (seen && prev == serial) {
			continue
		}
		for _, target := range n.targets {
			n.scheduleLocked(notifyKey{zone: origin, target: target}, serial)
		}
	}
	for origin := range n.serials {
		if _, ok := current[origin]; !ok {
			delete(n.serials, origin)
		}
	}
}

func (n *zoneNotifier) scheduleLocked(k notifyKey, serial uint32) {
	fl := n.flights[k]
	if fl == nil {
		fl = &notifyFl{}
		n.flights[k] = fl
	}
	fl.pending = serial
	fl.dirty = true
	if fl.running {
		// The running sender picks up the latest serial; the send in
		// flight carries an older one and is superseded.
		if fl.cancel != nil {
			fl.cancel()
		}
		return
	}
	fl.running = true
	n.wg.Add(1)
	go n.run(k, fl)
}

func (n *zoneNotifier) run(k notifyKey, fl *notifyFl) {
	defer n.wg.Done()
	for {
		n.mu.Lock()
		if !fl.dirty || n.stopped || fl.removed {
			fl.running = false
			if !fl.dirty && n.flights[k] == fl {
				delete(n.flights, k)
			}
			n.mu.Unlock()
			return
		}
		serial := fl.pending
		fl.dirty = false
		ctx, cancel := context.WithCancel(n.ctx)
		fl.cancel = cancel
		send := n.send
		n.mu.Unlock()

		err := send(ctx, k.zone, serial, k.target)
		superseded := ctx.Err() != nil

		n.mu.Lock()
		fl.cancel = nil
		n.mu.Unlock()
		cancel()
		if err != nil && !superseded && n.logger != nil {
			n.logger.Warnf("NOTIFY %s serial %d to %s failed: %v", k.zone, serial, k.target, err)
		}
	}
}

// NotifyAll schedules a NOTIFY of every known zone's current serial to every
// target (BIND "notify on load", F568): called once after startup, when the
// transports are listening, so secondaries pick up changes made while this
// primary was down. Asynchronous; coalesces with any change-driven send.
func (n *zoneNotifier) NotifyAll() {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.stopped || len(n.targets) == 0 {
		return
	}
	for origin, serial := range n.serials {
		for _, target := range n.targets {
			n.scheduleLocked(notifyKey{zone: origin, target: target}, serial)
		}
	}
	if n.logger != nil && len(n.serials) > 0 {
		n.logger.Infof("NOTIFY: announcing %d zone(s) to %d also_notify target(s) after startup", len(n.serials), len(n.targets))
	}
}

// SetTargets replaces the target list and send function (SIGHUP reload of
// transfer.also_notify / notify_key, F567). Sends to removed targets are
// cancelled and their pending serials dropped; added targets get NOTIFYs
// from the next serial change; later sends use send (in-flight sends to
// retained targets finish with the previous one). It does not block.
func (n *zoneNotifier) SetTargets(targets []string, send notifySendFunc) {
	if n == nil || send == nil {
		return
	}
	keep := make(map[string]bool, len(targets))
	for _, t := range targets {
		keep[t] = true
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.targets = append([]string(nil), targets...)
	n.send = send
	for k, fl := range n.flights {
		if keep[k.target] {
			continue
		}
		fl.removed = true
		fl.dirty = false
		if fl.cancel != nil {
			fl.cancel()
		}
		delete(n.flights, k)
	}
}

// Stop cancels in-flight NOTIFYs and waits for every sender goroutine to
// exit. Later Observe calls are no-ops. Safe to call more than once.
func (n *zoneNotifier) Stop() {
	if n == nil {
		return
	}
	n.mu.Lock()
	n.stopped = true
	n.mu.Unlock()
	n.cancel()
	n.wg.Wait()
}
