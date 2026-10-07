package cluster

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/cluster/raft"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Atomic zone batches (F497/F498).
//
// ProposeZoneBatch replicates a set of record changes to ONE zone as a single
// Raft entry. Every replica applies the batch all-or-nothing under the zone's
// write lock: the optional precondition fingerprint is checked first, then
// every op is applied to a staged copy of the touched owner names; only if all
// of them succeed is the staged data swapped in, the SOA serial bumped once and
// the mutation hook fired once. The outcome is a pure function of the
// replica's zone content and the entry, so all replicas take the same branch.
//
// Wire format / rolling upgrade (F499): the batch travels as a "create_zone"
// ZoneCommand with no nameservers and the batch in Metadata
// ({"zone_batch":{...}}). A brand-new command type would make a pre-F497
// node's in-memory ledger return "unknown command type", which applyWithRetry
// retries forever — wedging that node's apply loop. Pre-F497 nodes instead
// treat the envelope as a create_zone without nameservers: they log
// "create_zone for <zone> missing nameservers" and change nothing. That node
// then lacks the batch's changes (replica divergence until it next installs a
// snapshot), so every node MUST run an F497-capable build before any caller
// uses ProposeZoneBatch. The payload is versioned (v); a node that does not
// know a version rejects the batch deterministically instead of guessing.

// Zone batch op kinds.
const (
	// ZoneOpAdd adds RData as a Name/Type RR. Adding an RR that is already
	// present (same type, equal canonical RDATA) is a no-op (RFC 2181 §5: duplicates are
	// one RR).
	ZoneOpAdd = "add"
	// ZoneOpDeleteRRset removes every RR of Name/Type. Fails if there is none.
	ZoneOpDeleteRRset = "delete_rrset"
	// ZoneOpDeleteRData removes the single RR Name/Type/RData (canonical
	// RDATA comparison, names case-insensitive and absolute). Fails if absent.
	ZoneOpDeleteRData = "delete_rdata"
	// ZoneOpUpdate replaces the RR Name/Type/OldData with Name/Type/RData.
	// Fails if OldData is absent.
	ZoneOpUpdate = "update"
)

// zoneBatchVersion is the payload version this build produces and applies.
const zoneBatchVersion = 1

// zoneBatchVersionZoneGuard is the payload version of a batch whose
// precondition guards the whole zone (ZoneBatchPrecondition.Zone, F582). A
// node that only knows version 1 rejects it deterministically (nothing
// applied, ErrZoneBatchUnsupported) instead of applying it unguarded.
const zoneBatchVersionZoneGuard = 2

// MaxZoneBatchOps bounds one batch (one Raft entry).
const MaxZoneBatchOps = 1024

// ZoneOp is one record change inside a zone batch. Names may be relative to
// the zone origin or absolute; they must lie inside the zone. SOA records
// cannot be changed through a batch (the batch owns the serial bump).
type ZoneOp struct {
	Op      string `json:"op"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Class   string `json:"class,omitempty"`
	TTL     uint32 `json:"ttl,omitempty"`
	RData   string `json:"rdata,omitempty"`
	OldData string `json:"old_data,omitempty"`
}

// ZoneBatchPrecondition is the optimistic-concurrency guard of a batch.
// Fingerprint is the value ZoneFingerprint(zone, Names) returned when the
// caller planned the batch; at apply time every replica recomputes it over
// the same Names and rejects the whole batch (ErrZoneBatchConflict) if it
// differs, i.e. if any RR at those names changed in between. Names must
// include the owner name of every op. An empty Fingerprint disables the
// check (the batch is still atomic).
//
// Zone (F582) widens the guard to the whole zone: Fingerprint must then be
// the value ZoneContentFingerprint returned, and the batch is rejected if any
// RR of the zone or any SOA field other than the serial changed. Used when
// the batch's plan depends on the zone as a whole — an RFC 2136 prerequisite
// on the apex SOA, whose serial every write bumps. The serial itself is not
// compared: single-record writes bump it from each replica's own clock, so
// replicas may hold different serials for the same content and must still
// take the same branch.
type ZoneBatchPrecondition struct {
	Names       []string
	Fingerprint string
	Zone        bool
}

// ErrZoneBatchConflict reports that the zone content covered by the batch's
// precondition changed between planning and apply; nothing was applied.
var ErrZoneBatchConflict = errors.New("zone batch precondition failed: zone changed since the batch was planned")

// ErrZoneBatchUnsupported reports a batch payload version this node does not
// implement; nothing was applied.
var ErrZoneBatchUnsupported = errors.New("zone batch version not supported by this node")

// ZoneBatchOpError reports the op that made a batch fail; nothing was applied.
type ZoneBatchOpError struct {
	Index int
	Op    ZoneOp
	Err   error
}

func (e *ZoneBatchOpError) Error() string {
	return fmt.Sprintf("zone batch op %d (%s %s %s): %v", e.Index, e.Op.Op, e.Op.Name, e.Op.Type, e.Err)
}

func (e *ZoneBatchOpError) Unwrap() error { return e.Err }

// zoneBatchPayload is the replicated batch (Metadata of the envelope).
type zoneBatchPayload struct {
	V           int      `json:"v"`
	ID          string   `json:"id"`
	Ops         []ZoneOp `json:"ops"`
	Names       []string `json:"names,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	// Zone: Fingerprint is a ZoneContentFingerprint (v2 payloads, F582).
	Zone bool `json:"zone,omitempty"`
	// SerialDate is the YYYYMMDD00 serial prefix taken from the proposer's
	// clock, so every replica computes the same new serial (zone.IncrementSerial
	// reads the local wall clock).
	SerialDate uint32 `json:"serial_date"`
}

type zoneBatchEnvelope struct {
	Batch *zoneBatchPayload `json:"zone_batch"`
}

// zoneBatchWaiters routes a batch's apply result back to the proposer on the
// node that proposed it. Zero value is ready to use.
type zoneBatchWaiters struct {
	mu sync.Mutex
	m  map[string]chan error
}

func (w *zoneBatchWaiters) register(id string) chan error {
	ch := make(chan error, 1)
	w.mu.Lock()
	if w.m == nil {
		w.m = make(map[string]chan error)
	}
	w.m[id] = ch
	w.mu.Unlock()
	return ch
}

func (w *zoneBatchWaiters) unregister(id string) {
	w.mu.Lock()
	delete(w.m, id)
	w.mu.Unlock()
}

func (w *zoneBatchWaiters) deliver(id string, err error) {
	w.mu.Lock()
	ch := w.m[id]
	w.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- err:
	default: // already delivered (log replay of the same entry)
	}
}

// ProposeZoneBatch replicates ops on zoneName as ONE Raft entry and waits for
// it to be applied locally. It returns nil only if the batch was applied in
// full; ErrZoneBatchConflict, ErrZoneBatchUnsupported or a *ZoneBatchOpError
// mean nothing was applied (on any replica). *raft.ErrNotLeader is returned on
// a follower. Any other error after the proposal (e.g. the apply wait timed
// out after a leadership change) leaves the outcome unknown: the entry may
// still commit and apply later — all-or-nothing either way.
//
// All nodes must run a build with ProposeZoneBatch before it is used (see the
// rolling-upgrade note at the top of zone_batch.go).
func (c *Cluster) ProposeZoneBatch(zoneName string, ops []ZoneOp, pre ZoneBatchPrecondition) error {
	if !c.IsRaftMode() {
		return fmt.Errorf("cluster is not in Raft mode")
	}
	if normalizeClusterZoneName(zoneName) == "" {
		return fmt.Errorf("zone name is required")
	}
	if len(ops) == 0 {
		return fmt.Errorf("zone batch has no ops")
	}
	if len(ops) > MaxZoneBatchOps {
		return fmt.Errorf("zone batch has %d ops, limit is %d", len(ops), MaxZoneBatchOps)
	}
	for i, op := range ops {
		if err := checkZoneOpShape(op); err != nil {
			return &ZoneBatchOpError{Index: i, Op: op, Err: err}
		}
	}
	if pre.Fingerprint == "" && (len(pre.Names) > 0 || pre.Zone) {
		return fmt.Errorf("zone batch precondition names given without a fingerprint")
	}
	if pre.Fingerprint != "" {
		origin := normalizeClusterZoneName(zoneName)
		covered := make(map[string]bool, len(pre.Names))
		for _, n := range pre.Names {
			covered[batchQualify(n, origin)] = true
		}
		for i, op := range ops {
			if !covered[batchQualify(op.Name, origin)] {
				return &ZoneBatchOpError{Index: i, Op: op, Err: fmt.Errorf("owner name not covered by the precondition names")}
			}
		}
	}

	id, err := newZoneBatchID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	payload := zoneBatchPayload{
		V: zoneBatchVersion, ID: id, Ops: ops,
		Names: pre.Names, Fingerprint: pre.Fingerprint,
		SerialDate: uint32(now.Year()*10000+int(now.Month())*100+now.Day()) * 100,
	}
	if pre.Zone {
		payload.V, payload.Zone = zoneBatchVersionZoneGuard, true
	}
	meta, err := json.Marshal(zoneBatchEnvelope{Batch: &payload})
	if err != nil {
		return fmt.Errorf("marshal zone batch: %w", err)
	}

	ch := c.zoneBatches.register(id)
	defer c.zoneBatches.unregister(id)
	if err := c.proposeZoneChange(raft.ZoneCommand{Type: "create_zone", Zone: zoneName, Metadata: meta}); err != nil {
		return err
	}
	select {
	case res := <-ch:
		return res
	default:
		// Applied index advanced without this node running the hook for the
		// entry (e.g. superseded by a snapshot install).
		return fmt.Errorf("zone batch %s: committed but its apply result was not observed", id)
	}
}

func newZoneBatchID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("zone batch id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// decodeZoneBatch reports whether cmd is a zone-batch envelope and, if so,
// returns its payload (nil with ok=true when the envelope is malformed).
func decodeZoneBatch(cmd raft.ZoneCommand) (p *zoneBatchPayload, ok bool, err error) {
	if cmd.Type != "create_zone" || len(cmd.Metadata) == 0 {
		return nil, false, nil
	}
	var env zoneBatchEnvelope
	if err := json.Unmarshal(cmd.Metadata, &env); err != nil {
		return nil, true, fmt.Errorf("decode zone batch: %w", err)
	}
	if env.Batch == nil {
		return nil, false, nil
	}
	return env.Batch, true, nil
}

// applyZoneBatchCommand is the apply-hook branch for a batch envelope.
func (c *Cluster) applyZoneBatchCommand(cmd raft.ZoneCommand, p *zoneBatchPayload, decodeErr error) {
	err := decodeErr
	if err == nil {
		err = c.applyZoneBatch(cmd.Zone, p)
	}
	if err != nil {
		c.logger.Warnf("raft apply: zone batch on zone %s rejected, nothing applied: %v", cmd.Zone, err)
	}
	if p != nil {
		c.zoneBatches.deliver(p.ID, err)
	}
}

// applyZoneBatch applies p to zoneName all-or-nothing. Deterministic: depends
// only on the zone's content and p.
func (c *Cluster) applyZoneBatch(zoneName string, p *zoneBatchPayload) error {
	// Known shapes only: v1 without the zone guard, v2 with it.
	if !(p.V == zoneBatchVersion && !p.Zone) && !(p.V == zoneBatchVersionZoneGuard && p.Zone) {
		return fmt.Errorf("%w: v=%d", ErrZoneBatchUnsupported, p.V)
	}
	if len(p.Ops) == 0 || len(p.Ops) > MaxZoneBatchOps {
		return fmt.Errorf("zone batch has %d ops (allowed 1..%d)", len(p.Ops), MaxZoneBatchOps)
	}
	if c.zoneManager == nil {
		return fmt.Errorf("zoneManager not configured")
	}
	origin := normalizeClusterZoneName(zoneName)
	z, ok := c.zoneManager.Get(origin)
	if !ok {
		return fmt.Errorf("zone %s not found", origin)
	}

	z.Lock()
	if p.Fingerprint != "" {
		fp := zoneFingerprintLocked(z, p.Names)
		if p.Zone {
			fp = zoneContentFingerprintLocked(z)
		}
		if fp != p.Fingerprint {
			z.Unlock()
			return ErrZoneBatchConflict
		}
	}
	staged := make(map[string][]zone.Record)
	for i, op := range p.Ops {
		if err := stageZoneOp(z, staged, op); err != nil {
			z.Unlock()
			return &ZoneBatchOpError{Index: i, Op: op, Err: err}
		}
	}
	for name, recs := range staged {
		if len(recs) == 0 {
			delete(z.Records, name)
		} else {
			z.Records[name] = recs
		}
	}
	bumpSerialDeterministic(z, p.SerialDate)
	z.Unlock()

	c.zoneManager.NotifyMutated(origin)
	if err := c.zoneManager.PersistZone(origin); err != nil {
		c.logger.Warnf("raft apply: zone batch: failed to persist zone %s to disk: %v", origin, err)
	}
	return nil
}

func checkZoneOpShape(op ZoneOp) error {
	switch op.Op {
	case ZoneOpAdd, ZoneOpDeleteRRset, ZoneOpDeleteRData, ZoneOpUpdate:
	default:
		return fmt.Errorf("unknown op %q", op.Op)
	}
	rtype := strings.ToUpper(strings.TrimSpace(op.Type))
	if rtype == "" {
		return fmt.Errorf("record type is required")
	}
	if rtype == "SOA" {
		return fmt.Errorf("SOA records cannot be changed through a zone batch")
	}
	if strings.TrimSpace(op.Name) == "" {
		return fmt.Errorf("owner name is required")
	}
	switch op.Op {
	case ZoneOpAdd, ZoneOpDeleteRData, ZoneOpUpdate:
		if strings.TrimSpace(op.RData) == "" {
			return fmt.Errorf("record data is required")
		}
	}
	if op.Op == ZoneOpUpdate && strings.TrimSpace(op.OldData) == "" {
		return fmt.Errorf("old record data is required")
	}
	return nil
}

// stageZoneOp applies op to the staged view of z (caller holds z's write
// lock). Unstaged owner names read through to z.Records; staged slices are
// always fresh copies, so z is untouched until the caller commits.
func stageZoneOp(z *zone.Zone, staged map[string][]zone.Record, op ZoneOp) error {
	if err := checkZoneOpShape(op); err != nil {
		return err
	}
	rtype := strings.ToUpper(strings.TrimSpace(op.Type))
	name := batchQualify(op.Name, z.Origin)
	if !batchNameInZone(name, z.Origin) {
		return fmt.Errorf("record owner %s is outside zone %s", name, z.Origin)
	}
	cur, isStaged := staged[name]
	if !isStaged {
		cur = z.Records[name]
	}
	next := make([]zone.Record, 0, len(cur)+1)
	class := strings.ToUpper(strings.TrimSpace(op.Class))
	if class == "" {
		class = "IN"
	}

	switch op.Op {
	case ZoneOpAdd:
		if err := zone.ValidateRecordData(name, op.RData); err != nil {
			return err
		}
		next = append(next, cur...)
		for _, r := range cur {
			if strings.EqualFold(r.Type, rtype) && batchRDataEqual(rtype, r.RData, op.RData, z.Origin) {
				staged[name] = next
				return nil
			}
		}
		next = append(next, zone.Record{Name: name, TTL: op.TTL, Class: class, Type: rtype, RData: strings.TrimSpace(op.RData)})
	case ZoneOpDeleteRRset, ZoneOpDeleteRData:
		found := false
		for _, r := range cur {
			if strings.EqualFold(r.Type, rtype) && (op.Op == ZoneOpDeleteRRset || batchRDataEqual(rtype, r.RData, op.RData, z.Origin)) {
				found = true
				continue
			}
			next = append(next, r)
		}
		if !found {
			if op.Op == ZoneOpDeleteRRset {
				return fmt.Errorf("no %s record found for %s", rtype, name)
			}
			return fmt.Errorf("record not found: %s %s %s", name, rtype, op.RData)
		}
	case ZoneOpUpdate:
		if err := zone.ValidateRecordData(name, op.RData); err != nil {
			return err
		}
		found := false
		for _, r := range cur {
			if !found && strings.EqualFold(r.Type, rtype) && batchRDataEqual(rtype, r.RData, op.OldData, z.Origin) {
				found = true
				next = append(next, zone.Record{Name: name, TTL: op.TTL, Class: class, Type: rtype, RData: strings.TrimSpace(op.RData)})
				continue
			}
			next = append(next, r)
		}
		if !found {
			return fmt.Errorf("record not found: %s %s %s", name, rtype, op.OldData)
		}
	}
	staged[name] = next
	return nil
}

// bumpSerialDeterministic mirrors zone.IncrementSerial but takes the date
// prefix from the replicated entry instead of the local clock.
func bumpSerialDeterministic(z *zone.Zone, datePrefix uint32) {
	if z.SOA == nil {
		return
	}
	if datePrefix != 0 && zone.SerialIsNewer(datePrefix, z.SOA.Serial) {
		z.SOA.Serial = datePrefix + 1
	} else {
		z.SOA.Serial = zone.SerialIncrement(z.SOA.Serial)
	}
	records := z.Records[z.Origin]
	for i, r := range records {
		if strings.EqualFold(r.Type, "SOA") {
			records[i].RData = fmt.Sprintf("%s %s %d %d %d %d %d",
				z.SOA.MName, z.SOA.RName, z.SOA.Serial,
				z.SOA.Refresh, z.SOA.Retry, z.SOA.Expire, z.SOA.Minimum)
			break
		}
	}
}

// ZoneFingerprint returns the precondition fingerprint of the RRs owned by
// names (relative or absolute) in zoneName, for ZoneBatchPrecondition. SOA
// records are excluded (their serial is bumped by every write and is not
// computed identically on every replica by the single-record paths); RDATA is
// compared in canonical form, so the value is the same on every replica that
// holds the same records.
func (c *Cluster) ZoneFingerprint(zoneName string, names []string) (string, error) {
	if c.zoneManager == nil {
		return "", fmt.Errorf("zoneManager not configured")
	}
	origin := normalizeClusterZoneName(zoneName)
	z, ok := c.zoneManager.Get(origin)
	if !ok {
		return "", fmt.Errorf("zone %s not found", origin)
	}
	z.RLock()
	defer z.RUnlock()
	return zoneFingerprintLocked(z, names), nil
}

// ZoneContentFingerprint returns the whole-zone precondition fingerprint
// (ZoneBatchPrecondition.Zone, F582): every RR of every owner name, SOA RRs
// excluded, plus the SOA fields except the serial. Replica-independent like
// ZoneFingerprint; O(zone size), so callers use it only when their plan
// depends on the zone as a whole.
func (c *Cluster) ZoneContentFingerprint(zoneName string) (string, error) {
	if c.zoneManager == nil {
		return "", fmt.Errorf("zoneManager not configured")
	}
	origin := normalizeClusterZoneName(zoneName)
	z, ok := c.zoneManager.Get(origin)
	if !ok {
		return "", fmt.Errorf("zone %s not found", origin)
	}
	z.RLock()
	defer z.RUnlock()
	return zoneContentFingerprintLocked(z), nil
}

func zoneContentFingerprintLocked(z *zone.Zone) string {
	names := make([]string, 0, len(z.Records))
	for name := range z.Records {
		names = append(names, name)
	}
	fp := zoneFingerprintLocked(z, names)
	soa := "-"
	if z.SOA != nil {
		soa = fmt.Sprintf("%s %s %d %d %d %d %d", strings.ToLower(z.SOA.MName), strings.ToLower(z.SOA.RName),
			z.SOA.Refresh, z.SOA.Retry, z.SOA.Expire, z.SOA.Minimum, z.SOA.TTL)
	}
	sum := sha256.Sum256([]byte(fp + "\n" + soa))
	return "z1:" + hex.EncodeToString(sum[:])
}

func zoneFingerprintLocked(z *zone.Zone, names []string) string {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[batchQualify(n, z.Origin)] = true
	}
	owners := make([]string, 0, len(set))
	for n := range set {
		owners = append(owners, n)
	}
	sort.Strings(owners)

	h := sha256.New()
	for _, owner := range owners {
		var lines []string
		for _, r := range z.Records[owner] {
			rtype := strings.ToUpper(strings.TrimSpace(r.Type))
			if rtype == "SOA" {
				continue
			}
			class := strings.ToUpper(strings.TrimSpace(r.Class))
			if class == "" {
				class = "IN"
			}
			lines = append(lines, fmt.Sprintf("%s\t%d\t%s\t%s", class, r.TTL, rtype, canonicalRDataKey(rtype, r.RData, z.Origin)))
		}
		sort.Strings(lines)
		fmt.Fprintf(h, "%s\n%d\n", owner, len(lines))
		for _, l := range lines {
			fmt.Fprintf(h, "%s\n", l)
		}
	}
	return "v1:" + hex.EncodeToString(h.Sum(nil))
}

// batchRDataEqual compares RDATA in the replica-independent canonical form
// used by the fingerprint, so a replica holding an API-stored relative name
// and one holding its zone-file round-trip (absolute) select the same RR.
func batchRDataEqual(rtype, a, b, origin string) bool {
	return canonicalRDataKey(rtype, a, origin) == canonicalRDataKey(rtype, b, origin)
}

// batchNameOnlyTypes mirrors zone's name-only RDATA types: their presentation
// RDATA is numbers and domain names only, so names can be lowercased and
// absolutized without changing meaning.
var batchNameOnlyTypes = map[string]bool{
	"NS": true, "CNAME": true, "PTR": true, "DNAME": true, "MX": true,
	"SRV": true, "KX": true, "AFSDB": true, "RT": true, "PX": true, "MD": true,
	"MF": true, "MB": true, "MG": true, "MR": true, "MINFO": true, "RP": true,
}

// canonicalRDataKey renders RDATA in a replica-independent form: canonical
// wire bytes when the type is known and parses, with name-only types'
// domain names lowercased and made absolute against origin (an API-added
// relative target and its zone-file round-trip compare equal).
func canonicalRDataKey(rtype, rdata, origin string) string {
	s := strings.TrimSpace(rdata)
	if batchNameOnlyTypes[rtype] {
		fields := strings.Fields(strings.ToLower(s))
		for i, f := range fields {
			if _, err := strconv.ParseUint(f, 10, 32); err == nil {
				continue
			}
			fields[i] = batchQualify(f, origin)
		}
		s = strings.Join(fields, " ")
	}
	if protocol.RecordTypeFromText(rtype) != 0 {
		if rd := protocol.ParseRDataText(rtype, s); rd != nil {
			buf := make([]byte, rd.Len())
			if _, err := rd.Pack(buf, 0); err == nil {
				return "w:" + hex.EncodeToString(buf)
			}
		}
	}
	return "t:" + s
}

// batchQualify matches zone.Manager's owner-name keying (qualifyName):
// the name lowercased and made absolute against origin ("@" and "" are the origin).
func batchQualify(name, origin string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	origin = strings.TrimSpace(origin)
	if !strings.HasSuffix(origin, ".") {
		origin += "."
	}
	if name == "" || name == "@" {
		return origin
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	if origin == "." {
		return name + "."
	}
	return name + "." + origin
}

func batchNameInZone(name, origin string) bool {
	name = strings.ToLower(name)
	origin = strings.ToLower(origin)
	if !strings.HasSuffix(origin, ".") {
		origin += "."
	}
	if origin == "." {
		return true
	}
	return name == origin || strings.HasSuffix(name, "."+origin)
}
