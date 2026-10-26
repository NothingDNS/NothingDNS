package zone

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// MaxSOAValue bounds the SOA TTL and timers: RFC 2181 §8 limits TTLs to
// 2^31-1, and the timers are intervals of the same kind.
const MaxSOAValue = 1<<31 - 1

// ErrNoSOA reports a zone without an SOA record, whose SOA cannot be edited.
var ErrNoSOA = errors.New("zone has no SOA record")

// ErrZoneNotFound reports that the zone named in an SOA read or edit is not
// loaded.
var ErrZoneNotFound = errors.New("zone not found")

// SOAUpdate holds the SOA fields UpdateSOA changes; a nil field keeps its
// current value. The serial is not editable: UpdateSOA bumps it, so
// secondaries pick the change up through NOTIFY and a zone transfer.
type SOAUpdate struct {
	MName   *string `json:"mname,omitempty"`
	RName   *string `json:"rname,omitempty"`
	TTL     *uint32 `json:"ttl,omitempty"`
	Refresh *uint32 `json:"refresh,omitempty"`
	Retry   *uint32 `json:"retry,omitempty"`
	Expire  *uint32 `json:"expire,omitempty"`
	Minimum *uint32 `json:"minimum,omitempty"`
}

// IsEmpty reports whether u changes nothing.
func (u SOAUpdate) IsEmpty() bool {
	return u.MName == nil && u.RName == nil && u.TTL == nil &&
		u.Refresh == nil && u.Retry == nil && u.Expire == nil && u.Minimum == nil
}

// ApplyTo sets u's fields on soa. Names are made absolute against origin; the
// RNAME may be given as an e-mail address (see SOAMailbox). It does not
// validate the result: call ValidateSOA.
func (u SOAUpdate) ApplyTo(soa *SOARecord, origin string) error {
	origin = normalizeZoneName(origin)
	if u.MName != nil {
		soa.MName = absoluteDomainName(*u.MName, origin)
		if soa.MName == "" {
			return fmt.Errorf("SOA primary nameserver (mname) is required")
		}
	}
	if u.RName != nil {
		if strings.TrimSpace(*u.RName) == "" {
			return fmt.Errorf("SOA admin mailbox (rname) is required")
		}
		rname, err := SOAMailbox(*u.RName, origin)
		if err != nil {
			return err
		}
		soa.RName = rname
	}
	if u.TTL != nil {
		soa.TTL = *u.TTL
	}
	if u.Refresh != nil {
		soa.Refresh = *u.Refresh
	}
	if u.Retry != nil {
		soa.Retry = *u.Retry
	}
	if u.Expire != nil {
		soa.Expire = *u.Expire
	}
	if u.Minimum != nil {
		soa.Minimum = *u.Minimum
	}
	return nil
}

// ValidateSOA checks the fields an operator sets: both names are valid
// absolute domain names that the zone file can hold, every value fits in
// 2^31-1, refresh, retry and expire are non-zero, retry is shorter than
// refresh (a failed refresh is retried before the next one is due) and expire
// is longer than refresh (a secondary does not drop the zone before its first
// refresh). The serial is not checked.
func ValidateSOA(soa *SOARecord) error {
	if soa == nil {
		return ErrNoSOA
	}
	for _, n := range []struct{ field, name string }{{"mname", soa.MName}, {"rname", soa.RName}} {
		if n.name == "" || !strings.HasSuffix(n.name, ".") {
			return fmt.Errorf("SOA %s %q must be an absolute domain name", n.field, n.name)
		}
		if err := ValidateRecordData(n.name, ""); err != nil {
			return fmt.Errorf("SOA %s %q: %w", n.field, n.name, err)
		}
		parsed, err := protocol.ParseName(n.name)
		if err != nil {
			return fmt.Errorf("SOA %s %q: %w", n.field, n.name, err)
		}
		parsed.Release()
	}
	for _, v := range []struct {
		field string
		value uint32
	}{{"ttl", soa.TTL}, {"refresh", soa.Refresh}, {"retry", soa.Retry}, {"expire", soa.Expire}, {"minimum", soa.Minimum}} {
		if v.value > MaxSOAValue {
			return fmt.Errorf("SOA %s %d exceeds %d", v.field, v.value, MaxSOAValue)
		}
	}
	if soa.Refresh == 0 || soa.Retry == 0 || soa.Expire == 0 {
		return fmt.Errorf("SOA refresh, retry and expire must be greater than zero")
	}
	if soa.Retry >= soa.Refresh {
		return fmt.Errorf("SOA retry (%d) must be shorter than refresh (%d)", soa.Retry, soa.Refresh)
	}
	if soa.Expire <= soa.Refresh {
		return fmt.Errorf("SOA expire (%d) must be longer than refresh (%d)", soa.Expire, soa.Refresh)
	}
	return nil
}

// soaTTLLocked returns the TTL the zone serves its SOA with: the apex SOA
// record's, which the zone file writer also uses, else z.SOA.TTL. Caller
// holds z's lock.
func soaTTLLocked(z *Zone) uint32 {
	for _, r := range z.Records[z.Origin] {
		if strings.EqualFold(r.Type, "SOA") {
			return r.TTL
		}
	}
	return z.SOA.TTL
}

// SOA returns a copy of zoneName's SOA, with TTL set to the TTL the zone
// serves it with.
func (m *Manager) SOA(zoneName string) (SOARecord, error) {
	zoneName = normalizeZoneName(zoneName)
	m.mu.RLock()
	z, exists := m.zones[zoneName]
	m.mu.RUnlock()
	if !exists {
		return SOARecord{}, fmt.Errorf("%w: %s", ErrZoneNotFound, zoneName)
	}
	z.RLock()
	defer z.RUnlock()
	if z.SOA == nil {
		return SOARecord{}, fmt.Errorf("%w: %s", ErrNoSOA, zoneName)
	}
	soa := *z.SOA
	soa.TTL = soaTTLLocked(z)
	return soa, nil
}

// PlanSOAUpdate returns the SOA zoneName would have after u, without changing
// the zone, or the error UpdateSOA would return. The serial in the result is
// the current one.
func (m *Manager) PlanSOAUpdate(zoneName string, u SOAUpdate) (SOARecord, error) {
	zoneName = normalizeZoneName(zoneName)
	m.mu.RLock()
	z, exists := m.zones[zoneName]
	m.mu.RUnlock()
	if !exists {
		return SOARecord{}, fmt.Errorf("%w: %s", ErrZoneNotFound, zoneName)
	}
	z.RLock()
	defer z.RUnlock()
	return planSOAUpdateLocked(z, u)
}

func planSOAUpdateLocked(z *Zone, u SOAUpdate) (SOARecord, error) {
	if z.SOA == nil {
		return SOARecord{}, fmt.Errorf("%w: %s", ErrNoSOA, z.Origin)
	}
	if u.IsEmpty() {
		return SOARecord{}, fmt.Errorf("no SOA field to update")
	}
	next := *z.SOA
	next.TTL = soaTTLLocked(z)
	if err := u.ApplyTo(&next, z.Origin); err != nil {
		return SOARecord{}, err
	}
	if err := ValidateSOA(&next); err != nil {
		return SOARecord{}, err
	}
	return next, nil
}

// UpdateSOA changes the SOA fields u sets on zoneName, bumps the serial,
// persists the zone file and fires the mutation hook like the record
// mutations. The result is validated (ValidateSOA) before anything changes.
// It returns the new SOA.
func (m *Manager) UpdateSOA(zoneName string, u SOAUpdate) (SOARecord, error) {
	zoneName = normalizeZoneName(zoneName)

	m.mu.RLock()
	z, exists := m.zones[zoneName]
	m.mu.RUnlock()
	if !exists {
		return SOARecord{}, fmt.Errorf("%w: %s", ErrZoneNotFound, zoneName)
	}

	z.Lock()
	next, err := planSOAUpdateLocked(z, u)
	if err != nil {
		z.Unlock()
		return SOARecord{}, err
	}
	// A fresh SOARecord: the old one may still be referenced by a reader
	// that copied the pointer.
	z.SOA = &next
	for i, r := range z.Records[z.Origin] {
		if strings.EqualFold(r.Type, "SOA") {
			z.Records[z.Origin][i].TTL = next.TTL
		}
	}
	m.bumpSerial(z) // also rewrites the apex SOA record's RDATA
	result := *z.SOA
	z.Unlock()

	m.writeBackZoneFile(zoneName, z)

	m.notifyMutation(zoneName, false)
	return result, nil
}
