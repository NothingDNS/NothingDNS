package api

import (
	"strings"

	"github.com/nothingdns/nothingdns/internal/zone"
)

// ZoneService is the single source of truth for zone-related business
// logic, kept separate from the HTTP handler layer.
//
// The service layer is intentionally transport-agnostic: it returns typed
// DTOs (ZoneListResponse, ZoneDetailResponse) that the transport layer
// formats for its own protocol.
//
// To add a new zone operation:
//   - Add the business logic here (input validation, computation, error mapping)
//   - REST handler calls the service method, formats the HTTP response
type ZoneService struct {
	zoneManager *zone.Manager
}

// NewZoneService creates a ZoneService backed by the given zone.Manager.
func NewZoneService(zoneManager *zone.Manager) *ZoneService {
	return &ZoneService{zoneManager: zoneManager}
}

// ListZones returns a list of all zones with summary information.
// The response is capped at ZoneListMaxResults entries; Total reflects
// the unfiltered count so callers know if truncation occurred.
func (s *ZoneService) ListZones() *ZoneListResponse {
	resp := &ZoneListResponse{Zones: []ZoneSummary{}}
	if s.zoneManager == nil {
		return resp
	}

	zones := s.zoneManager.List()
	resp.Total = len(zones)

	// L-N5: cap the response. Operators with thousands of zones would
	// otherwise build a proportional JSON document and freeze the dashboard.
	count := 0
	for name, z := range zones {
		if count >= ZoneListMaxResults {
			resp.Truncated = true
			break
		}

		z.RLock()
		recordCount := 0
		for _, records := range z.Records {
			recordCount += len(records)
		}
		serial := uint32(0)
		if z.SOA != nil {
			serial = z.SOA.Serial
		}
		z.RUnlock()

		resp.Zones = append(resp.Zones, ZoneSummary{
			Name:    name,
			Serial:  serial,
			Records: recordCount,
		})
		count++
	}

	return resp
}

// GetZone returns detailed information about a single zone.
func (s *ZoneService) GetZone(name string) (*ZoneDetailResponse, bool) {
	if s.zoneManager == nil {
		return nil, false
	}

	z, ok := s.zoneManager.Get(name)
	if !ok {
		return nil, false
	}

	z.RLock()
	defer z.RUnlock()

	recordCount := 0
	for _, records := range z.Records {
		recordCount += len(records)
	}

	result := &ZoneDetailResponse{
		Name:    z.Origin,
		Records: recordCount,
	}

	if z.SOA != nil {
		result.Serial = z.SOA.Serial
		soaTTL := z.SOA.TTL
		for _, r := range z.Records[z.Origin] {
			if strings.EqualFold(r.Type, "SOA") {
				soaTTL = r.TTL
				break
			}
		}
		result.SOA = &SOADetail{
			MName:   z.SOA.MName,
			RName:   z.SOA.RName,
			TTL:     soaTTL,
			Serial:  z.SOA.Serial,
			Refresh: z.SOA.Refresh,
			Retry:   z.SOA.Retry,
			Expire:  z.SOA.Expire,
			Minimum: z.SOA.Minimum,
		}
	}

	// Records is the source of truth (as in the zone writer): transferred,
	// API-edited and KV-loaded zones carry their apex NS there while z.NS
	// stays empty, and z.NS also lists delegation NS (F715). z.NS remains
	// the fallback for zones built without apex NS records.
	var nsList []string
	for _, r := range z.Records[z.Origin] {
		if strings.EqualFold(r.Type, "NS") {
			nsList = append(nsList, r.RData)
		}
	}
	if len(nsList) == 0 {
		for _, ns := range z.NS {
			nsList = append(nsList, ns.NSDName)
		}
	}
	result.Nameservers = nsList

	return result, true
}

// ZoneExists reports whether a zone with the given name exists.
func (s *ZoneService) ZoneExists(name string) bool {
	if s.zoneManager == nil {
		return false
	}
	_, ok := s.zoneManager.Get(name)
	return ok
}

// ZoneManager returns the underlying zone manager. Use with caution —
// bypasses the service layer. Prefer service methods where possible.
func (s *ZoneService) ZoneManager() *zone.Manager {
	return s.zoneManager
}
