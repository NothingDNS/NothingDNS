package nothingdns

import (
	"context"
)

// DNSSECService handles DNSSEC validation status and signing keys (the
// /api/v1/dnssec endpoints).
type DNSSECService struct {
	t *Transport
}

// Status returns the validation status. It requires the operator role or
// higher.
//
// Enabled reports whether validation runs at all; RequireDNSSEC reports
// whether bogus answers are refused rather than served.
func (s *DNSSECService) Status(ctx context.Context) (*DNSSECStatus, error) {
	var out DNSSECStatus
	if err := s.t.doJSON(ctx, "GET", "/api/v1/dnssec/status", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Keys lists the DNSSEC signing keys — public metadata only. It requires the
// admin role. Private key material is never exposed by the API.
func (s *DNSSECService) Keys(ctx context.Context) (*DNSSECKeyList, error) {
	var out DNSSECKeyList
	if err := s.t.doJSON(ctx, "GET", "/api/v1/dnssec/keys", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
