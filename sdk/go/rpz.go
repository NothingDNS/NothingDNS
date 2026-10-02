package nothingdns

import (
	"context"
	"fmt"
	"strings"
)

// RPZActions are the policy actions accepted by RPZ.AddRule.
var RPZActions = []string{"NXDOMAIN", "NODATA", "CNAME", "OVERRIDE", "DROP", "PASSTHROUGH", "TCPONLY"}

// IsValidRPZAction reports whether action is a policy action accepted by
// RPZ.AddRule.
func IsValidRPZAction(action string) bool {
	for _, a := range RPZActions {
		if a == action {
			return true
		}
	}
	return false
}

// RPZService handles Response Policy Zones (the /api/v1/rpz endpoints).
type RPZService struct {
	t *Transport
}

// addRuleRequest is the JSON body of POST /api/v1/rpz/rules.
type addRuleRequest struct {
	Pattern      string  `json:"pattern"`
	Action       string  `json:"action"`
	OverrideData *string `json:"override_data,omitempty"`
}

// Stats returns RPZ statistics: rule counts, matches, lookups and the last
// reload time. It requires the operator role or higher.
func (s *RPZService) Stats(ctx context.Context) (*RPZStats, error) {
	var out RPZStats
	if err := s.t.doJSON(ctx, "GET", "/api/v1/rpz", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Rules lists the QNAME rules. It requires the operator role or higher. Check
// the returned RPZRuleList's Truncated before relying on Total.
func (s *RPZService) Rules(ctx context.Context) (*RPZRuleList, error) {
	var out RPZRuleList
	if err := s.t.doJSON(ctx, "GET", "/api/v1/rpz/rules", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AddRule adds a QNAME rule. It requires the admin role.
//
// pattern is the domain pattern, e.g. "ads.example.com" or "*.tracker.com".
// action is one of "NXDOMAIN" (refuse the name), "NODATA", "CNAME", "OVERRIDE"
// (use overrideData), "DROP", "PASSTHROUGH" or "TCPONLY". overrideData is the
// replacement answer for "CNAME"/"OVERRIDE" and may be nil otherwise. It
// returns the server's confirmation message.
//
// It fails with an *ErrValidationError for an unknown action.
func (s *RPZService) AddRule(ctx context.Context, pattern, action string, overrideData *string) (string, error) {
	if !IsValidRPZAction(action) {
		return "", &ErrValidationError{Message: fmt.Sprintf("action must be one of %s", strings.Join(RPZActions, ", "))}
	}
	body := addRuleRequest{Pattern: pattern, Action: action, OverrideData: overrideData}
	return s.t.doMessage(ctx, "POST", "/api/v1/rpz/rules", nil, body)
}

// DeleteRule deletes a QNAME rule by pattern. It requires the admin role. It
// returns the server's confirmation message.
func (s *RPZService) DeleteRule(ctx context.Context, pattern string) (string, error) {
	return s.t.doMessage(ctx, "DELETE", "/api/v1/rpz/rules", map[string]any{"pattern": pattern}, nil)
}

// Toggle flips RPZ filtering on/off. It requires the admin role. It returns
// the server's confirmation message.
func (s *RPZService) Toggle(ctx context.Context) (string, error) {
	return s.t.doMessage(ctx, "POST", "/api/v1/rpz/toggle", nil, nil)
}
