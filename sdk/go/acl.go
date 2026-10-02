package nothingdns

import (
	"context"
)

// ACLService handles client ACLs and the recursion allow list (the
// /api/v1/acl endpoints).
//
// Rules are evaluated in server-config order and the first match wins; once
// any rule exists, a client matching none of them is refused.
type ACLService struct {
	t *Transport
}

// Get returns the ACL rules plus the recursion allow list. It requires the
// operator role or higher.
//
// When the returned ACLConfig has Persistent set, the list is served from
// access_policy.json — the dashboard-managed file that overrides the YAML
// config on reload.
func (s *ACLService) Get(ctx context.Context) (*ACLConfig, error) {
	var out ACLConfig
	if err := s.t.doJSON(ctx, "GET", "/api/v1/acl", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Set replaces the full ACL rule list. It requires the admin role.
//
// rules is the complete new rule list, in evaluation order. This replaces the
// whole list — it is not a merge. To change one rule, read the current list
// with Get, edit it and send it back:
//
//	current, _ := client.ACL.Get(ctx)
//	client.ACL.Set(ctx, append(current.Rules, nothingdns.ACLRule{...}))
//
// It fails with an *ErrValidationError when rules is empty, to avoid
// accidentally wiping the ACL; pass an explicit non-empty list to clear rules
// selectively instead.
func (s *ACLService) Set(ctx context.Context, rules []ACLRule) (string, error) {
	if len(rules) == 0 {
		return "", &ErrValidationError{Message: "refusing to send an empty rule list; pass [] only deliberately"}
	}
	return s.t.doMessage(ctx, "PUT", "/api/v1/acl", nil, map[string]any{"rules": rules})
}

// Recursion returns the recursion allow list. It requires the operator role
// or higher.
func (s *ACLService) Recursion(ctx context.Context) (*RecursionAllowList, error) {
	var out RecursionAllowList
	if err := s.t.doJSON(ctx, "GET", "/api/v1/acl/recursion", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetRecursion replaces the recursion allow list. It requires the admin role.
//
// networks is the list of CIDR networks allowed to send recursive queries; an
// empty list denies recursion to every client. It returns the stored list as
// the server returned it.
func (s *ACLService) SetRecursion(ctx context.Context, networks []string) (*RecursionAllowList, error) {
	if networks == nil {
		networks = []string{}
	}
	var out RecursionAllowList
	body := map[string]any{"networks": networks}
	if err := s.t.doJSON(ctx, "PUT", "/api/v1/acl/recursion", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
