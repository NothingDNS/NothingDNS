package nothingdns

// Error translation tests, mirroring sdk/python/tests/test_errors.py and
// sdk/typescript/test/errors.test.mjs: the 401/403/404/429 mappings onto the
// package sentinels via errors.Is, the surfaced server message, and
// connection failures.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHTTPStatusMapsToTypedErrors(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)

	cases := []struct {
		name         string
		call         func(context.Context) error
		wantStatus   int
		wantSentinel error
	}{
		{"401 on login", func(ctx context.Context) error {
			_, err := c.Auth.Login(ctx, testUsername, testPassword+"-wrong", true)
			return err
		}, 401, ErrUnauthorized},
		{"403 on dnssec keys", func(ctx context.Context) error {
			_, err := c.DNSSEC.Keys(ctx)
			return err
		}, 403, ErrForbidden},
		{"429 on cache flush", func(ctx context.Context) error {
			_, err := c.Cache.Flush(ctx)
			return err
		}, 429, ErrRateLimited},
		{"404 on missing zone", func(ctx context.Context) error {
			_, err := c.Zones.Get(ctx, "missing.com")
			return err
		}, 404, ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call(context.Background())
			var apiErr *ErrAPIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected *ErrAPIError, got %T: %v", err, err)
			}
			wantEqual(t, "status code", apiErr.StatusCode, tc.wantStatus)
			wantTrue(t, errors.Is(err, tc.wantSentinel), "errors.Is matches the expected sentinel")

			// No other sentinel may match this status.
			for _, other := range []error{ErrUnauthorized, ErrForbidden, ErrNotFound, ErrRateLimited} {
				if errors.Is(other, tc.wantSentinel) {
					continue
				}
				if errors.Is(err, other) {
					t.Errorf("errors.Is unexpectedly matched %q", other)
				}
			}
		})
	}
}

func TestUnauthorizedSurfacesServerMessageAndPayload(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)

	_, err := c.Auth.Login(context.Background(), testUsername, testPassword+"-wrong", true)
	var apiErr *ErrAPIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *ErrAPIError, got %T: %v", err, err)
	}
	wantEqual(t, "status code", apiErr.StatusCode, 401)
	wantEqual(t, "server message", apiErr.Message, "invalid credentials")
	wantEqual(t, "payload", apiErr.Payload, map[string]any{"error": "invalid credentials"})
	wantTrue(t, errors.Is(err, ErrUnauthorized), "errors.Is ErrUnauthorized")
	wantTrue(t, !errors.Is(err, ErrForbidden), "errors.Is does not match ErrForbidden")
}

func TestNotFoundPayloadAndMessage(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)

	_, err := c.Zones.Get(context.Background(), "missing.com")
	var apiErr *ErrAPIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *ErrAPIError, got %T: %v", err, err)
	}
	wantTrue(t, errors.Is(err, ErrNotFound), "errors.Is ErrNotFound")
	wantTrue(t, strings.Contains(apiErr.Message, "missing.com"), "message names the zone")
	wantEqual(t, "payload", apiErr.Payload, map[string]any{"error": "Zone missing.com not found"})
}

func TestPredicateHelpersRejectNonAPIErrors(t *testing.T) {
	wantTrue(t, !IsNotFound(errors.New("nope")), "plain error is not a 404")
	wantTrue(t, !IsUnauthorized(nil), "nil error is not a 401")
	wantTrue(t, !IsForbidden(context.DeadlineExceeded), "context error is not a 403")
	wantTrue(t, !IsRateLimited(errors.New("nope")), "plain error is not a 429")
}

func TestAPIErrorStringIncludesStatusAndMessage(t *testing.T) {
	err := error(&ErrAPIError{StatusCode: 409, Message: "zone already exists"})

	wantTrue(t, strings.Contains(err.Error(), "409"), "string includes the status")
	wantTrue(t, strings.Contains(err.Error(), "zone already exists"), "string includes the message")
}

func TestUnreachableServerYieldsConnectionError(t *testing.T) {
	// Bind a port, note it, then release it so connections are refused.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	wantNoError(t, err)
	deadPort := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	c := NewClient(fmt.Sprintf("http://127.0.0.1:%d", deadPort), "", 2*time.Second, nil, nil)
	t.Cleanup(c.Close)

	_, err = c.Health(context.Background())
	if err == nil {
		t.Fatalf("expected a connection error, got nil")
	}
	var connErr *ErrConnectionError
	if !errors.As(err, &connErr) {
		t.Fatalf("expected *ErrConnectionError, got %T: %v", err, err)
	}
	wantTrue(t, strings.Contains(err.Error(), "could not reach NothingDNS"), "message names the server")
	wantTrue(t, connErr.Err != nil, "underlying transport error is preserved")
	wantTrue(t, strings.Contains(connErr.URL, fmt.Sprintf("127.0.0.1:%d", deadPort)), "URL points at the dead port")
}
