package nothingdns

import (
	"errors"
	"fmt"
)

// Sentinel errors used for matching with [errors.Is]. The typed errors
// returned by the SDK implement an Is method that maps HTTP status codes onto
// these sentinels, so a caller can branch on the semantic failure rather than
// on a raw status number:
//
//	if errors.Is(err, nothingdns.ErrNotFound) {
//	    // the zone does not exist
//	}
var (
	// ErrNotFound matches HTTP 404 — the resource does not exist.
	ErrNotFound = errors.New("nothingdns: resource not found")
	// ErrUnauthorized matches HTTP 401 — the token is missing, expired or
	// the credentials were rejected.
	ErrUnauthorized = errors.New("nothingdns: unauthorized")
	// ErrForbidden matches HTTP 403 — the token is valid but the account's
	// role is insufficient for the operation.
	ErrForbidden = errors.New("nothingdns: forbidden")
	// ErrRateLimited matches HTTP 429 — the endpoint's rate limit was hit.
	ErrRateLimited = errors.New("nothingdns: rate limited")
)

// ErrAPIError is returned when the NothingDNS server answers with a non-2xx
// HTTP status. It carries the status code, the human-readable message
// reported by the server (its "error" field, or the raw body when the payload
// is not JSON) and the decoded JSON payload when one was available.
//
// The error text is formatted as "NothingDNS API error <status>: <message>".
type ErrAPIError struct {
	// StatusCode is the HTTP status code of the response.
	StatusCode int
	// Message is the human-readable error text reported by the server.
	Message string
	// Payload is the decoded JSON body of the response, when it was a JSON
	// object. It is nil for non-JSON or array bodies.
	Payload map[string]any
}

// Error implements the error interface.
func (e *ErrAPIError) Error() string {
	return fmt.Sprintf("NothingDNS API error %d: %s", e.StatusCode, e.Message)
}

// Is maps this error onto the package sentinels so callers can use
// errors.Is with ErrNotFound, ErrUnauthorized, ErrForbidden and
// ErrRateLimited.
func (e *ErrAPIError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.StatusCode == 404
	case ErrUnauthorized:
		return e.StatusCode == 401
	case ErrForbidden:
		return e.StatusCode == 403
	case ErrRateLimited:
		return e.StatusCode == 429
	}
	return false
}

// ErrConnectionError is returned when the server could not be reached at all:
// DNS failure, refused connection, TLS error or timeout. The underlying cause
// is available through errors.As / Unwrap.
type ErrConnectionError struct {
	// URL is the full URL that could not be reached.
	URL string
	// Err is the underlying transport error.
	Err error
}

// Error implements the error interface.
func (e *ErrConnectionError) Error() string {
	return fmt.Sprintf("could not reach NothingDNS at %s: %v", e.URL, e.Err)
}

// Unwrap returns the underlying transport error.
func (e *ErrConnectionError) Unwrap() error { return e.Err }

// ErrValidationError is returned when a response body could not be decoded
// into the expected shape, or when an argument failed local validation before
// any request was made.
type ErrValidationError struct {
	// Message describes what went wrong.
	Message string
}

// Error implements the error interface.
func (e *ErrValidationError) Error() string { return e.Message }

// IsNotFound reports whether err is the API error raised for HTTP 404.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// IsUnauthorized reports whether err is the API error raised for HTTP 401 —
// a missing, expired or rejected token.
func IsUnauthorized(err error) bool { return errors.Is(err, ErrUnauthorized) }

// IsForbidden reports whether err is the API error raised for HTTP 403 — a
// valid token whose role is insufficient for the operation. The server's role
// hierarchy is viewer < operator < admin.
func IsForbidden(err error) bool { return errors.Is(err, ErrForbidden) }

// IsRateLimited reports whether err is the API error raised for HTTP 429.
func IsRateLimited(err error) bool { return errors.Is(err, ErrRateLimited) }
