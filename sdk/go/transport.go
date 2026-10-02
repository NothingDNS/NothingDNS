package nothingdns

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the default address of a NothingDNS server's HTTP
	// listener (the server.http section of the config).
	DefaultBaseURL = "http://localhost:8080"
	// DefaultTimeout is the default per-request timeout in seconds.
	DefaultTimeout = 30 * time.Second
)

// Transport performs authenticated HTTP calls against one NothingDNS server.
// It owns URL construction, the Authorization bearer header, query
// serialisation, JSON encoding, timeouts and the translation of HTTP failures
// into SDK errors. Resource namespaces (see [Client]) only describe what to
// call; the Transport decides how the request is made.
//
// A Transport is safe for concurrent use as long as its fields are not
// mutated; changing the token (SetToken) should be done before issuing
// concurrent requests. Each namespace on a [Client] shares one Transport.
type Transport struct {
	baseURL    string
	token      string
	httpClient *http.Client
	headers    map[string]string
}

// NewTransport builds a Transport for a server.
//
// baseURL is the address of the server's HTTP listener, e.g.
// "http://dns.example.com:8080". token may be a JWT from Auth.Login /
// Auth.Bootstrap or the static server.http.auth_token value; pass "" for an
// unauthenticated client. httpClient may be nil, in which case a client with
// DefaultTimeout is used; supply your own to control TLS, proxies or
// connection pooling. headers are extra default headers merged into every
// request.
func NewTransport(baseURL string, token string, timeout time.Duration, httpClient *http.Client, headers map[string]string) *Transport {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	h := make(map[string]string, len(headers))
	for k, v := range headers {
		h[k] = v
	}
	return &Transport{
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      token,
		httpClient: httpClient,
		headers:    h,
	}
}

// BaseURL returns the server address, without a trailing slash.
func (t *Transport) BaseURL() string { return t.baseURL }

// Token returns the bearer token currently sent with requests (or "").
func (t *Transport) Token() string { return t.token }

// SetToken sets the bearer token used by every subsequent request. Pass "" to
// continue unauthenticated. The value may be a JWT from Auth.Login /
// Auth.Bootstrap or the static server.http.auth_token from the server config.
func (t *Transport) SetToken(token string) { t.token = token }

// HTTPClient returns the underlying *http.Client.
func (t *Transport) HTTPClient() *http.Client { return t.httpClient }

// escape percent-encodes one path segment (zone names, source ids, usernames)
// so that a value containing "/" or other reserved characters cannot alter
// the request path.
func (t *Transport) escape(seg string) string { return url.PathEscape(seg) }

// buildQuery serialises query parameters, skipping nil values. It returns an
// empty string when there is nothing to send. Values are rendered with their
// natural string form; use only string, int, bool and float inputs.
func buildQuery(params map[string]any) string {
	if len(params) == 0 {
		return ""
	}
	values := url.Values{}
	for k, v := range params {
		if v == nil {
			continue
		}
		switch typed := v.(type) {
		case string:
			values.Set(k, typed)
		case bool:
			values.Set(k, strconv.FormatBool(typed))
		case int:
			values.Set(k, strconv.Itoa(typed))
		case int64:
			values.Set(k, strconv.FormatInt(typed, 10))
		case float64:
			values.Set(k, strconv.FormatFloat(typed, 'f', -1, 64))
		default:
			values.Set(k, "")
		}
	}
	if len(values) == 0 {
		return ""
	}
	return "?" + values.Encode()
}

// do performs one HTTP request and returns the raw response body. body, when
// non-nil, is JSON-encoded as the request payload. query holds optional query
// parameters (nil values are skipped). It returns an error for any non-2xx
// status and for any transport failure.
func (t *Transport) do(ctx context.Context, method, path string, query map[string]any, body any) ([]byte, error) {
	fullURL := t.baseURL + path + buildQuery(query)

	var reader io.Reader
	var hasBody bool
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, &ErrValidationError{Message: "could not encode request body: " + err.Error()}
		}
		reader = bytes.NewReader(encoded)
		hasBody = true
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return nil, &ErrConnectionError{URL: fullURL, Err: err}
	}
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, &ErrConnectionError{URL: fullURL, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &ErrConnectionError{URL: fullURL, Err: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, apiError(resp.StatusCode, respBody)
	}
	return respBody, nil
}

// apiError builds an *ErrAPIError from a non-2xx response. The server reports
// failures as {"error": "..."}; a non-JSON body falls back to the raw text so
// the message is never lost.
func apiError(status int, body []byte) error {
	e := &ErrAPIError{StatusCode: status, Message: "HTTP " + strconv.Itoa(status)}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		e.Payload = payload
		if reported, ok := payload["error"].(string); ok && reported != "" {
			e.Message = reported
		} else if reported, ok := payload["message"].(string); ok && reported != "" {
			e.Message = reported
		}
		return e
	}
	if text := strings.TrimSpace(string(body)); text != "" {
		const maxLen = 500
		if len(text) > maxLen {
			text = text[:maxLen]
		}
		e.Message = text
	}
	return e
}

// doJSON performs a request and decodes the JSON response into out. out may
// be nil to discard the body. A 2xx body that is not valid JSON produces an
// *ErrValidationError.
func (t *Transport) doJSON(ctx context.Context, method, path string, query map[string]any, body any, out any) error {
	raw, err := t.do(ctx, method, path, query, body)
	if err != nil {
		return err
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return &ErrValidationError{Message: "NothingDNS returned a body that could not be decoded: " + err.Error()}
	}
	return nil
}

// doMessage performs a request and returns the server's plain "message"
// acknowledgement. Endpoints that answer with a bare {"message": "..."} are
// decoded here so callers receive just the string.
func (t *Transport) doMessage(ctx context.Context, method, path string, query map[string]any, body any) (string, error) {
	raw, err := t.do(ctx, method, path, query, body)
	if err != nil {
		return "", err
	}
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &payload); err == nil {
		return payload.Message, nil
	}
	return string(raw), nil
}

// doText performs a request and returns the raw response body as text, for
// endpoints that serve non-JSON content such as the zone-file export.
func (t *Transport) doText(ctx context.Context, method, path string, query map[string]any) (string, error) {
	raw, err := t.do(ctx, method, path, query, nil)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
