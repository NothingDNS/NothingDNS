package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/propagation"
)

// newTestTracer returns a tracer with tracing enabled, no OTLP endpoint
// (in-memory recorder), and full sampling.
func newTestTracer() *Tracer {
	return NewTracer(Config{Enabled: true, SampleRate: 1.0})
}

// --- Span lifecycle ---

func TestStartEndSpan(t *testing.T) {
	tr := newTestTracer()
	defer func() { _ = tr.Shutdown(context.Background()) }()

	ctx, span := tr.StartSpan(context.Background(), "op")
	if span == nil {
		t.Fatal("expected non-nil span when tracing enabled")
	}
	if span.Name != "op" {
		t.Errorf("span name = %q, want %q", span.Name, "op")
	}
	if span.TraceID == ([16]byte{}) || span.SpanID == ([8]byte{}) {
		t.Error("expected non-zero trace/span IDs")
	}
	if len(ctx.Value(spanKey).(*Span).Attrs) != 0 {
		t.Error("expected clean span in context")
	}

	span.Attrs = append(span.Attrs, Attr{Key: "k", Value: "v"})
	tr.EndSpan(span, nil)

	spans := tr.Export()
	if len(spans) != 1 {
		t.Fatalf("Export() after end = %d spans, want 1", len(spans))
	}
	got := spans[0]
	if got.Name != "op" {
		t.Errorf("exported name = %q", got.Name)
	}
	var found bool
	for _, a := range got.Attrs {
		if a.Key == "k" && a.Value == "v" {
			found = true
		}
	}
	if !found {
		t.Errorf("attribute added between Start/End not exported: %v", got.Attrs)
	}
	if got.EndTime.IsZero() {
		t.Error("expected end time set")
	}
}

func TestEndSpanIdempotent(t *testing.T) {
	tr := newTestTracer()
	defer func() { _ = tr.Shutdown(context.Background()) }()

	_, span := tr.StartSpan(context.Background(), "op")
	tr.EndSpan(span, nil)
	tr.EndSpan(span, nil) // second call must not double-export

	if got := len(tr.Export()); got != 1 {
		t.Errorf("Export() = %d spans after double EndSpan, want 1", got)
	}
}

func TestDisabledTracerReturnsNilSpan(t *testing.T) {
	tr := NewTracer(Config{Enabled: false})
	defer func() { _ = tr.Shutdown(context.Background()) }()

	ctx, span := tr.StartSpan(context.Background(), "op")
	if span != nil {
		t.Error("expected nil span when tracing disabled")
	}
	if ctx == nil {
		t.Error("expected non-nil context")
	}
}

func TestNilTracerSafe(t *testing.T) {
	var tr *Tracer
	ctx, span := tr.StartSpan(context.Background(), "op")
	if span != nil || ctx == nil {
		t.Error("nil Tracer must behave like disabled")
	}
	tr.EndSpan(nil, nil)     // must not panic
	_ = tr.Shutdown(context.Background())
}

func TestErrorRecorded(t *testing.T) {
	tr := newTestTracer()
	defer func() { _ = tr.Shutdown(context.Background()) }()

	_, span := tr.StartSpan(context.Background(), "fail")
	tr.EndSpan(span, context.DeadlineExceeded)

	spans := tr.Export()
	if len(spans) != 1 {
		t.Fatalf("Export() = %d spans, want 1", len(spans))
	}
	// Err is facade-side state that the SDK round-trip cannot preserve; the
	// observable contract is the error attribute set by EndSpan.
	var hasError bool
	for _, a := range spans[0].Attrs {
		if a.Key == "error" && a.Value == true {
			hasError = true
		}
	}
	if !hasError {
		t.Errorf("EndSpan(err) did not set error=true attribute: %v", spans[0].Attrs)
	}
}

// --- Sampling ---

func TestSampleRateZeroDropsAll(t *testing.T) {
	tr := NewTracer(Config{Enabled: true, SampleRate: 0.000001})
	defer func() { _ = tr.Shutdown(context.Background()) }()

	for i := 0; i < 200; i++ {
		if _, span := tr.StartSpan(context.Background(), "op"); span != nil {
			t.Fatalf("near-zero sample rate returned a span at iteration %d", i)
		}
	}
}

func TestSampleRateOneKeepsAll(t *testing.T) {
	tr := newTestTracer()
	defer func() { _ = tr.Shutdown(context.Background()) }()

	for i := 0; i < 50; i++ {
		_, span := tr.StartSpan(context.Background(), "op")
		if span == nil {
			t.Fatalf("sample rate 1.0 dropped a span at iteration %d", i)
		}
		tr.EndSpan(span, nil)
	}
	if got := len(tr.Export()); got != 50 {
		t.Errorf("Export() = %d spans, want 50", got)
	}
}

func TestSampleRateFractional(t *testing.T) {
	tr := NewTracer(Config{Enabled: true, SampleRate: 0.5})
	defer func() { _ = tr.Shutdown(context.Background()) }()

	kept, total := 0, 2000
	for i := 0; i < total; i++ {
		if _, span := tr.StartSpan(context.Background(), "op"); span != nil {
			kept++
			tr.EndSpan(span, nil)
		}
	}
	// 0.5 across 2000 fresh trace IDs should land near half — the SDK's
	// TraceIDRatioBased hashes the trace ID deterministically. Accept a
	// generous band to avoid flakiness; the assertion that matters is
	// "neither everything nor nothing".
	if kept < total/4 || kept > total*3/4 {
		t.Errorf("sample rate 0.5 kept %d/%d spans — not a real probability", kept, total)
	}
}

// --- Parent/child via context ---

func TestChildInheritsTraceID(t *testing.T) {
	tr := newTestTracer()
	defer func() { _ = tr.Shutdown(context.Background()) }()

	ctx, parent := tr.StartSpan(context.Background(), "parent")
	_, child := tr.StartSpan(ctx, "child")
	if child.TraceID != parent.TraceID {
		t.Errorf("child trace ID %x != parent %x (distributed trace broken)",
			child.TraceID, parent.TraceID)
	}
	if child.ParentID != parent.SpanID {
		t.Errorf("child parent ID %x != parent span ID %x", child.ParentID, parent.SpanID)
	}
	tr.EndSpan(child, nil)
	tr.EndSpan(parent, nil)

	spans := tr.Export()
	if len(spans) != 2 {
		t.Fatalf("Export() = %d spans, want 2", len(spans))
	}
	if spans[0].TraceID != spans[1].TraceID {
		t.Error("exported parent and child have different trace IDs")
	}
}

// --- W3C TraceContext propagation ---

func TestW3CPropagationRoundTrip(t *testing.T) {
	tr := newTestTracer()
	defer func() { _ = tr.Shutdown(context.Background()) }()

	// Server side: extract from inbound headers.
	inbound := http.Header{}
	inbound.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	r := httptest.NewRequest("GET", "/api/v1/zones", nil)
	r.Header = inbound
	w := httptest.NewRecorder()

	var seenTraceID [16]byte
	captured := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if span := SpanFromContext(r.Context()); span != nil {
			seenTraceID = span.TraceID
			captured = true
		}
		w.WriteHeader(http.StatusOK)
	})

	Middleware(tr)(next).ServeHTTP(w, r)

	if !captured {
		t.Fatal("middleware did not put a span in the request context")
	}
	want := [16]byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36}
	if seenTraceID != want {
		t.Errorf("server span did not join inbound W3C trace: got %x want %x",
			seenTraceID, want)
	}
}

func TestMiddlewareInjectsOutboundContext(t *testing.T) {
	tr := newTestTracer()
	defer func() { _ = tr.Shutdown(context.Background()) }()

	r := httptest.NewRequest("GET", "/api/v1/cache/stats", nil)
	w := httptest.NewRecorder()

	var injected string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate an outbound call made while handling the request: the
		// middleware injected the server span's context into the request
		// headers, which an http.Client would propagate onward.
		injected = r.Header.Get("traceparent")
		w.WriteHeader(http.StatusOK)
	})

	Middleware(tr)(next).ServeHTTP(w, r)

	if injected == "" {
		t.Fatal("middleware did not inject traceparent for downstream propagation")
	}
	if !strings.HasPrefix(injected, "00-") {
		t.Errorf("injected traceparent %q is not W3C format", injected)
	}
}

func TestMiddlewareDisabledPassthrough(t *testing.T) {
	tr := NewTracer(Config{Enabled: false})
	defer func() { _ = tr.Shutdown(context.Background()) }()

	r := httptest.NewRequest("GET", "/api/v1/zones", nil)
	w := httptest.NewRecorder()
	called := false
	Middleware(tr)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(w, r)

	if !called {
		t.Error("disabled tracer must pass requests through")
	}
}

// --- Span name cardinality bounding (spanPath) ---

func TestSpanPathBoundedCardinality(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/", "/"},
		{"/api/v1/zones", "/api/v1/zones"},
		{"/api/v1/zones/example.com./records/www/A", "/api/v1/zones/*"},
		// Exactly three segments with a dynamic third → masked as :id
		{"/api/zones/12345", "/api/zones/:id"},
		{"/api/zones/550e8400e29b41d4a716446655440000", "/api/zones/:id"},
		// Two segments: no third segment to mask, path kept verbatim
		{"/zones/12345", "/zones/12345"},
		// Four or more segments → truncated to three + /*
		{"/api/v1/zones/12345", "/api/v1/zones/*"},
		{"/metrics", "/metrics"},
	}
	for _, c := range cases {
		if got := spanPath(c.in); got != c.want {
			t.Errorf("spanPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMiddlewareSpanNameBounded(t *testing.T) {
	tr := newTestTracer()
	defer func() { _ = tr.Shutdown(context.Background()) }()

	for _, path := range []string{
		"/api/v1/zones/example.com./records/www/A",
		"/api/v1/zones/other.test./records/mail/MX",
	} {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		Middleware(tr)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)
	}

	spans := tr.Export()
	if len(spans) != 2 {
		t.Fatalf("Export() = %d spans, want 2", len(spans))
	}
	if spans[0].Name != spans[1].Name {
		t.Errorf("dynamic paths produced distinct span names: %q vs %q",
			spans[0].Name, spans[1].Name)
	}
	if !strings.HasPrefix(spans[0].Name, "GET /api/v1/zones/*") {
		t.Errorf("span name %q not bounded", spans[0].Name)
	}
}

// --- Retention bounding ---

func TestRecorderRetentionBounded(t *testing.T) {
	tr := newTestTracer()
	defer func() { _ = tr.Shutdown(context.Background()) }()

	for i := 0; i < maxRetainedSpans+500; i++ {
		_, span := tr.StartSpan(context.Background(), "op")
		tr.EndSpan(span, nil)
	}
	spans := tr.Export()
	if len(spans) != maxRetainedSpans {
		t.Errorf("retained %d spans, want cap %d", len(spans), maxRetainedSpans)
	}
	if tr.DroppedSpans() != 500 {
		t.Errorf("DroppedSpans() = %d, want 500", tr.DroppedSpans())
	}
}

// --- TraceLevel ---

func TestTraceLevelRoundTrip(t *testing.T) {
	for _, want := range []TraceLevel{LevelNone, LevelBasic, LevelDetailed, LevelVerbose} {
		var got TraceLevel
		if err := got.UnmarshalText([]byte(want.String())); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", want.String(), err)
		}
		if got != want {
			t.Errorf("round trip %q -> %d, want %d", want.String(), got, want)
		}
	}
	var l TraceLevel
	if err := l.UnmarshalText([]byte("nope")); err == nil {
		t.Error("expected error for unknown level")
	}
}

// --- Span options ---

func TestSpanOptions(t *testing.T) {
	tr := newTestTracer()
	defer func() { _ = tr.Shutdown(context.Background()) }()

	_, span := tr.StartSpan(context.Background(), "op",
		WithAttr("req.id", "abc"),
		WithLevel(LevelDetailed),
	)
	if span.Level != LevelDetailed {
		t.Errorf("WithLevel not applied: %v", span.Level)
	}
	var found bool
	for _, a := range span.Attrs {
		if a.Key == "req.id" && a.Value == "abc" {
			found = true
		}
	}
	if !found {
		t.Error("WithAttr not applied")
	}
	tr.EndSpan(span, nil)
}

// --- Remote parent context (NewSpanContext) ---

func TestNewSpanContextRemoteParent(t *testing.T) {
	tr := newTestTracer()
	defer func() { _ = tr.Shutdown(context.Background()) }()

	var traceID [16]byte
	for i := range traceID {
		traceID[i] = byte(i + 1)
	}
	var parentID [8]byte
	for i := range parentID {
		parentID[i] = byte(0xA0 + i)
	}

	ctx := NewSpanContext(traceID, parentID)
	_, span := tr.StartSpan(ctx, "child")

	if span.TraceID != traceID {
		t.Errorf("child trace ID %x != remote parent %x", span.TraceID, traceID)
	}
	if span.ParentID != parentID {
		t.Errorf("child parent ID %x != remote parent %x", span.ParentID, parentID)
	}
	tr.EndSpan(span, nil)
}

// --- Attribute type mapping ---

func TestToKeyValueTypes(t *testing.T) {
	cases := []struct {
		attr Attr
		want string // attribute.Value type name suffix
	}{
		{Attr{"s", "x"}, "STRING"},
		{Attr{"b", true}, "BOOL"},
		{Attr{"i", 42}, "INT64"},
		{Attr{"f", 1.5}, "FLOAT64"},
		{Attr{"u", uint16(7)}, "INT64"},
		{Attr{"x", []byte{1, 2}}, "BYTESLICE"},
	}
	for _, c := range cases {
		kv := toKeyValue(c.attr)
		got := kv.Value.Type().String()
		if got != c.want {
			t.Errorf("toKeyValue(%v) type = %s, want %s", c.attr.Value, got, c.want)
		}
	}
}

// --- Propagator is W3C TraceContext ---

func TestGlobalPropagatorIsW3C(t *testing.T) {
	_ = newTestTracer() // sets the global propagator
	p := otelPropagator()
	_, ok := p.(propagation.TraceContext)
	if !ok {
		t.Errorf("global propagator is %T, want propagation.TraceContext", p)
	}
}

// --- Middleware concurrency safety ---

func TestMiddlewareConcurrent(t *testing.T) {
	tr := newTestTracer()
	defer func() { _ = tr.Shutdown(context.Background()) }()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("GET", "/api/v1/zones", nil)
			w := httptest.NewRecorder()
			Middleware(tr)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)
		}()
	}
	wg.Wait()
}
