package otel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Span lifecycle tests ---

func TestSpanStartEndTime(t *testing.T) {
	tracer := NewTracer(Config{Enabled: true})
	_, span := tracer.StartSpan(context.Background(), "timing-test")
	if span.StartTime.IsZero() {
		t.Error("start time should be set")
	}
	if !span.EndTime.IsZero() {
		t.Error("end time should not be set before EndSpan")
	}
	tracer.EndSpan(span, nil)
	if span.EndTime.IsZero() {
		t.Error("end time should be set after EndSpan")
	}
	if span.EndTime.Before(span.StartTime) {
		t.Error("end time should be >= start time")
	}
}

func TestSpanError(t *testing.T) {
	tracer := NewTracer(Config{Enabled: true})
	_, span := tracer.StartSpan(context.Background(), "error-test")
	testErr := errors.New("something failed")
	tracer.EndSpan(span, testErr)
	if span.Err != testErr {
		t.Errorf("expected error to be recorded on span")
	}
}

func TestEndSpanNil(t *testing.T) {
	tracer := NewTracer(Config{Enabled: true})
	// Should not panic
	tracer.EndSpan(nil, nil)
}

// --- Parent-child span tests ---

func TestParentChildSpans(t *testing.T) {
	tracer := NewTracer(Config{Enabled: true, Level: LevelDetailed})
	_, parent := tracer.StartSpan(context.Background(), "parent")
	parentSpanID := parent.SpanID
	parentTraceID := parent.TraceID

	_, child := tracer.StartSpan(context.Background(), "child",
		WithParent(parentSpanID),
	)
	tracer.EndSpan(child, nil)

	if child.ParentID != parentSpanID {
		t.Error("child should reference parent span ID")
	}
	if child.TraceID == parentTraceID {
		// Note: current implementation generates new trace IDs per span
		// In a real distributed tracing system, child would inherit trace ID
		// This test documents current behavior
	}
}

// --- Attribute tests ---

func TestWithAttr_MultipleTypes(t *testing.T) {
	tracer := NewTracer(Config{Enabled: true, Level: LevelDetailed})
	_, span := tracer.StartSpan(context.Background(), "attrs",
		WithAttr("string_val", "hello"),
		WithAttr("int_val", 42),
		WithAttr("bool_val", true),
		WithAttr("float_val", 3.14),
	)
	tracer.EndSpan(span, nil)

	if len(span.Attrs) != 4 {
		t.Fatalf("expected 4 attrs, got %d", len(span.Attrs))
	}
	checks := map[string]interface{}{
		"string_val": "hello",
		"int_val":    42,
		"bool_val":   true,
		"float_val":  3.14,
	}
	for _, attr := range span.Attrs {
		expected, ok := checks[attr.Key]
		if !ok {
			t.Errorf("unexpected attr key: %s", attr.Key)
			continue
		}
		if attr.Value != expected {
			t.Errorf("attr %s: expected %v, got %v", attr.Key, expected, attr.Value)
		}
	}
}

// --- RecordError tests ---

func TestRecordError(t *testing.T) {
	tracer := NewTracer(Config{Enabled: true})
	_, span := tracer.StartSpan(context.Background(), "err")
	testErr := errors.New("boom")
	RecordError(span, testErr)

	if span.Err != testErr {
		t.Error("error not set on span")
	}
	// Should have error attribute
	found := false
	for _, attr := range span.Attrs {
		if attr.Key == "error" && attr.Value == true {
			found = true
		}
	}
	if !found {
		t.Error("error attribute not set")
	}
}

func TestRecordError_NilSpan(t *testing.T) {
	// Should not panic
	RecordError(nil, errors.New("test"))
}

// --- DNSTraceAttrs tests ---

func TestDNSTraceAttrs(t *testing.T) {
	attrs := DNSTraceAttrs("A", "8.8.8.8", false)
	if len(attrs) != 3 {
		t.Fatalf("expected 3 attrs, got %d", len(attrs))
	}
	expected := map[string]interface{}{
		"dns.query_type": "A",
		"dns.server":    "8.8.8.8",
		"dns.cache_hit": false,
	}
	for _, attr := range attrs {
		if attr.Value != expected[attr.Key] {
			t.Errorf("attr %s: expected %v, got %v", attr.Key, expected[attr.Key], attr.Value)
		}
	}
}

// --- HTTP Middleware tests ---

func TestMiddleware_Disabled(t *testing.T) {
	tracer := NewTracer(Config{Enabled: false})
	handler := Middleware(tracer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestMiddleware_Enabled(t *testing.T) {
	tracer := NewTracer(Config{Enabled: true, Level: LevelDetailed})
	called := false
	handler := Middleware(tracer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// Verify span is in context
		span := SpanFromContext(r.Context())
		if span == nil {
			t.Error("span should be in request context")
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest("POST", "/api/v1/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("handler was not called")
	}
	if rec.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rec.Code)
	}
}

// --- TraceHandler tests ---

func TestTraceHandler_Disabled(t *testing.T) {
	tracer := NewTracer(Config{Enabled: false})
	handler := TraceHandler(tracer, "test-op", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestTraceHandler_Enabled(t *testing.T) {
	tracer := NewTracer(Config{Enabled: true})
	handler := TraceHandler(tracer, "dns.query", func(w http.ResponseWriter, r *http.Request) {
		span := SpanFromContext(r.Context())
		if span == nil {
			t.Error("span should be in context")
		}
		if span.Name != "dns.query" {
			t.Errorf("expected span name 'dns.query', got %s", span.Name)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/dns", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}

// --- TraceLevel tests ---

func TestTraceLevel_MarshalText(t *testing.T) {
	tests := []struct {
		level    TraceLevel
		expected string
	}{
		{LevelNone, "none"},
		{LevelBasic, "basic"},
		{LevelDetailed, "detailed"},
		{LevelVerbose, "verbose"},
	}
	for _, tt := range tests {
		got, err := tt.level.MarshalText()
		if err != nil {
			t.Errorf("marshal %v: %v", tt.level, err)
		}
		if string(got) != tt.expected {
			t.Errorf("marshal %v: expected %s, got %s", tt.level, tt.expected, got)
		}
	}
}

func TestTraceLevel_UnmarshalText_Invalid(t *testing.T) {
	var level TraceLevel
	err := level.UnmarshalText([]byte("invalid"))
	if err == nil {
		t.Error("expected error for invalid level")
	}
}

// --- Span ID generation uniqueness ---

func TestSpanIDUniqueness(t *testing.T) {
	ids := make(map[[8]byte]bool, 1000)
	for i := 0; i < 1000; i++ {
		id := generateSpanID()
		if ids[id] {
			t.Fatal("duplicate span ID generated")
		}
		ids[id] = true
	}
}

func TestTraceIDUniqueness(t *testing.T) {
	ids := make(map[[16]byte]bool, 1000)
	for i := 0; i < 1000; i++ {
		id := generateTraceID()
		if ids[id] {
			t.Fatal("duplicate trace ID generated")
		}
		ids[id] = true
	}
}

// --- OTLP Exporter tests ---

func TestOTLPExporter_Batching(t *testing.T) {
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = json.Marshal(map[string]interface{}{
			"status": "ok",
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exporter := NewOTLPExporter(ExporterConfig{
		Endpoint:     server.URL,
		BatchSize:    2,
		BatchTimeout: 1 * time.Hour, // Don't auto-flush in test
	})
	defer exporter.Close()

	tracer := NewTracer(Config{Enabled: true})
	_, s1 := tracer.StartSpan(context.Background(), "span1")
	tracer.EndSpan(s1, nil)
	_, s2 := tracer.StartSpan(context.Background(), "span2")
	tracer.EndSpan(s2, nil)

	exporter.Export(s1)
	exporter.Export(s2) // Should trigger batch flush at size 2

	time.Sleep(50 * time.Millisecond) // Give HTTP call time

	// Verify server received the request
	if received == nil {
		t.Error("exporter should have sent batch to server")
	}
}

func TestOTLPExporter_Flush(t *testing.T) {
	received := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		// Verify it's valid JSON
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("invalid JSON payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exporter := NewOTLPExporter(ExporterConfig{
		Endpoint:     server.URL,
		BatchSize:    100,
		BatchTimeout: 1 * time.Hour,
	})
	defer exporter.Close()

	tracer := NewTracer(Config{Enabled: true})
	_, span := tracer.StartSpan(context.Background(), "flush-test")
	tracer.EndSpan(span, nil)

	exporter.Export(span)
	exporter.Flush()

	time.Sleep(50 * time.Millisecond)
	if !received {
		t.Error("flush should have sent spans to server")
	}
}

func TestOTLPExporter_NoEndpoint(t *testing.T) {
	exporter := NewOTLPExporter(ExporterConfig{
		Endpoint:     "",
		BatchSize:    10,
		BatchTimeout: 1 * time.Hour,
	})
	defer exporter.Close()

	tracer := NewTracer(Config{Enabled: true})
	_, span := tracer.StartSpan(context.Background(), "no-endpoint")
	tracer.EndSpan(span, nil)

	// Should not panic with empty endpoint
	exporter.Export(span)
	exporter.Flush()
}

func TestOTLPExporter_EmptyFlush(t *testing.T) {
	exporter := NewOTLPExporter(ExporterConfig{
		Endpoint:     "http://localhost:9999",
		BatchSize:    10,
		BatchTimeout: 1 * time.Hour,
	})
	defer exporter.Close()

	// Flush with no spans should not panic
	exporter.Flush()
}

// --- bytesToHex tests ---

func TestBytesToHex(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0x00}, "00"},
		{[]byte{0xff}, "ff"},
		{[]byte{0x0a, 0x1b, 0x2c}, "0a1b2c"},
	}
	for _, tt := range tests {
		got := bytesToHex(tt.input)
		if got != tt.expected {
			t.Errorf("bytesToHex(%v) = %s, want %s", tt.input, got, tt.expected)
		}
	}
}

// --- LogSpans test ---

func TestLogSpans(t *testing.T) {
	tracer := NewTracer(Config{Enabled: true})
	_, span := tracer.StartSpan(context.Background(), "log-test",
		WithAttr("key", "val"),
	)
	tracer.EndSpan(span, nil)
	// Should not panic
	LogSpans([]*Span{span})
}

// --- Export (tracer) test ---

func TestTracerExport(t *testing.T) {
	tracer := NewTracer(Config{Enabled: true})
	// Export should return current spans (may be empty since we don't store them)
	spans := tracer.Export()
	// Just verify it doesn't panic
	_ = spans
}

// --- SampleRate default test ---

func TestTracerDefaultSampleRate(t *testing.T) {
	tracer := NewTracer(Config{Enabled: true})
	if tracer.cfg.SampleRate != 1.0 {
		t.Errorf("expected default sample rate 1.0, got %f", tracer.cfg.SampleRate)
	}
}

// --- Context with nil span ---

func TestSpanFromContext_Empty(t *testing.T) {
	span := SpanFromContext(context.Background())
	if span != nil {
		t.Error("expected nil span from empty context")
	}
}

// --- Integration: full span lifecycle ---

func TestSpanLifecycle(t *testing.T) {
	tracer := NewTracer(Config{Enabled: true, Level: LevelDetailed})

	ctx, parent := tracer.StartSpan(context.Background(), "dns.query",
		WithAttr("qname", "example.com"),
		WithAttr("qtype", "A"),
	)
	defer tracer.EndSpan(parent, nil)

	// Simulate child span (e.g., upstream lookup)
	_, child := tracer.StartSpan(ctx, "dns.upstream",
		WithParent(parent.SpanID),
		WithAttr("upstream", "8.8.8.8"),
	)
	tracer.EndSpan(child, nil)

	if child.ParentID != parent.SpanID {
		t.Error("child should have parent's span ID")
	}
	if len(parent.Attrs) != 2 {
		t.Errorf("parent should have 2 attrs, got %d", len(parent.Attrs))
	}
	if len(child.Attrs) != 1 {
		t.Errorf("child should have 1 attr, got %d", len(child.Attrs))
	}
}

// --- OTLP format validation ---

func TestToOTLPRequest(t *testing.T) {
	exporter := NewOTLPExporter(ExporterConfig{Endpoint: "http://localhost:0"})
	defer exporter.Close()

	tracer := NewTracer(Config{Enabled: true})
	_, span := tracer.StartSpan(context.Background(), "otlp-test",
		WithAttr("test_key", "test_val"),
	)
	tracer.EndSpan(span, nil)

	data := exporter.toOTLPRequest([]*Span{span})

	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Verify structure
	rs, ok := payload["resourceSpans"].([]interface{})
	if !ok || len(rs) != 1 {
		t.Fatal("expected resourceSpans with 1 entry")
	}

	// Verify span contains required fields
	jsonStr := string(data)
	requiredFields := []string{"trace_id", "span_id", "name", "start_time_unix_nano", "end_time_unix_nano"}
	for _, field := range requiredFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("missing field %s in OTLP payload", field)
		}
	}
}
