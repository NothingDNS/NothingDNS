package otel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// JaegerExporter tests
// ---------------------------------------------------------------------------

func TestNewJaegerExporter(t *testing.T) {
	e := NewJaegerExporter("http://localhost:14268")
	if e == nil {
		t.Fatal("NewJaegerExporter returned nil")
	}
	if e.endpoint != "http://localhost:14268" {
		t.Errorf("endpoint = %s, want http://localhost:14268", e.endpoint)
	}
	if e.client == nil {
		t.Error("client should be initialized")
	}
	if e.stopCh == nil {
		t.Error("stopCh should be initialized")
	}
	defer e.Close()
}

func TestJaegerExporter_ExportAndFlush(t *testing.T) {
	var receivedData []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedData = body
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	e := NewJaegerExporter(srv.URL)
	defer e.Close()

	span := &Span{
		TraceID:   [16]byte{1, 2, 3, 4},
		SpanID:    [8]byte{5, 6, 7, 8},
		Name:      "test-span",
		StartTime: time.Now(),
		EndTime:   time.Now().Add(100 * time.Millisecond),
	}

	e.Export(span)
	e.Flush()

	if len(receivedData) == 0 {
		t.Fatal("expected Jaeger to receive span data")
	}

	var decoded []*Span
	if err := json.Unmarshal(receivedData, &decoded); err != nil {
		t.Fatalf("expected valid JSON, got error: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected 1 span, got %d", len(decoded))
	}
	if decoded[0].Name != "test-span" {
		t.Errorf("expected span name 'test-span', got %s", decoded[0].Name)
	}
}

func TestJaegerExporter_FlushEmptyBatch(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := NewJaegerExporter(srv.URL)
	defer e.Close()

	e.Flush()

	if called {
		t.Error("Flush should not call server with empty batch")
	}
}

func TestJaegerExporter_FlushServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	e := NewJaegerExporter(srv.URL)
	defer e.Close()

	span := &Span{
		TraceID: [16]byte{1},
		SpanID:  [8]byte{2},
		Name:    "test",
	}
	e.Export(span)

	// Should not panic on server error
	e.Flush()
}

func TestJaegerExporter_ExportMultipleSpans(t *testing.T) {
	var receivedData []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedData = body
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	e := NewJaegerExporter(srv.URL)
	defer e.Close()

	for i := 0; i < 5; i++ {
		e.Export(&Span{
			TraceID: [16]byte{byte(i)},
			SpanID:  [8]byte{byte(i)},
			Name:    "span",
		})
	}

	e.Flush()

	var decoded []*Span
	if err := json.Unmarshal(receivedData, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(decoded) != 5 {
		t.Errorf("expected 5 spans, got %d", len(decoded))
	}
}

func TestJaegerExporter_Close(t *testing.T) {
	e := NewJaegerExporter("http://localhost:14268")

	done := make(chan struct{})
	go func() {
		e.Close()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked for too long")
	}
}

func TestJaegerExporter_BatchFlusherPeriodic(t *testing.T) {
	flushCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flushCount++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	e := NewJaegerExporter(srv.URL)
	e.ticker.Stop()
	e.ticker = time.NewTicker(50 * time.Millisecond)
	defer e.Close()

	e.Export(&Span{TraceID: [16]byte{1}, SpanID: [8]byte{2}, Name: "test"})

	time.Sleep(150 * time.Millisecond)

	if flushCount == 0 {
		t.Error("expected periodic flush to fire")
	}
}

// ---------------------------------------------------------------------------
// TraceLevel UnmarshalText edge cases
// ---------------------------------------------------------------------------

func TestTraceLevel_UnmarshalText_AllLevels(t *testing.T) {
	tests := []struct {
		input string
		want  TraceLevel
	}{
		{"none", LevelNone},
		{"basic", LevelBasic},
		{"detailed", LevelDetailed},
		{"verbose", LevelVerbose},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var level TraceLevel
			if err := level.UnmarshalText([]byte(tt.input)); err != nil {
				t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
			}
			if level != tt.want {
				t.Errorf("got %v, want %v", level, tt.want)
			}
		})
	}
}

func TestTraceLevel_UnmarshalText_Unknown(t *testing.T) {
	var level TraceLevel
	err := level.UnmarshalText([]byte("unknown"))
	if err == nil {
		t.Error("expected error for unknown level")
	}
	if !strings.Contains(err.Error(), "unknown trace level") {
		t.Errorf("error should mention 'unknown trace level', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// WithLevel option
// ---------------------------------------------------------------------------

func TestWithLevel(t *testing.T) {
	tracer := NewTracer(Config{Enabled: true})
	_, span := tracer.StartSpan(context.Background(), "test-op", WithLevel(LevelVerbose))

	if span.Level != LevelVerbose {
		t.Errorf("expected LevelVerbose, got %v", span.Level)
	}
	tracer.EndSpan(span, nil)
}

// ---------------------------------------------------------------------------
// NewSpanContext
// ---------------------------------------------------------------------------

func TestNewSpanContext(t *testing.T) {
	traceID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8}
	spanID := [8]byte{10, 20, 30, 40}

	ctx := NewSpanContext(traceID, spanID)

	span := SpanFromContext(ctx)
	if span == nil {
		t.Fatal("expected span in context")
	}
	if span.TraceID != traceID {
		t.Errorf("TraceID mismatch")
	}
	if span.SpanID != spanID {
		t.Errorf("SpanID mismatch")
	}
}

func TestNewSpanContext_EmptyIDs(t *testing.T) {
	ctx := NewSpanContext([16]byte{}, [8]byte{})

	span := SpanFromContext(ctx)
	if span == nil {
		t.Fatal("expected span even with zero IDs")
	}
}

// ---------------------------------------------------------------------------
// OTLP Exporter sendPayload error handling
// ---------------------------------------------------------------------------

func TestOTLPExporter_SendPayload_BadEndpoint(t *testing.T) {
	e := NewOTLPExporter(ExporterConfig{
		Endpoint:     "http://localhost:1",
		BatchSize:    10,
		BatchTimeout: time.Second,
	})
	defer e.Close()

	span := &Span{
		TraceID:   [16]byte{1},
		SpanID:    [8]byte{2},
		Name:      "test",
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}

	e.Export(span)

	// Flush to trigger send — should not panic even with unreachable endpoint
	e.Flush()
}
