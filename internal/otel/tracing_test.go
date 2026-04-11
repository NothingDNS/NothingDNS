package otel

import (
	"context"
	"testing"
)

func TestTracerBasic(t *testing.T) {
	cfg := Config{
		Enabled:    true,
		Level:      LevelBasic,
		SampleRate: 1.0,
	}

	tracer := NewTracer(cfg)

	ctx, span := tracer.StartSpan(context.Background(), "test-span")
	if span == nil {
		t.Fatal("span was nil")
	}
	defer tracer.EndSpan(span, nil)

	if span.Name != "test-span" {
		t.Errorf("expected name test-span, got %s", span.Name)
	}

	if span.TraceID == ([16]byte{}) {
		t.Error("trace ID was zero")
	}

	if span.SpanID == ([8]byte{}) {
		t.Error("span ID was zero")
	}

	// Check span is in context
	ctxSpan := SpanFromContext(ctx)
	if ctxSpan != span {
		t.Error("span not found in context")
	}

	tracer.EndSpan(span, nil)

	if span.EndTime.IsZero() {
		t.Error("end time was not set")
	}
}

func TestTracerDisabled(t *testing.T) {
	cfg := Config{
		Enabled: false,
	}

	tracer := NewTracer(cfg)

	_, span := tracer.StartSpan(context.Background(), "test-span")
	if span != nil {
		t.Error("span should be nil when disabled")
	}
}

func TestSpanOptions(t *testing.T) {
	cfg := Config{Enabled: true, Level: LevelDetailed, SampleRate: 1.0}
	tracer := NewTracer(cfg)

	parentID := generateSpanID()
	_, span := tracer.StartSpan(context.Background(), "child",
		WithParent(parentID),
		WithAttr("key1", "value1"),
		WithAttr("key2", 42),
		WithLevel(LevelVerbose),
	)
	defer tracer.EndSpan(span, nil)

	if span.ParentID != parentID {
		t.Errorf("parent ID mismatch")
	}

	if len(span.Attrs) != 2 {
		t.Errorf("expected 2 attrs, got %d", len(span.Attrs))
	}

	if span.Level != LevelVerbose {
		t.Errorf("level should be verbose")
	}
}

func TestTraceLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected TraceLevel
	}{
		{"none", LevelNone},
		{"basic", LevelBasic},
		{"detailed", LevelDetailed},
		{"verbose", LevelVerbose},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var level TraceLevel
			err := level.UnmarshalText([]byte(tt.input))
			if err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if level != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, level)
			}
		})
	}
}

func TestSpanContext(t *testing.T) {
	traceID := generateTraceID()
	spanID := generateSpanID()

	ctx := NewSpanContext(traceID, spanID)
	span := SpanFromContext(ctx)

	if span == nil {
		t.Fatal("span was nil")
	}

	if span.TraceID != traceID {
		t.Errorf("trace ID mismatch")
	}

	if span.SpanID != spanID {
		t.Errorf("span ID mismatch")
	}
}

func BenchmarkTracer(b *testing.B) {
	cfg := Config{Enabled: true, SampleRate: 1.0}
	tracer := NewTracer(cfg)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx2, span := tracer.StartSpan(ctx, "benchmark-span")
		tracer.EndSpan(span, nil)
		_ = ctx2
	}
}
