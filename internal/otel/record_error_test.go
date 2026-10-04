package otel

import (
	"context"
	"errors"
	"testing"
)

func TestEndSpanPreservesRecordedError(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	tr := newTestTracer()
	defer tr.Shutdown(context.Background())
	recorded := errors.New("recorded")
	completed := errors.New("completed")
	for _, tc := range []struct {
		name                   string
		record, complete, want error
	}{
		{"preserve", recorded, nil, recorded},
		{"override", recorded, completed, completed},
		{"success", nil, nil, nil},
		{"explicit", nil, completed, completed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, span := tr.StartSpan(context.Background(), tc.name)
			if tc.record != nil {
				RecordError(span, tc.record)
			}
			tr.EndSpan(span, tc.complete)
			tr.EndSpan(span, errors.New("late error"))
			if span.Err != tc.want {
				t.Fatalf("error=%v, want %v", span.Err, tc.want)
			}
			spans := tr.Export()
			if len(spans) != 1 {
				t.Fatalf("exported=%d, want 1", len(spans))
			}
			hasError := false
			for _, attr := range spans[0].Attrs {
				if attr.Key == "error" && attr.Value == true {
					hasError = true
				}
			}
			if hasError != (tc.want != nil) {
				t.Fatalf("error attribute=%v, want %v", hasError, tc.want != nil)
			}
		})
	}
}
