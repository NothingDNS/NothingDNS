package config

import (
	"testing"
	"time"
)

// F675: a NUL byte inside a flow sequence made the tokenizer yield empty
// scalars forever (readScalar stops at NUL without advancing and peek reports
// end of input as 0), so UnmarshalYAML never returned and grew without bound.
func TestUnmarshalYAML_NULByteDoesNotHang(t *testing.T) {
	for _, in := range []string{"a: [\x00]\n", "a: [1,\x00", "A:\n [\x10\x00\xc5\xf5\f\xb4:", "\x00", "a: 1\n\x00"} {
		done := make(chan error, 1)
		go func() { _, err := UnmarshalYAML(in); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%q: NUL byte accepted", in)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%q: UnmarshalYAML did not return", in)
		}
	}
}
