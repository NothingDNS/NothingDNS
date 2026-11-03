package upstream

import (
	"testing"
	"time"
)

func TestAnycastGroupAddBackendValidatesPortRange(t *testing.T) {
	newGroup := func() *AnycastGroup {
		return NewAnycastGroup("192.0.2.1", time.Second, time.Second)
	}
	for _, tc := range []struct {
		name    string
		port    int
		wantErr bool
	}{
		{name: "default", port: 0},
		{name: "minimum", port: 1},
		{name: "dns", port: 53},
		{name: "maximum", port: 65535},
		{name: "negative", port: -1, wantErr: true},
		{name: "above maximum", port: 65536, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := newGroup().AddBackend(&AnycastBackend{PhysicalIP: "192.0.2.2", Port: tc.port, Weight: 1})
			if (err != nil) != tc.wantErr {
				t.Fatalf("AddBackend() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
