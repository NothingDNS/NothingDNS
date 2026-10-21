package main

import "testing"

func TestEffectiveUDPListeners(t *testing.T) {
	cases := []struct {
		name       string
		configured int
		goos       string
		cpus       int
		want       int
	}{
		{"auto, linux 12 cpus", 0, "linux", 12, 4},
		{"auto, linux 4 cpus", 0, "linux", 4, 4},
		{"auto, linux 2 cpus", 0, "linux", 2, 1},
		{"auto, darwin", 0, "darwin", 12, 1},
		{"auto, windows", 0, "windows", 12, 1},
		{"explicit 1 forces a single socket", 1, "linux", 12, 1},
		{"explicit 8 is honoured", 8, "linux", 12, 8},
		{"explicit 2 on few cpus", 2, "linux", 1, 2},
		{"negative treated as auto", -3, "linux", 8, 4},
	}
	for _, tc := range cases {
		if got := effectiveUDPListeners(tc.configured, tc.goos, tc.cpus); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}
