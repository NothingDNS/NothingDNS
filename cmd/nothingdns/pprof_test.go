package main

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestStartPprofServesAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	addr, err := startPprof(ctx, "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + addr.String() + "/debug/pprof/"
	resp, err := http.Get(url + "heap?debug=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(body) == 0 {
		t.Fatalf("heap profile: status=%d len=%d", resp.StatusCode, len(body))
	}
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := http.Get(url); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("listener still serving after context cancel")
}
