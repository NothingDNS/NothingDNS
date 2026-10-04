package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestRecordUpdateHelpProducesValidCommand(t *testing.T) {
	help := captureStdout(t, func() {
		if code := printCommandHelp("record"); code != 0 {
			t.Fatalf("help exit %d", code)
		}
	})
	values := map[string]string{"<zone>": "example.test", "<name>": "www", "<type>": "A", "<old_data>": "192.0.2.1", "<new_data>": "192.0.2.2", "[ttl]": "600", "<rdata>": "192.0.2.2"}
	var args []string
	for _, line := range strings.Split(help, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "update" {
			continue
		}
		args = []string{"update"}
		for _, field := range fields[1:] {
			value, ok := values[field]
			if !ok {
				break
			}
			args = append(args, value)
		}
	}
	if args == nil {
		t.Fatal("record update missing from help")
	}
	called := false
	withAPIMock(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/zones/example.test/records" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["old_data"] != "192.0.2.1" || body["data"] != "192.0.2.2" || body["ttl"] != float64(600) {
			t.Errorf("update body=%v", body)
		}
		return jsonResponse(r, http.StatusOK, `{}`), nil
	}))
	if err := cmdRecord(args); err != nil {
		t.Fatalf("advertised syntax %v rejected: %v", args, err)
	}
	if !called {
		t.Fatal("advertised command did not reach API")
	}
}
