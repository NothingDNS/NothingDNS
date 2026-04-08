package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewAuditLogger_Disabled(t *testing.T) {
	al, err := NewAuditLogger(false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if al.enabled {
		t.Error("logger should be disabled")
	}
}

func TestAuditLogger_LogQuery_Disabled(t *testing.T) {
	al, _ := NewAuditLogger(false, "")
	// Should not panic
	al.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1",
		QueryName: "example.com",
		QueryType: "A",
	})
}

func TestAuditLogger_LogQuery_Stdout(t *testing.T) {
	al, err := NewAuditLogger(true, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer al.Close()

	// Redirect output for testing
	var buf bytes.Buffer
	al.output = &buf

	al.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1",
		QueryName: "example.com",
		QueryType: "A",
		Rcode:     "0",
		Latency:   5 * time.Millisecond,
		CacheHit:  false,
		Upstream:  "8.8.8.8:53",
	})

	output := buf.String()
	if !strings.Contains(output, "client=10.0.0.1") {
		t.Errorf("expected client IP in output, got: %s", output)
	}
	if !strings.Contains(output, "query=example.com") {
		t.Errorf("expected query name in output, got: %s", output)
	}
	if !strings.Contains(output, "type=A") {
		t.Errorf("expected query type in output, got: %s", output)
	}
	if !strings.Contains(output, "cache=miss") {
		t.Errorf("expected cache=miss in output, got: %s", output)
	}
	if !strings.Contains(output, "upstream=8.8.8.8:53") {
		t.Errorf("expected upstream in output, got: %s", output)
	}
}

func TestAuditLogger_LogQuery_CacheHit(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1",
		QueryName: "example.com",
		QueryType: "A",
		Rcode:     "0",
		CacheHit:  true,
	})

	output := buf.String()
	if !strings.Contains(output, "cache=hit") {
		t.Errorf("expected cache=hit in output, got: %s", output)
	}
}

func TestAuditLogger_LogQuery_NoUpstream(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1",
		QueryName: "example.com",
		QueryType: "AAAA",
		Rcode:     "0",
	})

	output := buf.String()
	if !strings.Contains(output, "upstream=-") {
		t.Errorf("expected upstream=- in output, got: %s", output)
	}
}

func TestAuditLogger_LogQuery_FileOutput(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "query.log")

	al, err := NewAuditLogger(true, logFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	al.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1",
		QueryName: "example.com",
		QueryType: "A",
		Rcode:     "0",
		Latency:   1 * time.Millisecond,
	})
	al.Close()

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}

	if !strings.Contains(string(data), "client=10.0.0.1") {
		t.Errorf("expected client IP in file output, got: %s", string(data))
	}
}

func TestAuditLogger_LogQuery_Append(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "query.log")

	al1, _ := NewAuditLogger(true, logFile)
	al1.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		QueryName: "first.example.com",
		QueryType: "A",
		Rcode:     "0",
	})
	al1.Close()

	al2, _ := NewAuditLogger(true, logFile)
	al2.LogQuery(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:01Z",
		QueryName: "second.example.com",
		QueryType: "A",
		Rcode:     "0",
	})
	al2.Close()

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}

	if !strings.Contains(string(data), "first.example.com") {
		t.Error("expected first query in log")
	}
	if !strings.Contains(string(data), "second.example.com") {
		t.Error("expected second query in log")
	}
}

func TestFormatAuditLine(t *testing.T) {
	entry := QueryAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		ClientIP:  "192.168.1.1",
		QueryName: "test.example.com.",
		QueryType: "MX",
		Rcode:     "0",
		Latency:   1234 * time.Microsecond,
		CacheHit:  true,
		Upstream:  "1.1.1.1:53",
	}

	line := formatQueryAuditLine(entry)

	if !strings.Contains(line, "2026-04-02T12:00:00Z") {
		t.Error("expected timestamp in line")
	}
	if !strings.Contains(line, "client=192.168.1.1") {
		t.Error("expected client IP in line")
	}
	if !strings.Contains(line, "type=MX") {
		t.Error("expected MX type in line")
	}
	if !strings.Contains(line, "cache=hit") {
		t.Error("expected cache=hit in line")
	}
	if !strings.Contains(line, "upstream=1.1.1.1:53") {
		t.Error("expected upstream in line")
	}
}

func TestLogAXFR(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogAXFR(AXFRAuditEntry{
		Timestamp:   "2026-04-02T12:00:00Z",
		ClientIP:    "10.0.0.1",
		Zone:        "example.com.",
		Action:      "completed",
		RecordCount: 100,
		Latency:     50 * time.Millisecond,
	})

	line := buf.String()
	if !strings.Contains(line, "zone=example.com.") {
		t.Error("expected zone in line")
	}
	if !strings.Contains(line, "action=completed") {
		t.Error("expected action in line")
	}
	if !strings.Contains(line, "records=100") {
		t.Error("expected record count in line")
	}
}

func TestLogIXFR(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogIXFR(IXFRAuditEntry{
		Timestamp:   "2026-04-02T12:00:00Z",
		ClientIP:    "10.0.0.2",
		Zone:        "test.com.",
		Action:      "request",
		RecordCount: 5,
		Latency:     10 * time.Millisecond,
	})

	line := buf.String()
	if !strings.Contains(line, "zone=test.com.") {
		t.Error("expected zone in line")
	}
}

func TestLogNOTIFY(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogNOTIFY(NOTIFYAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		ClientIP:  "192.168.1.1",
		Zone:      "example.com.",
		Action:    "received",
	})

	line := buf.String()
	if !strings.Contains(line, "zone=example.com.") {
		t.Error("expected zone in line")
	}
	if !strings.Contains(line, "action=received") {
		t.Error("expected action in line")
	}
}

func TestLogUpdate(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogUpdate(UpdateAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		ClientIP:  "10.0.0.3",
		Zone:      "dyn.example.com.",
		Action:    "completed",
		Rcode:     "0",
		Added:     2,
		Deleted:   1,
	})

	line := buf.String()
	if !strings.Contains(line, "zone=dyn.example.com.") {
		t.Error("expected zone in line")
	}
	if !strings.Contains(line, "added=2") {
		t.Error("expected added count in line")
	}
	if !strings.Contains(line, "deleted=1") {
		t.Error("expected deleted count in line")
	}
}

func TestLogReload(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogReload(ReloadAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		Action:    "start",
		Zones:     5,
		Error:     "",
	})

	line := buf.String()
	if !strings.Contains(line, "zones=5") {
		t.Error("expected zones count in line")
	}
}

func TestLogReload_WithError(t *testing.T) {
	al, _ := NewAuditLogger(true, "")
	defer al.Close()

	var buf bytes.Buffer
	al.output = &buf

	al.LogReload(ReloadAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		Action:    "failed",
		Zones:     3,
		Error:     "parse error at line 10",
	})

	line := buf.String()
	if !strings.Contains(line, "error=parse error at line 10") {
		t.Error("expected error in line")
	}
}

func TestFormatAXFRAuditLine(t *testing.T) {
	line := formatAXFRAuditLine(AXFRAuditEntry{
		Timestamp:   "2026-04-02T12:00:00Z",
		ClientIP:    "10.0.0.1",
		Zone:        "example.com.",
		Action:      "completed",
		RecordCount: 100,
		Latency:     50 * time.Millisecond,
	})

	if !strings.Contains(line, "zone=example.com.") {
		t.Error("expected zone in line")
	}
}

func TestFormatIXFRAuditLine(t *testing.T) {
	line := formatIXFRAuditLine(IXFRAuditEntry{
		Timestamp:   "2026-04-02T12:00:00Z",
		ClientIP:    "10.0.0.1",
		Zone:        "example.com.",
		Action:      "request",
		RecordCount: 5,
		Latency:     10 * time.Millisecond,
	})

	if !strings.Contains(line, "zone=example.com.") {
		t.Error("expected zone in line")
	}
}

func TestFormatNOTIFYAuditLine(t *testing.T) {
	line := formatNOTIFYAuditLine(NOTIFYAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		ClientIP:  "192.168.1.1",
		Zone:      "example.com.",
		Action:    "received",
	})

	if !strings.Contains(line, "zone=example.com.") {
		t.Error("expected zone in line")
	}
}

func TestFormatUpdateAuditLine(t *testing.T) {
	line := formatUpdateAuditLine(UpdateAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		ClientIP:  "10.0.0.3",
		Zone:      "dyn.example.com.",
		Action:    "completed",
		Rcode:     "0",
		Added:     2,
		Deleted:   1,
	})

	if !strings.Contains(line, "zone=dyn.example.com.") {
		t.Error("expected zone in line")
	}
}

func TestFormatReloadAuditLine(t *testing.T) {
	line := formatReloadAuditLine(ReloadAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		Action:    "start",
		Zones:     5,
		Error:     "",
	})

	if !strings.Contains(line, "zones=5") {
		t.Error("expected zones in line")
	}
}

func TestFormatReloadAuditLine_WithError(t *testing.T) {
	line := formatReloadAuditLine(ReloadAuditEntry{
		Timestamp: "2026-04-02T12:00:00Z",
		Action:    "failed",
		Zones:     3,
		Error:     "zone not found",
	})

	if !strings.Contains(line, "error=zone not found") {
		t.Error("expected error in line")
	}
}
