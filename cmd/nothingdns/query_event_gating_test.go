package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

func answerMsg(t *testing.T) *protocol.Message {
	t.Helper()
	n, err := protocol.ParseName("example.test.")
	if err != nil {
		t.Fatal(err)
	}
	m := &protocol.Message{Header: protocol.Header{ID: 7}}
	m.Questions = append(m.Questions, &protocol.Question{Name: n, QType: protocol.TypeA, QClass: protocol.ClassIN})
	m.Answers = append(m.Answers, &protocol.ResourceRecord{Name: n, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 60,
		Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}})
	return m
}

// The per-response answer summary only feeds the dashboard Query Log, so it
// must be skipped when no dashboard is attached and kept when one is.
func TestHeaderPolicyWriterSummarizesOnlyWithDashboard(t *testing.T) {
	req := answerMsg(t)

	without := &integratedHandler{}
	w := newHeaderPolicyWriter(without, &captureWriter{}, req).(*headerPolicyResponseWriter)
	if _, err := w.Write(answerMsg(t)); err != nil {
		t.Fatal(err)
	}
	if len(w.answers) != 0 {
		t.Fatalf("answers summarized without a dashboard: %v", w.answers)
	}

	with := &integratedHandler{dashboardServer: dashboard.NewServer()}
	defer with.dashboardServer.Stop()
	w = newHeaderPolicyWriter(with, &captureWriter{}, req).(*headerPolicyResponseWriter)
	if _, err := w.Write(answerMsg(t)); err != nil {
		t.Fatal(err)
	}
	if len(w.answers) != 1 || w.answers[0] != "A 192.0.2.1" {
		t.Fatalf("dashboard summary = %v, want [A 192.0.2.1]", w.answers)
	}
}

func TestAuditLoggerEnabledGate(t *testing.T) {
	var nilLogger *audit.AuditLogger
	if nilLogger.Enabled() {
		t.Fatal("nil audit logger must be disabled")
	}
	off, err := audit.NewAuditLogger(false, "")
	if err != nil {
		t.Fatal(err)
	}
	if off.Enabled() {
		t.Fatal("query_log=false logger must be disabled")
	}
}
