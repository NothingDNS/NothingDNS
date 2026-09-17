package main

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestSummarizeAnswers(t *testing.T) {
	if got := summarizeAnswers(nil); got != nil {
		t.Fatalf("nil message: got %v", got)
	}
	if got := summarizeAnswers(&protocol.Message{}); got != nil {
		t.Fatalf("empty answers: got %v", got)
	}

	msg := &protocol.Message{
		Answers: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
			},
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeCNAME,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataCNAME{CName: mustParseName(t, "www.example.com.")},
			},
		},
	}
	got := summarizeAnswers(msg)
	if len(got) != 2 {
		t.Fatalf("got %d answers, want 2: %v", len(got), got)
	}
	if !strings.HasPrefix(got[0], "A ") || !strings.Contains(got[0], "93.184.216.34") {
		t.Errorf("A answer = %q", got[0])
	}
	if !strings.HasPrefix(got[1], "CNAME ") {
		t.Errorf("CNAME answer = %q", got[1])
	}
}

func TestSummarizeAnswersCapsCountAndLength(t *testing.T) {
	answers := make([]*protocol.ResourceRecord, maxLoggedAnswers+3)
	for i := range answers {
		answers[i] = &protocol.ResourceRecord{
			Name:  mustParseName(t, "example.com."),
			Type:  protocol.TypeTXT,
			Class: protocol.ClassIN,
			Data:  &protocol.RDataTXT{Strings: []string{strings.Repeat("x", maxLoggedAnswerLen+40)}},
		}
	}
	got := summarizeAnswers(&protocol.Message{Answers: answers})
	if len(got) != maxLoggedAnswers+1 {
		t.Fatalf("got %d lines, want %d (capped + overflow marker)", len(got), maxLoggedAnswers+1)
	}
	if !strings.HasPrefix(got[len(got)-1], "+") {
		t.Errorf("overflow marker = %q", got[len(got)-1])
	}
	if !strings.HasSuffix(got[0], "…") {
		t.Errorf("long TXT should be truncated with ellipsis: %q", got[0])
	}
}
