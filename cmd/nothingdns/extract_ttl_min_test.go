package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// extractTTL bounds how long an answer is cached, so it must be the smallest
// positive record TTL: the cached answer may not outlive any record in it.
func TestExtractTTLIsSmallestPositiveAnswerTTL(t *testing.T) {
	mk := func(ttls ...uint32) *protocol.Message {
		m := &protocol.Message{}
		for _, ttl := range ttls {
			m.Answers = append(m.Answers, &protocol.ResourceRecord{TTL: ttl})
		}
		return m
	}

	for _, tc := range []struct {
		name string
		resp *protocol.Message
		want uint32
	}{
		{"nil response", nil, 300},
		{"no answers", mk(), 300},
		{"single record", mk(600), 600},
		{"long CNAME then short A", mk(3600, 30), 30},
		{"short first, long second", mk(45, 3000), 45},
		{"equal TTLs", mk(120, 120), 120},
		{"zero TTL records are skipped, not minimal", mk(0, 90, 0, 60), 60},
		{"only zero TTLs fall back to the default", mk(0, 0), 300},
		{"a nil record is skipped", &protocol.Message{Answers: []*protocol.ResourceRecord{nil, {TTL: 75}}}, 75},
		{"minimum of one second is honoured", mk(3600, 1), 1},
		{"maximum uint32 alone", mk(^uint32(0)), ^uint32(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractTTL(tc.resp); got != tc.want {
				t.Fatalf("extractTTL = %d, want %d", got, tc.want)
			}
		})
	}
}
