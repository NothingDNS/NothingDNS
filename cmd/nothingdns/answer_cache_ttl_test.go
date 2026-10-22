package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// answerCacheTTL decides how long a positive answer is cached. A record with
// TTL 0 "can only be used for the transaction in progress, and should not be
// cached" (RFC 1035 §3.2.1), so any such record makes the answer uncacheable;
// otherwise it is extractTTL's smallest positive TTL.
func TestAnswerCacheTTL(t *testing.T) {
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
		{"nil response uses the default", nil, 300},
		{"no answers uses the default", mk(), 300},
		{"single positive TTL", mk(600), 600},
		{"smallest positive TTL", mk(3600, 30), 30},
		{"a lone TTL 0 is not cacheable", mk(0), 0},
		{"TTL 0 first", mk(0, 3600), 0},
		{"TTL 0 last behind a long CNAME", mk(3600, 0), 0},
		{"TTL 0 in the middle", mk(300, 0, 60), 0},
		{"a nil record is skipped", &protocol.Message{Answers: []*protocol.ResourceRecord{nil, {TTL: 75}}}, 75},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := answerCacheTTL(tc.resp); got != tc.want {
				t.Fatalf("answerCacheTTL = %d, want %d", got, tc.want)
			}
		})
	}
}
