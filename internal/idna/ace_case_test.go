package idna

import "testing"

func TestToUnicodeACEPrefixCase(t *testing.T) {
	for _, prefix := range []string{"xn--", "XN--", "Xn--", "xN--"} {
		for _, tc := range []struct{ body, want string }{{"mnchen-3ya.de", "münchen.de"}, {"bcher-kva.example", "bücher.example"}, {"ihqwcrb4cv8a8dqg056pqjye.example", "他们为什么不说中文.example"}} {
			got, err := ToUnicode(prefix + tc.body)
			if err != nil || got != tc.want {
				t.Errorf("ToUnicode(%q)=%q,%v; want %q", prefix+tc.body, got, err, tc.want)
			}
			got, err = FromASCII(prefix + tc.body)
			if err != nil || got != tc.want {
				t.Errorf("FromASCII(%q)=%q,%v; want %q", prefix+tc.body, got, err, tc.want)
			}
		}
	}
	for _, s := range []string{"", "x", "XN", "Example.COM"} {
		got, err := ToUnicode(s)
		if err != nil || got != s {
			t.Errorf("ASCII control %q=%q,%v", s, got, err)
		}
	}
}
