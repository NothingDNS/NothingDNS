package protocol

import "testing"

// F700: the CAA tag was taken from a whitespace split of the raw text, so a
// quoted tag kept its quote characters (`"issue"` or `"a`) and was stored
// as-is; RFC 8659 §4.1.1 limits a tag to ASCII letters and digits.
func TestParseRDataTextCAATag(t *testing.T) {
	good := map[string]string{
		`0 issue "letsencrypt.org"`:   "issue",
		`0 ISSUE "x"`:                 "ISSUE",
		`128 iodef "mailto:a@b.c"`:    "iodef",
		`0 "issue" "letsencrypt.org"`: "issue",
		`0 issuewild ";"`:             "issuewild",
	}
	for in, tag := range good {
		rd, _ := ParseRDataText("CAA", in).(*RDataCAA)
		if rd == nil || rd.Tag != tag {
			t.Errorf("%q: tag = %+v, want %q", in, rd, tag)
		}
	}
	for _, in := range []string{`0 "a b" .`, `0 "a" b "c"`, `0 is-sue "x"`, `0 "" "x"`, `0 iss"ue "x"`} {
		if rd := ParseRDataText("CAA", in); rd != nil {
			t.Errorf("%q accepted: %+v", in, rd)
		}
	}
}
