package idna

import (
	"errors"
	"strings"
	"testing"
)

// F621: Profile.ToASCII applies UseSTD3Rules, AllowUnassigned and the
// RFC 5893 Bidi rule; the package-level ToASCII keeps its behaviour.

func mustACE(t *testing.T, u string) string {
	t.Helper()
	a, err := ToASCII(u)
	if err != nil {
		t.Fatalf("ToASCII(%q): %v", u, err)
	}
	return a
}

func TestProfileSTD3(t *testing.T) {
	off := Profile{AllowUnassigned: true}
	on := Profile{UseSTD3Rules: true, AllowUnassigned: true}
	for _, name := range []string{"_dmarc.example.com", "_sip._tcp.example", "-x.example"} {
		if _, err := off.ToASCII(name); err != nil {
			t.Errorf("STD3 off: %q rejected: %v", name, err)
		}
		if _, err := on.ToASCII(name); err == nil {
			t.Errorf("STD3 on: %q accepted", name)
		}
	}
	// Length and empty-label limits still apply with STD3 off.
	if _, err := off.ToASCII("a.." + "b"); !errors.Is(err, ErrEmptyLabel) {
		t.Errorf("empty label: %v", err)
	}
	if _, err := off.ToASCII(strings.Repeat("a", 64) + ".example"); !errors.Is(err, ErrLabelTooLong) {
		t.Errorf("long label: %v", err)
	}
	// Package ToASCII is unchanged: STD3 on, unassigned allowed.
	if _, err := ToASCII("_dmarc.example.com"); err == nil {
		t.Error("ToASCII accepted an underscore label")
	}
	if _, err := ToASCII(mustACE(t, "a\u0378b")); err != nil {
		t.Errorf("ToASCII rejected an unassigned A-label: %v", err)
	}
}

func TestProfileUnassigned(t *testing.T) {
	strict := Profile{UseSTD3Rules: true}
	for _, name := range []string{mustACE(t, "a\u0378b") + ".example", "a\u0378b.example", "XN--AB-G4B.example"} {
		if _, err := strict.ToASCII(name); !errors.Is(err, ErrUnassigned) {
			t.Errorf("%q: err=%v, want ErrUnassigned", name, err)
		}
	}
	for _, name := range []string{mustACE(t, "b\u00fccher") + ".example", "b\u00fccher.example", "www.example.com"} {
		if _, err := strict.ToASCII(name); err != nil {
			t.Errorf("%q rejected: %v", name, err)
		}
	}
	if _, err := (Profile{UseSTD3Rules: true, AllowUnassigned: true}).ToASCII("a\u0378b.example"); err != nil {
		t.Errorf("AllowUnassigned=true rejected: %v", err)
	}
}

func TestProfileBidiRule(t *testing.T) {
	p := Profile{UseSTD3Rules: true, AllowUnassigned: true, CheckBidi: true}
	cases := []struct {
		name string
		ok   bool
	}{
		{"\u05d0\u05d1.example", true},               // Hebrew
		{"\u0627\u0644\u0639\u0631\u0628.com", true}, // Arabic
		{"\u0627\u0661\u0662.example", true},         // AL then AN (rule 3 ends in AN)
		{"\u0627" + "1.example", true},               // AL then EN
		{"\u05d0\u05b0.example", true},               // trailing NSM after R
		{"\u05d0a.example", false},                   // rule 2: L in an RTL label
		{"a\u05d0.example", false},                   // rule 5: R in an LTR label
		{"\u0627\u0661" + "1.example", false},        // rule 4: EN and AN together
		{"\u05d0\u05d1.1abc", false},                 // rule 1: LTR label starts with EN in a Bidi domain
		{"1abc.example", true},                       // not a Bidi domain: not checked
		{"\u05d0-.example", false},                   // rule 3: ends with ES
		{mustACE(t, "\u05d0a") + ".example", false},  // A-label decoded and checked
	}
	for _, c := range cases {
		_, err := p.ToASCII(c.name)
		if c.ok && err != nil {
			t.Errorf("%q rejected: %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrInvalidBid) && !errors.Is(err, ErrHyphenEnd) {
			t.Errorf("%q: err=%v, want a Bidi violation", c.name, err)
		}
	}
	// Off: the same violation passes.
	if _, err := (Profile{UseSTD3Rules: true, AllowUnassigned: true}).ToASCII("\u05d0a.example"); err != nil {
		t.Errorf("CheckBidi=false rejected: %v", err)
	}
}

func TestBidiLabelOKDirect(t *testing.T) {
	// Direct rule checks independent of STD3 (rule 3: RTL label ending ES).
	if bidiLabelOK("\u05d0-") {
		t.Error("RTL label ending in ES accepted")
	}
	if !bidiLabelOK("\u05d0-\u05d1") {
		t.Error("RTL label with interior ES rejected")
	}
	if !bidiLabelOK("") {
		t.Error("empty label")
	}
}
