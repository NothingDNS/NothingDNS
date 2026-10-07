package idna

import "sort"

// RFC 5893 §2 Bidi rule (F621).
//
// The rule is defined over the Unicode Bidi_Class property, which the Go
// standard library does not expose. bidiClassOf reads it from bidiRanges
// (bidi_table.go), generated from the Unicode Bidi_Class data of the same
// Unicode version as the standard library's tables (F622; the earlier
// approximation from script/category tables misclassified e.g. U+0640
// ARABIC TATWEEL, the Hanifi Rohingya digits and the Garay and Sidetic
// scripts).

type bidiClass uint8

const (
	bidiL bidiClass = iota
	bidiR
	bidiAL
	bidiEN
	bidiAN
	bidiES
	bidiCS
	bidiET
	bidiON
	bidiBN
	bidiNSM
	bidiOther // B, S, WS and the explicit embedding/isolate controls
)

// bidiRange is one entry of bidiRanges: code points lo..hi (inclusive)
// have Bidi_Class class.
type bidiRange struct {
	lo, hi rune
	class  bidiClass
}

// bidiClassOf returns the Unicode Bidi_Class of r.
func bidiClassOf(r rune) bidiClass {
	i := sort.Search(len(bidiRanges), func(i int) bool { return bidiRanges[i].hi >= r })
	if i < len(bidiRanges) && bidiRanges[i].lo <= r {
		return bidiRanges[i].class
	}
	return bidiL
}

// isRTLLabel reports whether label is an RTL label (RFC 5893 §1.4: it
// contains a character of Bidi_Class R, AL or AN).
func isRTLLabel(label string) bool {
	for _, r := range label {
		if c := bidiClassOf(r); c == bidiR || c == bidiAL || c == bidiAN {
			return true
		}
	}
	return false
}

// checkBidiRule applies RFC 5893 §2 to every label of a Bidi domain name
// (one that contains an RTL label: a label holding an R, AL or AN
// character). Domains without an RTL label are not checked.
func checkBidiRule(labels []string) error {
	bidiDomain := false
	for _, l := range labels {
		if isRTLLabel(l) {
			bidiDomain = true
			break
		}
	}
	if !bidiDomain {
		return nil
	}
	for _, l := range labels {
		if !bidiLabelOK(l) {
			return ErrInvalidBid
		}
	}
	return nil
}

// bidiLabelOK reports whether one label satisfies the six conditions of
// RFC 5893 §2.
func bidiLabelOK(label string) bool {
	classes := make([]bidiClass, 0, len(label))
	for _, r := range label {
		classes = append(classes, bidiClassOf(r))
	}
	if len(classes) == 0 {
		return true
	}
	// 1. The first character must be L, R or AL.
	var rtl bool
	switch classes[0] {
	case bidiL:
	case bidiR, bidiAL:
		rtl = true
	default:
		return false
	}
	// Last character that is not NSM.
	end := len(classes) - 1
	for end >= 0 && classes[end] == bidiNSM {
		end--
	}
	last := classes[end] // end >= 0: classes[0] is not NSM
	hasEN, hasAN := false, false
	for _, c := range classes {
		switch c {
		case bidiEN:
			hasEN = true
		case bidiAN:
			hasAN = true
		}
		if rtl {
			// 2. RTL labels: only R, AL, AN, EN, ES, CS, ET, ON, BN, NSM.
			switch c {
			case bidiR, bidiAL, bidiAN, bidiEN, bidiES, bidiCS, bidiET, bidiON, bidiBN, bidiNSM:
			default:
				return false
			}
		} else {
			// 5. LTR labels: only L, EN, ES, CS, ET, ON, BN, NSM.
			switch c {
			case bidiL, bidiEN, bidiES, bidiCS, bidiET, bidiON, bidiBN, bidiNSM:
			default:
				return false
			}
		}
	}
	if rtl {
		// 3. Ends with R, AL, EN or AN (then zero or more NSM).
		// 4. EN and AN must not both be present.
		return (last == bidiR || last == bidiAL || last == bidiEN || last == bidiAN) && !(hasEN && hasAN)
	}
	// 6. LTR: ends with L or EN (then zero or more NSM).
	return last == bidiL || last == bidiEN
}
