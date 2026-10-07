//go:build ignore

// gen_idna_tables.go generates tables<version>.go, the Unicode data the
// IDNA2008 checks need, for the Unicode version of the running toolchain's
// standard library (F627–F631):
//
//   - bidiRanges: exact Bidi_Class (RFC 5893 Bidi rule);
//   - derivedRanges: the RFC 5892 §2/§3 derived property (PVALID, CONTEXTJ,
//     CONTEXTO, DISALLOWED, UNASSIGNED), computed with the §3 algorithm from
//     the categories of §2 (including the §2.6 exceptions and the empty §2.7
//     BackwardCompatible list);
//   - joiningRanges: Joining_Type (CONTEXTJ rule A.1) of PVALID code points;
//   - cccRanges, decompositions, compositions: Canonical_Combining_Class,
//     full canonical decompositions and primary composites, enough for an
//     exact NFC check (RFC 5891 §5.4) and for virama detection (A.1, A.2).
//
// Usage, once per supported toolchain (the standard library's Unicode
// version changes with the Go release; x/text selects the same version):
//
//	GOTOOLCHAIN=go1.26.6 go run gen_idna_tables.go -buildtag '!go1.27' -joining DerivedJoiningType-15.0.0.txt > tables15.0.0.go
//	GOTOOLCHAIN=go1.27.1 go run gen_idna_tables.go -buildtag 'go1.27'  -joining DerivedJoiningType-17.0.0.txt > tables17.0.0.go
//
// Sources: General_Category, Script and the PropList properties from the
// standard library; Bidi_Class, normalization and case folding from
// golang.org/x/text (already in the module graph; this file is
// build-ignored, so it adds no runtime dependency); Joining_Type from a UCD
// extracted/DerivedJoiningType.txt file whose header names the same Unicode
// version. The generator refuses to run when any source's Unicode version
// differs from unicode.Version.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/bidi"
	"golang.org/x/text/unicode/norm"
)

// Derived property values (must match derived.go).
const (
	propUnassigned = iota
	propPVALID
	propContextJ
	propContextO
	propDisallowed
)

var propNames = []string{"propUnassigned", "propPVALID", "propContextJ", "propContextO", "propDisallowed"}

// Joining types (must match derived.go).
const (
	jtU = iota
	jtL
	jtD
	jtR
	jtT
)

var jtNames = []string{"jtU", "jtL", "jtD", "jtR", "jtT"}

// exceptions is RFC 5892 §2.6 (category F).
var exceptions = map[rune]int{
	0x00DF: propPVALID, 0x03C2: propPVALID, 0x06FD: propPVALID, 0x06FE: propPVALID, 0x0F0B: propPVALID, 0x3007: propPVALID,
	0x00B7: propContextO, 0x0375: propContextO, 0x05F3: propContextO, 0x05F4: propContextO, 0x30FB: propContextO,
	0x0640: propDisallowed, 0x07FA: propDisallowed, 0x302E: propDisallowed, 0x302F: propDisallowed,
	0x3031: propDisallowed, 0x3032: propDisallowed, 0x3033: propDisallowed, 0x3034: propDisallowed, 0x3035: propDisallowed,
	0x303B: propDisallowed,
}

func init() {
	for r := rune(0x0660); r <= 0x0669; r++ {
		exceptions[r] = propContextO
	}
	for r := rune(0x06F0); r <= 0x06F9; r++ {
		exceptions[r] = propContextO
	}
}

// backwardCompatible is RFC 5892 §2.7 (category G); it is empty (no IANA
// update has added an entry).
var backwardCompatible = map[rune]int{}

var fold = cases.Fold()

func assigned(r rune) bool {
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs,
		unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z)
}

// defaultIgnorable is Default_Ignorable_Code_Point, derived as in
// DerivedCoreProperties.txt: Other_Default_Ignorable_Code_Point + Cf +
// Variation_Selector - White_Space - FFF9..FFFB - 13430..13440 -
// Prepended_Concatenation_Mark.
func defaultIgnorable(r rune) bool {
	if !unicode.In(r, unicode.Other_Default_Ignorable_Code_Point, unicode.Cf, unicode.Variation_Selector) {
		return false
	}
	if unicode.Is(unicode.White_Space, r) || unicode.Is(unicode.Prepended_Concatenation_Mark, r) {
		return false
	}
	return !(r >= 0xFFF9 && r <= 0xFFFB) && !(r >= 0x13430 && r <= 0x13440)
}

func removeDI(s string) string {
	return strings.Map(func(r rune) rune {
		if defaultIgnorable(r) {
			return -1
		}
		return r
	}, s)
}

// caseFold is toCasefold (CaseFolding.txt statuses C and F). x/text's
// cases.Fold leaves the Cherokee small letters unfolded, while
// CaseFolding.txt folds them to the capital letters (since Unicode 8.0), so
// they are mapped here.
func caseFold(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 0x13F8 && r <= 0x13FD:
			return r - 0x13F8 + 0x13F0
		case r >= 0xAB70 && r <= 0xABBF:
			return r - 0xAB70 + 0x13A0
		}
		return r
	}, fold.String(s))
}

// nfkcCasefold is NFKC_Casefold: the closure of NFKC(toCasefold(NFKC(X)))
// with Default_Ignorable_Code_Point removed. Checked against the UCD
// DerivedNormalizationProps.txt NFKC_CF mappings (P2-M1 evidence).
func nfkcCasefold(s string) string {
	for i := 0; i < 10; i++ {
		t := removeDI(norm.NFKC.String(caseFold(norm.NFKC.String(s))))
		if t == s {
			return t
		}
		s = t
	}
	return s
}

// derived implements RFC 5892 §3.
func derived(r rune) int {
	if v, ok := exceptions[r]; ok { // F
		return v
	}
	if v, ok := backwardCompatible[r]; ok { // G
		return v
	}
	if !assigned(r) && !unicode.Is(unicode.Noncharacter_Code_Point, r) { // J
		return propUnassigned
	}
	if r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') { // E
		return propPVALID
	}
	if unicode.Is(unicode.Join_Control, r) { // H
		return propContextJ
	}
	if utf8.ValidRune(r) { // B (surrogates are not valid strings; they fall to DISALLOWED)
		s := string(r)
		if nfkcCasefold(norm.NFC.String(s)) != s {
			return propDisallowed
		}
	} else {
		return propDisallowed
	}
	if defaultIgnorable(r) || unicode.Is(unicode.White_Space, r) || unicode.Is(unicode.Noncharacter_Code_Point, r) { // C
		return propDisallowed
	}
	if (r >= 0x20D0 && r <= 0x20FF) || (r >= 0x1D100 && r <= 0x1D1FF) || (r >= 0x1D200 && r <= 0x1D24F) { // D
		return propDisallowed
	}
	// I: Hangul_Syllable_Type L, V or T.
	if (r >= 0x1100 && r <= 0x11FF) || (r >= 0xA960 && r <= 0xA97C) || (r >= 0xD7B0 && r <= 0xD7C6) || (r >= 0xD7CB && r <= 0xD7FB) {
		return propDisallowed
	}
	if unicode.In(r, unicode.Ll, unicode.Lu, unicode.Lo, unicode.Nd, unicode.Lm, unicode.Mn, unicode.Mc) { // A
		return propPVALID
	}
	return propDisallowed
}

var bidiNames = map[bidi.Class]string{
	bidi.L: "bidiL", bidi.R: "bidiR", bidi.AL: "bidiAL", bidi.EN: "bidiEN", bidi.AN: "bidiAN",
	bidi.ES: "bidiES", bidi.CS: "bidiCS", bidi.ET: "bidiET", bidi.ON: "bidiON",
	bidi.BN: "bidiBN", bidi.NSM: "bidiNSM",
}

func bidiClass(r rune) string {
	if !utf8.ValidRune(r) {
		return "bidiL"
	}
	p, _ := bidi.LookupRune(r)
	if n, ok := bidiNames[p.Class()]; ok {
		return n
	}
	return "bidiOther" // B, S, WS and the explicit embedding/isolate controls
}

func readJoining(path string) map[rune]int {
	f, err := os.Open(path)
	if err != nil {
		fail("%v", err)
	}
	defer f.Close()
	out := map[rune]int{}
	s := bufio.NewScanner(f)
	hdr := regexp.MustCompile(`DerivedJoiningType-([0-9.]+)\.txt`)
	version := ""
	for s.Scan() {
		line := s.Text()
		if version == "" {
			if m := hdr.FindStringSubmatch(line); m != nil {
				version = m[1]
			}
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Split(line, ";")
		if len(fields) != 2 {
			continue
		}
		lo, hi := parseRange(strings.TrimSpace(fields[0]))
		v := map[string]int{"L": jtL, "D": jtD, "R": jtR, "T": jtT}[strings.TrimSpace(fields[1])]
		if v == 0 {
			continue // U and C do not take part in rule A.1
		}
		for r := lo; r <= hi; r++ {
			out[r] = v
		}
	}
	if err := s.Err(); err != nil {
		fail("%v", err)
	}
	if version != unicode.Version {
		fail("%s is Unicode %q, the standard library is Unicode %s", path, version, unicode.Version)
	}
	return out
}

func parseRange(s string) (rune, rune) {
	lo, hi, ok := strings.Cut(s, "..")
	a, err := strconv.ParseUint(lo, 16, 32)
	if err != nil {
		fail("bad code point %q", s)
	}
	b := a
	if ok {
		if b, err = strconv.ParseUint(hi, 16, 32); err != nil {
			fail("bad code point %q", s)
		}
	}
	return rune(a), rune(b)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen_idna_tables: "+format+"\n", args...)
	os.Exit(1)
}

func ccc(r rune) uint8 {
	if !utf8.ValidRune(r) {
		return 0
	}
	return norm.NFD.PropertiesString(string(r)).CCC()
}

func isHangulSyllable(r rune) bool { return r >= 0xAC00 && r <= 0xD7A3 }

// writeRanges writes the run-length ranges of f over all code points,
// omitting runs whose value is def.
func writeRanges(w *bufio.Writer, name, typ, comment string, f func(rune) string, def string) {
	fmt.Fprintf(w, "\n%s\nvar %s = [...]%s{\n", comment, name, typ)
	start, prev := rune(0), f(0)
	flush := func(end rune) {
		if prev != def {
			fmt.Fprintf(w, "\t{0x%04X, 0x%04X, %s},\n", start, end, prev)
		}
	}
	for r := rune(1); r <= unicode.MaxRune; r++ {
		if c := f(r); c != prev {
			flush(r - 1)
			start, prev = r, c
		}
	}
	flush(unicode.MaxRune)
	fmt.Fprint(w, "}\n")
}

func main() {
	buildTag := flag.String("buildtag", "", "build constraint of the generated file (e.g. go1.27 or !go1.27)")
	joiningFile := flag.String("joining", "", "UCD extracted/DerivedJoiningType.txt of the standard library's Unicode version")
	flag.Parse()
	if *buildTag == "" || *joiningFile == "" {
		fail("-buildtag and -joining are required")
	}
	for name, v := range map[string]string{"x/text/unicode/bidi": bidi.UnicodeVersion, "x/text/unicode/norm": norm.Version, "x/text/cases": cases.UnicodeVersion} {
		if v != unicode.Version {
			fail("%s tables are Unicode %s, the standard library is Unicode %s; use a matching toolchain", name, v, unicode.Version)
		}
	}
	joining := readJoining(*joiningFile)

	props := make([]int, unicode.MaxRune+1)
	for r := range props {
		props[r] = derived(rune(r))
	}
	// The A.1 regular expression only looks at the neighbours of ZWNJ; in a
	// label that passes the derived-property check those are PVALID or
	// CONTEXTJ/CONTEXTO code points, so Joining_Type is recorded for PVALID
	// code points only. CONTEXTJ/CONTEXTO code points must be U or C.
	for r, v := range joining {
		if p := props[r]; p == propContextJ || p == propContextO {
			fail("%U is %s with Joining_Type %s", r, propNames[p], jtNames[v])
		}
	}

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	fmt.Fprintf(w, `// Code generated by "go run gen_idna_tables.go -buildtag '%s'"; DO NOT EDIT.

//go:build %s

package idna

// tablesUnicodeVersion is the Unicode version of the data below; it equals
// the standard library's unicode.Version for the toolchains selected by the
// build constraint (checked by TestTablesUnicodeVersion).
const tablesUnicodeVersion = %q
`, *buildTag, *buildTag, unicode.Version)

	writeRanges(w, "bidiRanges", "bidiRange",
		"// bidiRanges lists the code point ranges whose Bidi_Class is not L, sorted\n// and non-overlapping. Every code point outside them is L.",
		bidiClass, "bidiL")
	writeRanges(w, "derivedRanges", "runeRange8",
		"// derivedRanges is the RFC 5892 derived property of every assigned code\n// point (and of the noncharacters, which are DISALLOWED). Every code point\n// outside them is UNASSIGNED.",
		func(r rune) string { return propNames[props[r]] }, "propUnassigned")
	writeRanges(w, "joiningRanges", "runeRange8",
		"// joiningRanges is the Joining_Type (L, D, R, T) of PVALID code points;\n// every other code point is treated as U (rule A.1 needs no other value).",
		func(r rune) string {
			if props[r] != propPVALID {
				return "jtU"
			}
			return jtNames[joining[r]]
		}, "jtU")
	writeRanges(w, "cccRanges", "runeRange8",
		"// cccRanges is the non-zero Canonical_Combining_Class of code points.",
		func(r rune) string { return strconv.Itoa(int(ccc(r))) }, "0")

	// Full canonical decompositions (Hangul syllables are algorithmic).
	type comp struct{ a, b, c rune }
	var comps []comp
	fmt.Fprint(w, "\n// decompositions maps code points to their full canonical decomposition\n// (Hangul syllables excluded: they decompose algorithmically), sorted.\nvar decompositions = [...]decompEntry{\n")
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) || isHangulSyllable(r) {
			continue
		}
		s := string(r)
		d := norm.NFD.String(s)
		if d == s {
			continue
		}
		fmt.Fprintf(w, "\t{0x%04X, %+q},\n", r, d)
		if norm.NFC.String(s) != s {
			continue // singleton, excluded or non-starter decomposition
		}
		// Primary composite: find the pair (a, b) with NFC(a+b) == r and
		// NFD(a)+b canonically equivalent to NFD(r).
		dr := []rune(d)
		found := false
		for k := len(dr) - 1; k >= 1 && !found; k-- {
			rest := append(append([]rune{}, dr[:k]...), dr[k+1:]...)
			a := []rune(norm.NFC.String(string(rest)))
			if len(a) != 1 {
				continue
			}
			if norm.NFC.String(string(a[0])+string(dr[k])) == s && norm.NFD.String(string(a[0])+string(dr[k])) == d {
				comps = append(comps, comp{a[0], dr[k], r})
				found = true
			}
		}
		if !found {
			fail("no composition pair for %U", r)
		}
	}
	fmt.Fprint(w, "}\n")
	sort.Slice(comps, func(i, j int) bool {
		if comps[i].a != comps[j].a {
			return comps[i].a < comps[j].a
		}
		return comps[i].b < comps[j].b
	})
	fmt.Fprint(w, "\n// compositions lists the primary composites (Hangul excluded) by their\n// canonical decomposition pair, sorted by (a, b).\nvar compositions = [...]compEntry{\n")
	for i, c := range comps {
		if i > 0 && comps[i-1].a == c.a && comps[i-1].b == c.b {
			fail("duplicate composition pair %U %U", c.a, c.b)
		}
		fmt.Fprintf(w, "\t{0x%04X, 0x%04X, 0x%04X},\n", c.a, c.b, c.c)
	}
	fmt.Fprint(w, "}\n")
}
