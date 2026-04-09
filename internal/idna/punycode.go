// Package idna implements Punycode encoding/decoding per RFC 3492.
package idna

import "strings"

// Punycode base and delimiter constants
const (
	base      = 36
	delimiter = '-'
	tmin      = 1
	tmax      = 26
	skew      = 38
	damp      = 700
	// initialBias is the starting bias for the first delta.
	initialBias = 72
	// initialN is the first code point for the encoded suffix.
	initialN = 128 // 0x80
)

// digitToChar converts a digit value to its character representation.
func digitToChar(digit int) rune {
	switch {
	case digit >= 0 && digit <= 25:
		return rune('a' + digit)
	case digit >= 26 && digit <= 35:
		return rune('0' + digit - 26)
	default:
		return rune('a') // Should not happen
	}
}

// charToDigit converts a character to its digit value.
func charToDigit(char rune) int {
	switch {
	case char >= 'a' && char <= 'z':
		return int(char - 'a')
	case char >= 'A' && char <= 'Z':
		return int(char - 'A')
	case char >= '0' && char <= '9':
		return int(char - '0' + 26)
	default:
		return -1
	}
}

// encodePunycode encodes a Unicode string to punycode.
func encodePunycode(src string) string {
	// Convert string to rune slice for processing
	runes := []rune(src)

	// Phase 1: Find ASCII-only prefix
	var prefix []rune
	for _, r := range runes {
		if r < 0x80 {
			prefix = append(prefix, r)
		} else {
			break
		}
	}

	// Phase 2: Encode the non-ASCII suffix
	var encoded strings.Builder

	if len(prefix) > 0 {
		encoded.WriteString(string(prefix))
		encoded.WriteString("-")
	}

	// Handle non-ASCII suffix
	if len(runes) > len(prefix) {
		suffix := runes[len(prefix):]
		encoded.WriteString(encodeSuffix(suffix))
	}

	return encoded.String()
}

// encodeSuffix encodes the non-ASCII suffix to punycode.
// Implements RFC 3492 Bootstring algorithm correctly.
func encodeSuffix(src []rune) string {
	if len(src) == 0 {
		return ""
	}

	var out strings.Builder

	// RFC 3492 algorithm state
	n := initialN        // First non-ASCII code point (0x80)
	delta := 0          // Cumulative delta
	bias := initialBias
	h := 0              // Number of code points processed (starts at 0 for suffix)

	// Handle all characters - first pass just counts ASCII
	for _, r := range src {
		if r < initialN {
			h++
		}
	}

	// If all ASCII, nothing to encode
	if h == len(src) {
		return ""
	}

	// Main loop - process all non-ASCII characters
	for h < len(src) {
		// Find the next smallest code point >= n
		m := initialN
		for i := h; i < len(src); i++ {
			if int(src[i]) >= m {
				m = int(src[i])
			}
		}

		// Calculate delta
		delta += (m - n) * (h + 1)
		n = m

		// Process each character
		for i := h; i < len(src); i++ {
			if int(src[i]) < n {
				delta++
			}
			if int(src[i]) == n {
				// Encode delta using adapation function
				q := delta
				for {
					var k int
					if bias <= tmax {
						k = tmin
					} else if bias >= tmax+tmin {
						k = tmax
					} else {
						k = bias - tmin
					}

					if q < k {
						break
					}

					out.WriteRune(digitToChar(k + (q-k)%26))
					q = (q - k) / 26
					bias = adapt(q, bias, false)
				}

				out.WriteRune(digitToChar(q))
				bias = adapt(delta, bias, false)
				delta = 0
				h++
			}
		}
	}

	return out.String()
}


// decodePunycode decodes a punycode string to Unicode.
func decodePunycode(src string) string {
	if src == "" {
		return ""
	}

	// Check for ASCII-only (no hyphens or all before hyphen)
	if !strings.Contains(src, string(delimiter)) {
		return src
	}

	// Find the last hyphen
	lastHyphen := strings.LastIndex(src, "-")
	if lastHyphen < 0 {
		return src
	}

	// Everything before the last hyphen is the basic prefix (ASCII)
	prefix := src[:lastHyphen]
	encoded := src[lastHyphen+1:]

	if encoded == "" {
		return prefix
	}

	// Decode the suffix
	var (
		n     int = initialN
		bias  = initialBias
		i     = 0
		out   []rune
	)

	// Initialize output with the prefix
	for _, r := range prefix {
		out = append(out, r)
	}

	for pos := 0; pos < len(encoded); pos++ {
		char := rune(encoded[pos])
		if char == delimiter {
			// End of encoded part
			break
		}

		oldI := i
		weight := 1

		for k := base; ; k += base {
			if pos >= len(encoded) {
				return string(out)
			}

			digit := charToDigit(char)
			if digit < 0 {
				return string(out)
			}

			i += digit * weight

			t := k - bias
			if t < tmin {
				t = tmin
			}
			if t > tmax {
				t = tmax
			}

			if digit < t {
				break
			}

			weight *= (base - t)
			pos++
			if pos < len(encoded) {
				char = rune(encoded[pos])
			}
		}

		bias = adapt(i-oldI, len(out)+1, oldI == 0)

		n += i / (len(out) + 1)
		i = i % (len(out) + 1)

		// Insert n at position i
		if i == 0 {
			out = append([]rune{rune(n)}, out...)
		} else if i >= len(out) {
			out = append(out, rune(n))
		} else {
			// Insert in the middle
			out = append(out[:i], append([]rune{rune(n)}, out[i:]...)...)
		}

		i++
	}

	return string(out)
}

// adapt adjusts the bias for delta arithmetic.
func adapt(delta, numPoints int, first bool) int {
	if first {
		delta = delta / damp
	} else {
		delta = delta / skew
	}

	delta += delta / numPoints

	k := 0
	for delta > ((base - tmin) * tmax) / 2 {
		delta = delta / (base - tmin)
		k += base
	}

	return k + ((base - tmin + 1)*delta)/(delta+skew)
}