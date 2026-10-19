// JavaScript string semantics the TypeScript reference relies on implicitly.
// Byte-identical `checks` (Gold) need Go to see text exactly as Node does:
// the same UTF-8 decoding, the same UTF-16 code units, the same whitespace set,
// the same lowercasing, and the same number formatting.
package certify

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
)

// DecodeUTF8 decodes bytes the way Node's Buffer#toString("utf8") does: the
// WHATWG UTF-8 decoder, replacing each maximal invalid subpart with one U+FFFD.
// A leading BOM is kept. Go's own decoder emits one U+FFFD per invalid byte,
// which would change character counts.
func DecodeUTF8(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			sb.WriteByte(c)
			i++
			continue
		}
		var need int
		var cp rune
		lower, upper := byte(0x80), byte(0xBF)
		switch {
		case c >= 0xC2 && c <= 0xDF:
			need, cp = 1, rune(c&0x1F)
		case c >= 0xE0 && c <= 0xEF:
			need, cp = 2, rune(c&0x0F)
			if c == 0xE0 {
				lower = 0xA0
			} else if c == 0xED {
				upper = 0x9F
			}
		case c >= 0xF0 && c <= 0xF4:
			need, cp = 3, rune(c&0x07)
			if c == 0xF0 {
				lower = 0x90
			} else if c == 0xF4 {
				upper = 0x8F
			}
		default:
			sb.WriteRune(unicode.ReplacementChar)
			i++
			continue
		}
		j := i + 1
		ok := true
		for k := 0; k < need; k++ {
			if j >= len(b) || b[j] < lower || b[j] > upper {
				ok = false
				break
			}
			cp = cp<<6 | rune(b[j]&0x3F)
			lower, upper = 0x80, 0xBF
			j++
		}
		if !ok {
			// The bytes consumed so far form the maximal subpart; the byte that
			// broke the sequence is decoded afresh.
			sb.WriteRune(unicode.ReplacementChar)
			i = j
			continue
		}
		sb.WriteRune(cp)
		i = j
	}
	return sb.String()
}

// CodeUnitString re-encodes s so that every UTF-16 code unit becomes exactly one
// Go rune. JavaScript regular expressions without the `u` flag count code units:
// an astral character is two units for `[^\n]{0,40}`. BMP characters map to
// themselves; surrogate units map to the otherwise unused range U+F0000+, so they
// are single non-whitespace, non-word runes, as in JavaScript.
func CodeUnitString(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		if r < 0x10000 {
			sb.WriteRune(r)
			continue
		}
		hi, lo := utf16.EncodeRune(r)
		sb.WriteRune(0xF0000 + hi - 0xD800)
		sb.WriteRune(0xF0000 + lo - 0xD800)
	}
	return sb.String()
}

// JSWhitespaceClass is the body of a regexp character class matching exactly
// JavaScript's \s (WhiteSpace + LineTerminator). Go's \s is ASCII-only and omits \v.
const JSWhitespaceClass = `\t\n\x{0B}\f\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}`

// IsJSWhitespace reports whether r is in JavaScript's \s / String#trim set.
func IsJSWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// JSTrim is String#trim.
func JSTrim(s string) string { return strings.TrimFunc(s, IsJSWhitespace) }

// JSToLower is String#toLowerCase: Unicode full lowercasing, including the two
// context rules Go's simple mapping lacks (U+0130 → "i\u0307" and final sigma).
func JSToLower(s string) string {
	rs := []rune(s)
	var sb strings.Builder
	for i, r := range rs {
		switch {
		case r == 0x130:
			sb.WriteString("i\u0307")
		case r == 0x3A3 && isFinalSigma(rs, i):
			sb.WriteRune(0x3C2)
		default:
			sb.WriteRune(unicode.ToLower(r))
		}
	}
	return sb.String()
}

// Final_Sigma: preceded by a cased letter (skipping case-ignorables) and not
// followed by one.
func isFinalSigma(rs []rune, i int) bool {
	before := false
	for j := i - 1; j >= 0; j-- {
		if isCaseIgnorable(rs[j]) {
			continue
		}
		before = isCased(rs[j])
		break
	}
	if !before {
		return false
	}
	for j := i + 1; j < len(rs); j++ {
		if isCaseIgnorable(rs[j]) {
			continue
		}
		return !isCased(rs[j])
	}
	return true
}

func isCased(r rune) bool {
	return unicode.IsUpper(r) || unicode.IsLower(r) || unicode.IsTitle(r) || unicode.Is(unicode.Other_Lowercase, r) || unicode.Is(unicode.Other_Uppercase, r)
}

func isCaseIgnorable(r rune) bool {
	switch r {
	case '\'', '.', ':', '^', '`', 0xAD, 0xB7, 0x2018, 0x2019, 0x2024, 0x2027:
		return true
	}
	return unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf, unicode.Lm, unicode.Sk)
}

// JSNumber formats f as JavaScript's Number#toString (and JSON.stringify) does.
func JSNumber(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "null" // JSON.stringify; never produced from parsed JSON
	}
	if f == 0 {
		return "0" // includes -0
	}
	if f < 0 {
		return "-" + JSNumber(-f)
	}
	// Shortest round-trip digits, as ECMAScript requires: d.ddde±x.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expStr)
	k := len(digits)
	n := exp + 1 // value = 0.digits × 10^n
	switch {
	case k <= n && n <= 21:
		return digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return "0." + strings.Repeat("0", -n) + digits
	}
	sign := "+"
	if n-1 < 0 {
		sign = "-"
	}
	m := digits[:1]
	if k > 1 {
		m += "." + digits[1:]
	}
	return m + "e" + sign + strconv.Itoa(abs(n-1))
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// JSString is String(v) for JSON/YAML-decoded values.
func JSString(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		switch {
		case math.IsNaN(x):
			return "NaN"
		case math.IsInf(x, 1):
			return "Infinity"
		case math.IsInf(x, -1):
			return "-Infinity"
		}
		return JSNumber(x)
	case yamlBinary:
		return DecodeUTF8(x) // Buffer#toString()
	case json.Number:
		f, _ := strconv.ParseFloat(string(x), 64)
		return JSNumber(f)
	case int:
		return JSNumber(float64(x))
	case int64:
		return JSNumber(float64(x))
	case uint64:
		return JSNumber(float64(x))
	case []any:
		// Array#toString joins with commas; null/undefined items become "".
		parts := make([]string, len(x))
		for i, it := range x {
			if it != nil {
				parts[i] = JSString(it)
			}
		}
		return strings.Join(parts, ",")
	case map[string]any:
		return "[object Object]"
	}
	return ""
}
