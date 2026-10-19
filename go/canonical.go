// Canonical JSON (spec §3): keys sorted by UTF-8 byte order, no whitespace,
// strings and numbers serialized exactly as JavaScript's JSON.stringify does.
package certify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ToGeneric converts any JSON-marshalable value (structs included) into the
// generic tree CanonicalJSON accepts. Struct fields with `omitempty` play the
// role of TypeScript's `undefined` (dropped).
func ToGeneric(v any) (any, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return DecodeJSON(buf.Bytes())
}

// DecodeJSON parses JSON into a generic tree with numbers kept as json.Number.
func DecodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("unexpected data after JSON value")
	}
	return out, nil
}

// CanonicalJSON serializes a generic JSON tree canonically.
func CanonicalJSON(v any) (string, error) {
	var sb strings.Builder
	if err := writeCanonical(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// MustCanonicalJSON is CanonicalJSON for values built by this package.
func MustCanonicalJSON(v any) string {
	g, err := ToGeneric(v)
	if err != nil {
		panic(err)
	}
	s, err := CanonicalJSON(g)
	if err != nil {
		panic(err)
	}
	return s
}

// JSONDigest is "sha256:" + hex(sha256(canonical JSON)).
func JSONDigest(v any) (string, error) {
	g, err := ToGeneric(v)
	if err != nil {
		return "", err
	}
	s, err := CanonicalJSON(g)
	if err != nil {
		return "", err
	}
	return "sha256:" + SHA256Hex([]byte(s)), nil
}

func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func writeCanonical(sb *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if x {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		sb.WriteString(QuoteJS(x))
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil {
			return fmt.Errorf("invalid number %q: %w", x, err)
		}
		sb.WriteString(JSNumber(f))
	case float64:
		sb.WriteString(JSNumber(x))
	case int:
		sb.WriteString(JSNumber(float64(x)))
	case []any:
		sb.WriteByte('[')
		for i, it := range x {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := writeCanonical(sb, it); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // Go strings compare by UTF-8 bytes
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(QuoteJS(k))
			sb.WriteByte(':')
			if err := writeCanonical(sb, x[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("canonical JSON: unsupported type %T", v)
	}
	return nil
}

// QuoteJS is JSON.stringify for a string: only `"`, `\` and C0 controls are
// escaped; everything else (including U+2028/U+2029, <, >, &) is written raw.
func QuoteJS(s string) string {
	var sb strings.Builder
	sb.Grow(len(s) + 2)
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&sb, `\u%04x`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
	return sb.String()
}
