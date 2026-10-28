// Package canon produces canonical JSON for hashing and signing.
//
// It follows RFC 8785 (JCS) for the subset PoCC uses: object keys are sorted,
// there is no insignificant whitespace, strings are not HTML-escaped, and all
// numbers must be integers (amounts are carried in integer micro-units).
package canon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Marshal returns the canonical JSON encoding of v.
func Marshal(v any) ([]byte, error) {
	return MarshalWithout(v)
}

// MarshalWithout returns the canonical JSON encoding of v with the given
// top-level keys removed. It is used to sign a document without its "sig".
func MarshalWithout(v any, drop ...string) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return nil, err
	}
	if m, ok := x.(map[string]any); ok {
		for _, k := range drop {
			delete(m, k)
		}
	}
	var buf bytes.Buffer
	if err := write(&buf, x); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func write(b *bytes.Buffer, x any) error {
	switch t := x.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return fmt.Errorf("canon: non-integer number %s", s)
		}
		if s == "-0" {
			s = "0"
		}
		b.WriteString(s)
	case string:
		var sb bytes.Buffer
		enc := json.NewEncoder(&sb)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(t); err != nil {
			return err
		}
		b.Write(bytes.TrimRight(sb.Bytes(), "\n"))
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := write(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canon: unsupported type %T", x)
	}
	return nil
}
