package cli

import (
	"fmt"
	"strconv"
	"strings"
)

// mini TOML reader/writer — just enough of TOML for the Codex CLI
// config (~/.codex/config.toml): bare keys, [dotted.table] headers,
// dotted keys, basic/literal strings, integers, floats, booleans,
// single-line arrays of scalars and inline tables. Multiline strings,
// arrays of tables and multiline arrays are rejected with a parse
// error (the JS uses the full confbox parser; this subset covers the
// shapes proxygo itself writes plus typical hand edits — the same
// trade-off the dashboard's TOML port documents in
// internal/api/clitools.go).
//
// Key order is preserved (insertion order), like confbox.

type tomlTable struct {
	order []string
	vals  map[string]any // string | int64 | float64 | bool | []any | *tomlTable
}

func newTomlTable() *tomlTable { return &tomlTable{vals: map[string]any{}} }

func (t *tomlTable) get(key string) (any, bool) {
	v, ok := t.vals[key]
	return v, ok
}

func (t *tomlTable) set(key string, v any) {
	if _, ok := t.vals[key]; !ok {
		t.order = append(t.order, key)
	}
	t.vals[key] = v
}

func (t *tomlTable) del(key string) {
	if _, ok := t.vals[key]; !ok {
		return
	}
	delete(t.vals, key)
	for i, k := range t.order {
		if k == key {
			t.order = append(t.order[:i], t.order[i+1:]...)
			break
		}
	}
}

// child returns the sub-table at key, creating it when create is set.
func (t *tomlTable) child(key string, create bool) *tomlTable {
	if v, ok := t.vals[key]; ok {
		if ct, ok := v.(*tomlTable); ok {
			return ct
		}
		return nil
	}
	if !create {
		return nil
	}
	ct := newTomlTable()
	t.set(key, ct)
	return ct
}

func (t *tomlTable) navigate(path []string, create bool) *tomlTable {
	cur := t
	for _, p := range path {
		cur = cur.child(p, create)
		if cur == nil {
			return nil
		}
	}
	return cur
}

func (t *tomlTable) str(key string) string {
	if v, ok := t.vals[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func parseTOML(text string) (*tomlTable, error) {
	root := newTomlTable()
	cur := root
	for ln, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(stripTOMLComment(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[[") {
			return nil, fmt.Errorf("line %d: arrays of tables are not supported by the Go TOML subset", ln+1)
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("line %d: malformed table header", ln+1)
			}
			path, err := parseTOMLKeyPath(line[1 : len(line)-1])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", ln+1, err)
			}
			cur = root.navigate(path, true)
			if cur == nil {
				return nil, fmt.Errorf("line %d: table path conflicts with a value", ln+1)
			}
			continue
		}
		eq := indexTOMLEquals(line)
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", ln+1)
		}
		path, err := parseTOMLKeyPath(strings.TrimSpace(line[:eq]))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", ln+1, err)
		}
		val, rest, err := parseTOMLValue(strings.TrimSpace(line[eq+1:]))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", ln+1, err)
		}
		if strings.TrimSpace(rest) != "" {
			return nil, fmt.Errorf("line %d: trailing characters after value", ln+1)
		}
		parent := cur
		if len(path) > 1 {
			parent = cur.navigate(path[:len(path)-1], true)
			if parent == nil {
				return nil, fmt.Errorf("line %d: key path conflicts with a value", ln+1)
			}
		}
		parent.set(path[len(path)-1], val)
	}
	return root, nil
}

// stripTOMLComment removes a # comment that is outside any string.
func stripTOMLComment(s string) string {
	inBasic, inLiteral := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inBasic:
			if c == '\\' {
				i++
			} else if c == '"' {
				inBasic = false
			}
		case inLiteral:
			if c == '\'' {
				inLiteral = false
			}
		case c == '"':
			inBasic = true
		case c == '\'':
			inLiteral = true
		case c == '#':
			return s[:i]
		}
	}
	return s
}

func indexTOMLEquals(s string) int {
	inBasic, inLiteral := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inBasic:
			if c == '\\' {
				i++
			} else if c == '"' {
				inBasic = false
			}
		case inLiteral:
			if c == '\'' {
				inLiteral = false
			}
		case c == '"':
			inBasic = true
		case c == '\'':
			inLiteral = true
		case c == '=':
			return i
		}
	}
	return -1
}

func parseTOMLKeyPath(s string) ([]string, error) {
	var out []string
	for _, part := range splitTOMLDotted(s) {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty key in path %q", s)
		}
		if strings.HasPrefix(part, "\"") {
			v, _, err := parseTOMLBasicString(part)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		out = append(out, part)
	}
	return out, nil
}

// splitTOMLDotted splits on dots outside quoted keys.
func splitTOMLDotted(s string) []string {
	var out []string
	var cur strings.Builder
	inBasic, inLiteral := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inBasic:
			cur.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			} else if c == '"' {
				inBasic = false
			}
		case inLiteral:
			cur.WriteByte(c)
			if c == '\'' {
				inLiteral = false
			}
		case c == '"':
			inBasic = true
			cur.WriteByte(c)
		case c == '\'':
			inLiteral = true
			cur.WriteByte(c)
		case c == '.':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}

// parseTOMLValue parses one value at the start of s, returning the
// value and the unconsumed remainder.
func parseTOMLValue(s string) (any, string, error) {
	if s == "" {
		return nil, "", fmt.Errorf("missing value")
	}
	switch {
	case strings.HasPrefix(s, "\""):
		if strings.HasPrefix(s, "\"\"\"") {
			return nil, "", fmt.Errorf("multiline strings are not supported by the Go TOML subset")
		}
		return parseTOMLBasicString(s)
	case strings.HasPrefix(s, "'"):
		if strings.HasPrefix(s, "'''") {
			return nil, "", fmt.Errorf("multiline strings are not supported by the Go TOML subset")
		}
		end := strings.Index(s[1:], "'")
		if end < 0 {
			return nil, "", fmt.Errorf("unterminated literal string")
		}
		return s[1 : 1+end], s[1+end+1:], nil
	case strings.HasPrefix(s, "{"):
		return parseTOMLInlineTable(s)
	case strings.HasPrefix(s, "["):
		return parseTOMLArray(s)
	default:
		// Bare token: read to the next top-level , } ] or whitespace run.
		end := len(s)
		for i := 0; i < len(s); i++ {
			if s[i] == ',' || s[i] == '}' || s[i] == ']' || s[i] == ' ' || s[i] == '\t' {
				end = i
				break
			}
		}
		tok := s[:end]
		switch tok {
		case "true":
			return true, s[end:], nil
		case "false":
			return false, s[end:], nil
		}
		if n, err := strconv.ParseInt(strings.ReplaceAll(tok, "_", ""), 0, 64); err == nil {
			return n, s[end:], nil
		}
		if f, err := strconv.ParseFloat(strings.ReplaceAll(tok, "_", ""), 64); err == nil {
			return f, s[end:], nil
		}
		return nil, "", fmt.Errorf("unsupported value %q", tok)
	}
}

func parseTOMLBasicString(s string) (string, string, error) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			return b.String(), s[i+1:], nil
		}
		if c == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'u':
				if i+4 < len(s) {
					if n, err := strconv.ParseInt(s[i+1:i+5], 16, 32); err == nil {
						b.WriteRune(rune(n))
						i += 4
						continue
					}
				}
				return "", "", fmt.Errorf("bad \\u escape")
			default:
				return "", "", fmt.Errorf("bad escape \\%c", s[i])
			}
			continue
		}
		b.WriteByte(c)
	}
	return "", "", fmt.Errorf("unterminated string")
}

func parseTOMLInlineTable(s string) (*tomlTable, string, error) {
	tbl := newTomlTable()
	rest := strings.TrimSpace(s[1:])
	if strings.HasPrefix(rest, "}") {
		return tbl, rest[1:], nil
	}
	for {
		eq := indexTOMLEquals(rest)
		if eq < 0 {
			return nil, "", fmt.Errorf("malformed inline table")
		}
		path, err := parseTOMLKeyPath(strings.TrimSpace(rest[:eq]))
		if err != nil {
			return nil, "", err
		}
		val, r, err := parseTOMLValue(strings.TrimSpace(rest[eq+1:]))
		if err != nil {
			return nil, "", err
		}
		parent := tbl
		if len(path) > 1 {
			parent = tbl.navigate(path[:len(path)-1], true)
		}
		parent.set(path[len(path)-1], val)
		rest = strings.TrimSpace(r)
		if strings.HasPrefix(rest, ",") {
			rest = strings.TrimSpace(rest[1:])
			continue
		}
		if strings.HasPrefix(rest, "}") {
			return tbl, rest[1:], nil
		}
		return nil, "", fmt.Errorf("malformed inline table")
	}
}

func parseTOMLArray(s string) ([]any, string, error) {
	var out []any
	rest := strings.TrimSpace(s[1:])
	if strings.HasPrefix(rest, "]") {
		return out, rest[1:], nil
	}
	for {
		val, r, err := parseTOMLValue(rest)
		if err != nil {
			return nil, "", err
		}
		out = append(out, val)
		rest = strings.TrimSpace(r)
		if strings.HasPrefix(rest, ",") {
			rest = strings.TrimSpace(rest[1:])
			if strings.HasPrefix(rest, "]") { // trailing comma
				return out, rest[1:], nil
			}
			continue
		}
		if strings.HasPrefix(rest, "]") {
			return out, rest[1:], nil
		}
		return nil, "", fmt.Errorf("malformed array")
	}
}

// stringifyTOML renders the document confbox-style: scalar entries of
// a table first (insertion order), then each sub-table under its own
// [dotted.header], depth-first.
func stringifyTOML(root *tomlTable) string {
	var b strings.Builder
	writeTOMLTable(&b, root, nil)
	return b.String()
}

func writeTOMLTable(b *strings.Builder, t *tomlTable, path []string) {
	if len(path) > 0 {
		b.WriteString("[" + strings.Join(path, ".") + "]\n")
	}
	for _, k := range t.order {
		if _, isTbl := t.vals[k].(*tomlTable); isTbl {
			continue
		}
		b.WriteString(k + " = " + tomlValueString(t.vals[k]) + "\n")
	}
	for _, k := range t.order {
		if ct, isTbl := t.vals[k].(*tomlTable); isTbl {
			b.WriteString("\n")
			writeTOMLTable(b, ct, append(append([]string{}, path...), k))
		}
	}
}

func tomlValueString(v any) string {
	switch x := v.(type) {
	case string:
		return strconv.Quote(x)
	case bool:
		return strconv.FormatBool(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		s := strconv.FormatFloat(x, 'g', -1, 64)
		if !strings.ContainsAny(s, ".e") {
			s += ".0"
		}
		return s
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = tomlValueString(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *tomlTable:
		parts := make([]string, 0, len(x.order))
		for _, k := range x.order {
			parts = append(parts, k+" = "+tomlValueString(x.vals[k]))
		}
		return "{ " + strings.Join(parts, ", ") + " }"
	}
	return strconv.Quote(fmt.Sprint(v))
}
