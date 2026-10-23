package cli

import (
	"strconv"
	"strings"
)

// Oh My Pi models.yml handling. The JS uses confbox (full YAML); the
// Go port treats the file as text and surgically replaces/removes
// only the providers.9router block by indentation — other providers
// and comments survive byte-for-byte (the same text-op approach the
// dashboard port uses for Hermes YAML in internal/api/clitools.go).

type yamlLine struct {
	raw     string
	indent  int
	content string // trimmed of indent and trailing space
	blank   bool
}

func yamlLines(text string) []yamlLine {
	parts := strings.Split(text, "\n")
	out := make([]yamlLine, len(parts))
	for i, p := range parts {
		trimmed := strings.TrimRight(p, " \t\r")
		indent := 0
		for indent < len(trimmed) && trimmed[indent] == ' ' {
			indent++
		}
		out[i] = yamlLine{raw: p, indent: indent, content: strings.TrimSpace(trimmed), blank: strings.TrimSpace(trimmed) == ""}
	}
	return out
}

// yamlBlockSpan returns [start, end) line indexes of the block opened
// at line `at` (children = following lines with greater indent; blank
// lines belong to the block).
func yamlBlockSpan(lines []yamlLine, at int) (int, int) {
	base := lines[at].indent
	end := at + 1
	for end < len(lines) {
		l := lines[end]
		if !l.blank && l.indent <= base {
			break
		}
		end++
	}
	return at, end
}

func yamlFindKey(lines []yamlLine, from, to, indent int, key string) int {
	for i := from; i < to && i < len(lines); i++ {
		if !lines[i].blank && lines[i].indent == indent && lines[i].content == key+":" {
			return i
		}
	}
	return -1
}

// ompProviders locates the top-level providers: block and its child
// indent. Returns (-1, -1, 2) when absent.
func ompProviders(lines []yamlLine) (header, end, childIndent int) {
	for i, l := range lines {
		if !l.blank && l.indent == 0 && l.content == "providers:" {
			_, e := yamlBlockSpan(lines, i)
			ci := 2
			for j := i + 1; j < e; j++ {
				if !lines[j].blank {
					ci = lines[j].indent
					break
				}
			}
			return i, e, ci
		}
	}
	return -1, -1, 2
}

func ompScalar(s string) string {
	if s == "" {
		return `""`
	}
	needsQuote := strings.Contains(s, ": ") || strings.Contains(s, " #") ||
		strings.TrimSpace(s) != s
	if !needsQuote && len(s) > 0 {
		switch s[0] {
		case '!', '&', '*', '?', '|', '>', '%', '@', '`', '"', '\'', '#', ',', '[', ']', '{', '}':
			needsQuote = true
		}
	}
	if needsQuote {
		return strconv.Quote(s)
	}
	return s
}

func ompUnscalar(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}

// ompRead9Router extracts the providers.9router scalar values
// (baseUrl, apiKey, discovery.type) from models.yml text.
func ompRead9Router(text string) map[string]string {
	out := map[string]string{}
	lines := yamlLines(text)
	hdr, end, ci := ompProviders(lines)
	if hdr < 0 {
		return out
	}
	at := yamlFindKey(lines, hdr+1, end, ci, "9router")
	if at < 0 {
		return out
	}
	_, bEnd := yamlBlockSpan(lines, at)
	// Direct children: minimal indent among non-blank lines after the header.
	childIndent := -1
	for j := at + 1; j < bEnd; j++ {
		if !lines[j].blank {
			childIndent = lines[j].indent
			break
		}
	}
	if childIndent < 0 {
		return out
	}
	for j := at + 1; j < bEnd; j++ {
		l := lines[j]
		if l.blank || l.indent != childIndent {
			continue
		}
		if strings.HasPrefix(l.content, "discovery:") {
			_, dEnd := yamlBlockSpan(lines, j)
			for k := j + 1; k < dEnd; k++ {
				if !lines[k].blank && strings.HasPrefix(lines[k].content, "type:") {
					out["discovery.type"] = ompUnscalar(strings.TrimPrefix(lines[k].content, "type:"))
				}
			}
			continue
		}
		if idx := strings.Index(l.content, ":"); idx > 0 {
			key := l.content[:idx]
			if key == "baseUrl" || key == "apiKey" {
				out[key] = ompUnscalar(l.content[idx+1:])
			}
		}
	}
	return out
}

func ompBlockLines(pad string, ctx toolCtx) []string {
	inner := pad + "  "
	return []string{
		pad + "9router:",
		inner + "baseUrl: " + ompScalar(v1(ctx.BaseURL)),
		inner + "apiKey: " + ompScalar(ctx.APIKey),
		inner + "api: openai-completions",
		inner + "authHeader: true",
		inner + "disableStrictTools: true",
		inner + "discovery:",
		inner + "  type: proxy",
	}
}

func joinYAML(lines []string) string {
	s := strings.Join(lines, "\n")
	// Trim trailing blank lines, end with exactly one newline
	// (an entirely empty document stays empty, like confbox "{}"→"").
	s = strings.TrimRight(s, "\n")
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return s + "\n"
}

// ompApply9Router returns the file text with providers.9router set to
// the 9router block (replaced in place or inserted).
func ompApply9Router(text string, ctx toolCtx) string {
	lines := yamlLines(text)
	raws := make([]string, len(lines))
	for i, l := range lines {
		raws[i] = l.raw
	}
	// Drop the synthetic trailing element Split adds for a final \n.
	if len(raws) > 0 && raws[len(raws)-1] == "" {
		raws = raws[:len(raws)-1]
		lines = lines[:len(lines)-1]
	}
	hdr, end, ci := ompProviders(lines)
	pad := strings.Repeat(" ", ci)
	block := ompBlockLines(pad, ctx)
	if hdr < 0 {
		out := append(append([]string{}, raws...), "providers:")
		out = append(out, block...)
		return joinYAML(out)
	}
	if at := yamlFindKey(lines, hdr+1, end, ci, "9router"); at >= 0 {
		_, bEnd := yamlBlockSpan(lines, at)
		out := append([]string{}, raws[:at]...)
		out = append(out, block...)
		out = append(out, raws[bEnd:]...)
		return joinYAML(out)
	}
	out := append([]string{}, raws[:hdr+1]...)
	out = append(out, block...)
	out = append(out, raws[hdr+1:]...)
	return joinYAML(out)
}

// ompRemove9Router removes the providers.9router block (and the
// providers: header when nothing remains under it).
func ompRemove9Router(text string) (string, bool) {
	lines := yamlLines(text)
	raws := make([]string, len(lines))
	for i, l := range lines {
		raws[i] = l.raw
	}
	if len(raws) > 0 && raws[len(raws)-1] == "" {
		raws = raws[:len(raws)-1]
		lines = lines[:len(lines)-1]
	}
	hdr, end, ci := ompProviders(lines)
	if hdr < 0 {
		return text, false
	}
	at := yamlFindKey(lines, hdr+1, end, ci, "9router")
	if at < 0 {
		return text, false
	}
	_, bEnd := yamlBlockSpan(lines, at)
	out := append([]string{}, raws[:at]...)
	out = append(out, raws[bEnd:]...)
	// If providers: has no children left, drop the header too.
	lines2 := yamlLines(strings.Join(out, "\n"))
	hdr2, end2, _ := ompProviders(lines2)
	if hdr2 >= 0 {
		hasChild := false
		for j := hdr2 + 1; j < end2; j++ {
			if !lines2[j].blank {
				hasChild = true
				break
			}
		}
		if !hasChild {
			out = append(out[:hdr2], out[end2:]...)
		}
	}
	return joinYAML(out), true
}
