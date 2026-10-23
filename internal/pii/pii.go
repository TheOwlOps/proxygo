// Package pii redacts personally identifiable information and leaked
// credentials from LLM request bodies before they are sent upstream
// (Feature Pack F6). It is an additive, opt-in feature of the Go port —
// not a port of any JS behaviour.
//
// Fail-open by design (mirrors internal/rtk): RedactBody never panics
// and never fails a request; malformed bodies are left untouched.
//
// Conservative by design: every pattern is anchored to a recognisable
// shape, credit-card candidates must pass the Luhn checksum, phone
// candidates must not be glued to other digits, and 12-digit VN
// national IDs are only redacted when explicitly enabled (they are too
// easily confused with order/tracking numbers). When in doubt, don't
// redact.
package pii

import (
	"regexp"
	"strings"
)

// Options controls optional, higher-false-positive redaction classes.
type Options struct {
	// NationalID enables redaction of 12-digit VN national IDs (CCCD).
	// Default false (settings key piiRedactNationalId).
	NationalID bool
}

// Replacement markers.
const (
	MarkerEmail      = "[EMAIL]"
	MarkerPhone      = "[PHONE]"
	MarkerCard       = "[CARD]"
	MarkerAPIKey     = "[API_KEY]"
	MarkerNationalID = "[NATIONAL_ID]"
)

var (
	// Bearer credentials first: the pattern consumes the token so the
	// whole "Bearer <token>" becomes a single [API_KEY].
	reBearer = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9\-._~+/=]{8,}`)
	// JWTs: header and payload segments are base64url of JSON objects,
	// so both start with "eyJ".
	reJWT = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	// OpenAI-style keys (sk-…, incl. sk-proj-… / sk-ant-…).
	reOpenAIKey = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{10,}`)
	// GitHub tokens: classic PATs/OAuth/app tokens + fine-grained PATs.
	reGitHubKey  = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`)
	reGitHubFine = regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`)
	// AWS access key IDs.
	reAWSKey = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	// Slack tokens.
	reSlackKey = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`)

	reEmail = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

	// Credit-card candidate: 13–19 digits with optional single space or
	// dash separators. Candidates are Luhn-validated before replacing.
	reCardCandidate = regexp.MustCompile(`\d(?:[ -]?\d){12,18}`)
	// 12-digit VN national ID candidate (contiguous digits only).
	reNationalIDCandidate = regexp.MustCompile(`\d{12}`)
	// +84 VN numbers: +84 followed by 9 digits, optional separators.
	rePhoneVNIntl = regexp.MustCompile(`\+84[ .-]?\d(?:[ .-]?\d){8}`)
	// Generic international: + followed by 8–15 digits (E.164 bounds),
	// optional separators.
	rePhoneIntl = regexp.MustCompile(`\+\d(?:[ .-]?\d){7,14}`)
	// VN domestic mobile: 0 + 9 digits, optional separators. The second
	// digit is validated against the VN mobile prefixes (03/05/07/08/09).
	rePhoneVN = regexp.MustCompile(`0\d(?:[ .-]?\d){8}`)
)

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func digitsOnly(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// luhnValid reports whether a string of digits passes the Luhn checksum.
func luhnValid(digits string) bool {
	if len(digits) == 0 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum > 0 && sum%10 == 0
}

// replaceValidated splices replacements into s for matches of re that
// are not glued to a digit on either side and that validate accepts.
// validate returns the replacement text, or ok=false to keep the match.
func replaceValidated(s string, re *regexp.Regexp, validate func(match string) (string, bool)) (string, int) {
	idx := re.FindAllStringIndex(s, -1)
	if len(idx) == 0 {
		return s, 0
	}
	var b strings.Builder
	last := 0
	n := 0
	for _, m := range idx {
		start, end := m[0], m[1]
		if start > 0 && isDigit(s[start-1]) {
			continue // part of a longer digit run — not a standalone value
		}
		if end < len(s) && isDigit(s[end]) {
			continue
		}
		repl, ok := validate(s[start:end])
		if !ok {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(repl)
		last = end
		n++
	}
	if n == 0 {
		return s, 0
	}
	b.WriteString(s[last:])
	return b.String(), n
}

// RedactText redacts one string and returns the result plus the number
// of replacements made.
func RedactText(s string, opts Options) (string, int) {
	if s == "" {
		return s, 0
	}
	total := 0
	apply := func(re *regexp.Regexp, marker string) {
		s = re.ReplaceAllStringFunc(s, func(string) string {
			total++
			return marker
		})
	}

	// Credentials first (Bearer consumes its token whole).
	apply(reBearer, MarkerAPIKey)
	apply(reJWT, MarkerAPIKey)
	apply(reOpenAIKey, MarkerAPIKey)
	apply(reGitHubKey, MarkerAPIKey)
	apply(reGitHubFine, MarkerAPIKey)
	apply(reAWSKey, MarkerAPIKey)
	apply(reSlackKey, MarkerAPIKey)

	apply(reEmail, MarkerEmail)

	// Credit cards: candidate shape + digit count + Luhn.
	var n int
	s, n = replaceValidated(s, reCardCandidate, func(match string) (string, bool) {
		digits := digitsOnly(match)
		if len(digits) < 13 || len(digits) > 19 || !luhnValid(digits) {
			return "", false
		}
		return MarkerCard, true
	})
	total += n

	// VN national ID (opt-in only).
	if opts.NationalID {
		s, n = replaceValidated(s, reNationalIDCandidate, func(string) (string, bool) {
			return MarkerNationalID, true
		})
		total += n
	}

	// Phones: most specific shapes first.
	s, n = replaceValidated(s, rePhoneVNIntl, func(match string) (string, bool) {
		if len(digitsOnly(match)) != 11 {
			return "", false
		}
		return MarkerPhone, true
	})
	total += n
	s, n = replaceValidated(s, rePhoneIntl, func(match string) (string, bool) {
		if d := len(digitsOnly(match)); d < 8 || d > 15 {
			return "", false
		}
		return MarkerPhone, true
	})
	total += n
	s, n = replaceValidated(s, rePhoneVN, func(match string) (string, bool) {
		digits := digitsOnly(match)
		if len(digits) != 10 {
			return "", false
		}
		switch digits[1] {
		case '3', '5', '7', '8', '9': // VN mobile prefixes
			return MarkerPhone, true
		}
		return "", false
	})
	total += n

	return s, total
}

// RedactBody walks a chat request body in place and redacts PII in
// message content strings across the OpenAI / Claude / Gemini shapes
// (including tool-result content). It returns the total number of
// replacements. It never panics: a malformed body is left as-is
// (fail-open, like RTK).
func RedactBody(body map[string]any, opts Options) (count int) {
	if body == nil {
		return 0
	}
	defer func() { _ = recover() }()

	// Claude top-level system prompt (string or text blocks).
	if v, ok := body["system"]; ok {
		body["system"] = redactContent(v, opts, &count)
	}
	// OpenAI / Claude messages; OpenAI Responses input items.
	for _, key := range []string{"messages", "input"} {
		if items, ok := body[key].([]any); ok {
			redactItems(items, opts, &count)
		}
	}
	// Gemini contents + system instruction.
	if items, ok := body["contents"].([]any); ok {
		redactGeminiItems(items, opts, &count)
	}
	for _, key := range []string{"systemInstruction", "system_instruction"} {
		if si, ok := body[key].(map[string]any); ok {
			redactGeminiItems([]any{si}, opts, &count)
		}
	}
	return count
}

// redactItems handles OpenAI/Claude message items and OpenAI Responses
// input items: the item's "content" (string or parts) and, for
// function_call_output items, its "output" (string or parts).
func redactItems(items []any, opts Options, count *int) {
	for _, raw := range items {
		msg, ok := raw.(map[string]any)
		if !ok || msg == nil {
			continue
		}
		if v, ok := msg["content"]; ok {
			msg["content"] = redactContent(v, opts, count)
		}
		if v, ok := msg["output"]; ok {
			msg["output"] = redactContent(v, opts, count)
		}
	}
}

// redactContent redacts a content value: a plain string, or an array of
// content parts (handled by redactPart).
func redactContent(v any, opts Options, count *int) any {
	switch c := v.(type) {
	case string:
		out, n := RedactText(c, opts)
		*count += n
		return out
	case []any:
		for i, p := range c {
			c[i] = redactPart(p, opts, count)
		}
		return c
	}
	return v
}

// redactPart redacts one content part. Text-bearing keys across the
// shapes: "text" (text / input_text / output_text parts, Gemini text
// parts) and "content" (Claude tool_result blocks: a string or nested
// text parts).
func redactPart(p any, opts Options, count *int) any {
	part, ok := p.(map[string]any)
	if !ok || part == nil {
		return p
	}
	if v, ok := part["text"]; ok {
		part["text"] = redactContent(v, opts, count)
	}
	if v, ok := part["content"]; ok {
		part["content"] = redactContent(v, opts, count)
	}
	return part
}

// redactGeminiItems handles Gemini contents: each content's "parts"
// carry "text" strings; functionResponse parts carry free-form tool
// results, deep-walked for strings.
func redactGeminiItems(items []any, opts Options, count *int) {
	for _, raw := range items {
		content, ok := raw.(map[string]any)
		if !ok || content == nil {
			continue
		}
		parts, ok := content["parts"].([]any)
		if !ok {
			continue
		}
		for _, praw := range parts {
			part, ok := praw.(map[string]any)
			if !ok || part == nil {
				continue
			}
			if v, ok := part["text"].(string); ok {
				out, n := RedactText(v, opts)
				*count += n
				part["text"] = out
			}
			for _, key := range []string{"functionResponse", "function_response"} {
				if fr, ok := part[key].(map[string]any); ok {
					if rv, ok := fr["response"]; ok {
						fr["response"] = redactDeep(rv, opts, count)
					}
				}
			}
		}
	}
}

// redactDeep redacts every string leaf of a free-form JSON value (used
// for Gemini functionResponse payloads).
func redactDeep(v any, opts Options, count *int) any {
	switch t := v.(type) {
	case string:
		out, n := RedactText(t, opts)
		*count += n
		return out
	case []any:
		for i, e := range t {
			t[i] = redactDeep(e, opts, count)
		}
		return t
	case map[string]any:
		for k, e := range t {
			t[k] = redactDeep(e, opts, count)
		}
		return t
	}
	return v
}
