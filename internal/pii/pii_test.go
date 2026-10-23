package pii_test

import (
	"testing"

	"9router-go/internal/pii"
)

func TestRedactText(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		opts  pii.Options
		want  string
		count int
	}{
		// --- emails ---
		{"email basic", "mail me at alice.nguyen@example.com ok", pii.Options{}, "mail me at [EMAIL] ok", 1},
		{"email plus tag + subdomain", "bob+promo@mail.example.co.uk", pii.Options{}, "[EMAIL]", 1},
		{"email trailing punctuation", "mail: alice@example.com.", pii.Options{}, "mail: [EMAIL].", 1},

		// --- phones: VN domestic ---
		{"vn phone plain", "call 0912345678 now", pii.Options{}, "call [PHONE] now", 1},
		{"vn phone spaces", "0912 345 678", pii.Options{}, "[PHONE]", 1},
		{"vn phone dots", "0912.345.678", pii.Options{}, "[PHONE]", 1},
		{"vn phone dashes", "0987-654-321", pii.Options{}, "[PHONE]", 1},
		// --- phones: +84 ---
		{"vn intl plain", "+84912345678", pii.Options{}, "[PHONE]", 1},
		{"vn intl spaces", "+84 912 345 678", pii.Options{}, "[PHONE]", 1},
		{"vn intl dots", "+84.912.345.678", pii.Options{}, "[PHONE]", 1},
		// --- phones: generic international ---
		{"intl us spaced", "+1 202 555 0123", pii.Options{}, "[PHONE]", 1},
		{"intl uk plain", "+442071234567", pii.Options{}, "[PHONE]", 1},
		{"intl jp dashes", "+81-3-1234-5678", pii.Options{}, "[PHONE]", 1},

		// --- credit cards (Luhn-valid) ---
		{"card spaces", "card 4111 1111 1111 1111 end", pii.Options{}, "card [CARD] end", 1},
		{"card contiguous", "4111111111111111", pii.Options{}, "[CARD]", 1},
		{"card dashes", "4111-1111-1111-1111", pii.Options{}, "[CARD]", 1},
		{"card amex 15", "378282246310005", pii.Options{}, "[CARD]", 1},
		{"card mc", "5500005555555559", pii.Options{}, "[CARD]", 1},
		// --- credit cards (Luhn-invalid → untouched) ---
		{"card bad check digit", "4111 1111 1111 1112", pii.Options{}, "4111 1111 1111 1112", 0},
		{"card 13-digit non-luhn", "1234567890123", pii.Options{}, "1234567890123", 0},
		{"card 14-digit non-luhn", "12345678901234", pii.Options{}, "12345678901234", 0},

		// --- API-key-like tokens ---
		{"openai key", "key sk-proj-AbCdEfGh1234567890IjKl done", pii.Options{}, "key [API_KEY] done", 1},
		{"openai key bare", "sk-1234567890abcdef", pii.Options{}, "[API_KEY]", 1},
		{"github pat classic", "ghp_1234567890abcdefghijklmnopqrstuvwx", pii.Options{}, "[API_KEY]", 1},
		{"github pat fine", "github_pat_11ABCDEFG0aBcDeFgHiJkL_mNoPqRsTuVwXyZ1234", pii.Options{}, "[API_KEY]", 1},
		{"aws key id", "AKIAIOSFODNN7EXAMPLE", pii.Options{}, "[API_KEY]", 1},
		{"slack token", "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUv", pii.Options{}, "[API_KEY]", 1},
		{"jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", pii.Options{}, "[API_KEY]", 1},
		{"bearer", "Authorization: Bearer abcdef1234567890token", pii.Options{}, "Authorization: [API_KEY]", 1},
		{"bearer lowercase", "bearer xyz123456789", pii.Options{}, "[API_KEY]", 1},
		{"bearer jwt single replacement", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature123", pii.Options{}, "[API_KEY]", 1},
		{"bearer too short untouched", "Bearer abc", pii.Options{}, "Bearer abc", 0},

		// --- national ID: opt-in ---
		{"national id off by default", "cccd 001234567890", pii.Options{}, "cccd 001234567890", 0},
		{"national id on", "cccd 001234567890", pii.Options{NationalID: true}, "cccd [NATIONAL_ID]", 1},
		{"national id glued to longer run stays", "id:1234567890123", pii.Options{NationalID: true}, "id:1234567890123", 0},
		{"national id separated 12 digits stays", "4111 1111 1111", pii.Options{NationalID: true}, "4111 1111 1111", 0},

		// --- tricky negatives: must survive ---
		{"date survives", "shipped on 2026-10-23 today", pii.Options{}, "shipped on 2026-10-23 today", 0},
		{"datetime survives", "at 2026-10-23 05:01:10 sharp", pii.Options{}, "at 2026-10-23 05:01:10 sharp", 0},
		{"order number survives", "order 12345678 confirmed", pii.Options{}, "order 12345678 confirmed", 0},
		{"order dashed survives", "order #20261023-00123", pii.Options{}, "order #20261023-00123", 0},
		{"short digit runs survive", "pin 1234 and code 567890", pii.Options{}, "pin 1234 and code 567890", 0},
		{"landline 11 digits survives", "02412345678", pii.Options{}, "02412345678", 0},
		{"short phone fragment survives", "call 0903 back", pii.Options{}, "call 0903 back", 0},
		{"version string survives", "release v1.2.3 build 4567", pii.Options{}, "release v1.2.3 build 4567", 0},
		{"plain text", "hello world, no secrets here", pii.Options{}, "hello world, no secrets here", 0},
		{"empty", "", pii.Options{}, "", 0},

		// --- mixed ---
		{"mixed four", "mail alice@example.com, call 0912345678, card 4111111111111111, key sk-1234567890abcdef",
			pii.Options{}, "mail [EMAIL], call [PHONE], card [CARD], key [API_KEY]", 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, n := pii.RedactText(tc.in, tc.opts)
			if got != tc.want {
				t.Fatalf("RedactText(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if n != tc.count {
				t.Fatalf("RedactText(%q) count = %d, want %d", tc.in, n, tc.count)
			}
		})
	}
}

func TestRedactBodyWalk(t *testing.T) {
	body := map[string]any{
		"model":  "openai/gpt-x",
		"system": "Admin contact: admin@example.com",
		"messages": []any{
			map[string]any{"role": "user", "content": "my phone is 0912345678"},
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "text", "text": "charged card 4111 1111 1111 1111 today"},
			}},
			map[string]any{"role": "tool", "content": "result sent to alice@example.com"},
			map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": "token ghp_1234567890abcdefghijklmnopqrstuvwx"},
				map[string]any{"type": "text", "text": "and my key sk-1234567890abcdef"},
			}},
		},
		"input": []any{
			map[string]any{"type": "function_call_output", "call_id": "c1", "output": "call me at +84 912 345 678"},
		},
		"contents": []any{
			map[string]any{"role": "user", "parts": []any{
				map[string]any{"text": "gemini contact bob@example.com"},
				map[string]any{"functionResponse": map[string]any{
					"name":     "lookup",
					"response": map[string]any{"note": "reach carol@example.com"},
				}},
			}},
		},
	}

	n := pii.RedactBody(body, pii.Options{})
	if n != 9 {
		t.Fatalf("RedactBody count = %d, want 9", n)
	}
	if got := body["system"]; got != "Admin contact: [EMAIL]" {
		t.Fatalf("system = %v", got)
	}
	if got := body["model"]; got != "openai/gpt-x" {
		t.Fatalf("model must be untouched, got %v", got)
	}
	msgs := body["messages"].([]any)
	if got := msgs[0].(map[string]any)["content"]; got != "my phone is [PHONE]" {
		t.Fatalf("user content = %v", got)
	}
	assistantParts := msgs[1].(map[string]any)["content"].([]any)
	if got := assistantParts[0].(map[string]any)["text"]; got != "charged card [CARD] today" {
		t.Fatalf("assistant text = %v", got)
	}
	if got := msgs[2].(map[string]any)["content"]; got != "result sent to [EMAIL]" {
		t.Fatalf("tool content = %v", got)
	}
	userParts := msgs[3].(map[string]any)["content"].([]any)
	if got := userParts[0].(map[string]any)["content"]; got != "token [API_KEY]" {
		t.Fatalf("tool_result content = %v", got)
	}
	if got := userParts[0].(map[string]any)["tool_use_id"]; got != "t1" {
		t.Fatalf("tool_use_id must be untouched, got %v", got)
	}
	if got := userParts[1].(map[string]any)["text"]; got != "and my key [API_KEY]" {
		t.Fatalf("user text part = %v", got)
	}
	input := body["input"].([]any)
	if got := input[0].(map[string]any)["output"]; got != "call me at [PHONE]" {
		t.Fatalf("function_call_output = %v", got)
	}
	contents := body["contents"].([]any)
	parts := contents[0].(map[string]any)["parts"].([]any)
	if got := parts[0].(map[string]any)["text"]; got != "gemini contact [EMAIL]" {
		t.Fatalf("gemini text = %v", got)
	}
	fr := parts[1].(map[string]any)["functionResponse"].(map[string]any)
	if got := fr["response"].(map[string]any)["note"]; got != "reach [EMAIL]" {
		t.Fatalf("functionResponse note = %v", got)
	}
}

func TestRedactBodyMalformed(t *testing.T) {
	if n := pii.RedactBody(nil, pii.Options{}); n != 0 {
		t.Fatalf("nil body count = %d, want 0", n)
	}
	weird := map[string]any{
		"messages": []any{
			nil, "oops", 42.0,
			map[string]any{"content": nil},
			map[string]any{"content": []any{nil, "x", map[string]any{"text": 5.0}}},
			map[string]any{"role": "user"}, // no content at all
		},
		"contents": "not-an-array",
		"system":   123.0,
		"input":    []any{map[string]any{"output": []any{map[string]any{"text": "mail a@b.co"}}}},
	}
	// Must not panic; the one well-formed nested text is still redacted.
	n := pii.RedactBody(weird, pii.Options{})
	if n != 1 {
		t.Fatalf("malformed body count = %d, want 1", n)
	}
}
