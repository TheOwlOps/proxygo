// Package rtk is the Go port of open-sse/rtk/ (9Router v0.5.104):
// compress tool_result content in LLM request bodies before translation.
//
// Fail-open by design (mirrors the JS): any panic/error inside a filter or
// in CompressMessages leaves the body untouched — RTK must never break a
// request. Error tool results are preserved verbatim (is_error blocks and
// Kiro status:"error" results are skipped).
//
// Length semantics: the JS measures text with String.length (UTF-16 code
// units). Go uses rune counts here, which match for the BMP; astral-plane
// characters count 1 instead of 2 — stats/min-size thresholds can differ
// by that much on emoji-heavy payloads, compression behaviour is the same.
package rtk

import (
	"fmt"
	"strings"
)

// Constants mirror open-sse/rtk/constants.js (Rust parity values).
const (
	RawCap           = 10 * 1024 * 1024 // RAW_CAP: skip blobs above this
	MinCompressSize  = 500              // MIN_COMPRESS_SIZE
	DetectWindow     = 1024             // DETECT_WINDOW: autodetect peek
	GitDiffHunkMax   = 100              // GIT_DIFF_HUNK_MAX_LINES
	GitLogMaxLines   = 200              // GIT_LOG_MAX_LINES
	DedupLineMax     = 2000             // DEDUP_LINE_MAX
	GrepPerFileMax   = 10               // GREP_PER_FILE_MAX
	FindPerDirMax    = 10               // FIND_PER_DIR_MAX
	FindTotalDirMax  = 20               // FIND_TOTAL_DIR_MAX
	StatusMaxFiles   = 10               // STATUS_MAX_FILES
	StatusMaxUntrack = 10               // STATUS_MAX_UNTRACKED
	LSExtSummaryTop  = 5                // LS_EXT_SUMMARY_TOP
	TreeMaxLines     = 200              // TREE_MAX_LINES
	SearchPerDirMax  = 10               // SEARCH_LIST_PER_DIR_MAX
	SearchTotalDirs  = 20               // SEARCH_LIST_TOTAL_DIR_MAX
	TruncateHead     = 120              // SMART_TRUNCATE_HEAD
	TruncateTail     = 60               // SMART_TRUNCATE_TAIL
	TruncateMinLines = 250              // SMART_TRUNCATE_MIN_LINES
	ReadNumberedMin  = 0.7              // READ_NUMBERED_MIN_HIT_RATIO
)

// Filter names (constants.js FILTERS).
const (
	FilterGitDiff       = "git-diff"
	FilterGitStatus     = "git-status"
	FilterGitLog        = "git-log"
	FilterGrep          = "grep"
	FilterFind          = "find"
	FilterLS            = "ls"
	FilterTree          = "tree"
	FilterDedupLog      = "dedup-log"
	FilterSmartTruncate = "smart-truncate"
	FilterReadNumbered  = "read-numbered"
	FilterSearchList    = "search-list"
	FilterBuildOutput   = "build-output"
)

// jsLen measures a string the way JS String.length approximately does
// (rune count; see package doc for the astral-plane caveat).
func jsLen(s string) int { return len([]rune(s)) }

// head returns the first DetectWindow runes of s (JS slice on the string).
func headOf(s string) string {
	r := []rune(s)
	if len(r) > DetectWindow {
		return string(r[:DetectWindow])
	}
	return s
}

// Hit records one compressed text (index.js stats.hits entry).
type Hit struct {
	Shape  string
	Filter string
	Saved  int
}

// Stats mirrors the JS stats object returned by compressMessages.
type Stats struct {
	BytesBefore int
	BytesAfter  int
	Hits        []Hit
}

// FormatRtkLog mirrors formatRtkLog in index.js.
func FormatRtkLog(stats *Stats) string {
	if stats == nil || len(stats.Hits) == 0 {
		return ""
	}
	saved := stats.BytesBefore - stats.BytesAfter
	pct := "0"
	if stats.BytesBefore > 0 {
		pct = fmt.Sprintf("%.1f", float64(saved)/float64(stats.BytesBefore)*100)
	}
	seen := map[string]bool{}
	var filters []string
	for _, h := range stats.Hits {
		if !seen[h.Filter] {
			seen[h.Filter] = true
			filters = append(filters, h.Filter)
		}
	}
	return fmt.Sprintf("[RTK] saved %dB / %dB (%s%%) via [%s] hits=%d",
		saved, stats.BytesBefore, pct, strings.Join(filters, ","), len(stats.Hits))
}

// safeApply mirrors applyFilter.js: a panicking filter passes the raw
// text through unchanged.
func safeApply(fn FilterFunc, text string) (out string) {
	if fn == nil {
		return text
	}
	defer func() {
		if recover() != nil {
			out = text
		}
	}()
	return fn(text)
}

// compressText mirrors compressText in index.js.
func compressText(text string, stats *Stats, shape string) string {
	bytesIn := jsLen(text)
	stats.BytesBefore += bytesIn

	if bytesIn < MinCompressSize || bytesIn > RawCap {
		stats.BytesAfter += bytesIn
		return text
	}

	fn, name := AutoDetectFilter(text)
	if fn == nil {
		stats.BytesAfter += bytesIn
		return text
	}

	out := safeApply(fn, text)

	// Safety: never return empty, never grow the input.
	if out == "" || jsLen(out) >= bytesIn {
		stats.BytesAfter += bytesIn
		return text
	}

	stats.BytesAfter += jsLen(out)
	stats.Hits = append(stats.Hits, Hit{Shape: shape, Filter: name, Saved: bytesIn - jsLen(out)})
	return out
}

// CompressMessages mirrors compressMessages in index.js: it compresses
// tool_result content IN-PLACE and returns stats, or nil when disabled,
// when there is nothing to walk, or on any internal error (fail-open).
func CompressMessages(body map[string]any, enabled bool) (stats *Stats) {
	if !enabled || body == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			stats = nil
		}
	}()

	// Kiro format: conversationState.history + currentMessage.
	if cs, ok := body["conversationState"]; ok && cs != nil {
		return compressKiroFormat(body)
	}

	var items []any
	if msgs, ok := body["messages"].([]any); ok {
		items = msgs
	} else if input, ok := body["input"].([]any); ok {
		items = input
	}
	if items == nil {
		return nil
	}

	stats = &Stats{}
	for _, raw := range items {
		msg, ok := raw.(map[string]any)
		if !ok || msg == nil {
			continue
		}

		// Shape 4: OpenAI Responses function_call_output.
		if msg["type"] == "function_call_output" {
			switch out := msg["output"].(type) {
			case string:
				msg["output"] = compressText(out, stats, "openai-responses-string")
			case []any:
				for _, praw := range out {
					part, ok := praw.(map[string]any)
					if !ok {
						continue
					}
					if part["type"] == "input_text" {
						if text, ok := part["text"].(string); ok {
							part["text"] = compressText(text, stats, "openai-responses-array")
						}
					}
				}
			}
			continue
		}

		// Shape 1: OpenAI tool message with string content.
		if msg["role"] == "tool" {
			if content, ok := msg["content"].(string); ok {
				msg["content"] = compressText(content, stats, "openai-tool")
				continue
			}
		}

		content, ok := msg["content"].([]any)
		if !ok {
			continue
		}

		// Shape 1b: OpenAI tool message with text parts.
		if msg["role"] == "tool" {
			for _, praw := range content {
				part, ok := praw.(map[string]any)
				if !ok {
					continue
				}
				if part["type"] == "text" {
					if text, ok := part["text"].(string); ok {
						part["text"] = compressText(text, stats, "openai-tool-array")
					}
				}
			}
			continue
		}

		// Shapes 2/3: blocks with tool_result entries.
		for _, braw := range content {
			block, ok := braw.(map[string]any)
			if !ok || block["type"] != "tool_result" {
				continue
			}
			if block["is_error"] == true {
				continue // preserve error traces
			}
			switch c := block["content"].(type) {
			case string:
				block["content"] = compressText(c, stats, "claude-string")
			case []any:
				for _, praw := range c {
					part, ok := praw.(map[string]any)
					if !ok {
						continue
					}
					if part["type"] == "text" {
						if text, ok := part["text"].(string); ok {
							part["text"] = compressText(text, stats, "claude-array")
						}
					}
				}
			}
		}
	}
	return stats
}

// compressKiroFormat mirrors compressKiroFormat in index.js.
func compressKiroFormat(body map[string]any) (stats *Stats) {
	stats = &Stats{}
	defer func() {
		if recover() != nil {
			stats = nil
		}
	}()
	state, _ := body["conversationState"].(map[string]any)
	var all []any
	if state != nil {
		if hist, ok := state["history"].([]any); ok {
			all = append(all, hist...)
		}
		if cur, ok := state["currentMessage"]; ok && cur != nil {
			all = append(all, cur)
		}
	}
	for _, raw := range all {
		msg, _ := raw.(map[string]any)
		uim, _ := getMap(msg, "userInputMessage")
		ctx, _ := getMap(uim, "userInputMessageContext")
		toolResults, _ := ctx["toolResults"].([]any)
		for _, traw := range toolResults {
			tr, _ := traw.(map[string]any)
			if tr == nil {
				continue
			}
			if tr["status"] == "error" {
				continue // preserve error traces
			}
			parts, _ := tr["content"].([]any)
			for _, praw := range parts {
				part, _ := praw.(map[string]any)
				if part == nil {
					continue
				}
				if text, ok := part["text"].(string); ok {
					part["text"] = compressText(text, stats, "kiro-tool-result")
				}
			}
		}
	}
	return stats
}

// getMap reads a nested map[string]any (nil-safe).
func getMap(m map[string]any, key string) (map[string]any, bool) {
	if m == nil {
		return nil, false
	}
	sub, ok := m[key].(map[string]any)
	return sub, ok
}
