package executors

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// WindsurfExecutor ports open-sse/executors/windsurf.js: Codeium gRPC-web
// chat. Wire protocol: POST application/grpc-web+proto to
// exa.language_server_pb.LanguageServerService/GetChatMessage with a
// hand-rolled protobuf GetChatMessageRequest (Metadata{api_key, ide_name,
// ide_version, extension_version, session_id, locale}, cascade_id,
// ModelOrAlias{model_uid}, repeated ChatMessage{role, content,
// tool_call_id}). Auth: credentials.accessToken || apiKey is both the
// Bearer header and Metadata.api_key.
//
// The upstream answers gRPC-web frames (1-byte flag + BE uint32 length):
// data frames carry CompletionChunk protobufs (field1 ContentChunk text,
// field3 DoneChunk usage, field4 ErrorChunk), trailer frames (0x80) carry
// grpc-status/grpc-message. This executor converts them to an OpenAI SSE
// stream — always SSE, as in the JS (transformToSSE) — ResponseFormat
// "openai". Refresh returns nil (JS: apiKey is long-lived, refresh is
// handled out-of-band).
//
// Live-unverified: needs a real Codeium/Windsurf apiKey.
type WindsurfExecutor struct{ *Base }

const windsurfDefaultChatURL = "https://server.codeium.com/exa.language_server_pb.LanguageServerService/GetChatMessage"
const windsurfIDEName = "windsurf"
const windsurfIDEVersion = "3.14.0"
const windsurfExtVersion = "3.14.0"
const windsurfLocale = "en-US"

// windsurfModelAliasMap ports MODEL_ALIAS_MAP (catalog name → wire name).
var windsurfModelAliasMap = map[string]string{
	"swe-1.6-fast":                  "swe-1-6-fast",
	"swe-1.6":                       "swe-1-6",
	"swe-1.5-fast":                  "swe-1-5-fast",
	"swe-1.5":                       "swe-1-5",
	"claude-opus-4.7-max":           "claude-opus-4-7-max",
	"claude-opus-4.7-xhigh":         "claude-opus-4-7-xhigh",
	"claude-opus-4.7-high":          "claude-opus-4-7-high",
	"claude-opus-4.7-medium":        "claude-opus-4-7-medium",
	"claude-opus-4.7-low":           "claude-opus-4-7-low",
	"claude-opus-4.7-review":        "opus-4-7-review",
	"claude-sonnet-4.6-thinking-1m": "claude-sonnet-4-6-thinking-1m",
	"claude-sonnet-4.6-1m":          "claude-sonnet-4-6-1m",
	"claude-sonnet-4.6-thinking":    "claude-sonnet-4-6-thinking",
	"claude-sonnet-4.6":             "claude-sonnet-4-6",
	"claude-opus-4.6-thinking":      "claude-opus-4-6-thinking",
	"claude-opus-4.6":               "claude-opus-4-6",
	"claude-opus-4.5-thinking":      "MODEL_CLAUDE_4_5_OPUS_THINKING",
	"claude-opus-4.5":               "MODEL_CLAUDE_4_5_OPUS",
	"claude-sonnet-4.5-thinking":    "MODEL_PRIVATE_3",
	"claude-sonnet-4.5":             "MODEL_PRIVATE_2",
	"claude-haiku-4.5":              "MODEL_PRIVATE_11",
	"gpt-5.5-xhigh-fast":            "gpt-5-5-xhigh-priority",
	"gpt-5.5-high-fast":             "gpt-5-5-high-priority",
	"gpt-5.5-medium-fast":           "gpt-5-5-medium-priority",
	"gpt-5.5-low-fast":              "gpt-5-5-low-priority",
	"gpt-5.5-none-fast":             "gpt-5-5-none-priority",
	"gpt-5.5-xhigh":                 "gpt-5-5-xhigh",
	"gpt-5.5-high":                  "gpt-5-5-high",
	"gpt-5.5-medium":                "gpt-5-5-medium",
	"gpt-5.5-low":                   "gpt-5-5-low",
	"gpt-5.5-none":                  "gpt-5-5-none",
	"gpt-5.5-review":                "gpt-5-5-review",
	"gpt-5.5":                       "gpt-5-5-medium",
	"gpt-5.4-xhigh-fast":            "gpt-5-4-xhigh-priority",
	"gpt-5.4-high-fast":             "gpt-5-4-high-priority",
	"gpt-5.4-medium-fast":           "gpt-5-4-medium-priority",
	"gpt-5.4-low-fast":              "gpt-5-4-low-priority",
	"gpt-5.4-none-fast":             "gpt-5-4-none-priority",
	"gpt-5.4-xhigh":                 "gpt-5-4-xhigh",
	"gpt-5.4-high":                  "gpt-5-4-high",
	"gpt-5.4-medium":                "gpt-5-4-medium",
	"gpt-5.4-low":                   "gpt-5-4-low",
	"gpt-5.4-none":                  "gpt-5-4-none",
	"gpt-5.4-mini-xhigh":            "gpt-5-4-mini-xhigh",
	"gpt-5.4-mini-high":             "gpt-5-4-mini-high",
	"gpt-5.4-mini-medium":           "gpt-5-4-mini-medium",
	"gpt-5.4-mini-low":              "gpt-5-4-mini-low",
	"gpt-5.4":                       "gpt-5-4-medium",
	"gpt-5.3-codex-xhigh-fast":      "gpt-5-3-codex-xhigh-priority",
	"gpt-5.3-codex-high-fast":       "gpt-5-3-codex-high-priority",
	"gpt-5.3-codex-medium-fast":     "gpt-5-3-codex-medium-priority",
	"gpt-5.3-codex-low-fast":        "gpt-5-3-codex-low-priority",
	"gpt-5.3-codex-xhigh":           "gpt-5-3-codex-xhigh",
	"gpt-5.3-codex-high":            "gpt-5-3-codex-high",
	"gpt-5.3-codex-medium":          "gpt-5-3-codex-medium",
	"gpt-5.3-codex-low":             "gpt-5-3-codex-low",
	"gpt-5.3-codex":                 "gpt-5-3-codex-medium",
	"gpt-5.2-xhigh":                 "MODEL_GPT_5_2_XHIGH",
	"gpt-5.2-high":                  "MODEL_GPT_5_2_HIGH",
	"gpt-5.2-medium":                "MODEL_GPT_5_2_MEDIUM",
	"gpt-5.2-low":                   "MODEL_GPT_5_2_LOW",
	"gpt-5.2-none":                  "MODEL_GPT_5_2_NONE",
	"gpt-5.2":                       "MODEL_GPT_5_2_MEDIUM",
	"gpt-5":                         "gpt-5",
	"gpt-4.1":                       "MODEL_CHAT_GPT_4_1_2025_04_14",
	"gpt-4.1-mini":                  "gpt-4.1-mini",
	"gpt-4o":                        "MODEL_CHAT_GPT_4O_2024_08_06",
	"gemini-3.1-pro-high":           "gemini-3-1-pro-high",
	"gemini-3.1-pro-low":            "gemini-3-1-pro-low",
	"gemini-3.1-pro":                "gemini-3-1-pro-high",
	"gemini-3.0-flash-high":         "MODEL_GOOGLE_GEMINI_3_0_FLASH_HIGH",
	"gemini-3.0-flash-medium":       "MODEL_GOOGLE_GEMINI_3_0_FLASH_MEDIUM",
	"gemini-3.0-flash-low":          "MODEL_GOOGLE_GEMINI_3_0_FLASH_LOW",
	"gemini-3.0-flash-minimal":      "MODEL_GOOGLE_GEMINI_3_0_FLASH_MINIMAL",
	"gemini-3.0-flash":              "MODEL_GOOGLE_GEMINI_3_0_FLASH_HIGH",
	"gemini-2.5-pro":                "MODEL_GOOGLE_GEMINI_2_5_PRO",
	"deepseek-v4":                   "deepseek-v4",
	"kimi-k2.6":                     "kimi-k2-6",
	"kimi-k2.5":                     "kimi-k2-5",
	"glm-5.1":                       "glm-5-1",
}

func windsurfResolveModelID(model string) string {
	if v, ok := windsurfModelAliasMap[model]; ok {
		return v
	}
	return model
}

// --- minimal protobuf encoder (wire types 0 varint, 2 length-delimited) ---

func windsurfEncodeVarint(value uint64) []byte {
	var out []byte
	v := value
	for v > 0x7f {
		out = append(out, byte(v&0x7f)|0x80)
		v >>= 7
	}
	return append(out, byte(v&0x7f))
}

func windsurfConcat(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func windsurfEncodeField(fieldNum int, payload []byte) []byte {
	return windsurfConcat(windsurfEncodeVarint(uint64(fieldNum<<3|2)), windsurfEncodeVarint(uint64(len(payload))), payload)
}

func windsurfEncodeString(fieldNum int, value string) []byte {
	return windsurfEncodeField(fieldNum, []byte(value))
}

func windsurfBuildMetadata(apiKey, sessionID string) []byte {
	return windsurfConcat(
		windsurfEncodeString(1, apiKey),
		windsurfEncodeString(2, windsurfIDEName),
		windsurfEncodeString(3, windsurfIDEVersion),
		windsurfEncodeString(4, windsurfExtVersion),
		windsurfEncodeString(5, sessionID),
		windsurfEncodeString(6, windsurfLocale),
	)
}

type windsurfChatMsg struct {
	role       string
	content    string
	toolCallID string
}

func windsurfBuildChatMessage(msg windsurfChatMsg) []byte {
	parts := [][]byte{windsurfEncodeString(1, msg.role), windsurfEncodeString(2, msg.content)}
	if msg.toolCallID != "" {
		parts = append(parts, windsurfEncodeString(3, msg.toolCallID))
	}
	return windsurfConcat(parts...)
}

// windsurfBuildGetChatMessageRequest ports buildGetChatMessageRequest.
func windsurfBuildGetChatMessageRequest(apiKey, model string, messages []windsurfChatMsg) []byte {
	parts := [][]byte{
		windsurfEncodeField(1, windsurfBuildMetadata(apiKey, newUUID())),
		windsurfEncodeString(2, newUUID()),
		windsurfEncodeField(3, windsurfEncodeString(1, model)),
	}
	for _, msg := range messages {
		parts = append(parts, windsurfEncodeField(4, windsurfBuildChatMessage(msg)))
	}
	return windsurfConcat(parts...)
}

// windsurfGrpcWebFrame ports grpcWebFrame.
func windsurfGrpcWebFrame(payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	frame[0] = 0x00
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	return frame
}

// --- protobuf response decoder ---

func windsurfReadVarint(buf []byte, offset int) (uint64, int) {
	var result uint64
	var shift uint
	for offset < len(buf) {
		b := buf[offset]
		offset++
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return result, offset
}

func windsurfDecodeStringField(buf []byte, targetField int) (string, bool) {
	offset := 0
	for offset < len(buf) {
		var tag uint64
		tag, offset = windsurfReadVarint(buf, offset)
		fieldNum := int(tag >> 3)
		wireType := int(tag & 0x07)
		switch wireType {
		case 2:
			var length uint64
			length, offset = windsurfReadVarint(buf, offset)
			end := offset + int(length)
			if end > len(buf) {
				return "", false
			}
			payload := buf[offset:end]
			offset = end
			if fieldNum == targetField {
				return string(payload), true
			}
		case 0:
			_, offset = windsurfReadVarint(buf, offset)
		case 1:
			offset += 8
		case 5:
			offset += 4
		default:
			return "", false
		}
	}
	return "", false
}

func windsurfDecodeDoneChunk(buf []byte) (int, int) {
	offset := 0
	var usageBytes []byte
	for offset < len(buf) {
		var tag uint64
		tag, offset = windsurfReadVarint(buf, offset)
		fieldNum := int(tag >> 3)
		wireType := int(tag & 0x07)
		if wireType == 2 {
			var length uint64
			length, offset = windsurfReadVarint(buf, offset)
			end := offset + int(length)
			if end > len(buf) {
				break
			}
			if fieldNum == 1 {
				usageBytes = buf[offset:end]
			}
			offset = end
		} else if wireType == 0 {
			_, offset = windsurfReadVarint(buf, offset)
		} else {
			break
		}
	}
	if usageBytes == nil {
		return 0, 0
	}
	prompt, completion := 0, 0
	offset = 0
	for offset < len(usageBytes) {
		var tag uint64
		tag, offset = windsurfReadVarint(usageBytes, offset)
		fieldNum := int(tag >> 3)
		wireType := int(tag & 0x07)
		if wireType == 0 {
			var v uint64
			v, offset = windsurfReadVarint(usageBytes, offset)
			if fieldNum == 1 {
				prompt = int(v)
			} else if fieldNum == 2 {
				completion = int(v)
			}
		} else if wireType == 2 {
			var length uint64
			length, offset = windsurfReadVarint(usageBytes, offset)
			offset += int(length)
		} else {
			break
		}
	}
	return prompt, completion
}

type windsurfChunk struct {
	kind             string // "content" | "done" | "error" | "unknown"
	text             string
	promptTokens     int
	completionTokens int
	message          string
}

// windsurfDecodeCompletionChunk ports decodeCompletionChunk.
func windsurfDecodeCompletionChunk(buf []byte) windsurfChunk {
	offset := 0
	for offset < len(buf) {
		var tag uint64
		tag, offset = windsurfReadVarint(buf, offset)
		fieldNum := int(tag >> 3)
		wireType := int(tag & 0x07)
		switch wireType {
		case 2:
			var length uint64
			length, offset = windsurfReadVarint(buf, offset)
			end := offset + int(length)
			if end > len(buf) {
				return windsurfChunk{kind: "unknown"}
			}
			payload := buf[offset:end]
			offset = end
			switch fieldNum {
			case 1:
				if text, ok := windsurfDecodeStringField(payload, 1); ok {
					return windsurfChunk{kind: "content", text: text}
				}
			case 3:
				prompt, completion := windsurfDecodeDoneChunk(payload)
				return windsurfChunk{kind: "done", promptTokens: prompt, completionTokens: completion}
			case 4:
				msg, _ := windsurfDecodeStringField(payload, 1)
				if msg == "" {
					msg = "unknown windsurf error"
				}
				return windsurfChunk{kind: "error", message: msg}
			}
			// field 2 = ToolCallChunk — not handled in the JS either; skip.
		case 0:
			_, offset = windsurfReadVarint(buf, offset)
		case 1:
			offset += 8
		case 5:
			offset += 4
		default:
			return windsurfChunk{kind: "unknown"}
		}
	}
	return windsurfChunk{kind: "unknown"}
}

// windsurfMessagesFromOpenAI ports openAIMessagesToWs.
func windsurfMessagesFromOpenAI(messages []any) []windsurfChatMsg {
	out := make([]windsurfChatMsg, 0, len(messages))
	for _, raw := range messages {
		m, _ := raw.(map[string]any)
		if m == nil {
			continue
		}
		role := getStr(m, "role")
		if role == "" {
			role = "user"
		}
		var content string
		switch c := m["content"].(type) {
		case string:
			content = c
		case []any:
			for _, part := range c {
				if pm, _ := part.(map[string]any); pm != nil && pm["type"] == "text" {
					content += getStr(pm, "text")
				}
			}
		}
		out = append(out, windsurfChatMsg{role: role, content: content, toolCallID: getStr(m, "tool_call_id")})
	}
	return out
}

func windsurfBuildHeaders(cred Credential) map[string]string {
	token := cred.AccessToken
	if token == "" {
		token = cred.APIKey
	}
	headers := map[string]string{
		"Content-Type": "application/grpc-web+proto",
		"Accept":       "application/grpc-web+proto",
		"User-Agent":   "windsurf/" + windsurfIDEVersion,
		"X-Grpc-Web":   "1",
	}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	return headers
}

func NewWindsurfExecutor() *WindsurfExecutor {
	e := &WindsurfExecutor{}
	e.Base = &Base{ProviderID: "windsurf"}
	return e
}

func (e *WindsurfExecutor) Execute(ctx context.Context, p *ProviderInfo, cred Credential, body []byte) (*ExecResult, error) {
	if p == nil {
		p = &ProviderInfo{ID: "windsurf"}
	}
	url := p.BaseURL
	if url == "" {
		url = windsurfDefaultChatURL
	}
	apiKey := cred.AccessToken
	if apiKey == "" {
		apiKey = cred.APIKey
	}
	bodyMap, _ := decodeBody(body)
	model := ModelOf(bodyMap)
	wsModel := windsurfResolveModelID(model)

	rawMessages, _ := bodyMap["messages"].([]any)
	wsMessages := windsurfMessagesFromOpenAI(rawMessages)
	if len(wsMessages) == 0 {
		wsMessages = append(wsMessages, windsurfChatMsg{role: "user", content: ""})
	}

	protoPayload := windsurfBuildGetChatMessageRequest(apiKey, wsModel, wsMessages)
	framed := windsurfGrpcWebFrame(protoPayload)

	headers := windsurfBuildHeaders(cred)
	for k, v := range cred.OverrideHeaders {
		headers[k] = v
	}

	// doPost is a plain POST with the shared connect-timeout handling; the
	// payload here is the framed protobuf, not JSON.
	resp, err := doPost(ctx, url, headers, framed, connectTimeout(p))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		// JS: `if (!upstream.ok && upstream.status !== 200)` — return as-is.
		// (doPost only hands back a response once headers arrive.)
		if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
			return &ExecResult{Response: resp, URL: url, Headers: headers, TransformedBody: protoPayload}, nil
		}
	}

	pr, pw := io.Pipe()
	go func() {
		defer resp.Body.Close()
		windsurfConvertToSSE(resp.Body, pw, model)
		_ = pw.Close()
	}()
	return &ExecResult{
		Response: &http.Response{
			StatusCode: 200, Status: "200 OK",
			Header: http.Header{"Content-Type": []string{"text/event-stream"}, "Cache-Control": []string{"no-cache"}, "Connection": []string{"keep-alive"}},
			Body:   pr,
		},
		URL: url, Headers: headers, TransformedBody: protoPayload, ResponseFormat: "openai",
	}, nil
}

// windsurfConvertToSSE ports transformToSSE's stream loop: read gRPC-web
// frames incrementally, emit OpenAI chunks.
func windsurfConvertToSSE(r io.Reader, w io.Writer, model string) {
	responseID := fmt.Sprintf("chatcmpl-ws-%d", time.Now().UnixMilli())
	created := nowUnix()
	roleEmitted := false
	totalText := ""
	promptTokens, completionTokens := 0, 0
	hadError := ""

	emitChunk := func(delta map[string]any, finish any, usage map[string]any) {
		chunk := map[string]any{
			"id": responseID, "object": "chat.completion.chunk", "created": created, "model": model,
			"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
		}
		if usage != nil {
			chunk["usage"] = usage
		}
		raw, _ := marshalJSON(chunk)
		_, _ = io.WriteString(w, "data: "+string(raw)+"\n\n")
	}
	emitErrorAndDone := func(msg string) {
		raw, _ := marshalJSON(map[string]any{"error": map[string]any{"message": msg, "type": "windsurf_error", "code": "upstream_error"}})
		_, _ = io.WriteString(w, "data: "+string(raw)+"\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}

	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			break // EOF (clean or mid-frame) — JS drains what it has, then finishes.
		}
		flag := header[0]
		length := binary.BigEndian.Uint32(header[1:5])
		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			break
		}
		if flag == 0x80 {
			trailer := string(payload)
			if msg, isErr := windsurfParseTrailer(trailer); isErr {
				hadError = msg
			}
			continue
		}
		if flag != 0x00 {
			continue
		}
		chunk := windsurfDecodeCompletionChunk(payload)
		switch chunk.kind {
		case "content":
			if chunk.text != "" {
				totalText += chunk.text
				if !roleEmitted {
					emitChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
					roleEmitted = true
				}
				emitChunk(map[string]any{"content": chunk.text}, nil, nil)
			}
		case "done":
			promptTokens = chunk.promptTokens
			completionTokens = chunk.completionTokens
		case "error":
			hadError = chunk.message
		}
	}

	if hadError != "" {
		emitErrorAndDone(hadError)
		return
	}
	if !roleEmitted && totalText != "" {
		emitChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
		emitChunk(map[string]any{"content": totalText}, nil, nil)
	}
	var usage map[string]any
	if promptTokens > 0 || completionTokens > 0 {
		usage = map[string]any{"prompt_tokens": promptTokens, "completion_tokens": completionTokens, "total_tokens": promptTokens + completionTokens}
	}
	emitChunk(map[string]any{}, "stop", usage)
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	_ = totalText
}

var windsurfTrailerStatusRe = regexp.MustCompile(`(?i)grpc-status:\s*(\d+)`)
var windsurfTrailerMsgRe = regexp.MustCompile(`(?i)grpc-message:\s*(.+)`)

// windsurfParseTrailer extracts a non-zero grpc-status error from a
// trailer frame payload ("grpc-status: N\r\ngrpc-message: ...").
func windsurfParseTrailer(trailer string) (string, bool) {
	m := windsurfTrailerStatusRe.FindStringSubmatch(trailer)
	if m == nil || m[1] == "0" {
		return "", false
	}
	if mm := windsurfTrailerMsgRe.FindStringSubmatch(trailer); mm != nil {
		msg := strings.TrimSpace(mm[1])
		// JS: decodeURIComponent — PathUnescape matches except for %2F etc.
		// semantics in paths; trailer messages are plain text, so it is
		// equivalent for the messages this surfaces.
		if decoded, err := url.PathUnescape(msg); err == nil {
			msg = decoded
		}
		return msg, true
	}
	return "gRPC status " + m[1], true
}
