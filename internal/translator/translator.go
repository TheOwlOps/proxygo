// Package translator is the Go port of open-sse/translator/.
//
// The pipeline pivots through OpenAI as the intermediate format, exactly
// like the JS original: a translator registered for an exact "from:to"
// pair runs as a direct route, otherwise the request/response hops
// from -> openai -> to.
//
// Contract notes (see docs/GO_CONTRACT.md):
//   - Body is map[string]any; unknown fields are preserved, never dropped.
//   - Register's ResFn is the *streaming chunk* translator, mirroring the
//     JS register() whose responseFn consumes SSE chunks. Non-streaming
//     response bodies are translated by TranslateResponse, which uses a
//     parallel internal registry populated by the same init() calls.
//   - The JS translateRequest/translateResponse take (model, stream,
//     credentials, provider) arguments that the Go contract folds away:
//     model/stream are read from the body, and provider-capability-driven
//     steps (thinking normalization via applyThinking, Claude cloaking,
//     prepareClaudeRequest's provider quirks) are reduced to their
//     provider-independent subset, documented per function.
package translator

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Body is a JSON request/response/chunk body.
type Body = map[string]any

// ReqFn translates a request body from one format to another.
type ReqFn func(body Body) (Body, error)

// ResFn translates one streaming chunk. It may return zero, one or many
// output chunks. A nil chunk signals end-of-stream flush (used by the
// openai-responses converters, mirroring the JS null-chunk convention).
type ResFn func(chunk Body, state *StreamState) ([]Body, error)

// bodyFn translates a complete (non-streaming) response body.
type bodyFn func(body Body) (Body, error)

var (
	mu           sync.RWMutex
	reqRegistry  = map[string]ReqFn{}
	resRegistry  = map[string]ResFn{}
	bodyRegistry = map[string]bodyFn{}
)

// Register registers a translator pair, mirroring the JS register().
// Either function may be nil.
func Register(from, to string, req ReqFn, res ResFn) {
	mu.Lock()
	defer mu.Unlock()
	key := from + ":" + to
	if req != nil {
		reqRegistry[key] = req
	}
	if res != nil {
		resRegistry[key] = res
	}
}

// registerBody registers a non-streaming response translator (internal).
func registerBody(from, to string, fn bodyFn) {
	mu.Lock()
	defer mu.Unlock()
	bodyRegistry[from+":"+to] = fn
}

func lookupReq(from, to string) ReqFn {
	mu.RLock()
	defer mu.RUnlock()
	return reqRegistry[from+":"+to]
}

func lookupRes(from, to string) ResFn {
	mu.RLock()
	defer mu.RUnlock()
	return resRegistry[from+":"+to]
}

func lookupBody(from, to string) bodyFn {
	mu.RLock()
	defer mu.RUnlock()
	return bodyRegistry[from+":"+to]
}

// ToolCallState tracks one in-flight tool call across stream chunks.
type ToolCallState struct {
	Index      int
	ID         string
	Name       string
	Args       string // accumulated argument JSON fragments (claude input_json_delta)
	BlockIndex int    // claude content-block index (openai -> claude)
}

// StreamState mirrors the JS initState() object: one state per stream,
// shared by every chunk translation in the pipeline.
type StreamState struct {
	// Base fields (all formats), from initState() in translator/index.js.
	MessageID            string
	Model                string
	TextBlockStarted     bool
	ThinkingBlockStarted bool
	InThinkingBlock      bool
	CurrentBlockIndex    int
	HasCurrentBlock      bool // JS uses null for "no block"; Has=false mirrors null
	ToolCalls            map[int]*ToolCallState
	FinishReason         string
	FinishReasonSent     bool
	Usage                Body
	ContentBlockIndex    int

	// Claude <-> OpenAI streaming extras.
	ToolCallIndex        int
	ServerToolBlockIndex int
	MessageStartSent     bool
	NextBlockIndex       int
	TextBlockIndex       int
	TextBlockClosed      bool
	ThinkingBlockIndex   int
	ToolArgBuffers       map[int]string
	ToolNameMap          map[string]string // prefixed/cloaked name -> original

	// Gemini streaming extras.
	FunctionIndex           int
	GeminiToolCallCount     int
	PendingThoughtSignature string
	SessionID               string

	// Kiro streaming extras (response/kiro-to-openai.js state fields).
	ChunkIndex int
	HadToolUse bool

	// openai-responses extras, from initState()'s responses branch.
	Seq                  int
	ResponseID           string
	Created              int64
	Started              bool
	MsgTextBuf           map[int]string
	MsgItemAdded         map[int]bool
	MsgContentAdded      map[int]bool
	MsgItemDone          map[int]bool
	ReasoningID          string
	ReasoningIndex       int
	ReasoningBuf         string
	ReasoningPartAdded   bool
	ReasoningDone        bool
	InThinking           bool
	FuncArgsBuf          map[int]string
	FuncNames            map[int]string
	FuncCallIDs          map[int]string
	FuncItemAdded        map[int]bool
	FuncArgsDone         map[int]bool
	FuncItemDone         map[int]bool
	CustomToolNames      map[string]bool
	ResponsesUsage       Body
	CompletionPending    bool
	CompletedSent        bool
	CompletedOutputItems map[int]Body

	// Responses -> OpenAI streaming extras.
	ChatID              string
	CurrentToolCallID   string
	RespToolChatIndex   map[string]int
	RespToolArgsEmitted map[int]bool

	// TargetFormat is the format of the chunks being consumed (the "from"
	// of TranslateStreamChunk); the responses converter's flush logic
	// branches on it exactly like the JS state.targetFormat.
	TargetFormat string

	Error Body
}

// NewStreamState mirrors initState(sourceFormat) in the JS index.js:
// base fields for every format, plus the responses-specific block when
// the client format is openai-responses.
func NewStreamState(sourceFormat string) *StreamState {
	s := &StreamState{
		ContentBlockIndex:    -1,
		ServerToolBlockIndex: -1,
		ReasoningIndex:       -1,
		ToolCalls:            map[int]*ToolCallState{},
		ToolArgBuffers:       map[int]string{},
	}
	if sourceFormat == FormatOpenAIResponses {
		now := time.Now()
		s.ResponseID = fmt.Sprintf("resp_%d", now.UnixMilli())
		s.Created = now.Unix()
		s.MsgTextBuf = map[int]string{}
		s.MsgItemAdded = map[int]bool{}
		s.MsgContentAdded = map[int]bool{}
		s.MsgItemDone = map[int]bool{}
		s.FuncArgsBuf = map[int]string{}
		s.FuncNames = map[int]string{}
		s.FuncCallIDs = map[int]string{}
		s.FuncItemAdded = map[int]bool{}
		s.FuncArgsDone = map[int]bool{}
		s.FuncItemDone = map[int]bool{}
		s.CustomToolNames = map[string]bool{}
		s.CompletedOutputItems = map[int]Body{}
		s.RespToolChatIndex = map[string]int{}
		s.RespToolArgsEmitted = map[int]bool{}
	}
	return s
}

// ensureMaps lazily initialises maps so a zero-value StreamState built by
// a caller (as the JS stream layer does) is safe to use.
func (s *StreamState) ensureMaps() {
	if s.ToolCalls == nil {
		s.ToolCalls = map[int]*ToolCallState{}
	}
	if s.ToolArgBuffers == nil {
		s.ToolArgBuffers = map[int]string{}
	}
	if s.MsgTextBuf == nil {
		s.MsgTextBuf = map[int]string{}
	}
	if s.MsgItemAdded == nil {
		s.MsgItemAdded = map[int]bool{}
	}
	if s.MsgContentAdded == nil {
		s.MsgContentAdded = map[int]bool{}
	}
	if s.MsgItemDone == nil {
		s.MsgItemDone = map[int]bool{}
	}
	if s.FuncArgsBuf == nil {
		s.FuncArgsBuf = map[int]string{}
	}
	if s.FuncNames == nil {
		s.FuncNames = map[int]string{}
	}
	if s.FuncCallIDs == nil {
		s.FuncCallIDs = map[int]string{}
	}
	if s.FuncItemAdded == nil {
		s.FuncItemAdded = map[int]bool{}
	}
	if s.FuncArgsDone == nil {
		s.FuncArgsDone = map[int]bool{}
	}
	if s.FuncItemDone == nil {
		s.FuncItemDone = map[int]bool{}
	}
	if s.CustomToolNames == nil {
		s.CustomToolNames = map[string]bool{}
	}
	if s.CompletedOutputItems == nil {
		s.CompletedOutputItems = map[int]Body{}
	}
	if s.RespToolChatIndex == nil {
		s.RespToolChatIndex = map[string]int{}
	}
	if s.RespToolArgsEmitted == nil {
		s.RespToolArgsEmitted = map[int]bool{}
	}
}

// TranslateRequest translates a request body from format `from` to format
// `to`, pivoting through OpenAI unless a direct route is registered.
// Mirrors translateRequest() in the JS index.js, minus the steps that need
// provider/credential context the Go contract does not pass (thinking
// normalization, cloaking, session capture). The portable pre/post steps
// are kept: ensureToolCallIds, fixMissingToolResponses (skipped for kiro),
// filterToOpenAIFormat for openai targets, and the provider-independent
// part of prepareClaudeRequest for claude targets.
func TranslateRequest(from, to string, body Body) (Body, error) {
	if body == nil {
		return nil, fmt.Errorf("translator: nil request body")
	}
	result := deepCopyBody(body)

	ensureToolCallIds(result)
	if to != FormatKiro {
		fixMissingToolResponses(result)
	}

	if from != to {
		if direct := lookupReq(from, to); direct != nil {
			out, err := direct(result)
			if err != nil {
				return nil, err
			}
			result = out
		} else {
			if from != FormatOpenAI {
				if fn := lookupReq(from, FormatOpenAI); fn != nil {
					out, err := fn(result)
					if err != nil {
						return nil, err
					}
					result = out
				}
			}
			if to != FormatOpenAI {
				if fn := lookupReq(FormatOpenAI, to); fn != nil {
					out, err := fn(result)
					if err != nil {
						return nil, err
					}
					result = out
				}
			}
		}
	}

	if to == FormatOpenAI {
		result = filterToOpenAIFormat(result, false)
	}
	if to == FormatClaude {
		result = prepareClaudeRequestLite(result, detectClientLastRole(body))
	}
	return result, nil
}

// TranslateResponse translates a complete (non-streaming) response body
// from format `from` to format `to`, with the same direct/pivot routing
// as TranslateRequest. (The JS codebase has no separate non-streaming
// response translators — bodies are assembled from chunks by its stream
// layer — so these converters are written to produce exactly the body
// the chunk pipeline would assemble.)
func TranslateResponse(from, to string, body Body) (Body, error) {
	if body == nil {
		return nil, fmt.Errorf("translator: nil response body")
	}
	if from == to {
		return deepCopyBody(body), nil
	}
	if direct := lookupBody(from, to); direct != nil {
		return direct(deepCopyBody(body))
	}
	result := deepCopyBody(body)
	if from != FormatOpenAI {
		fn := lookupBody(from, FormatOpenAI)
		if fn == nil {
			return result, nil
		}
		out, err := fn(result)
		if err != nil {
			return nil, err
		}
		result = out
	}
	if to != FormatOpenAI {
		if fn := lookupBody(FormatOpenAI, to); fn != nil {
			out, err := fn(result)
			if err != nil {
				return nil, err
			}
			result = out
		}
	}
	return result, nil
}

// TranslateStreamChunk translates one streaming chunk from format `from`
// (the chunk's native format) to format `to` (the client's format),
// mirroring translateResponse() in the JS index.js. A nil chunk is the
// end-of-stream flush signal and is forwarded to the converter.
func TranslateStreamChunk(from, to string, chunk Body, state *StreamState) ([]Body, error) {
	if state == nil {
		state = NewStreamState(to)
	}
	state.ensureMaps()
	state.TargetFormat = from

	if from == to {
		if chunk == nil {
			return nil, nil
		}
		return []Body{chunk}, nil
	}

	if direct := lookupRes(from, to); direct != nil {
		return direct(chunk, state)
	}

	var results []Body
	if chunk != nil {
		results = []Body{chunk}
	}

	if from != FormatOpenAI {
		if fn := lookupRes(from, FormatOpenAI); fn != nil {
			var next []Body
			for _, r := range resultsOrNil(results, chunk) {
				out, err := fn(r, state)
				if err != nil {
					return nil, err
				}
				next = append(next, out...)
			}
			// A nil (flush) chunk with no first hop still flushes the second.
			if chunk == nil && len(results) == 0 {
				out, err := fn(nil, state)
				if err != nil {
					return nil, err
				}
				next = append(next, out...)
			}
			results = next
		}
	}

	if to != FormatOpenAI {
		if fn := lookupRes(FormatOpenAI, to); fn != nil {
			var final []Body
			for _, r := range results {
				out, err := fn(r, state)
				if err != nil {
					return nil, err
				}
				final = append(final, out...)
			}
			if chunk == nil && len(results) == 0 {
				out, err := fn(nil, state)
				if err != nil {
					return nil, err
				}
				final = append(final, out...)
			}
			results = final
		}
	}

	return results, nil
}

func resultsOrNil(results []Body, chunk Body) []Body {
	if len(results) > 0 {
		return results
	}
	if chunk == nil {
		return nil
	}
	return results
}

// NeedsTranslation mirrors needsTranslation() in the JS index.js.
func NeedsTranslation(sourceFormat, targetFormat string) bool {
	return sourceFormat != targetFormat
}

// DetectFormatByEndpoint mirrors detectFormatByEndpoint() in formats.js.
func DetectFormatByEndpoint(pathname string, body Body) (string, bool) {
	switch {
	case contains(pathname, "/v1/responses"):
		return FormatOpenAIResponses, true
	case contains(pathname, "/v1/messages"):
		return FormatClaude, true
	case contains(pathname, "/v1/chat/completions"):
		if _, ok := body["input"].([]any); ok {
			return FormatOpenAI, true
		}
	}
	return "", false
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}

// detectClientLastRole ports detectClientLastRole() from the JS index.js.
func detectClientLastRole(body Body) string {
	if msgs, ok := body["messages"].([]any); ok && len(msgs) > 0 {
		if last, ok := msgs[len(msgs)-1].(map[string]any); ok {
			role, _ := last["role"].(string)
			return role
		}
		return ""
	}
	var items []any
	if c, ok := body["contents"].([]any); ok {
		items = c
	} else if in, ok := body["input"].([]any); ok {
		items = in
	}
	if len(items) == 0 {
		return ""
	}
	last, _ := items[len(items)-1].(map[string]any)
	role, _ := last["role"].(string)
	if role == RoleAssistant || role == GeminiRoleModel {
		return RoleAssistant
	}
	return ""
}
