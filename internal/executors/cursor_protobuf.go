package executors

// Port of open-sse/utils/cursorProtobuf.js — ConnectRPC protobuf wire
// format for the Cursor API, hand-rolled exactly like the JS (no protoc).
//
// Layout: wire primitives → message encoders (ChatService
// StreamUnifiedChatRequestWithTools) → ConnectRPC framing → response
// extraction → agent.v1 google.protobuf.Value / MCP codec.
//
// Where JS numbers are concerned: field numbers, enum values and flags on
// this wire are all small, so Go uint64 varints are a strict superset of
// the JS 32-bit-shift behaviour for every value that occurs in practice.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ---------- wire types & field numbers (FIELD in cursorProtobuf.js) ----------

const (
	pbWireVarint  = 0
	pbWireFixed64 = 1
	pbWireLen     = 2
	pbWireFixed32 = 5
)

const (
	cursorRoleUser      = 1
	cursorRoleAssistant = 2

	cursorUnifiedModeChat  = 1
	cursorUnifiedModeAgent = 2

	cursorThinkingUnspecified = 0
	cursorThinkingMedium      = 1
	cursorThinkingHigh        = 2

	cursorClientSideToolV2MCP = 19
)

// StreamUnifiedChatRequestWithTools / StreamUnifiedChatRequest fields.
const (
	fldRequest        = 1
	fldMessages       = 1
	fldUnknown2       = 2
	fldInstruction    = 3
	fldUnknown4       = 4
	fldModel          = 5
	fldWebTool        = 8
	fldUnknown13      = 13
	fldCursorSetting  = 15
	fldUnknown19      = 19
	fldConversationID = 23
	fldMetadata       = 26
	fldIsAgentic      = 27
	fldSupportedTools = 29
	fldMessageIDs     = 30
	fldMCPTools       = 34
	fldLargeContext   = 35
	fldUnknown38      = 38
	fldUnifiedMode    = 46
	fldUnknown47      = 47
	fldShouldDisable  = 48
	fldThinkingLevel  = 49
	fldUnknown51      = 51
	fldUnknown53      = 53
	fldUnifiedModeNam = 54
)

// ConversationMessage fields.
const (
	fldMsgContent        = 1
	fldMsgRole           = 2
	fldMsgID             = 13
	fldMsgToolResults    = 18
	fldMsgIsAgentic      = 29
	fldMsgServerBubbleID = 32
	fldMsgUnifiedMode    = 47
	fldMsgSupportedTools = 51
)

// ConversationMessage.ToolResult fields.
const (
	fldToolResultCallID     = 1
	fldToolResultName       = 2
	fldToolResultIndex      = 3
	fldToolResultRawArgs    = 5
	fldToolResultResult     = 8
	fldToolResultToolCall   = 11
	fldToolResultModelCalID = 12
)

// ClientSideToolV2Result fields.
const (
	fldCV2RTool        = 1
	fldCV2RMCPResult   = 28
	fldCV2RCallID      = 35
	fldCV2RModelCallID = 48
	fldCV2RToolIndex   = 49
)

// MCPResult fields.
const (
	fldMCPResultSelectedTool = 1
	fldMCPResultResult       = 2
)

// ClientSideToolV2Call fields.
const (
	fldCV2CTool        = 1
	fldCV2CMCPParams   = 27
	fldCV2CCallID      = 3
	fldCV2CName        = 9
	fldCV2CRawArgs     = 10
	fldCV2CToolIndex   = 48
	fldCV2CModelCallID = 49
)

// Model / Instruction / CursorSetting / Metadata / MessageId / MCPTool.
const (
	fldModelName  = 1
	fldModelEmpty = 4

	fldInstructionText = 1

	fldSettingPath     = 1
	fldSettingUnknown3 = 3
	fldSettingUnknown6 = 6
	fldSettingUnknown8 = 8
	fldSettingUnknown9 = 9

	fldSetting6Field1 = 1
	fldSetting6Field2 = 2

	fldMetaPlatform  = 1
	fldMetaArch      = 2
	fldMetaVersion   = 3
	fldMetaCWD       = 4
	fldMetaTimestamp = 5

	fldMsgIDID      = 1
	fldMsgIDSummary = 2
	fldMsgIDRole    = 3

	fldMCPToolName   = 1
	fldMCPToolDesc   = 2
	fldMCPToolParams = 3
	fldMCPToolServer = 4
)

// StreamUnifiedChatResponseWithTools / response fields.
const (
	fldRespToolCall = 1
	fldRespResponse = 2

	fldToolID       = 3
	fldToolName     = 9
	fldToolRawArgs  = 10
	fldToolIsLast   = 11
	fldToolIsLastAl = 15
	fldToolMCPParam = 27

	fldMCPToolsList  = 1
	fldMCPNestedName = 1
	fldMCPNestedParm = 3

	fldResponseText = 1
	fldThinking     = 25
	fldThinkingText = 1
)

// ---------- primitive encoding ----------

func pbEncodeVarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v&0x7F)|0x80)
		v >>= 7
	}
	return append(out, byte(v&0x7F))
}

// pbEncodeField mirrors encodeField(): value is uint64/int for VARINT,
// string/[]byte for LEN, float64 for FIXED64 (double LE). Other types
// encode as empty LEN, exactly like the JS fall-through.
func pbEncodeField(fieldNum, wireType int, value any) []byte {
	tag := pbEncodeVarint(uint64(fieldNum<<3 | wireType))
	switch wireType {
	case pbWireVarint:
		var v uint64
		switch n := value.(type) {
		case int:
			v = uint64(n)
		case int64:
			v = uint64(n)
		case uint64:
			v = n
		case bool:
			if n {
				v = 1
			}
		}
		return append(tag, pbEncodeVarint(v)...)
	case pbWireLen:
		var data []byte
		switch s := value.(type) {
		case string:
			data = []byte(s)
		case []byte:
			data = s
		}
		out := append(tag, pbEncodeVarint(uint64(len(data)))...)
		return append(out, data...)
	case pbWireFixed64:
		var f float64
		switch n := value.(type) {
		case float64:
			f = n
		case int:
			f = float64(n)
		}
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], math.Float64bits(f))
		return append(tag, buf[:]...)
	}
	return []byte{}
}

func pbConcat(parts ...[]byte) []byte {
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

func pbLen(field int, payload []byte) []byte { return pbEncodeField(field, pbWireLen, payload) }
func pbStr(field int, s string) []byte       { return pbEncodeField(field, pbWireLen, s) }
func pbVar(field int, v uint64) []byte       { return pbEncodeField(field, pbWireVarint, v) }
func pbStrOpt(field int, s string) []byte {
	if s == "" {
		return nil
	}
	return pbStr(field, s)
}

// ---------- primitive decoding ----------

type pbFieldValue struct {
	WireType int
	Varint   uint64
	Bytes    []byte
}

// pbMessage is a decoded protobuf message: field number → occurrences in
// wire order, plus the first-seen field order (the JS Map preserves it,
// and rejectExecRequest depends on it).
type pbMessage struct {
	fields map[int][]pbFieldValue
	order  []int
}

func (m *pbMessage) has(n int) bool {
	if m == nil {
		return false
	}
	_, ok := m.fields[n]
	return ok
}

func (m *pbMessage) get(n int) []pbFieldValue {
	if m == nil {
		return nil
	}
	return m.fields[n]
}

// keys returns unique field numbers in first-seen wire order.
func (m *pbMessage) keys() []int {
	if m == nil {
		return nil
	}
	return m.order
}

func (m *pbMessage) firstBytes(n int) []byte {
	vals := m.get(n)
	if len(vals) == 0 {
		return nil
	}
	return vals[0].Bytes
}

func (m *pbMessage) firstString(n int) string {
	b := m.firstBytes(n)
	if b == nil {
		return ""
	}
	return string(b)
}

func (m *pbMessage) firstVarint(n int) uint64 {
	vals := m.get(n)
	if len(vals) == 0 {
		return 0
	}
	return vals[0].Varint
}

func pbDecodeVarint(buf []byte, offset int) (uint64, int) {
	var result uint64
	var shift uint
	pos := offset
	for pos < len(buf) {
		b := buf[pos]
		result |= uint64(b&0x7F) << shift
		pos++
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return result, pos
}

// pbDecodeField mirrors decodeField(): returns field number, wire type,
// value and the next offset. Unknown wire types consume only the tag
// (the JS returns a null value and advances past the tag).
func pbDecodeField(buf []byte, offset int) (int, int, pbFieldValue, int, bool) {
	if offset >= len(buf) {
		return 0, 0, pbFieldValue{}, offset, false
	}
	tag, pos := pbDecodeVarint(buf, offset)
	fieldNum := int(tag >> 3)
	wireType := int(tag & 0x07)
	val := pbFieldValue{WireType: wireType}
	switch wireType {
	case pbWireVarint:
		var v uint64
		v, pos = pbDecodeVarint(buf, pos)
		val.Varint = v
	case pbWireLen:
		length, pos2 := pbDecodeVarint(buf, pos)
		end := pos2 + int(length)
		if end > len(buf) {
			end = len(buf)
		}
		val.Bytes = buf[pos2:end]
		pos = end
	case pbWireFixed64:
		end := pos + 8
		if end > len(buf) {
			end = len(buf)
		}
		val.Bytes = buf[pos:end]
		pos = end
	case pbWireFixed32:
		end := pos + 4
		if end > len(buf) {
			end = len(buf)
		}
		val.Bytes = buf[pos:end]
		pos = end
	}
	return fieldNum, wireType, val, pos, true
}

func pbDecodeMessage(data []byte) *pbMessage {
	msg := &pbMessage{fields: map[int][]pbFieldValue{}}
	pos := 0
	for pos < len(data) {
		fieldNum, _, val, newPos, ok := pbDecodeField(data, pos)
		if !ok || fieldNum == 0 && newPos == pos {
			break
		}
		if _, seen := msg.fields[fieldNum]; !seen {
			msg.order = append(msg.order, fieldNum)
		}
		msg.fields[fieldNum] = append(msg.fields[fieldNum], val)
		if newPos <= pos {
			break
		}
		pos = newPos
	}
	return msg
}

// ---------- tool name / id helpers ----------

// formatToolName ports formatToolName(): "toolName" → "mcp_custom_toolName",
// "mcp__server__tool" → "mcp_server_tool".
func formatToolName(name string) string {
	base := name
	if base == "" {
		base = "tool"
	}
	if strings.HasPrefix(base, "mcp__") {
		rest := base[len("mcp__"):]
		if idx := strings.Index(rest, "__"); idx >= 0 {
			server := rest[:idx]
			if server == "" {
				server = "custom"
			}
			toolName := rest[idx+2:]
			if toolName == "" {
				toolName = "tool"
			}
			return "mcp_" + server + "_" + toolName
		}
		if rest == "" {
			rest = "tool"
		}
		return "mcp_custom_" + rest
	}
	if strings.HasPrefix(base, "mcp_") {
		return base
	}
	return "mcp_custom_" + base
}

// parseToolName ports parseToolName(): "mcp_server_tool" →
// (serverName, selectedTool).
func parseToolName(formattedName string) (string, string) {
	if !strings.HasPrefix(formattedName, "mcp_") {
		name := formattedName
		if name == "" {
			name = "tool"
		}
		return "custom", name
	}
	tail := formattedName[len("mcp_"):]
	idx := strings.Index(tail, "_")
	if idx < 0 {
		if tail == "" {
			tail = "tool"
		}
		return "custom", tail
	}
	server := tail[:idx]
	if server == "" {
		server = "custom"
	}
	tool := tail[idx+1:]
	if tool == "" {
		tool = "tool"
	}
	return server, tool
}

// parseToolID splits a tool_call_id on the "\nmc_" delimiter Cursor uses
// for the model_call_id.
func parseToolID(id string) (toolCallID string, modelCallID string, hasModel bool) {
	const delim = "\nmc_"
	if idx := strings.Index(id, delim); idx >= 0 {
		return id[:idx], id[idx+len(delim):], true
	}
	return id, "", false
}

// ---------- message encoding ----------

// CursorToolResult is one ConversationMessage.ToolResult entry
// (the JS toolResult object threaded through encodeRequest).
type CursorToolResult struct {
	ToolCallID    string
	ToolName      string // tool_name || name
	RawArgs       string // raw_args, default "{}"
	ResultContent string // result_content || result
	ToolIndex     int    // tool_index || index, default 1
}

// CursorToolDef is one client tool definition for encodeMcpTool
// ( OpenAI {function:{name,description,parameters}} or flat {name,…} ).
type CursorToolDef struct {
	Name        string
	Description string
	InputSchema map[string]any
}

func encodeMcpResult(selectedTool, resultContent string) []byte {
	return pbConcat(
		pbStr(fldMCPResultSelectedTool, selectedTool),
		pbStr(fldMCPResultResult, resultContent),
	)
}

func encodeClientSideToolV2Result(toolCallID, modelCallID string, hasModel bool, selectedTool, resultContent string, toolIndex int) []byte {
	if toolIndex <= 0 {
		toolIndex = 1
	}
	parts := [][]byte{
		pbVar(fldCV2RTool, cursorClientSideToolV2MCP),
		pbLen(fldCV2RMCPResult, encodeMcpResult(selectedTool, resultContent)),
		pbStr(fldCV2RCallID, toolCallID),
	}
	if hasModel {
		parts = append(parts, pbStr(fldCV2RModelCallID, modelCallID))
	}
	parts = append(parts, pbVar(fldCV2RToolIndex, uint64(toolIndex)))
	return pbConcat(parts...)
}

// encodeMcpParamsForCall builds MCPParams{ tools: [MCPTool] } for a call.
func encodeMcpParamsForCall(toolName, rawArgs, serverName string) []byte {
	tool := pbConcat(
		pbStr(fldMCPToolName, toolName),
		pbStr(fldMCPToolParams, rawArgs),
		pbStr(fldMCPToolServer, serverName),
	)
	return pbLen(fldMCPToolsList, tool)
}

func encodeClientSideToolV2Call(toolCallID, toolName, selectedTool, serverName, rawArgs, modelCallID string, hasModel bool, toolIndex int) []byte {
	if toolIndex <= 0 {
		toolIndex = 1
	}
	parts := [][]byte{
		pbVar(fldCV2CTool, cursorClientSideToolV2MCP),
		pbLen(fldCV2CMCPParams, encodeMcpParamsForCall(selectedTool, rawArgs, serverName)),
		pbStr(fldCV2CCallID, toolCallID),
		pbStr(fldCV2CName, toolName),
		pbStr(fldCV2CRawArgs, rawArgs),
		pbVar(fldCV2CToolIndex, uint64(toolIndex)),
	}
	if hasModel {
		parts = append(parts, pbStr(fldCV2CModelCallID, modelCallID))
	}
	return pbConcat(parts...)
}

// EncodeToolResult ports encodeToolResult().
func EncodeToolResult(tr CursorToolResult) []byte {
	toolName := formatToolName(tr.ToolName)
	rawArgs := tr.RawArgs
	if rawArgs == "" {
		rawArgs = "{}"
	}
	toolCallID, modelCallID, hasModel := parseToolID(tr.ToolCallID)
	toolIndex := tr.ToolIndex
	if toolIndex <= 0 {
		toolIndex = 1
	}
	serverName, selectedTool := parseToolName(toolName)

	parts := [][]byte{
		pbStr(fldToolResultCallID, toolCallID),
		pbStr(fldToolResultName, toolName),
		pbVar(fldToolResultIndex, uint64(toolIndex)),
	}
	if hasModel {
		parts = append(parts, pbStr(fldToolResultModelCalID, modelCallID))
	}
	parts = append(parts,
		pbStr(fldToolResultRawArgs, rawArgs),
		pbLen(fldToolResultResult, encodeClientSideToolV2Result(toolCallID, modelCallID, hasModel, selectedTool, tr.ResultContent, toolIndex)),
		pbLen(fldToolResultToolCall, encodeClientSideToolV2Call(toolCallID, toolName, selectedTool, serverName, rawArgs, modelCallID, hasModel, toolIndex)),
	)
	return pbConcat(parts...)
}

// CursorMessage is one conversation message for encodeRequest. ToolCalls
// only contributes its count (splitting mixed assistant payloads); the
// calls themselves are not encoded into ChatService messages, exactly
// like the JS.
type CursorMessage struct {
	Content       string
	Role          string // "user" → USER, anything else → ASSISTANT (JS ternary)
	ToolCallCount int
	ToolResults   []CursorToolResult
}

func encodeMessage(content string, role int, messageID string, isLast, hasTools bool, toolResults []CursorToolResult, serverBubbleID string) []byte {
	parts := [][]byte{
		pbStr(fldMsgContent, content),
		pbVar(fldMsgRole, uint64(role)),
		pbStr(fldMsgID, messageID),
	}
	if serverBubbleID != "" {
		parts = append(parts, pbStr(fldMsgServerBubbleID, serverBubbleID))
	}
	for _, tr := range toolResults {
		parts = append(parts, pbLen(fldMsgToolResults, EncodeToolResult(tr)))
	}
	mode := uint64(cursorUnifiedModeChat)
	if hasTools {
		mode = cursorUnifiedModeAgent
	}
	parts = append(parts,
		pbVar(fldMsgIsAgentic, boolUint(hasTools)),
		pbVar(fldMsgUnifiedMode, mode),
	)
	if isLast && hasTools {
		parts = append(parts, pbLen(fldMsgSupportedTools, pbEncodeVarint(1)))
	}
	return pbConcat(parts...)
}

func boolUint(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func encodeInstruction(text string) []byte {
	if text == "" {
		return []byte{}
	}
	return pbStr(fldInstructionText, text)
}

func encodeModel(modelName string) []byte {
	return pbConcat(
		pbStr(fldModelName, modelName),
		pbLen(fldModelEmpty, []byte{}),
	)
}

func encodeCursorSetting() []byte {
	unknown6 := pbConcat(
		pbLen(fldSetting6Field1, []byte{}),
		pbLen(fldSetting6Field2, []byte{}),
	)
	return pbConcat(
		pbStr(fldSettingPath, `cursor\aisettings`),
		pbLen(fldSettingUnknown3, []byte{}),
		pbLen(fldSettingUnknown6, unknown6),
		pbVar(fldSettingUnknown8, 1),
		pbVar(fldSettingUnknown9, 1),
	)
}

// cursorRuntimeInfo supplies the process fields encodeMetadata sends.
// The JS reads process.platform/arch/version + cwd; Go has no Node
// version, so Version carries the JS fallback default ("v20.0.0").
type cursorRuntimeInfo struct {
	Platform string // JS process.platform spelling: linux|darwin|win32
	Arch     string // JS process.arch spelling: x64|arm64
	Version  string
	CWD      string
	Now      time.Time
}

func defaultCursorRuntime() cursorRuntimeInfo {
	platform := "linux"
	switch runtime.GOOS {
	case "windows":
		platform = "win32"
	case "darwin":
		platform = "darwin"
	}
	arch := "x64"
	if runtime.GOARCH == "arm64" {
		arch = "arm64"
	}
	cwd, err := os.Getwd()
	if err != nil || cwd == "" {
		cwd = "/"
	}
	return cursorRuntimeInfo{
		Platform: platform,
		Arch:     arch,
		Version:  "v20.0.0",
		CWD:      cwd,
		Now:      time.Now(),
	}
}

func encodeMetadataWith(rt cursorRuntimeInfo) []byte {
	ts := rt.Now.UTC().Format("2006-01-02T15:04:05.000Z07:00")
	return pbConcat(
		pbStr(fldMetaPlatform, rt.Platform),
		pbStr(fldMetaArch, rt.Arch),
		pbStr(fldMetaVersion, rt.Version),
		pbStr(fldMetaCWD, rt.CWD),
		pbStr(fldMetaTimestamp, ts),
	)
}

func encodeMessageID(messageID string, role int, summaryID string) []byte {
	parts := [][]byte{pbStr(fldMsgIDID, messageID)}
	if summaryID != "" {
		parts = append(parts, pbStr(fldMsgIDSummary, summaryID))
	}
	parts = append(parts, pbVar(fldMsgIDRole, uint64(role)))
	return pbConcat(parts...)
}

func encodeMcpTool(tool CursorToolDef) []byte {
	var parts [][]byte
	if tool.Name != "" {
		parts = append(parts, pbStr(fldMCPToolName, tool.Name))
	}
	if tool.Description != "" {
		parts = append(parts, pbStr(fldMCPToolDesc, tool.Description))
	}
	if len(tool.InputSchema) > 0 {
		// JS: JSON.stringify(inputSchema). Go marshals maps with sorted
		// keys; the server parses the JSON, so this is wire-equivalent.
		if b, err := json.Marshal(tool.InputSchema); err == nil {
			parts = append(parts, pbStr(fldMCPToolParams, string(b)))
		}
	}
	parts = append(parts, pbStr(fldMCPToolServer, "custom"))
	return pbConcat(parts...)
}

// ---------- request building ----------

// cursorNewUUID is indirected for fixture tests (the JS uses uuid v4).
var cursorNewUUID = newUUID

// EncodeRequest ports encodeRequest(): builds StreamUnifiedChatRequest.
func EncodeRequest(messages []CursorMessage, modelName string, tools []CursorToolDef, reasoningEffort string, forceAgentMode bool) []byte {
	hasTools := len(tools) > 0
	isAgentic := hasTools || forceAgentMode

	// Guardrail: split a mixed assistant payload (tool calls + results in
	// one message) into separate assistant messages, like the JS.
	type normMsg struct {
		msg CursorMessage
	}
	var normalized []normMsg
	for i, msg := range messages {
		hasCalls := msg.ToolCallCount > 0
		hasResults := len(msg.ToolResults) > 0
		if msg.Role == "assistant" && hasCalls && hasResults {
			trimmed := msg
			trimmed.ToolResults = nil
			normalized = append(normalized, normMsg{msg: trimmed})
			currentIDs := map[string]bool{}
			for _, tr := range msg.ToolResults {
				if tr.ToolCallID != "" {
					currentIDs[tr.ToolCallID] = true
				}
			}
			skip := false
			if i+1 < len(messages) {
				next := messages[i+1]
				if next.Role == "assistant" && len(next.ToolResults) > 0 {
					nextIDs := map[string]bool{}
					for _, tr := range next.ToolResults {
						if tr.ToolCallID != "" {
							nextIDs[tr.ToolCallID] = true
						}
					}
					same := len(currentIDs) > 0 && len(currentIDs) == len(nextIDs)
					if same {
						for id := range currentIDs {
							if !nextIDs[id] {
								same = false
								break
							}
						}
					}
					skip = same
				}
			}
			if !skip {
				normalized = append(normalized, normMsg{
					msg: CursorMessage{Role: "assistant", Content: "", ToolResults: msg.ToolResults},
				})
			}
			continue
		}
		normalized = append(normalized, normMsg{msg: msg})
	}

	type prepared struct {
		content     string
		role        int
		messageID   string
		isLast      bool
		toolResults []CursorToolResult
	}
	var formatted []prepared
	type msgIDEntry struct {
		id   string
		role int
	}
	var messageIDs []msgIDEntry
	for i, nm := range normalized {
		role := cursorRoleAssistant
		if nm.msg.Role == "user" {
			role = cursorRoleUser
		}
		id := cursorNewUUID()
		formatted = append(formatted, prepared{
			content:     nm.msg.Content,
			role:        role,
			messageID:   id,
			isLast:      i == len(normalized)-1,
			toolResults: nm.msg.ToolResults,
		})
		messageIDs = append(messageIDs, msgIDEntry{id: id, role: role})
	}

	thinkingLevel := cursorThinkingUnspecified
	if reasoningEffort == "medium" {
		thinkingLevel = cursorThinkingMedium
	} else if reasoningEffort == "high" {
		thinkingLevel = cursorThinkingHigh
	}

	var parts [][]byte
	for _, fm := range formatted {
		parts = append(parts, pbLen(fldMessages, encodeMessage(fm.content, fm.role, fm.messageID, fm.isLast, hasTools, fm.toolResults, "")))
	}
	parts = append(parts,
		pbVar(fldUnknown2, 1),
		pbLen(fldInstruction, encodeInstruction("")),
		pbVar(fldUnknown4, 1),
		pbLen(fldModel, encodeModel(modelName)),
		pbStr(fldWebTool, ""),
		pbVar(fldUnknown13, 1),
		pbLen(fldCursorSetting, encodeCursorSetting()),
		pbVar(fldUnknown19, 1),
		pbStr(fldConversationID, cursorNewUUID()),
		pbLen(fldMetadata, encodeMetadataWith(defaultCursorRuntime())),
		pbVar(fldIsAgentic, boolUint(isAgentic)),
	)
	if isAgentic {
		parts = append(parts, pbLen(fldSupportedTools, pbEncodeVarint(1)))
	}
	for _, mid := range messageIDs {
		parts = append(parts, pbLen(fldMessageIDs, encodeMessageID(mid.id, mid.role, "")))
	}
	for _, tool := range tools {
		parts = append(parts, pbLen(fldMCPTools, encodeMcpTool(tool)))
	}
	modeName := "Ask"
	mode := cursorUnifiedModeChat
	if isAgentic {
		mode = cursorUnifiedModeAgent
		modeName = "Agent"
	}
	parts = append(parts,
		pbVar(fldLargeContext, 0),
		pbVar(fldUnknown38, 0),
		pbVar(fldUnifiedMode, uint64(mode)),
		pbStr(fldUnknown47, ""),
		pbVar(fldShouldDisable, boolUint(!isAgentic)),
		pbVar(fldThinkingLevel, uint64(thinkingLevel)),
		pbVar(fldUnknown51, 0),
		pbVar(fldUnknown53, 1),
		pbStr(fldUnifiedModeNam, modeName),
	)
	return pbConcat(parts...)
}

// BuildChatRequest ports buildChatRequest(): wraps EncodeRequest as
// field 1 of StreamUnifiedChatRequestWithTools.
func BuildChatRequest(messages []CursorMessage, modelName string, tools []CursorToolDef, reasoningEffort string, forceAgentMode bool) []byte {
	return pbLen(fldRequest, EncodeRequest(messages, modelName, tools, reasoningEffort, forceAgentMode))
}

// BuildToolResultRequest ports buildToolResultRequest(): a standalone
// frame carrying field 2 (client_side_tool_v2_result).
func BuildToolResultRequest(tr CursorToolResult) []byte {
	toolCallID, modelCallID, hasModel := parseToolID(tr.ToolCallID)
	rawName := tr.ToolName
	selectedTool := rawName
	if strings.HasPrefix(selectedTool, "mcp_custom_") {
		selectedTool = selectedTool[len("mcp_custom_"):]
	} else if strings.HasPrefix(selectedTool, "mcp_") {
		selectedTool = selectedTool[len("mcp_"):]
	}
	parts := [][]byte{
		pbVar(fldCV2RTool, cursorClientSideToolV2MCP),
		pbLen(fldCV2RMCPResult, encodeMcpResult(selectedTool, tr.ResultContent)),
		pbStr(fldCV2RCallID, toolCallID),
	}
	if hasModel {
		parts = append(parts, pbStr(fldCV2RModelCallID, modelCallID))
	}
	// tool_index intentionally omitted (None per the Rust source the JS cites).
	return pbLen(2, pbConcat(parts...))
}

// WrapConnectRPCFrame ports wrapConnectRPCFrame(): 1 flag byte +
// 4-byte big-endian length + payload, gzip when compress is set.
func WrapConnectRPCFrame(payload []byte, compress bool) []byte {
	finalPayload := payload
	var flags byte
	if compress {
		var buf bytes.Buffer
		gw, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
		if err == nil {
			_, _ = gw.Write(payload)
			_ = gw.Close()
			finalPayload = buf.Bytes()
			flags = 0x01
		}
	}
	frame := make([]byte, 5+len(finalPayload))
	frame[0] = flags
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(finalPayload)))
	copy(frame[5:], finalPayload)
	return frame
}

// GenerateCursorBody ports generateCursorBody(): framed ChatService body.
func GenerateCursorBody(messages []CursorMessage, modelName string, tools []CursorToolDef, reasoningEffort string, forceAgentMode bool) []byte {
	protobuf := BuildChatRequest(messages, modelName, tools, reasoningEffort, forceAgentMode)
	return WrapConnectRPCFrame(protobuf, false) // Cursor doesn't support compressed requests
}

// GenerateToolResultBody ports generateToolResultBody().
func GenerateToolResultBody(tr CursorToolResult) []byte {
	return WrapConnectRPCFrame(BuildToolResultRequest(tr), false)
}

// ---------- response framing / parsing ----------

// ParseConnectRPCFrame ports parseConnectRPCFrame(): parses one frame
// from the front of buf. ok=false means more bytes are needed.
func ParseConnectRPCFrame(buf []byte) (flags byte, payload []byte, consumed int, ok bool) {
	if len(buf) < 5 {
		return 0, nil, 0, false
	}
	flags = buf[0]
	length := int(binary.BigEndian.Uint32(buf[1:5]))
	if len(buf) < 5+length {
		return 0, nil, 0, false
	}
	payload = buf[5 : 5+length]
	if flags == 0x01 {
		if dec, err := gunzipBytes(payload); err == nil {
			payload = dec
		}
	}
	return flags, payload, 5 + length, true
}

func gunzipBytes(b []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	return io.ReadAll(gr)
}

func inflateBytes(b []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

func inflateRawBytes(b []byte) ([]byte, error) {
	fr := flate.NewReader(bytes.NewReader(b))
	defer fr.Close()
	return io.ReadAll(fr)
}

// decompressPayload ports the executor's decompressPayload(): JSON error
// payloads pass through untouched; flags 1/2/3 try gzip → zlib → raw
// deflate in order and fall back to the raw payload.
func decompressPayload(payload []byte, flags byte) []byte {
	if len(payload) > 10 && payload[0] == 0x7b && payload[1] == 0x22 {
		if strings.HasPrefix(string(payload), `{"error"`) {
			return payload
		}
	}
	if flags == 0x01 || flags == 0x02 || flags == 0x03 {
		if out, err := gunzipBytes(payload); err == nil {
			return out
		}
		if out, err := inflateBytes(payload); err == nil {
			return out
		}
		if out, err := inflateRawBytes(payload); err == nil {
			return out
		}
		return payload
	}
	return payload
}

// cursorFrame is one frame read by readCursorFrame.
type cursorFrame struct {
	status  string // "ok" | "skip" | "done"
	payload []byte
	offset  int
}

// readCursorFrame ports readCursorFrame() from executors/cursor.js.
func readCursorFrame(buf []byte, offset int) cursorFrame {
	if offset+5 > len(buf) {
		return cursorFrame{status: "done", offset: offset}
	}
	flags := buf[offset]
	length := int(binary.BigEndian.Uint32(buf[offset+1 : offset+5]))
	if offset+5+length > len(buf) {
		return cursorFrame{status: "done", offset: offset}
	}
	payload := buf[offset+5 : offset+5+length]
	newOffset := offset + 5 + length
	payload = decompressPayload(payload, flags)
	if payload == nil {
		return cursorFrame{status: "skip", offset: newOffset}
	}
	return cursorFrame{status: "ok", payload: payload, offset: newOffset}
}

// ---------- response extraction ----------

// CursorToolCallExtracted is one decoded ClientSideToolV2Call
// (extractToolCall's return shape).
type CursorToolCallExtracted struct {
	ID           string
	Type         string // always "function"
	FunctionName string
	FunctionArgs string
	IsLast       bool
}

// CursorExtract is extractTextFromResponse's return shape.
type CursorExtract struct {
	Text        string
	HasText     bool
	Thinking    string
	HasThinking bool
	ToolCall    *CursorToolCallExtracted
	// Raw + DecodeError are set when decoding fails (JS: raw base64 +
	// decodeError message). Error mirrors the JS `error` field, which the
	// current JS always leaves null on these paths.
	Raw         string
	DecodeError string
}

func extractToolCall(toolCallData []byte) *CursorToolCallExtracted {
	toolCall := pbDecodeMessage(toolCallData)
	var toolCallID, toolName, rawArgs string
	var isLast bool

	if toolCall.has(fldToolID) {
		fullID := toolCall.firstString(fldToolID)
		toolCallID = strings.SplitN(fullID, "\n", 2)[0]
	}
	if toolCall.has(fldToolName) {
		toolName = toolCall.firstString(fldToolName)
	}
	if toolCall.has(fldToolIsLast) {
		isLast = toolCall.firstVarint(fldToolIsLast) != 0
	}
	if toolCall.has(fldToolMCPParam) {
		mcpParams := pbDecodeMessage(toolCall.firstBytes(fldToolMCPParam))
		if mcpParams.has(fldMCPToolsList) {
			tool := pbDecodeMessage(mcpParams.firstBytes(fldMCPToolsList))
			if tool.has(fldMCPNestedName) {
				toolName = tool.firstString(fldMCPNestedName)
			}
			if tool.has(fldMCPNestedParm) {
				rawArgs = tool.firstString(fldMCPNestedParm)
			}
		}
	}
	if rawArgs == "" && toolCall.has(fldToolRawArgs) {
		rawArgs = toolCall.firstString(fldToolRawArgs)
	}
	if toolCallID != "" && toolName != "" {
		if rawArgs == "" {
			rawArgs = "{}"
		}
		return &CursorToolCallExtracted{
			ID:           toolCallID,
			Type:         "function",
			FunctionName: toolName,
			FunctionArgs: rawArgs,
			IsLast:       isLast,
		}
	}
	return nil
}

func extractTextAndThinking(responseData []byte) (text string, hasText bool, thinking string, hasThinking bool) {
	nested := pbDecodeMessage(responseData)
	if nested.has(fldResponseText) {
		text = nested.firstString(fldResponseText)
		hasText = true
	}
	if nested.has(fldThinking) {
		thinkingMsg := pbDecodeMessage(nested.firstBytes(fldThinking))
		if thinkingMsg.has(fldThinkingText) {
			thinking = thinkingMsg.firstString(fldThinkingText)
			hasThinking = true
		}
	}
	return text, hasText, thinking, hasThinking
}

// ExtractTextFromResponse ports extractTextFromResponse().
func ExtractTextFromResponse(payload []byte) (result CursorExtract) {
	defer func() {
		if r := recover(); r != nil {
			result = CursorExtract{
				Raw:         base64Encode(payload),
				DecodeError: fmt.Sprintf("%v", r),
			}
		}
	}()
	fields := pbDecodeMessage(payload)
	if fields.has(fldRespToolCall) {
		if tc := extractToolCall(fields.firstBytes(fldRespToolCall)); tc != nil {
			return CursorExtract{ToolCall: tc}
		}
	}
	if fields.has(fldRespResponse) {
		text, hasText, thinking, hasThinking := extractTextAndThinking(fields.firstBytes(fldRespResponse))
		// JS: `if (text || thinking)` — empty strings are falsy there.
		if text != "" || thinking != "" {
			return CursorExtract{Text: text, HasText: hasText, Thinking: thinking, HasThinking: hasThinking}
		}
	}
	return CursorExtract{}
}

func base64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// ---------- agent.v1: google.protobuf.Value + MCP ----------

const (
	pbValueNull   = 1
	pbValueNumber = 2
	pbValueString = 3
	pbValueBool   = 4
	pbValueStruct = 5
	pbValueList   = 6

	pbStructFields = 1
	pbMapKey       = 1
	pbMapValue     = 2
	pbListValues   = 1

	mtdName        = 1
	mtdDescription = 2
	mtdInputSchema = 3
	mtdProvider    = 4
	mtdToolName    = 5

	mcpToolsTool = 1

	mcpArgsName     = 1
	mcpArgsEntry    = 2
	mcpArgsCallID   = 3
	mcpArgsToolName = 5

	mcrSuccess     = 1
	mcrError       = 2
	mcrToolNotFoun = 5
	mcsContent     = 1
	mcsIsError     = 2
	mccText        = 1
	mccImage       = 2
	mtcText        = 1
	micData        = 1
	micMime        = 2
	merMessage     = 1
	tnfName        = 1
)

// EncodeAgentValue ports encodeAgentValue(): a google.protobuf.Value
// oneof body (no outer tag). Supported Go types mirror the JS values:
// nil, bool, float64/int, string, []any, map[string]any. Map keys are
// sorted (JS object order is insertion order, which a decoded Go map no
// longer carries; struct fields are unordered on the wire semantically).
func EncodeAgentValue(value any) []byte {
	switch v := value.(type) {
	case nil:
		return pbVar(pbValueNull, 0)
	case bool:
		return pbVar(pbValueBool, boolUint(v))
	case float64:
		return pbEncodeField(pbValueNumber, pbWireFixed64, v)
	case float32:
		return pbEncodeField(pbValueNumber, pbWireFixed64, float64(v))
	case int:
		return pbEncodeField(pbValueNumber, pbWireFixed64, float64(v))
	case int64:
		return pbEncodeField(pbValueNumber, pbWireFixed64, float64(v))
	case json.Number:
		f, _ := v.Float64()
		return pbEncodeField(pbValueNumber, pbWireFixed64, f)
	case string:
		return pbStr(pbValueString, v)
	case []any:
		var items [][]byte
		for _, item := range v {
			items = append(items, pbLen(pbListValues, EncodeAgentValue(item)))
		}
		return pbLen(pbValueList, pbConcat(items...))
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var entries [][]byte
		for _, k := range keys {
			entry := pbConcat(
				pbStr(pbMapKey, k),
				pbLen(pbMapValue, EncodeAgentValue(v[k])),
			)
			entries = append(entries, pbLen(pbStructFields, entry))
		}
		return pbLen(pbValueStruct, pbConcat(entries...))
	default:
		return pbStr(pbValueString, fmt.Sprintf("%v", v))
	}
}

// DecodeAgentValue ports decodeAgentValue().
func DecodeAgentValue(data []byte) any {
	fields := pbDecodeMessage(data)
	if fields.has(pbValueNull) {
		return nil
	}
	if fields.has(pbValueBool) {
		return fields.firstVarint(pbValueBool) != 0
	}
	if fields.has(pbValueNumber) {
		b := fields.firstBytes(pbValueNumber)
		if len(b) == 8 {
			return math.Float64frombits(binary.LittleEndian.Uint64(b))
		}
		return float64(0)
	}
	if fields.has(pbValueString) {
		return fields.firstString(pbValueString)
	}
	if fields.has(pbValueStruct) {
		result := map[string]any{}
		structMsg := pbDecodeMessage(fields.firstBytes(pbValueStruct))
		for _, entry := range structMsg.get(pbStructFields) {
			pair := pbDecodeMessage(entry.Bytes)
			key := pair.firstString(pbMapKey)
			if key != "" {
				result[key] = DecodeAgentValue(pair.firstBytes(pbMapValue))
			}
		}
		return result
	}
	if fields.has(pbValueList) {
		listMsg := pbDecodeMessage(fields.firstBytes(pbValueList))
		var out []any
		for _, item := range listMsg.get(pbListValues) {
			out = append(out, DecodeAgentValue(item.Bytes))
		}
		return out
	}
	return nil
}

// EncodeMcpToolDefinition ports encodeMcpToolDefinition()
// (agent.v1.McpToolDefinition; provider is always "9router").
func EncodeMcpToolDefinition(tool CursorToolDef) []byte {
	schema := tool.InputSchema
	if schema == nil {
		schema = map[string]any{}
	}
	return pbConcat(
		pbStr(mtdName, tool.Name),
		pbStr(mtdDescription, tool.Description),
		pbLen(mtdInputSchema, EncodeAgentValue(schema)),
		pbStr(mtdProvider, "9router"),
		pbStr(mtdToolName, tool.Name),
	)
}

// EncodeMcpTools ports encodeMcpTools(): AgentRunRequest.mcp_tools body
// (repeated McpToolDefinition under field 1). Empty when no tools.
func EncodeMcpTools(tools []CursorToolDef) []byte {
	if len(tools) == 0 {
		return []byte{}
	}
	parts := make([][]byte, 0, len(tools))
	for _, tool := range tools {
		parts = append(parts, pbLen(mcpToolsTool, EncodeMcpToolDefinition(tool)))
	}
	return pbConcat(parts...)
}

// CursorMcpArgs is decodeMcpArgs' return shape.
type CursorMcpArgs struct {
	Name       string
	ToolCallID string
	ToolName   string
	Args       map[string]any
}

// DecodeMcpArgs ports decodeMcpArgs() (agent.v1.McpArgs).
func DecodeMcpArgs(data []byte) CursorMcpArgs {
	msg := pbDecodeMessage(data)
	args := map[string]any{}
	for _, entry := range msg.get(mcpArgsEntry) {
		pair := pbDecodeMessage(entry.Bytes)
		key := pair.firstString(pbMapKey)
		if key != "" {
			args[key] = DecodeAgentValue(pair.firstBytes(pbMapValue))
		}
	}
	return CursorMcpArgs{
		Name:       msg.firstString(mcpArgsName),
		ToolCallID: msg.firstString(mcpArgsCallID),
		ToolName:   msg.firstString(mcpArgsToolName),
		Args:       args,
	}
}

// EncodeMcpResultSuccess ports encodeMcpResultSuccess().
func EncodeMcpResultSuccess(textItems []string, imageItems []CursorMcpImage, isError bool) []byte {
	var parts [][]byte
	for _, text := range textItems {
		parts = append(parts, pbLen(mcsContent, pbLen(mccText, pbStr(mtcText, text))))
	}
	for _, img := range imageItems {
		mime := img.MimeType
		if mime == "" {
			mime = "application/octet-stream"
		}
		imgMsg := pbConcat(pbLen(micData, img.Data), pbStr(micMime, mime))
		parts = append(parts, pbLen(mcsContent, pbLen(mccImage, imgMsg)))
	}
	parts = append(parts, pbVar(mcsIsError, boolUint(isError)))
	return pbLen(mcrSuccess, pbConcat(parts...))
}

// CursorMcpImage is one image item for EncodeMcpResultSuccess.
type CursorMcpImage struct {
	Data     []byte
	MimeType string
}

// EncodeMcpResultError ports encodeMcpResultError().
func EncodeMcpResultError(message string) []byte {
	return pbLen(mcrError, pbStr(merMessage, message))
}

// EncodeMcpResultToolNotFound ports encodeMcpResultToolNotFound().
func EncodeMcpResultToolNotFound(name string) []byte {
	return pbLen(mcrToolNotFoun, pbStr(tnfName, name))
}
