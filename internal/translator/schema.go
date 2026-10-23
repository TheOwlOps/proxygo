package translator

// Format identifiers — port of translator/formats.js (FORMATS).
const (
	FormatOpenAI          = "openai"
	FormatOpenAIResponses = "openai-responses"
	FormatOpenAIResponse  = "openai-response"
	FormatClaude          = "claude"
	FormatGemini          = "gemini"
	FormatGeminiCLI       = "gemini-cli"
	FormatVertex          = "vertex"
	FormatCodex           = "codex"
	FormatAntigravity     = "antigravity"
	FormatKiro            = "kiro"
	FormatCursor          = "cursor"
	FormatOllama          = "ollama"
	FormatCommandCode     = "commandcode"
)

// Role enums — port of translator/schema/roles.js.
const (
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
	RoleSystem    = "system"
	RoleDeveloper = "developer"
)

// Gemini / Antigravity roles.
const (
	GeminiRoleUser  = "user"
	GeminiRoleModel = "model"
)

// OpenAI finish_reason values — port of schema/finishReasons.js.
const (
	OpenAIFinishStop          = "stop"
	OpenAIFinishLength        = "length"
	OpenAIFinishToolCalls     = "tool_calls"
	OpenAIFinishContentFilter = "content_filter"
)

// Claude stop_reason values.
const (
	ClaudeStopEndTurn      = "end_turn"
	ClaudeStopMaxTokens    = "max_tokens"
	ClaudeStopToolUse      = "tool_use"
	ClaudeStopStopSequence = "stop_sequence"
	ClaudeStopRefusal      = "refusal"
)

// Gemini finishReason values.
const (
	GeminiFinishStop              = "STOP"
	GeminiFinishMaxTokens         = "MAX_TOKENS"
	GeminiFinishSafety            = "SAFETY"
	GeminiFinishRecitation        = "RECITATION"
	GeminiFinishBlocklist         = "BLOCKLIST"
	GeminiFinishProhibitedContent = "PROHIBITED_CONTENT"
)

// Content-block type discriminators — port of schema/blocks.js.
const (
	OpenAIBlockText       = "text"
	OpenAIBlockImageURL   = "image_url"
	OpenAIBlockImage      = "image"
	OpenAIBlockInputAudio = "input_audio"
	OpenAIBlockAudioURL   = "audio_url"
	OpenAIBlockFile       = "file"
	OpenAIBlockFunction   = "function"
)

const (
	ClaudeBlockText                = "text"
	ClaudeBlockImage               = "image"
	ClaudeBlockDocument            = "document"
	ClaudeBlockToolUse             = "tool_use"
	ClaudeBlockToolResult          = "tool_result"
	ClaudeBlockContainerUpload     = "container_upload"
	ClaudeBlockThinking            = "thinking"
	ClaudeBlockRedactedThinking    = "redacted_thinking"
	ClaudeBlockServerToolUse       = "server_tool_use"
	ClaudeBlockWebSearchToolResult = "web_search_tool_result"
)

// OpenAI Responses API item types — port of schema/blocks.js.
const (
	ResponsesItemMessage              = "message"
	ResponsesItemFunctionCall         = "function_call"
	ResponsesItemFunctionCallOutput   = "function_call_output"
	ResponsesItemCustomToolCall       = "custom_tool_call"
	ResponsesItemCustomToolCallOutput = "custom_tool_call_output"
	ResponsesItemAdditionalTools      = "additional_tools"
	ResponsesItemReasoning            = "reasoning"
	ResponsesItemOutputText           = "output_text"
	ResponsesItemInputText            = "input_text"
	ResponsesItemInputImage           = "input_image"
	ResponsesItemSummaryText          = "summary_text"
)

// Valid OpenAI content/message block types (filterToOpenAIFormat).
var (
	validOpenAIContentTypes = []string{
		OpenAIBlockText, OpenAIBlockImageURL, OpenAIBlockImage,
		OpenAIBlockInputAudio, OpenAIBlockAudioURL, OpenAIBlockFile,
	}
	validOpenAIMessageTypes = []string{
		OpenAIBlockText, OpenAIBlockImageURL, OpenAIBlockImage,
		"tool_calls", ClaudeBlockToolResult,
	}
)

// Shared defaults — port of schema/defaults.js and config values.
const (
	// ModelFallback is used when an upstream chunk omits the model id.
	ModelFallback = "unknown"
	// DefaultImageMIME is the fallback image mime for untyped base64 blobs.
	DefaultImageMIME = "image/png"
	// DefaultMaxTokens / DefaultMinTokens — config/runtimeConfig.js.
	DefaultMaxTokens = 64000
	DefaultMinTokens = 32000
	// ClaudeSystemPrompt — config/appConstants.js CLAUDE_SYSTEM_PROMPT.
	ClaudeSystemPrompt = "You are Claude Code, Anthropic's official CLI for Claude."
)
