package translator

import (
	"regexp"
	"strconv"
	"strings"
)

// ---------- Kiro constants (config/kiroConstants.js) ----------

const (
	KiroAgenticSuffix  = "-agentic"
	KiroThinkingSuffix = "-thinking"

	// Tool spec limits enforced by the Kiro conversation canonicalizer.
	KiroToolNameMaxLength        = 64
	KiroToolDescriptionMaxLength = 10237
	KiroToolIDMaxLength          = 64

	KiroCodeWhispererTarget = "AmazonCodeWhispererStreamingService.GenerateAssistantResponse"

	KiroThinkingBudgetDefault = 16000
)

// Public default CodeWhisperer profile ARNs (us-east-1), keyed by auth
// method — port of KIRO_DEFAULT_PROFILE_ARNS.
var kiroDefaultProfileARNs = map[string]string{
	"builder-id": "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX",
	"social":     "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
}

// KiroDefaultProfileARN is the back-compat single default (Builder ID).
const KiroDefaultProfileARN = "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX"

// resolveDefaultProfileArn ports resolveDefaultProfileArn: social
// (Google/GitHub) sign-ins map to the social profile, everything else to
// the Builder ID profile.
func resolveDefaultProfileArn(authMethod string) string {
	if authMethod == "google" || authMethod == "github" {
		return kiroDefaultProfileARNs["social"]
	}
	return kiroDefaultProfileARNs["builder-id"]
}

// KiroAgenticSystemPrompt is KIRO_AGENTIC_SYSTEM_PROMPT, verbatim.
const KiroAgenticSystemPrompt = `# CRITICAL: CHUNKED WRITE PROTOCOL (MANDATORY)

You MUST follow these rules for ALL file operations. Violation causes server timeouts and task failure.

## ABSOLUTE LIMITS
- **MAXIMUM 350 LINES** per single write/edit operation - NO EXCEPTIONS
- **RECOMMENDED 300 LINES** or less for optimal performance
- **NEVER** write entire files in one operation if >300 lines

## MANDATORY CHUNKED WRITE STRATEGY

### For NEW FILES (>300 lines total):
1. FIRST: Write initial chunk (first 250-300 lines) using write_to_file/fsWrite
2. THEN: Append remaining content in 250-300 line chunks using file append operations
3. REPEAT: Continue appending until complete

### For EDITING EXISTING FILES:
1. Use surgical edits (apply_diff/targeted edits) - change ONLY what's needed
2. NEVER rewrite entire files - use incremental modifications
3. Split large refactors into multiple small, focused edits

### For LARGE CODE GENERATION:
1. Generate in logical sections (imports, types, functions separately)
2. Write each section as a separate operation
3. Use append operations for subsequent sections

## EXAMPLES OF CORRECT BEHAVIOR

CORRECT: Writing a 600-line file
- Operation 1: Write lines 1-300 (initial file creation)
- Operation 2: Append lines 301-600

CORRECT: Editing multiple functions
- Operation 1: Edit function A
- Operation 2: Edit function B
- Operation 3: Edit function C

WRONG: Writing 500 lines in single operation -> TIMEOUT
WRONG: Rewriting entire file to change 5 lines -> TIMEOUT
WRONG: Generating massive code blocks without chunking -> TIMEOUT

## WHY THIS MATTERS
- Server has 2-3 minute timeout for operations
- Large writes exceed timeout and FAIL completely
- Chunked writes are FASTER and more RELIABLE
- Failed writes waste time and require retry

REMEMBER: When in doubt, write LESS per operation. Multiple small operations > one large operation.`

// ---------- model suffix intent (kiroConstants resolveKiroModel*) ----------

// resolveKiroModel ports resolveKiroModel: strip the synthetic
// -agentic / -thinking suffixes (agentic first, then thinking).
func resolveKiroModel(model string) (upstream string, agentic, thinking bool) {
	upstream = model
	if strings.HasSuffix(upstream, KiroAgenticSuffix) {
		agentic = true
		upstream = strings.TrimSuffix(upstream, KiroAgenticSuffix)
	}
	if strings.HasSuffix(upstream, KiroThinkingSuffix) {
		thinking = true
		upstream = strings.TrimSuffix(upstream, KiroThinkingSuffix)
	}
	return upstream, agentic, thinking
}

// ---------- thinking (thinkingUnified extractThinking/parseSuffix subset,
// concerns/thinking.js effortToBudget, kiroConstants thinking helpers) ----

var kiroLevelToBudget = map[string]int{
	"none": 0, "minimal": 512, "low": 1024, "medium": 8192,
	"high": 24576, "xhigh": 32768, "max": 128000,
}

// effortToBudget ports concerns/thinking.js effortToBudget; ok=false when
// the level is unrecognised (JS undefined).
func effortToBudget(effort string) (int, bool) {
	if effort == "" {
		return 0, false
	}
	b, ok := kiroLevelToBudget[strings.ToLower(effort)]
	return b, ok
}

// thinkingConfig is the subset of thinkingUnified's extractThinking
// result the Kiro resolvers consume: mode none|auto|level|budget.
type thinkingConfig struct {
	mode   string
	level  string
	budget int
}

var suffixRe = regexp.MustCompile(`^(.*)\(([^()]+)\)\s*$`)

// parseSuffix ports thinkingUnified.parseSuffix: a trailing "(…)" group
// on the model id is a thinking override (level, budget number, none/off,
// auto, ultra).
func parseSuffix(model string) (cleanModel string, override *thinkingConfig) {
	m := suffixRe.FindStringSubmatch(model)
	if m == nil {
		return model, nil
	}
	cleanModel = strings.TrimSpace(m[1])
	raw := strings.ToLower(strings.TrimSpace(m[2]))
	switch {
	case raw == "none" || raw == "off":
		return cleanModel, &thinkingConfig{mode: "none"}
	case raw == "auto":
		return cleanModel, &thinkingConfig{mode: "auto"}
	case raw == "ultra":
		return cleanModel, &thinkingConfig{mode: "level", level: raw}
	case isAllDigits(raw):
		n, _ := strconv.Atoi(raw)
		return cleanModel, &thinkingConfig{mode: "budget", budget: n}
	}
	if _, ok := kiroLevelToBudget[raw]; ok {
		return cleanModel, &thinkingConfig{mode: "level", level: raw}
	}
	return cleanModel, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// extractThinking ports thinkingUnified.extractThinking: Claude
// output_config.effort → OpenAI reasoning_effort/reasoning.effort →
// Claude thinking object → Gemini thinkingConfig → Qwen enable_thinking.
func extractThinking(body Body) *thinkingConfig {
	if body == nil {
		return nil
	}
	if oc := obj(body, "output_config"); oc != nil {
		if e := str(oc, "effort"); e != "" {
			return effortConfig(e)
		}
	}
	effort := str(body, "reasoning_effort")
	if effort == "" {
		if r := obj(body, "reasoning"); r != nil {
			effort = str(r, "effort")
		}
	}
	if effort != "" {
		return effortConfig(effort)
	}
	if t := obj(body, "thinking"); t != nil {
		switch str(t, "type") {
		case "disabled":
			return &thinkingConfig{mode: "none"}
		case "adaptive", "enabled":
			if b, ok := num(t, "budget_tokens"); ok && b > 0 {
				return &thinkingConfig{mode: "budget", budget: int(b)}
			}
			return &thinkingConfig{mode: "auto"}
		}
	}
	tc := obj(body, "thinkingConfig")
	if tc == nil {
		if gc := obj(body, "generationConfig"); gc != nil {
			tc = obj(gc, "thinkingConfig")
		}
	}
	if tc == nil {
		if req := obj(body, "request"); req != nil {
			if gc := obj(req, "generationConfig"); gc != nil {
				tc = obj(gc, "thinkingConfig")
			}
		}
	}
	if tc != nil {
		if lvl := str(tc, "thinkingLevel"); lvl != "" {
			return &thinkingConfig{mode: "level", level: strings.ToLower(lvl)}
		}
		if tb, ok := num(tc, "thinkingBudget"); ok {
			switch {
			case tb == 0:
				return &thinkingConfig{mode: "none"}
			case tb < 0:
				return &thinkingConfig{mode: "auto"}
			default:
				return &thinkingConfig{mode: "budget", budget: int(tb)}
			}
		}
	}
	if v, ok := body["enable_thinking"].(bool); ok {
		if !v {
			return &thinkingConfig{mode: "none"}
		}
		if tb, ok2 := num(body, "thinking_budget"); ok2 && tb > 0 {
			return &thinkingConfig{mode: "budget", budget: int(tb)}
		}
		return &thinkingConfig{mode: "auto"}
	}
	return nil
}

func effortConfig(effort string) *thinkingConfig {
	e := strings.ToLower(effort)
	switch e {
	case "none", "off":
		return &thinkingConfig{mode: "none"}
	case "auto":
		return &thinkingConfig{mode: "auto"}
	default:
		return &thinkingConfig{mode: "level", level: e}
	}
}

// kiroModelIntent mirrors resolveKiroModelIntent + resolveKiroModel.
type kiroModelIntent struct {
	model            string // clean model after parseSuffix
	upstream         string
	agentic          bool
	thinking         bool
	thinkingOverride *thinkingConfig
}

func resolveKiroModelIntent(model string) kiroModelIntent {
	clean, override := parseSuffix(model)
	upstream, agentic, thinking := resolveKiroModel(clean)
	return kiroModelIntent{
		model: clean, upstream: upstream, agentic: agentic,
		thinking: thinking, thinkingOverride: override,
	}
}

// applyKiroThinkingOverride ports applyKiroThinkingOverride: fold a
// model(level) suffix override back into a body copy.
func applyKiroThinkingOverride(body Body, override *thinkingConfig) Body {
	if override == nil {
		return body
	}
	next := deepCopyBody(body)
	if override.mode == "budget" {
		delete(next, "output_config")
		delete(next, "reasoning_effort")
		delete(next, "reasoning")
		next["thinking"] = Body{"type": "enabled", "budget_tokens": override.budget}
		return next
	}
	effort := override.mode
	if override.mode == "level" {
		effort = override.level
	}
	oc := obj(next, "output_config")
	merged := Body{}
	for k, v := range oc {
		merged[k] = v
	}
	merged["effort"] = effort
	next["output_config"] = merged
	return next
}

// resolveKiroThinkingBudget ports resolveKiroThinkingBudget minus the
// Anthropic-Beta header signal (headers are not part of the Go ReqFn
// contract): thinking config → <thinking_mode> tag in messages/system →
// model-name hint.
func resolveKiroThinkingBudget(body Body, model string) (int, bool) {
	if cfg := extractThinking(body); cfg != nil {
		switch {
		case cfg.mode == "none":
			return 0, false
		case cfg.mode == "level" && cfg.level == "disabled":
			return 0, false
		case cfg.mode == "budget":
			return cfg.budget, true
		case cfg.mode == "level":
			if b, ok := effortToBudget(cfg.level); ok {
				return b, true
			}
			return KiroThinkingBudgetDefault, true
		default: // auto
			return KiroThinkingBudgetDefault, true
		}
	}
	if containsThinkingModeTag(body) {
		return KiroThinkingBudgetDefault, true
	}
	if model != "" {
		m := strings.ToLower(model)
		if strings.Contains(m, "thinking") || strings.Contains(m, "-reason") {
			return KiroThinkingBudgetDefault, true
		}
	}
	return 0, false
}

// buildThinkingSystemPrefix ports buildThinkingSystemPrefix (budget
// clamped to 1..32000).
func buildThinkingSystemPrefix(budget int) string {
	if budget <= 0 {
		budget = KiroThinkingBudgetDefault
	}
	if budget > 32000 {
		budget = 32000
	}
	return "<thinking_mode>enabled</thinking_mode>\n<max_thinking_length>" + itoa(budget) + "</max_thinking_length>"
}

func containsThinkingModeTag(body Body) bool {
	for _, m := range arr(body, "messages") {
		msg, _ := m.(map[string]any)
		if msg == nil {
			continue
		}
		role := str(msg, "role")
		if role != RoleSystem && role != RoleUser {
			continue
		}
		switch c := msg["content"].(type) {
		case string:
			if containsTagInText(c) {
				return true
			}
		case []any:
			for _, part := range c {
				if pm, ok := part.(map[string]any); ok && containsTagInText(str(pm, "text")) {
					return true
				}
			}
		}
	}
	if s := str(body, "system"); s != "" && containsTagInText(s) {
		return true
	}
	return false
}

func containsTagInText(text string) bool {
	if !strings.Contains(text, "<thinking_mode>") {
		return false
	}
	return strings.Contains(text, "<thinking_mode>enabled</thinking_mode>") ||
		strings.Contains(text, "<thinking_mode>interleaved</thinking_mode>")
}

// ---------- native effort fields (buildKiroAdditionalModelRequestFields) --

var claudeVersionRe = regexp.MustCompile(`(?:^|[/.])claude(?:[/.][a-z]+)*[/.](\d+)(?:[/.](\d+))?(?:[/.]|$)`)

type claudeVersion struct {
	major int
	minor int
	has   bool // minor present
}

func parseClaudeVersion(model string) (claudeVersion, bool) {
	normalized := strings.ReplaceAll(strings.ToLower(model), "-", ".")
	m := claudeVersionRe.FindStringSubmatch(normalized)
	if m == nil {
		return claudeVersion{}, false
	}
	major, _ := strconv.Atoi(m[1])
	v := claudeVersion{major: major}
	if m[2] != "" {
		v.minor, _ = strconv.Atoi(m[2])
		v.has = true
	}
	return v, true
}

// kiroModelLacksXhigh: 4.6-and-below Claude models cap at high; unknown
// models stay conservative.
func kiroModelLacksXhigh(model string) bool {
	v, ok := parseClaudeVersion(model)
	if !ok {
		return true
	}
	return v.major == 4 && v.has && v.minor <= 6
}

func kiroEffortValue(body Body) (string, bool) {
	if oc := obj(body, "output_config"); oc != nil {
		if e := str(oc, "effort"); e != "" {
			return e, true
		}
	}
	if e := str(body, "reasoning_effort"); e != "" {
		return e, true
	}
	if r := obj(body, "reasoning"); r != nil {
		if e := str(r, "effort"); e != "" {
			return e, true
		}
	}
	return "", false
}

// extractKiroEffortLevel ports extractKiroEffortLevel (Claude path).
func extractKiroEffortLevel(body Body, model string) (string, bool) {
	effort, ok := kiroEffortValue(body)
	if !ok {
		return "", false
	}
	switch n := strings.ToLower(effort); n {
	case "none", "off", "disabled":
		return "", false
	case "xhigh":
		if kiroModelLacksXhigh(model) {
			return "high", true
		}
		return "xhigh", true
	case "max":
		return "max", true
	case "low", "medium", "high":
		return n, true
	}
	return "", false
}

// extractKiroGptEffortLevel ports extractKiroGptEffortLevel.
func extractKiroGptEffortLevel(body Body) (string, bool) {
	effort, ok := kiroEffortValue(body)
	if !ok {
		return "", false
	}
	switch n := strings.ToLower(effort); n {
	case "max":
		return "xhigh", true
	case "low", "medium", "high", "xhigh":
		return n, true
	}
	return "", false
}

var gpt56Re = regexp.MustCompile(`(?:^|[/.])gpt[/.]5[/.]6(?:[/.]|$)`)

// resolveKiroEffortPath ports resolveKiroEffortPath: "reasoning" for
// GPT-5.6, "output_config" for supported Claude models, "" otherwise.
func resolveKiroEffortPath(model string) string {
	normalized := strings.ReplaceAll(strings.ToLower(model), "-", ".")
	if gpt56Re.MatchString(normalized) {
		return "reasoning"
	}
	if !strings.Contains(normalized, "claude") {
		return ""
	}
	v, ok := parseClaudeVersion(model)
	if !ok {
		return ""
	}
	dateSuffixMinor := v.has && v.minor >= 1000
	if v.major < 4 || (v.major == 4 && (!v.has || v.minor <= 5 || dateSuffixMinor)) {
		return ""
	}
	return "output_config"
}

// buildKiroAdditionalModelRequestFieldsForModel ports
// buildKiroAdditionalModelRequestFieldsForModel (+ its inner builder);
// returns nil when the model/effort pair has no native field mapping.
func buildKiroAdditionalModelRequestFieldsForModel(body Body, model string) Body {
	path := resolveKiroEffortPath(model)
	if path == "" {
		return nil
	}
	if path == "reasoning" {
		effort, ok := extractKiroGptEffortLevel(body)
		if !ok {
			return nil
		}
		return Body{"reasoning": Body{"effort": effort}}
	}
	effort, ok := extractKiroEffortLevel(body, model)
	if !ok {
		return nil
	}
	return Body{
		"thinking":      Body{"type": "adaptive", "display": "summarized"},
		"output_config": Body{"effort": effort},
	}
}

// usesKiroNativeGptEffort ports usesKiroNativeGptEffort.
func usesKiroNativeGptEffort(body Body, model string) bool {
	if resolveKiroEffortPath(model) != "reasoning" {
		return false
	}
	_, ok := extractKiroGptEffortLevel(body)
	return ok
}
