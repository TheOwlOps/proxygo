package translator

import (
	"regexp"
	"strings"
)

// ---------- formats/gemini.js helpers ----------

// defaultSafetySettings ports DEFAULT_SAFETY_SETTINGS.
func defaultSafetySettings() []any {
	mk := func(cat string) Body {
		return Body{"category": cat, "threshold": "OFF"}
	}
	return []any{
		mk("HARM_CATEGORY_HATE_SPEECH"),
		mk("HARM_CATEGORY_DANGEROUS_CONTENT"),
		mk("HARM_CATEGORY_SEXUALLY_EXPLICIT"),
		mk("HARM_CATEGORY_HARASSMENT"),
		mk("HARM_CATEGORY_CIVIC_INTEGRITY"),
	}
}

var unsupportedSchemaConstraints = map[string]bool{
	"minLength": true, "maxLength": true, "exclusiveMinimum": true, "exclusiveMaximum": true,
	"minItems": true, "maxItems": true, "format": true, "multipleOf": true,
	"uniqueItems": true, "contains": true,
	"unevaluatedProperties": true, "unevaluatedItems": true, "contentSchema": true,
	"prefixItems": true, "additionalItems": true,
	"default": true, "examples": true,
	"$schema": true, "$defs": true, "definitions": true, "const": true, "$ref": true, "$comment": true,
	"deprecated": true, "readOnly": true, "writeOnly": true,
	"additionalProperties": true, "propertyNames": true, "patternProperties": true, "enumDescriptions": true,
	"anyOf": true, "oneOf": true, "allOf": true, "not": true,
	"dependencies": true, "dependentSchemas": true, "dependentRequired": true,
	"title": true, "optional": true, "if": true, "then": true, "else": true,
	"contentMediaType": true, "contentEncoding": true,
	"cornerRadius": true, "fillColor": true, "fontFamily": true, "fontSize": true, "fontWeight": true,
	"gap": true, "padding": true, "strokeColor": true, "strokeThickness": true, "textColor": true,
	"errorMessage": true, "errorMessages": true, "x-errorMessage": true, "x-errorMessages": true,
	"markdownDescription": true, "x-intellij-html-description": true,
	"x-taplo-info": true, "x-taplo": true, "doNotSuggest": true, "suggestSortText": true,
	"minProperties": true, "maxProperties": true,
}

// cleanJSONSchemaForAntigravity ports cleanJSONSchemaForAntigravity
// from formats/gemini.js. The caller passes a deep copy (the JS mutates a
// structuredClone); this function mutates and returns its argument.
func cleanJSONSchemaForAntigravity(schema any) any {
	m, ok := schema.(map[string]any)
	if !ok {
		return schema
	}
	convertConstToEnum(m)
	convertEnumValuesToStrings(m)
	mergeAllOf(m)
	convertPrefixItems(m)
	flattenAnyOfOneOf(m)
	flattenTypeArrays(m)
	ensureObjectType(m)
	ensureArrayItems(m)
	removeUnsupportedKeywords(m)
	cleanupRequired(m)
	addPlaceholders(m)
	return m
}

func eachValue(v any, fn func(map[string]any)) {
	switch t := v.(type) {
	case map[string]any:
		fn(t)
		for _, val := range t {
			eachValue(val, fn)
		}
	case []any:
		for _, val := range t {
			eachValue(val, fn)
		}
	}
}

func convertConstToEnum(root Body) {
	eachValue(root, func(m map[string]any) {
		if c, present := m["const"]; present {
			if _, hasEnum := m["enum"]; !hasEnum {
				m["enum"] = []any{c}
				delete(m, "const")
			}
		}
	})
}

func convertEnumValuesToStrings(root Body) {
	eachValue(root, func(m map[string]any) {
		if enum, ok := m["enum"].([]any); ok {
			out := make([]any, len(enum))
			for i, v := range enum {
				out[i] = stringOrJSON(v)
			}
			m["enum"] = out
			if !has(m, "type") {
				m["type"] = "string"
			}
		}
	})
}

// stringOrJSON mirrors JS String(v) for enum scalars.
func stringOrJSON(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	default:
		if _, isNum := numVal(v); isNum {
			return stringifyJSON(v)
		}
		return stringifyJSON(v)
	}
}

func mergeAllOf(root Body) {
	eachValue(root, func(m map[string]any) {
		allOf, ok := m["allOf"].([]any)
		if !ok {
			return
		}
		mergedProps := Body{}
		hasProps := false
		var mergedRequired []any
		for _, itemV := range allOf {
			item, ok := itemV.(map[string]any)
			if !ok {
				continue
			}
			if props, ok := item["properties"].(map[string]any); ok {
				hasProps = true
				for k, v := range props {
					mergedProps[k] = v
				}
			}
			if req, ok := item["required"].([]any); ok {
				for _, r := range req {
					found := false
					for _, existing := range mergedRequired {
						if existing == r {
							found = true
						}
					}
					if !found {
						mergedRequired = append(mergedRequired, r)
					}
				}
			}
		}
		delete(m, "allOf")
		if hasProps {
			props := Body{}
			if existing, ok := m["properties"].(map[string]any); ok {
				for k, v := range existing {
					props[k] = v
				}
			}
			for k, v := range mergedProps {
				props[k] = v
			}
			m["properties"] = props
		}
		if len(mergedRequired) > 0 {
			req := append([]any{}, arr(m, "required")...)
			m["required"] = append(req, mergedRequired...)
		}
	})
}

func convertPrefixItems(root Body) {
	eachValue(root, func(m map[string]any) {
		prefix, ok := m["prefixItems"].([]any)
		if !ok || len(prefix) == 0 {
			return
		}
		var variants []any
		for _, s := range prefix {
			if sm, ok := s.(map[string]any); ok && str(sm, "type") != "null" {
				variants = append(variants, s)
			}
		}
		if !has(m, "items") {
			if len(variants) == 1 {
				m["items"] = variants[0]
			} else if len(variants) > 1 {
				m["items"] = Body{"anyOf": variants}
			}
		}
		delete(m, "prefixItems")
	})
}

func selectBestSchema(items []any) int {
	bestIdx, bestScore := 0, -1
	for i, itemV := range items {
		item, _ := itemV.(map[string]any)
		score := 0
		t := ""
		if item != nil {
			t = str(item, "type")
		}
		if t == "object" || (item != nil && has(item, "properties")) {
			score = 3
		} else if t == "array" || (item != nil && has(item, "items")) {
			score = 2
		} else if t != "" && t != "null" {
			score = 1
		}
		if score > bestScore {
			bestScore = score
			bestIdx = i
		}
	}
	return bestIdx
}

func flattenAnyOfOneOf(root Body) {
	eachValue(root, func(m map[string]any) {
		for _, key := range []string{"anyOf", "oneOf"} {
			items, ok := m[key].([]any)
			if !ok || len(items) == 0 {
				continue
			}
			var nonNull []any
			for _, s := range items {
				if sm, ok := s.(map[string]any); ok && str(sm, "type") == "null" {
					continue
				}
				if s == nil {
					continue
				}
				nonNull = append(nonNull, s)
			}
			if len(nonNull) > 0 {
				selected, _ := nonNull[selectBestSchema(nonNull)].(map[string]any)
				delete(m, key)
				for k, v := range selected {
					m[k] = v
				}
			}
		}
	})
}

func flattenTypeArrays(root Body) {
	eachValue(root, func(m map[string]any) {
		if types, ok := m["type"].([]any); ok {
			var nonNull []any
			for _, t := range types {
				if t != "null" {
					nonNull = append(nonNull, t)
				}
			}
			if len(nonNull) > 0 {
				m["type"] = nonNull[0]
			} else {
				m["type"] = "string"
			}
		}
	})
}

func ensureObjectType(v any) {
	switch t := v.(type) {
	case map[string]any:
		if has(t, "properties") && !has(t, "type") {
			t["type"] = "object"
		}
		for key, val := range t {
			if key == "properties" {
				if props, ok := val.(map[string]any); ok {
					for _, sub := range props {
						ensureObjectType(sub)
					}
				} else {
					ensureObjectType(val)
				}
			} else {
				ensureObjectType(val)
			}
		}
	case []any:
		for _, val := range t {
			ensureObjectType(val)
		}
	}
}

func ensureArrayItems(v any) {
	switch t := v.(type) {
	case map[string]any:
		if str(t, "type") == "array" && !has(t, "items") {
			t["items"] = Body{"type": "string"}
		}
		for _, val := range t {
			ensureArrayItems(val)
		}
	case []any:
		for _, val := range t {
			ensureArrayItems(val)
		}
	}
}

func removeUnsupportedKeywords(v any) {
	switch t := v.(type) {
	case map[string]any:
		for key := range t {
			if unsupportedSchemaConstraints[key] || strings.HasPrefix(key, "x-") {
				delete(t, key)
			}
		}
		for _, val := range t {
			removeUnsupportedKeywords(val)
		}
	case []any:
		for _, val := range t {
			removeUnsupportedKeywords(val)
		}
	}
}

func cleanupRequired(v any) {
	switch t := v.(type) {
	case map[string]any:
		if req, ok := t["required"].([]any); ok {
			if props, pok := t["properties"].(map[string]any); pok {
				var valid []any
				for _, field := range req {
					if name, ok := field.(string); ok {
						if _, exists := props[name]; exists {
							valid = append(valid, field)
						}
					}
				}
				if len(valid) == 0 {
					delete(t, "required")
				} else {
					t["required"] = valid
				}
			}
		}
		for _, val := range t {
			cleanupRequired(val)
		}
	case []any:
		for _, val := range t {
			cleanupRequired(val)
		}
	}
}

func addPlaceholders(v any) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			t["type"] = "object"
			t["properties"] = Body{
				"reason": Body{"type": "string", "description": "Brief explanation of why you are calling this tool"},
			}
			t["required"] = []any{"reason"}
			return
		}
		if str(t, "type") == "object" {
			props, _ := t["properties"].(map[string]any)
			if len(props) == 0 {
				t["properties"] = Body{
					"reason": Body{"type": "string", "description": "Brief explanation of why you are calling this tool"},
				}
				t["required"] = []any{"reason"}
			}
		}
		for _, val := range t {
			addPlaceholders(val)
		}
	case []any:
		for _, val := range t {
			addPlaceholders(val)
		}
	}
}

// sanitizeFunctionResponsePayload ports the $ref -> _ref recursive rename.
func sanitizeFunctionResponsePayload(v any) any {
	switch t := v.(type) {
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = sanitizeFunctionResponsePayload(val)
		}
		return out
	case map[string]any:
		out := Body{}
		for k, val := range t {
			key := k
			if key == "$ref" {
				key = "_ref"
			}
			out[key] = sanitizeFunctionResponsePayload(val)
		}
		return out
	default:
		return v
	}
}

func sanitizeFunctionResponsePart(part Body) Body {
	fr := obj(part, "functionResponse")
	if fr == nil {
		return part
	}
	resp := fr["response"]
	if _, isObj := resp.(map[string]any); !isObj {
		if _, isArr := resp.([]any); !isArr {
			return part
		}
	}
	cp := deepCopyBody(part)
	cpFR := obj(cp, "functionResponse")
	cpFR["response"] = sanitizeFunctionResponsePayload(resp)
	return cp
}

func moveFunctionResponsesLast(parts []any) []any {
	var responses, others []any
	for _, p := range parts {
		if pm, ok := p.(map[string]any); ok && obj(pm, "functionResponse") != nil {
			responses = append(responses, p)
		} else {
			others = append(others, p)
		}
	}
	if len(responses) == 0 {
		return parts
	}
	return append(others, responses...)
}

var gemini4Re = regexp.MustCompile(`(?:^|/)gemini-4(?:$|[-.])`)

// isGemini4Model ports isGemini4Model from providers/capabilities.js.
func isGemini4Model(model string) bool {
	return gemini4Re.MatchString(model)
}

// normalizeGeminiContents ports normalizeGeminiContents from formats/gemini.js.
func normalizeGeminiContents(contents []any, model string) []any {
	frLast := isGemini4Model(model)
	var out []Body
	for _, cv := range contents {
		c, _ := cv.(map[string]any)
		if c == nil || str(c, "role") == "" {
			continue
		}
		rawParts := arr(c, "parts")
		if rawParts == nil {
			continue
		}
		var parts []any
		for _, pv := range rawParts {
			pm, ok := pv.(map[string]any)
			if !ok || len(pm) == 0 {
				continue
			}
			parts = append(parts, sanitizeFunctionResponsePart(pm))
		}
		if len(parts) == 0 {
			continue
		}
		if n := len(out); n > 0 && out[n-1]["role"] == c["role"] {
			out[n-1]["parts"] = append(arr(out[n-1], "parts"), parts...)
			if frLast {
				out[n-1]["parts"] = moveFunctionResponsesLast(arr(out[n-1], "parts"))
			}
		} else {
			cp := deepCopyBody(c)
			cp["parts"] = parts
			out = append(out, cp)
		}
	}
	result := make([]any, 0, len(out))
	for _, c := range out {
		result = append(result, c)
	}
	if len(out) > 0 && str(out[0], "role") != GeminiRoleUser {
		result = append([]any{Body{"role": GeminiRoleUser, "parts": []any{Body{"text": "..."}}}}, result...)
		out = append([]Body{{"role": GeminiRoleUser, "parts": []any{Body{"text": "..."}}}}, out...)
	}
	if len(out) > 0 && str(out[len(out)-1], "role") == GeminiRoleModel {
		lastParts := arr(out[len(out)-1], "parts")
		var fnCalls []Body
		for _, pv := range lastParts {
			if pm, ok := pv.(map[string]any); ok && obj(pm, "functionCall") != nil {
				fnCalls = append(fnCalls, pm)
			}
		}
		if len(fnCalls) > 0 {
			var responses []any
			for _, p := range fnCalls {
				call := obj(p, "functionCall")
				name := "tool"
				if call != nil && str(call, "name") != "" {
					name = str(call, "name")
				}
				fr := Body{"name": name, "response": Body{"result": "Continue."}}
				if call != nil && str(call, "id") != "" {
					fr["id"] = str(call, "id")
				}
				responses = append(responses, Body{"functionResponse": fr})
			}
			result = append(result, Body{"role": GeminiRoleUser, "parts": responses})
		} else {
			result = append(result, Body{"role": GeminiRoleUser, "parts": []any{Body{"text": "Continue."}}})
		}
	}
	return result
}

// convertOpenAIContentToParts ports convertOpenAIContentToParts.
func convertOpenAIContentToParts(content any) []any {
	var parts []any
	switch c := content.(type) {
	case string:
		parts = append(parts, Body{"text": c})
	case []any:
		for _, iv := range c {
			item, ok := iv.(map[string]any)
			if !ok {
				continue
			}
			switch str(item, "type") {
			case OpenAIBlockText:
				parts = append(parts, Body{"text": str(item, "text")})
			case OpenAIBlockImageURL:
				iu := obj(item, "image_url")
				if iu == nil {
					continue
				}
				url := str(iu, "url")
				if strings.HasPrefix(url, "data:") {
					comma := strings.Index(url, ",")
					if comma == -1 {
						continue
					}
					mimePart := url[5:comma]
					mimeType := strings.SplitN(mimePart, ";", 2)[0]
					parts = append(parts, Body{
						"inlineData": Body{"mime_type": mimeType, "data": url[comma+1:]},
					})
				} else if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
					parts = append(parts, Body{
						"fileData": Body{"fileUri": url, "mimeType": "image/*"},
					})
				}
			case OpenAIBlockInputAudio:
				if ia := obj(item, "input_audio"); ia != nil && str(ia, "data") != "" {
					format := str(ia, "format")
					if format == "" {
						format = "wav"
					}
					mimeType := "audio/" + format
					if format == "mp3" {
						mimeType = "audio/mpeg"
					}
					parts = append(parts, Body{
						"inlineData": Body{"mime_type": mimeType, "data": str(ia, "data")},
					})
				}
			case OpenAIBlockAudioURL:
				if au := obj(item, "audio_url"); au != nil {
					url := str(au, "url")
					if strings.HasPrefix(url, "data:") {
						comma := strings.Index(url, ",")
						if comma == -1 {
							continue
						}
						mimeType := strings.SplitN(url[5:comma], ";", 2)[0]
						parts = append(parts, Body{
							"inlineData": Body{"mime_type": mimeType, "data": url[comma+1:]},
						})
					}
				}
			case OpenAIBlockFile:
				if file := obj(item, "file"); file != nil {
					url := str(file, "file_data")
					if strings.HasPrefix(url, "data:") {
						comma := strings.Index(url, ",")
						if comma == -1 {
							continue
						}
						mimeType := strings.SplitN(url[5:comma], ";", 2)[0]
						parts = append(parts, Body{
							"inlineData": Body{"mime_type": mimeType, "data": url[comma+1:]},
						})
					}
				}
			}
		}
	}
	return parts
}

// sanitizeGeminiFunctionName ports sanitizeGeminiFunctionName.
func sanitizeGeminiFunctionName(name string) string {
	if name == "" {
		return "_unknown"
	}
	var sb strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '_' || r == '.' || r == ':' || r == '-' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	s := sb.String()
	if len(s) > 0 {
		if c := s[0]; !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
			s = "_" + s
		}
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// toolCallIDUniquifier ports createToolCallIdUniquifier.
type toolCallIDUniquifier struct {
	used map[string]bool
}

func (u *toolCallIDUniquifier) next(id string) string {
	if id == "" {
		return id
	}
	if !u.used[id] {
		u.used[id] = true
		return id
	}
	n := 2
	candidate := id + "-" + itoa(n)
	for u.used[candidate] {
		n++
		candidate = id + "-" + itoa(n)
	}
	u.used[candidate] = true
	return candidate
}
