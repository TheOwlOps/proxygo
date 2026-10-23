package executors

import (
	"encoding/json"
	"strconv"
	"time"
)

func nowUnix() int64 { return time.Now().Unix() }

func int64Str(v int64) string { return strconv.FormatInt(v, 10) }

// Shared JSON helpers (payloads are decoded with UseNumber in request
// bodies but plain Unmarshal in EventStream frames, so both numeric shapes
// appear; getFloat in default.go handles both).
type jsonNumber = json.Number

func marshalJSON(v any) ([]byte, error) { return json.Marshal(v) }

func unmarshalJSON(b []byte, v any) error { return json.Unmarshal(b, v) }
