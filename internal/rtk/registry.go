package rtk

// Port of open-sse/rtk/registry.js. Note the JS quirk kept faithfully:
// build-output is reachable through autodetect but is NOT in the
// resolveFilter registry.

// FilterFunc compresses one tool_result text.
type FilterFunc func(string) string

var registry = map[string]FilterFunc{
	FilterGitDiff:       GitDiff,
	FilterGitStatus:     GitStatus,
	FilterGitLog:        GitLog,
	FilterGrep:          Grep,
	FilterFind:          Find,
	FilterDedupLog:      DedupLog,
	FilterLS:            LS,
	FilterTree:          Tree,
	FilterSmartTruncate: SmartTruncate,
	FilterReadNumbered:  ReadNumbered,
	FilterSearchList:    SearchList,
}

// Rust resolve_filter aliases (pipe_cmd.rs): grep|rg, find|fd.
var aliases = map[string]FilterFunc{
	"rg": Grep,
	"fd": Find,
}

// ResolveFilter mirrors resolveFilter in registry.js.
func ResolveFilter(name string) FilterFunc {
	if fn, ok := registry[name]; ok {
		return fn
	}
	if fn, ok := aliases[name]; ok {
		return fn
	}
	return nil
}

// AllFilters mirrors allFilters in registry.js.
func AllFilters() map[string]FilterFunc {
	out := make(map[string]FilterFunc, len(registry))
	for k, v := range registry {
		out[k] = v
	}
	return out
}
