package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// `proxygo show [tool…]` — port of cli/src/cli/commands/show.js:
// print the proxygo settings currently written in each CLI tool's
// LOCAL config: base URL, (masked) API key and models. Read-only and
// offline: never contacts a server and never prints a full key.

var showHelp = `
Usage: proxygo show [tool…] [options]

Show the proxygo settings each CLI tool on THIS machine is currently using.
Read-only: reads local config files, contacts no server.

  proxygo show                 # every supported tool
  proxygo show claude          # one tool
  proxygo show claude codex    # several (or: --tools claude,codex)

Tools: ` + strings.Join(append(append([]string{}, toolIDs...), "all"), ", ") + `

Options:
  --tools <list>   Comma-separated tools (same as positional names)
  --json           Machine-readable output (API key still masked)
  -h, --help       Show this help
`

type showOptions struct {
	tools []string
	json  bool
	help  bool
}

func parseShowArgs(args []string) (showOptions, error) {
	var opts showOptions
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--tools":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("missing value for --tools")
			}
			i++
			opts.tools = append(opts.tools, strings.Split(args[i], ",")...)
		case a == "--json":
			opts.json = true
		case a == "-h" || a == "--help":
			opts.help = true
		case !strings.HasPrefix(a, "-"):
			opts.tools = append(opts.tools, a)
		default:
			return opts, fmt.Errorf("unknown option: %s", a)
		}
	}
	return opts, nil
}

// showRecord is one tool's normalized, key-safe record (show.js
// inspect()).
type showRecord struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Files      []string          `json:"files"`
	Configured bool              `json:"configured"`
	BaseURL    *string           `json:"baseUrl"`
	APIKey     *string           `json:"apiKey"`
	Models     map[string]string `json:"models"`
	Active     *bool             `json:"active,omitempty"`
	Error      string            `json:"error,omitempty"`

	order []string // model key order for text output (JS insertion order)
}

func inspectTool(t toolDef) showRecord {
	rec := showRecord{ID: t.id, Name: t.name, Files: t.paths(), Models: map[string]string{}}
	s, err := t.show()
	if err != nil {
		rec.Error = err.Error()
		return rec
	}
	rec.Configured = s.BaseURL != "" || s.APIKey != "" || len(s.Models) > 0
	if s.BaseURL != "" {
		rec.BaseURL = &s.BaseURL
	}
	if s.APIKey != "" {
		masked := maskKey(s.APIKey)
		rec.APIKey = &masked
	}
	for _, m := range s.Models {
		if _, dup := rec.Models[m.Key]; !dup {
			rec.order = append(rec.order, m.Key)
		}
		rec.Models[m.Key] = m.Value
	}
	rec.Active = s.Active
	return rec
}

func printShowRecord(w io.Writer, r showRecord) {
	if r.Error != "" {
		fmt.Fprintf(w, "❌ %s: %s\n", r.Name, r.Error)
		return
	}
	if !r.Configured {
		fmt.Fprintf(w, "• %s: not configured for proxygo (%s)\n", r.Name, r.Files[0])
		return
	}
	inactive := ""
	if r.Active != nil && !*r.Active {
		inactive = "  (proxygo present but not the active provider)"
	}
	fmt.Fprintf(w, "✅ %s%s\n", r.Name, inactive)
	fmt.Fprintf(w, "   File:     %s\n", strings.Join(r.Files, ", "))
	base := "(none)"
	if r.BaseURL != nil {
		base = *r.BaseURL
	}
	key := "(none)"
	if r.APIKey != nil {
		key = *r.APIKey
	}
	fmt.Fprintf(w, "   Base URL: %s\n", base)
	fmt.Fprintf(w, "   API key:  %s\n", key)
	if len(r.Models) == 0 {
		fmt.Fprintln(w, "   Models:   (none set — the tool's own default applies)")
		return
	}
	fmt.Fprintln(w, "   Models:")
	width := 0
	for _, k := range r.order {
		if len(k) > width {
			width = len(k)
		}
	}
	for _, k := range r.order {
		fmt.Fprintf(w, "     %-*s  %s\n", width, k, r.Models[k])
	}
}

func cmdShow(args []string, stdout, stderr io.Writer) int {
	opts, err := parseShowArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "❌ %s\n", err)
		fmt.Fprint(stdout, showHelp)
		return 1
	}
	if opts.help {
		fmt.Fprint(stdout, showHelp)
		return 0
	}
	tools := toolList
	if len(opts.tools) > 0 {
		tools, err = resolveTools(opts.tools)
		if err != nil {
			fmt.Fprintf(stderr, "❌ %s\n", err)
			return 1
		}
	}
	records := make([]showRecord, 0, len(tools))
	for _, t := range tools {
		records = append(records, inspectTool(t))
	}
	if opts.json {
		raw, _ := json.MarshalIndent(records, "", "  ")
		fmt.Fprintln(stdout, string(raw))
	} else {
		for i, r := range records {
			if i > 0 {
				fmt.Fprintln(stdout)
			}
			printShowRecord(stdout, r)
		}
	}
	for _, r := range records {
		if r.Error != "" {
			return 1
		}
	}
	return 0
}
