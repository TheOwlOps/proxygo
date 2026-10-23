package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"proxygo/internal/db"
)

// `proxygo connect <server-url>` — port of
// cli/src/cli/commands/connect.js: point local CLI tools at a REMOTE
// proxygo server. Nothing runs locally: log in with the dashboard
// password, reuse/create an API key for this machine, then write the
// tools' settings files (tools.go). The password and API key are
// never printed (key is masked).
//
// Port adaptations (documented):
//   - The JS interactive prompts are enquirer's masked Password and
//     MultiSelect widgets. The Go port reads plain lines from stdin
//     (no new dependencies): the password is NOT echo-masked — prefer
//     --password / PROXYGO_PASSWORD — and tool selection takes a
//     comma-separated line (Enter = claude). Non-terminal stdin keeps
//     the exact JS behaviour (password required via flag/env, tools
//     default to claude).
//   - Requests go direct (no proxy), like the JS fetch.

var connectHelp = `
Usage: proxygo connect <server-url> [options]

Configure CLI tools on THIS machine to use a remote proxygo server.
No local server is started:

  proxygo connect http://<server-host>:20128
  proxygo connect http://<server-host>:20128 --tools claude,codex,opencode

Options:
  --tools <list>         Comma-separated tools to configure (prompted if omitted
                         in a terminal; default: claude). Supported:
                         ` + strings.Join(append(append([]string{}, toolIDs...), "all"), ", ") + `
  --password <pw>        Dashboard password (or env PROXYGO_PASSWORD;
                         prompted if omitted — preferred, keeps it out of shell history)
  --save                 After a successful login, save the password for this server
                         to the CLI data dir's connect.env (plain text, mode 600) so
                         later runs skip the prompt. Delete that file to forget it.
  --key-name <name>      API key name to reuse/create (default: cli-<hostname>)
  --api-key <key>        Use this API key, skip login + key lookup
  --model <model>        Model for all non-Claude tools (default: each tool's own
                         model on the server, else the server's OpenCode model;
                         omp needs none — it discovers every server model)
  --fable|--opus|--sonnet|--haiku <model>
                         Override a Claude Code tier (default: the server's value)
  --print-env            Also print OpenAI-compatible env vars for other CLIs
  --reset                Remove proxygo settings from the selected tools and exit
  -h, --help             Show this help

Models come from the server's own CLI-tools config (set on its dashboard).
Nothing is hardcoded: a Claude tier the server leaves unset is left unset,
and a non-Claude tool with no model anywhere is skipped. Flags override:

  proxygo connect http://<server-host>:20128 --tools claude --sonnet cc/claude-sonnet-5-5
  proxygo connect http://<server-host>:20128 --tools codex,opencode --model ocg/deepseek-flash
`

type connectOptions struct {
	url      string
	tools    []string
	password string
	save     bool
	keyName  string
	apiKey   string
	model    string
	models   map[string]string // tier flag → model
	printEnv bool
	reset    bool
	help     bool
}

func parseConnectArgs(args []string) (connectOptions, error) {
	hostname, _ := os.Hostname()
	keyName := "cli-" + hostname
	if len(keyName) > 64 {
		keyName = keyName[:64]
	}
	opts := connectOptions{password: os.Getenv("PROXYGO_PASSWORD"), keyName: keyName, models: map[string]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch {
		case a == "--password":
			opts.password, err = next()
		case a == "--key-name":
			opts.keyName, err = next()
		case a == "--api-key":
			opts.apiKey, err = next()
		case a == "--tools":
			var v string
			v, err = next()
			opts.tools = strings.Split(v, ",")
		case a == "--model":
			opts.model, err = next()
		case a == "--save":
			opts.save = true
		case a == "--print-env":
			opts.printEnv = true
		case a == "--reset":
			opts.reset = true
		case a == "-h" || a == "--help":
			opts.help = true
		case strings.HasPrefix(a, "--") && tierFlag(a) != "":
			opts.models[tierFlag(a)], err = next()
		case !strings.HasPrefix(a, "-") && opts.url == "":
			opts.url = a
		default:
			return opts, fmt.Errorf("unknown option: %s", a)
		}
		if err != nil {
			return opts, err
		}
	}
	return opts, nil
}

func tierFlag(a string) string {
	for _, m := range claudeTiers {
		if "--"+m.flag == a {
			return m.flag
		}
	}
	return ""
}

// normalizeServerURL ports normalizeServerUrl: keep only the origin.
func normalizeServerURL(input string) (string, error) {
	raw := strings.TrimSpace(input)
	if !regexp.MustCompile(`(?i)^https?://`).MatchString(raw) {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid server URL: %s", input)
	}
	return u.Scheme + "://" + u.Host, nil
}

// ── saved password (connect.env in the CLI data dir) ────────────────

func savedEnvPath() string { return filepath.Join(db.DataDir(), "connect.env") }

func loadSavedPassword(server string) string {
	raw, err := os.ReadFile(savedEnvPath())
	if err != nil {
		return ""
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		m := regexp.MustCompile(`^([A-Z_]+)=(.*)$`).FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		var v string
		if err := json.Unmarshal([]byte(m[2]), &v); err == nil {
			env[m[1]] = v
		} else {
			env[m[1]] = m[2]
		}
	}
	if env["PROXYGO_SERVER"] == server && env["PROXYGO_PASSWORD"] != "" {
		return env["PROXYGO_PASSWORD"]
	}
	return ""
}

func savePassword(server, password string) (string, error) {
	file := savedEnvPath()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return "", err
	}
	srv, _ := json.Marshal(server)
	pw, _ := json.Marshal(password)
	body := fmt.Sprintf("PROXYGO_SERVER=%s\nPROXYGO_PASSWORD=%s\n", srv, pw)
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		return "", err
	}
	_ = os.Chmod(file, 0o600)
	return file, nil
}

// ── server HTTP (direct, like the JS fetch) ─────────────────────────

var connectHTTPClient = &http.Client{
	Transport: &http.Transport{Proxy: nil},
	Timeout:   60 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // JS: redirect: "manual"
	},
}

type connectResponse struct {
	status  int
	headers http.Header
	data    map[string]any
	raw     string
}

var controlChars = regexp.MustCompile(`[\x00-\x1f\x7f]`)

func connectRequest(rawURL string, method string, body any, cookie, apiKey string) (connectResponse, error) {
	var out connectResponse
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return out, err
		}
		reader = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		return out, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := connectHTTPClient.Do(req)
	if err != nil {
		origin := rawURL
		if u, perr := url.Parse(rawURL); perr == nil {
			origin = u.Scheme + "://" + u.Host
		}
		return out, fmt.Errorf("cannot reach %s: %v", origin, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out.status = resp.StatusCode
	out.headers = resp.Header
	out.raw = string(raw)
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err == nil && data != nil {
		// Server-controlled strings get printed later — strip control
		// chars (terminal escape injection), like the JS.
		if e, ok := data["error"].(string); ok {
			data["error"] = controlChars.ReplaceAllString(e, "")
		}
		out.data = data
	}
	return out, nil
}

func extractAuthCookie(headers http.Header) string {
	for _, c := range headers.Values("Set-Cookie") {
		if m := regexp.MustCompile(`(?:^|,\s*)auth_token=([^;]+)`).FindStringSubmatch(c); m != nil {
			return "auth_token=" + m[1]
		}
	}
	return ""
}

func connectLogin(server, password string) (string, error) {
	res, err := connectRequest(server+"/api/auth/login", "POST", map[string]any{"password": password}, "", "")
	if err != nil {
		return "", err
	}
	if res.status == 200 && res.data != nil && res.data["success"] == true {
		cookie := extractAuthCookie(res.headers)
		if cookie == "" {
			return "", fmt.Errorf("login succeeded but server returned no session cookie")
		}
		return cookie, nil
	}
	msg := "unknown error"
	if res.data != nil && strOf(res.data["error"]) != "" {
		msg = strOf(res.data["error"])
	}
	return "", fmt.Errorf("login failed (%d): %s", res.status, msg)
}

func getOrCreateAPIKey(server, cookie, keyName string) (string, bool, error) {
	list, err := connectRequest(server+"/api/keys", "GET", nil, cookie, "")
	if err != nil {
		return "", false, err
	}
	if list.status == 401 {
		return "", false, fmt.Errorf("unauthorized listing API keys — wrong password or session rejected")
	}
	if list.status != 200 {
		return "", false, fmt.Errorf("failed to list API keys (%d): %s", list.status, strOf(list.data["error"]))
	}
	var keys []any
	if list.data != nil {
		keys, _ = list.data["keys"].([]any)
	}
	for _, e := range keys {
		k, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if active, ok := k["isActive"].(bool); ok && !active {
			continue
		}
		if strOf(k["name"]) == keyName && strOf(k["key"]) != "" {
			return strOf(k["key"]), false, nil
		}
	}
	created, err := connectRequest(server+"/api/keys", "POST", map[string]any{"name": keyName}, cookie, "")
	if err != nil {
		return "", false, err
	}
	if created.status != 201 || created.data == nil || strOf(created.data["key"]) == "" {
		return "", false, fmt.Errorf("failed to create API key (%d): %s", created.status, strOf(created.data["error"]))
	}
	return strOf(created.data["key"]), true, nil
}

// fetchServerModels ports fetchServerModels: only model ids are taken
// from the server's own cli-tools config — never its baseUrl/apiKey.
type serverModels struct {
	claude map[string]string // tier flag → model
	byTool map[string]string
	shared string
}

func fetchServerModels(server, cookie string, tools []toolDef) serverModels {
	out := serverModels{claude: map[string]string{}, byTool: map[string]string{}}
	if cookie == "" {
		return out
	}
	get := func(route string) map[string]any {
		res, err := connectRequest(server+"/api/cli-tools/"+route, "GET", nil, cookie, "")
		if err != nil || res.status != 200 {
			return nil
		}
		return res.data
	}
	hasClaude := false
	for _, t := range tools {
		if t.id == "claude" {
			hasClaude = true
		}
	}
	if hasClaude {
		if data := get("claude-settings"); data != nil {
			env := jsonChild(jsonChild(data, "settings"), "env")
			for _, m := range claudeTiers {
				if isStr(env[m.envKey]) {
					out.claude[m.flag] = strOf(env[m.envKey])
				}
			}
		}
	}
	// Each tool's own server config; OpenCode doubles as the shared
	// fallback, so fetch it even when opencode wasn't selected.
	var wanted []toolDef
	seen := map[string]bool{}
	needsAny := false
	for _, t := range tools {
		if t.id != "claude" && t.needsModel {
			needsAny = true
		}
		if t.route != "" {
			wanted = append(wanted, t)
			seen[t.id] = true
		}
	}
	if oc, ok := toolByID("opencode"); ok && !seen["opencode"] && needsAny {
		wanted = append(wanted, oc)
	}
	for _, t := range wanted {
		data := get(t.route)
		if data == nil || t.serverModel == nil {
			continue
		}
		if model := t.serverModel(data); model != "" {
			out.byTool[t.id] = model
		}
	}
	out.shared = out.byTool["opencode"]
	return out
}

func listServerModelIDs(server, apiKey string) (map[string]bool, error) {
	res, err := connectRequest(server+"/v1/models", "GET", nil, "", apiKey)
	if err != nil {
		return nil, err
	}
	if res.status == 401 {
		return nil, fmt.Errorf("API key rejected by server (/v1/models returned 401)")
	}
	if res.status != 200 {
		return nil, nil
	}
	out := map[string]bool{}
	if res.data != nil {
		if data, ok := res.data["data"].([]any); ok {
			for _, e := range data {
				if m, ok := e.(map[string]any); ok && strOf(m["id"]) != "" {
					out[strOf(m["id"])] = true
				}
			}
		}
	}
	return out, nil
}

// ── prompts (line-based adaptation; see header) ─────────────────────

func readerIsTTY(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func promptLine(br *bufio.Reader, stdout io.Writer, msg string) (string, error) {
	fmt.Fprint(stdout, msg)
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func cmdConnect(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	opts, err := parseConnectArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "❌ %s\n", err)
		fmt.Fprint(stdout, connectHelp)
		return 1
	}
	if opts.help {
		fmt.Fprint(stdout, connectHelp)
		return 0
	}
	if !opts.reset && opts.url == "" {
		fmt.Fprint(stdout, connectHelp)
		return 1
	}
	br := bufio.NewReader(stdin)
	tty := readerIsTTY(stdin)

	// Pick tools before any network call: bad names fail fast.
	var tools []toolDef
	switch {
	case len(opts.tools) > 0:
		tools, err = resolveTools(opts.tools)
		if err != nil {
			fmt.Fprintf(stderr, "❌ %s\n", err)
			return 1
		}
	case opts.reset && !tty:
		tools, err = resolveTools([]string{"claude"})
		if err != nil {
			fmt.Fprintf(stderr, "❌ %s\n", err)
			return 1
		}
	case tty:
		fmt.Fprintf(stdout, "Tools (%s, all): ", strings.Join(toolIDs, ", "))
		line, perr := promptLine(br, stdout, "")
		if perr != nil {
			fmt.Fprintln(stdout, "Cancelled.")
			return 130
		}
		if line == "" {
			line = "claude"
		}
		tools, err = resolveTools(strings.Split(line, ","))
		if err != nil {
			fmt.Fprintf(stderr, "❌ %s\n", err)
			return 1
		}
	default:
		tools, _ = resolveTools([]string{"claude"})
	}

	if opts.reset {
		failed := 0
		for _, t := range tools {
			files, rerr := t.reset()
			switch {
			case rerr != nil:
				failed++
				fmt.Fprintf(stdout, "❌ %s: %s\n", t.name, rerr)
			case len(files) > 0:
				fmt.Fprintf(stdout, "✅ %s: removed proxygo settings (%s)\n", t.name, strings.Join(files, ", "))
			default:
				fmt.Fprintf(stdout, "• %s: nothing to reset\n", t.name)
			}
		}
		if failed > 0 {
			return 1
		}
		return 0
	}

	server, err := normalizeServerURL(opts.url)
	if err != nil {
		fmt.Fprintf(stderr, "❌ %s\n", err)
		return 1
	}
	if strings.HasPrefix(server, "http://") &&
		!regexp.MustCompile(`^http://(localhost|127\.0\.0\.1|\[::1\])(:|$)`).MatchString(server) {
		fmt.Fprintln(stdout, "⚠ Plain HTTP: password and API key travel unencrypted. Use only on a trusted LAN/VPN.")
	}

	apiKey := opts.apiKey
	cookie := ""
	if apiKey != "" {
		fmt.Fprintln(stdout, "• Using provided API key")
	} else {
		saved := ""
		if opts.password == "" {
			saved = loadSavedPassword(server)
			if saved != "" {
				fmt.Fprintf(stdout, "• Using saved password (%s)\n", savedEnvPath())
			}
		}
		password := opts.password
		if password == "" {
			password = saved
		}
		if password == "" {
			if !tty {
				fmt.Fprintln(stderr, "❌ Password required: pass --password or set PROXYGO_PASSWORD")
				return 1
			}
			pw, perr := promptLine(br, stdout, "proxygo dashboard password: ")
			if perr != nil {
				fmt.Fprintln(stdout, "Cancelled.")
				return 130
			}
			password = pw
		}
		fmt.Fprintf(stdout, "• Logging in to %s\n", server)
		cookie, err = connectLogin(server, password)
		if err != nil {
			if saved != "" {
				err = fmt.Errorf("%v — saved password may be stale; delete %s or pass --password", err, savedEnvPath())
			}
			fmt.Fprintf(stderr, "❌ %s\n", err)
			return 1
		}
		if opts.save && password != saved {
			if path, serr := savePassword(server, password); serr == nil {
				fmt.Fprintf(stdout, "• Saved password to %s (plain text, mode 600)\n", path)
			}
		}
		key, created, kerr := getOrCreateAPIKey(server, cookie, opts.keyName)
		if kerr != nil {
			fmt.Fprintf(stderr, "❌ %s\n", kerr)
			return 1
		}
		apiKey = key
		verb := "Reusing"
		if created {
			verb = "Created"
		}
		fmt.Fprintf(stdout, "• %s API key %q (%s)\n", verb, opts.keyName, maskKey(apiKey))
	}

	// Models always come from the server's own cli-tools config;
	// flags override.
	srvModels := fetchServerModels(server, cookie, tools)
	if cookie == "" {
		fmt.Fprintln(stdout, "• --api-key given: can't read the server's models (needs a dashboard login) — pass model flags")
	}

	available, err := listServerModelIDs(server, apiKey)
	if err != nil {
		fmt.Fprintf(stderr, "❌ %s\n", err)
		return 1
	}
	warnMissing := func(label, model, flag string) {
		if available == nil {
			return
		}
		id := strings.TrimSuffix(model, "[1m]") // Claude Code context marker
		if !available[id] {
			fmt.Fprintf(stdout, "⚠ %s: %q not listed by server — override with %s <model>\n", label, model, flag)
		}
	}

	// Claude tiers: flag > server value > unset.
	claudeModels := map[string]string{}
	var claudeUnset []string
	hasClaude := false
	for _, t := range tools {
		if t.id == "claude" {
			hasClaude = true
		}
	}
	if hasClaude {
		for _, m := range claudeTiers {
			model := opts.models[m.flag]
			if model == "" {
				model = srvModels.claude[m.flag]
			}
			claudeModels[m.envKey] = model
			if model != "" {
				warnMissing("claude "+m.flag, model, "--"+m.flag)
			} else {
				claudeUnset = append(claudeUnset, m.flag)
			}
		}
	}
	// Other tools: --model > tool's own server model > OpenCode model.
	toolModels := map[string]string{}
	var fromOpenCode []string
	for _, t := range tools {
		if t.id == "claude" || !t.needsModel {
			continue
		}
		model := opts.model
		if model == "" {
			model = srvModels.byTool[t.id]
		}
		if model == "" {
			model = srvModels.shared
			if model != "" && opts.model == "" && srvModels.byTool[t.id] == "" {
				fromOpenCode = append(fromOpenCode, t.id)
			}
		}
		toolModels[t.id] = model
	}
	{
		seen := map[string]bool{}
		for _, m := range toolModels {
			if m != "" && !seen[m] {
				seen[m] = true
				warnMissing("model", m, "--model")
			}
		}
	}
	if len(fromOpenCode) > 0 {
		fmt.Fprintf(stdout, "• %s: no own model on the server — using its OpenCode model\n", strings.Join(fromOpenCode, ", "))
	}

	failed, skipped := 0, 0
	for _, t := range tools {
		if t.id != "claude" && t.needsModel && toolModels[t.id] == "" {
			skipped++
			fmt.Fprintf(stdout, "⏭  %s: no model configured on the server — skipped (pass --model <model>)\n", t.name)
			continue
		}
		ctx := toolCtx{BaseURL: server, APIKey: apiKey, Model: toolModels[t.id], ClaudeModels: claudeModels}
		files, aerr := t.apply(ctx)
		if aerr != nil {
			failed++
			fmt.Fprintf(stdout, "❌ %s: %s\n", t.name, aerr)
			continue
		}
		fmt.Fprintf(stdout, "✅ %s → %s\n", t.name, strings.Join(files, ", "))
	}
	fmt.Fprintf(stdout, "   Base URL: %s/v1\n", server)
	if hasClaude {
		for _, m := range claudeTiers {
			if claudeModels[m.envKey] != "" {
				fmt.Fprintf(stdout, "   %s=%s\n", m.envKey, claudeModels[m.envKey])
			}
		}
		if len(claudeUnset) > 0 {
			fmt.Fprintf(stdout, "   Claude %s: not set on the server — Claude Code's own default applies (or pass --%s <model>)\n",
				strings.Join(claudeUnset, ", "), claudeUnset[0])
		}
	}
	ids := make([]string, 0, len(tools))
	for _, t := range tools {
		ids = append(ids, t.id)
		if toolModels[t.id] != "" {
			fmt.Fprintf(stdout, "   %s model: %s\n", t.id, toolModels[t.id])
		}
	}
	for _, t := range tools {
		if t.id == "omp" {
			fmt.Fprintln(stdout, "   omp models: every server model, listed under proxygo in /model")
		}
	}
	fmt.Fprintf(stdout, "   Restart the tools to apply. Undo: proxygo connect --reset --tools %s\n", strings.Join(ids, ","))

	if opts.printEnv {
		fmt.Fprintln(stdout, "\nOpenAI-compatible CLIs (codex, opencode, aider, …):")
		fmt.Fprintf(stdout, "   OPENAI_BASE_URL=%s/v1\n", server)
		fmt.Fprintf(stdout, "   OPENAI_API_KEY=%s\n", apiKey)
	}
	if failed > 0 || skipped > 0 {
		return 1
	}
	return 0
}
