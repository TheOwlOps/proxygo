// Package cli is the Go port of the npm `9router` launcher
// (~/workspace/9router/cli/cli.js + src/cli/commands).
//
// What the JS launcher does, and how the Go port maps it:
//
//   - JS spawns a bundled Next standalone server (app/server.js) with Node.
//     Go adaptation: there is no bundled JS app — the launcher starts the
//     Go server binary `9router` (see findServerBinary for the search
//     order). Everything else (flags, port, data dir, dashboard URL)
//     keeps the JS semantics.
//   - JS kills every pre-existing 9router process and whatever listens on
//     the port before starting. Go adaptation (deliberately safer): the
//     CLI only ever stops a server it started itself, tracked in
//     <dataDir>/9router.pid; a foreign process on the port is reported,
//     never killed.
//   - JS checks the npm registry for updates and can show an interactive
//     interface menu / terminal UI after start. The Go CLI is not
//     distributed via npm, so the update check reads the project's
//     GitHub releases instead (update.go; --skip-update still skips it,
//     failures stay silent like the JS); the interactive menu/TUI is
//     not ported (the dashboard + `status`/`open` cover it).
//   - Tray: the JS tray is a GUI (systray2 on macOS/Linux, PowerShell
//     NotifyIcon on Windows). The Go port adds no GUI dependencies: the
//     `tray` command starts the server detached exactly like `start` and
//     prints the limitation (see cmdTray). A pure-Go systray library
//     that is cgo-free on every platform does not exist today
//     (fyne.io/systray is cgo-free on Windows/Linux but needs cgo on
//     macOS; getlantern/systray needs cgo throughout) — adopting one is
//     a parent decision, so the stub stays.
//   - JS subcommands `connect` / `show` / `xai video` are ported in
//     connect.go / show.go / xai.go (+ tools.go for the per-tool
//     config files, matching the JS cli-tools behaviour).
package cli

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Version mirrors cli/package.json ("version": "0.5.104") — the JS CLI
// prints pkg.version for --version.
const Version = "0.5.104"

// AppName is pkg.name in the JS package.json.
const AppName = "9router"

// JS launcher constants (cli.js).
const (
	DefaultPort = 20128
	DefaultHost = "0.0.0.0"
)

// options are the launcher flags shared by start/tray (JS cli.js parsing).
type options struct {
	Port       int
	Host       string
	NoBrowser  bool
	Log        bool
	Tray       bool
	SkipUpdate bool // --skip-update: skip the GitHub-releases update check
	ServerBin  string
}

func defaultOptions() options {
	return options{Port: DefaultPort, Host: DefaultHost}
}

// Run is the CLI entry point; it returns the process exit code.
func Run(args []string) int {
	return run(args, os.Stdout, os.Stderr, os.Stdin)
}

func run(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	if len(args) == 0 {
		// JS: bare `9router` starts the server with default flags.
		return cmdStart(defaultOptions(), stdout, stderr)
	}

	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, helpText)
		return 0
	case "-v", "--version", "version":
		fmt.Fprintln(stdout, Version)
		return 0
	case "start":
		opts, code, ok := parseFlags(args[1:], stdout, stderr)
		if !ok {
			return code
		}
		return cmdStart(opts, stdout, stderr)
	case "stop":
		if _, code, ok := parseFlags(args[1:], stdout, stderr); !ok {
			return code
		}
		return cmdStop(stdout, stderr)
	case "status":
		opts, code, ok := parseFlags(args[1:], stdout, stderr)
		if !ok {
			return code
		}
		return cmdStatus(opts, stdout, stderr)
	case "open":
		opts, code, ok := parseFlags(args[1:], stdout, stderr)
		if !ok {
			return code
		}
		return cmdOpen(opts, stdout, stderr)
	case "tray":
		opts, code, ok := parseFlags(args[1:], stdout, stderr)
		if !ok {
			return code
		}
		opts.Tray = true
		return runTray(opts, stdout, stderr)
	case "reset-password":
		return cmdResetPassword(args[1:], stdout, stderr, stdin)
	case "update":
		return cmdUpdate(args[1:], stdout, stderr)
	case "connect":
		return cmdConnect(args[1:], stdout, stderr, stdin)
	case "show":
		return cmdShow(args[1:], stdout, stderr)
	case "xai":
		if len(args) > 1 && args[1] == "video" {
			return cmdXaiVideo(args[2:], stdout, stderr)
		}
		fmt.Fprintln(stderr, "Usage: 9router xai video \"<prompt>\" [options]")
		fmt.Fprint(stdout, xaiVideoHelp)
		return 1
	}

	// Anything else starting with a flag is the JS launcher flow
	// (`9router --port 8080`, `9router --tray`, …).
	if strings.HasPrefix(args[0], "-") {
		opts, code, ok := parseFlags(args, stdout, stderr)
		if !ok {
			return code
		}
		if opts.Tray {
			return runTray(opts, stdout, stderr)
		}
		return cmdStart(opts, stdout, stderr)
	}

	fmt.Fprintf(stderr, "Unknown command: %s\n\n%s", args[0], helpText)
	return 1
}

// parseFlags parses the JS launcher flags. It returns ok=false when it
// already handled the invocation (help/version printed, or an error).
func parseFlags(args []string, stdout, stderr io.Writer) (options, int, bool) {
	opts := defaultOptions()
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, bool) {
			if i+1 >= len(args) {
				fmt.Fprintf(stderr, "Missing value for %s\n", a)
				return "", false
			}
			i++
			return args[i], true
		}
		switch a {
		case "-p", "--port":
			v, ok := next()
			if !ok {
				return opts, 1, false
			}
			p, err := strconv.Atoi(v)
			if err != nil || p <= 0 || p > 65535 {
				// JS: parseInt(...) || DEFAULT_PORT — invalid falls back.
				p = DefaultPort
			}
			opts.Port = p
		case "-H", "--host":
			v, ok := next()
			if !ok {
				return opts, 1, false
			}
			opts.Host = v
		case "-n", "--no-browser":
			opts.NoBrowser = true
		case "-l", "--log":
			opts.Log = true
		case "-t", "--tray":
			opts.Tray = true
		case "--skip-update":
			opts.SkipUpdate = true
		case "--server":
			v, ok := next()
			if !ok {
				return opts, 1, false
			}
			opts.ServerBin = v
		case "-h", "--help":
			fmt.Fprint(stdout, helpText)
			return opts, 0, false
		case "-v", "--version":
			fmt.Fprintln(stdout, Version)
			return opts, 0, false
		default:
			fmt.Fprintf(stderr, "Unknown option: %s\n", a)
			return opts, 1, false
		}
	}
	return opts, 0, true
}

// CompareVersions ports compareVersions from cli.js: 1 if a > b,
// -1 if a < b, 0 if equal (first three numeric components).
func CompareVersions(a, b string) int {
	pa := versionParts(a)
	pb := versionParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] > pb[i] {
			return 1
		}
		if pa[i] < pb[i] {
			return -1
		}
	}
	return 0
}

func versionParts(v string) [3]int {
	var out [3]int
	for i, s := range strings.Split(strings.TrimPrefix(v, "v"), ".") {
		if i >= 3 {
			break
		}
		n, _ := strconv.Atoi(s)
		out[i] = n
	}
	return out
}

const helpText = `Usage: 9router-cli [command] [options]

Commands:
  start               Start the 9Router server (default when no command)
  stop                Stop the server started by this CLI (pid file)
  status              Show whether the server is running + health
  open                Open the dashboard in a browser
  tray                Start detached (tray GUI not ported — see notes)
  connect <url>       Configure local CLI tools for a remote 9router server
                      (run "9router-cli connect --help" for options)
  show [tool…]        Show each tool's current 9router config (offline)
  xai video "<prompt>"  Generate a Grok Imagine video via the local gateway
  reset-password      Reset the dashboard password to the default
                      (clears the stored hash in the local DB)
  update              Update the server binary from GitHub Releases
  version             Show version

Options (start/tray; also accepted bare, like the JS launcher):
  -p, --port <port>   Port to run the server (default: 20128)
  -H, --host <host>   Host to bind (default: 0.0.0.0)
  -n, --no-browser    Don't open browser automatically
  -l, --log           Run in foreground showing server logs
  -t, --tray          Background mode (JS: system tray; Go: detached + note)
  --skip-update       Skip the update check (GitHub releases)
  --server <path>     Path to the 9router server binary (Go addition;
                      else $NINEROUTER_SERVER_BIN, a sibling binary,
                      then PATH)
  -h, --help          Show this help message
  -v, --version       Show version

Dashboard: http://localhost:20128/dashboard
`
