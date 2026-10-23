package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"proxygo/internal/db"
)

// cmdResetPassword ports the JS dashboard "Reset Password to Default"
// flow (cli/src/cli/menus/settings.js → POST /api/auth/reset-password →
// updateSettings({ password: null })): clearing the stored bcrypt hash
// makes the server fall back to INITIAL_PASSWORD || the built-in default
// at next login (see internal/api VerifyPassword).
//
// The JS flow goes through the running server's API; the Go CLI writes
// the same SQLite DB directly via internal/db (the Go equivalent of
// `updateSettings`), so it also works while the server is stopped. The
// default literal is never printed.
func cmdResetPassword(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	yes := false
	for _, a := range args {
		switch a {
		case "--yes", "-y":
			yes = true
		case "-h", "--help":
			fmt.Fprintln(stdout, "Usage: proxygo-cli reset-password [--yes]")
			fmt.Fprintln(stdout, "Reset the dashboard password to the default by clearing the stored hash in the local DB.")
			return 0
		default:
			fmt.Fprintf(stderr, "Unknown option: %s\n", a)
			return 1
		}
	}

	if !yes {
		fmt.Fprint(stdout, "Reset dashboard password to default? [y/N] ")
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		line = strings.ToLower(strings.TrimSpace(line))
		if line != "y" && line != "yes" {
			fmt.Fprintln(stdout, "Aborted.")
			return 0
		}
	}
	return resetPasswordInDir(db.DataDir(), stdout, stderr)
}

func resetPasswordInDir(dir string, stdout, stderr io.Writer) int {
	store, err := db.OpenInDir(dir)
	if err != nil {
		fmt.Fprintf(stderr, "Error: cannot open ProxyGo database in %s: %v\n", dir, err)
		return 1
	}
	defer store.Close()

	settings, err := store.GetSettings()
	if err != nil {
		fmt.Fprintf(stderr, "Error: cannot read settings: %v\n", err)
		return 1
	}
	if hash, _ := settings["password"].(string); hash == "" {
		fmt.Fprintln(stdout, "No stored dashboard password — the default is already in effect.")
		return 0
	}

	// updateSettings({ password: null }) in the JS.
	if _, err := store.UpdateSettings(db.Record{"password": nil}); err != nil {
		fmt.Fprintf(stderr, "Error: cannot update settings: %v\n", err)
		return 1
	}

	after, err := store.GetSettings()
	if err != nil {
		fmt.Fprintf(stderr, "Error: cannot re-read settings: %v\n", err)
		return 1
	}
	if hash, _ := after["password"].(string); hash != "" {
		fmt.Fprintln(stderr, "Error: password hash still present after update.")
		return 1
	}

	fmt.Fprintln(stdout, "✅ Dashboard password reset to default.")
	fmt.Fprintln(stdout, "   The next login uses INITIAL_PASSWORD if set, otherwise the built-in default.")
	fmt.Fprintln(stdout, "   (Stored hash cleared in the local DB — a running server picks this up from the shared DB.)")
	return 0
}
