//go:build !windows

package cli

import "io"

// runTray on non-Windows platforms keeps the pre-F7 behaviour: this
// port ships no tray GUI for macOS/Linux (a cgo-free pure-Go systray
// for those platforms does not exist), so it delegates to cmdTray —
// detached server start plus the explanatory note (see server.go).
// Windows has a real Shell_NotifyIcon tray; see tray_windows.go.
func runTray(opts options, stdout, stderr io.Writer) int {
	return cmdTray(opts, stdout, stderr)
}
