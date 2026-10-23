//go:build !windows

package pxpipe

import (
	"os"
	"syscall"
)

// detachAttr makes the child a session leader so it survives the
// server process exiting (same approach as the headroom proxy).
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// terminateProcess: SIGTERM first (the pxpipe server shuts down
// gracefully on it), SIGKILL when force is set.
func terminateProcess(pid int, force bool) {
	if pid <= 0 {
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	if force {
		_ = proc.Kill()
		return
	}
	_ = proc.Signal(syscall.SIGTERM)
}
