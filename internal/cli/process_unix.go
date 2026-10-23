//go:build !windows

package cli

import (
	"os"
	"syscall"
)

// detachAttr makes the spawned server a session leader so it survives
// the CLI (and its terminal) exiting — the Go equivalent of the JS
// spawn(..., { detached: true }).
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// terminateProcess ports the JS kill behaviour: SIGTERM first
// (graceful), SIGKILL when force is set.
func terminateProcess(pid int, force bool) {
	if pid <= 0 {
		return
	}
	if force {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
}

var _ = os.Getpid
