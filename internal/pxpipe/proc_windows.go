//go:build windows

package pxpipe

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: the child keeps
// running after the server process exits.
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: 0x00000008 | 0x00000200}
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH").CombinedOutput()
	return err == nil && strings.Contains(string(out), strconv.Itoa(pid))
}

// terminateProcess: taskkill /T (tree), /F when force is set.
func terminateProcess(pid int, force bool) {
	if pid <= 0 {
		return
	}
	args := []string{"/T", "/PID", strconv.Itoa(pid)}
	if force {
		args = []string{"/F", "/T", "/PID", strconv.Itoa(pid)}
	}
	_ = exec.Command("taskkill", args...).Run()
}
