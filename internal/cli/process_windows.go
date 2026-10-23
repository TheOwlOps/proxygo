//go:build windows

package cli

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: the server keeps running
// after the CLI exits, like the JS detached spawn.
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: 0x00000008 | 0x00000200}
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), strconv.Itoa(pid))
}

// terminateProcess ports the JS taskkill behaviour (/T tree kill,
// /F when force is set).
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
