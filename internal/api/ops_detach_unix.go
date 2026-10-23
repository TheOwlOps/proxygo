//go:build !windows

package api

import "syscall"

// sysProcDetached starts the managed child process in its own session
// so it survives the parent and does not receive its signals.
func sysProcDetached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
