//go:build windows

package api

import "syscall"

// sysProcDetached starts the managed child process in a new process
// group (the Windows analogue of Setsid): it does not share the
// parent's console control events.
func sysProcDetached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}
