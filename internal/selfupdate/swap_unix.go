//go:build !windows

package selfupdate

import "os"

// swapFile replaces target with the downloaded tmp file. A rename
// within the same directory is atomic on unix and works on a running
// executable (the process keeps the old inode until it exits).
func swapFile(tmp, target string) error {
	return os.Rename(tmp, target)
}
