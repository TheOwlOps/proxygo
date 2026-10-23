//go:build windows

package selfupdate

import "os"

// swapFile replaces target with the downloaded tmp file. Windows
// locks a running executable against overwrite/delete but allows
// renaming it, so: move the running exe aside to <exe>.old, move the
// new binary into place, and drop the .old on the next successful
// update (it cannot be deleted while the old process still runs —
// the supervisor/CLI relaunch runs the NEW binary, after which the
// .old is a plain file). If the second rename fails, the original is
// moved back.
func swapFile(tmp, target string) error {
	old := target + ".old"
	_ = os.Remove(old) // stale .old from a previous update; fine if locked/absent
	if err := os.Rename(target, old); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Rename(old, target) // best-effort restore
		return err
	}
	return nil
}
