//go:build darwin || linux

package agentbox

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// processGroupWaitDelay is the time to wait for a process group to exit
// after sending SIGKILL before giving up on pipe reads.
const processGroupWaitDelay = 3 * time.Second

// setupProcessGroup configures cmd to run in its own session (via Setsid)
// and sets up a Cancel function that kills the entire process group when
// the associated context is cancelled. Setsid (rather than Setpgid) gives
// the child its own session, which also prevents orphaned grandchildren
// from holding stdout/stderr pipes open after timeout.
func setupProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setpgid = false
	cmd.SysProcAttr.Pgid = 0

	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		pid := cmd.Process.Pid
		// Guard: kill(-1) kills ALL user processes; kill(0) kills the caller's
		// process group. Both are catastrophic and must never happen.
		// Treat invalid PIDs as "already done" rather than risking mass kill.
		if pid <= 1 {
			return os.ErrProcessDone
		}
		if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
			// ESRCH means the process (group) no longer exists.
			if errors.Is(err, syscall.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
		return nil
	}
	cmd.WaitDelay = processGroupWaitDelay
}
