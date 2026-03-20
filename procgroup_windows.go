//go:build windows

package agentbox

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

// processGroupWaitDelay is the time to wait for a process to exit
// after termination before giving up on pipe reads.
const processGroupWaitDelay = 3 * time.Second

// setupProcessGroup configures cmd to run in a new Windows process group.
// This enables clean termination of the process and its children via
// TerminateProcess.
//
// Note: For full process tree cleanup, Job Objects should be used
// (requires golang.org/x/sys/windows). The current implementation uses
// CREATE_NEW_PROCESS_GROUP which handles the common case of sandboxed
// native Windows processes and their direct children.
//
// If cmd.SysProcAttr is already set (e.g., by platform WrapCommand for
// sandbox Token or Job Object setup), this function merges the
// CREATE_NEW_PROCESS_GROUP flag instead of overwriting.
func setupProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= syscall.CREATE_NEW_PROCESS_GROUP
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		// On Windows, Process.Kill() calls TerminateProcess which
		// terminates the process and all its threads.
		return cmd.Process.Kill()
	}
	cmd.WaitDelay = processGroupWaitDelay
}
