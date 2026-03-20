//go:build windows

package agentbox

import (
	"os/exec"
	"syscall"
	"testing"
)

// CREATE_SUSPENDED is a Windows process creation flag (0x4) that creates
// the process in a suspended state. It's not exported by syscall package.
const createSuspendedFlag = 0x4

func TestSetupProcessGroupWindows(t *testing.T) {
	t.Run("sets CreationFlags", func(t *testing.T) {
		cmd := exec.Command("cmd.exe", "/c", "echo", "hello")
		setupProcessGroup(cmd)

		if cmd.SysProcAttr == nil {
			t.Fatal("SysProcAttr should not be nil")
		}
		spa := cmd.SysProcAttr
		if spa.CreationFlags&syscall.CREATE_NEW_PROCESS_GROUP == 0 {
			t.Error("CREATE_NEW_PROCESS_GROUP flag not set")
		}
	})

	t.Run("sets Cancel function", func(t *testing.T) {
		cmd := exec.Command("cmd.exe", "/c", "echo", "hello")
		setupProcessGroup(cmd)

		if cmd.Cancel == nil {
			t.Error("Cancel function should be set")
		}
	})

	t.Run("sets WaitDelay", func(t *testing.T) {
		cmd := exec.Command("cmd.exe", "/c", "echo", "hello")
		setupProcessGroup(cmd)

		if cmd.WaitDelay != processGroupWaitDelay {
			t.Errorf("WaitDelay = %v, want %v", cmd.WaitDelay, processGroupWaitDelay)
		}
	})

	t.Run("Cancel returns ErrProcessDone when process is nil", func(t *testing.T) {
		cmd := exec.Command("cmd.exe", "/c", "echo", "hello")
		setupProcessGroup(cmd)

		// Process is nil before Start(), Cancel should return ErrProcessDone.
		err := cmd.Cancel()
		if err == nil {
			t.Error("expected non-nil error from Cancel before Start")
		}
	})

	t.Run("merges with existing SysProcAttr", func(t *testing.T) {
		cmd := exec.Command("cmd.exe", "/c", "echo", "hello")
		// Simulate platform WrapCommand setting Token and CREATE_SUSPENDED.
		existingFlags := uint32(createSuspendedFlag)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: existingFlags,
		}

		setupProcessGroup(cmd)

		// Should have both CREATE_SUSPENDED and CREATE_NEW_PROCESS_GROUP.
		if cmd.SysProcAttr.CreationFlags&createSuspendedFlag == 0 {
			t.Error("existing CREATE_SUSPENDED flag was lost")
		}
		if cmd.SysProcAttr.CreationFlags&syscall.CREATE_NEW_PROCESS_GROUP == 0 {
			t.Error("CREATE_NEW_PROCESS_GROUP flag not set")
		}
	})
}
