//go:build windows

package agentbox

import (
	"os/exec"
	"syscall"
	"testing"
)

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
}
