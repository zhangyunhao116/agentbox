//go:build darwin || linux

package agentbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestSetupProcessGroup(t *testing.T) {
	t.Run("nil SysProcAttr", func(t *testing.T) {
		cmd := exec.Command("echo", "hello")
		setupProcessGroup(cmd)

		if cmd.SysProcAttr == nil {
			t.Fatal("expected SysProcAttr to be set, got nil")
		}
		if !cmd.SysProcAttr.Setsid {
			t.Error("expected Setsid to be true")
		}
		if cmd.Cancel == nil {
			t.Error("expected Cancel to be set")
		}
		if cmd.WaitDelay == 0 {
			t.Error("expected WaitDelay to be set")
		}
	})

	t.Run("existing SysProcAttr preserved", func(t *testing.T) {
		cmd := exec.Command("echo", "hello")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			// Set a field that should be preserved.
			Noctty: true,
		}
		setupProcessGroup(cmd)

		if !cmd.SysProcAttr.Setsid {
			t.Error("expected Setsid to be true")
		}
		if !cmd.SysProcAttr.Noctty {
			t.Error("expected Noctty to remain true after setupProcessGroup")
		}
	})

	t.Run("Cancel returns ErrProcessDone when process is nil", func(t *testing.T) {
		cmd := exec.Command("echo", "hello")
		setupProcessGroup(cmd)

		// Process is nil before Start(), Cancel should return ErrProcessDone.
		err := cmd.Cancel()
		if !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("expected os.ErrProcessDone, got %v", err)
		}
	})

	t.Run("Cancel returns ErrProcessDone when process already exited", func(t *testing.T) {
		cmd := exec.CommandContext(context.Background(), "true")
		setupProcessGroup(cmd)

		if err := cmd.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		// Wait for the process to exit.
		_ = cmd.Wait()

		// Process has exited, Cancel should return ErrProcessDone.
		err := cmd.Cancel()
		if !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("expected os.ErrProcessDone, got %v", err)
		}
	})

	t.Run("Cancel returns ErrProcessDone for dangerous PIDs", func(t *testing.T) {
		for _, pid := range []int{-1, 0, 1} {
			cmd := exec.CommandContext(context.Background(), "sleep", "10")
			setupProcessGroup(cmd)
			if err := cmd.Start(); err != nil {
				t.Fatalf("Start: %v", err)
			}
			realPid := cmd.Process.Pid
			cmd.Process.Pid = pid

			err := cmd.Cancel()
			if !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("pid=%d: expected os.ErrProcessDone, got %v", pid, err)
			}

			// Restore real PID and clean up.
			cmd.Process.Pid = realPid
			_ = syscall.Kill(-realPid, syscall.SIGKILL)
			_ = cmd.Wait()
		}
	})
}
