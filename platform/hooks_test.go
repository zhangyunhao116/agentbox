package platform

import (
	"errors"
	"os/exec"
	"testing"
)

func TestRegisterPostStartHook(t *testing.T) {
	t.Run("registers and pops hook", func(t *testing.T) {
		cmd := exec.Command("echo", "test")
		called := false
		hook := func(*exec.Cmd) error {
			called = true
			return nil
		}

		RegisterPostStartHook(cmd, hook)
		retrieved := PopPostStartHook(cmd)

		if retrieved == nil {
			t.Fatal("expected hook to be retrieved")
		}
		if err := retrieved(cmd); err != nil {
			t.Errorf("hook returned error: %v", err)
		}
		if !called {
			t.Error("hook was not called")
		}
	})

	t.Run("returns nil for unregistered cmd", func(t *testing.T) {
		cmd := exec.Command("echo", "test")
		hook := PopPostStartHook(cmd)
		if hook != nil {
			t.Error("expected nil hook for unregistered command")
		}
	})

	t.Run("removes hook after pop", func(t *testing.T) {
		cmd := exec.Command("echo", "test")
		RegisterPostStartHook(cmd, func(*exec.Cmd) error { return nil })

		_ = PopPostStartHook(cmd)
		second := PopPostStartHook(cmd)

		if second != nil {
			t.Error("hook should be removed after first pop")
		}
	})

	t.Run("handles nil cmd", func(t *testing.T) {
		RegisterPostStartHook(nil, func(*exec.Cmd) error { return nil })
		hook := PopPostStartHook(nil)
		if hook != nil {
			t.Error("expected nil hook for nil cmd")
		}
	})

	t.Run("handles nil hook", func(t *testing.T) {
		cmd := exec.Command("echo", "test")
		RegisterPostStartHook(cmd, nil)
		hook := PopPostStartHook(cmd)
		if hook != nil {
			t.Error("expected nil hook when registering nil")
		}
	})

	t.Run("hook can return error", func(t *testing.T) {
		cmd := exec.Command("echo", "test")
		testErr := errors.New("test error")
		hook := func(*exec.Cmd) error {
			return testErr
		}

		RegisterPostStartHook(cmd, hook)
		retrieved := PopPostStartHook(cmd)

		if retrieved == nil {
			t.Fatal("expected hook to be retrieved")
		}
		if err := retrieved(cmd); !errors.Is(err, testErr) {
			t.Errorf("expected error %v, got %v", testErr, err)
		}
	})

	t.Run("multiple commands independent", func(t *testing.T) {
		cmd1 := exec.Command("echo", "one")
		cmd2 := exec.Command("echo", "two")

		call1 := false
		call2 := false

		RegisterPostStartHook(cmd1, func(*exec.Cmd) error {
			call1 = true
			return nil
		})
		RegisterPostStartHook(cmd2, func(*exec.Cmd) error {
			call2 = true
			return nil
		})

		hook1 := PopPostStartHook(cmd1)
		if hook1 == nil {
			t.Fatal("expected hook1 to be retrieved")
		}
		_ = hook1(cmd1)

		if !call1 {
			t.Error("hook1 was not called")
		}
		if call2 {
			t.Error("hook2 should not be called yet")
		}

		hook2 := PopPostStartHook(cmd2)
		if hook2 == nil {
			t.Fatal("expected hook2 to be retrieved")
		}
		_ = hook2(cmd2)

		if !call2 {
			t.Error("hook2 was not called")
		}
	})
}
