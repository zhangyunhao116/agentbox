//go:build linux

package linux

import (
	"context"
	"os/exec"
	"syscall"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
)

func TestNew(t *testing.T) {
	p := New()
	if p == nil {
		t.Fatal("New() returned nil")
	}
}

func TestName(t *testing.T) {
	p := New()
	if got := p.Name(); got != "linux-namespace" {
		t.Errorf("Name() = %q, want %q", got, "linux-namespace")
	}
}

func TestAvailable(t *testing.T) {
	p := New()
	if !p.Available() {
		t.Error("Available() = false, want true on Linux")
	}
}

func TestCapabilities(t *testing.T) {
	p := New()
	caps := p.Capabilities()

	// On Linux, network deny and PID isolation should always be available.
	if !caps.NetworkDeny {
		t.Error("Capabilities().NetworkDeny = false, want true")
	}
	if !caps.PIDIsolation {
		t.Error("Capabilities().PIDIsolation = false, want true")
	}
	if !caps.SyscallFilter {
		t.Error("Capabilities().SyscallFilter = false, want true")
	}
	if !caps.ProcessHarden {
		t.Error("Capabilities().ProcessHarden = false, want true")
	}
	if !caps.NetworkProxy {
		t.Error("Capabilities().NetworkProxy = false, want true")
	}
}

func TestCheckDependencies(t *testing.T) {
	p := New()
	check := p.CheckDependencies()
	if check == nil {
		t.Fatal("CheckDependencies() returned nil")
	}
	// On a modern Linux kernel, there should be no errors.
	if !check.OK() {
		t.Errorf("CheckDependencies() has errors: %v", check.Errors)
	}
}

func TestCleanup(t *testing.T) {
	p := New()
	if err := p.Cleanup(context.Background()); err != nil {
		t.Errorf("Cleanup() error: %v", err)
	}
}

func TestImplementsPlatformInterface(t *testing.T) {
	// Compile-time check that Platform implements platform.Platform.
	var _ platform.Platform = (*Platform)(nil)
}

func TestWrapCommand_NilConfig(t *testing.T) {
	p := New()
	cmd := exec.CommandContext(context.Background(), "/bin/echo", "hello")
	err := p.WrapCommand(context.Background(), cmd, nil)
	if err != nil {
		t.Fatalf("WrapCommand(nil cfg) error: %v", err)
	}
	if cmd.SysProcAttr == nil {
		t.Fatal("WrapCommand(nil cfg) did not set SysProcAttr")
	}
	// Should have at least user, mount, and PID namespace flags.
	flags := cmd.SysProcAttr.Cloneflags
	if flags&syscall.CLONE_NEWUSER == 0 {
		t.Error("CLONE_NEWUSER not set")
	}
	if flags&syscall.CLONE_NEWNS == 0 {
		t.Error("CLONE_NEWNS not set")
	}
	if flags&syscall.CLONE_NEWPID == 0 {
		t.Error("CLONE_NEWPID not set")
	}
}

func TestWrapCommand_WithConfig(t *testing.T) {
	p := New()
	cmd := exec.CommandContext(context.Background(), "/bin/echo", "hello")
	cfg := &platform.WrapConfig{
		WritableRoots:           []string{"/tmp"},
		NeedsNetworkRestriction: true,
		Shell:                   "/bin/sh",
	}
	err := p.WrapCommand(context.Background(), cmd, cfg)
	if err != nil {
		t.Fatalf("WrapCommand(full cfg) error: %v", err)
	}
	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr is nil after WrapCommand")
	}
	flags := cmd.SysProcAttr.Cloneflags
	// All four namespace flags should be set.
	for _, flag := range []struct {
		name string
		val  uintptr
	}{
		{"CLONE_NEWUSER", syscall.CLONE_NEWUSER},
		{"CLONE_NEWNS", syscall.CLONE_NEWNS},
		{"CLONE_NEWPID", syscall.CLONE_NEWPID},
		{"CLONE_NEWNET", syscall.CLONE_NEWNET},
	} {
		if flags&flag.val == 0 {
			t.Errorf("%s not set", flag.name)
		}
	}
}

func TestWrapCommand_NetworkRestriction(t *testing.T) {
	p := New()
	cmd := exec.CommandContext(context.Background(), "/bin/echo")
	cfg := &platform.WrapConfig{NeedsNetworkRestriction: true}
	if err := p.WrapCommand(context.Background(), cmd, cfg); err != nil {
		t.Fatalf("WrapCommand error: %v", err)
	}
	if cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWNET == 0 {
		t.Error("CLONE_NEWNET should be set when NeedsNetworkRestriction=true")
	}
}

func TestWrapCommand_NoNetworkRestriction(t *testing.T) {
	p := New()
	cmd := exec.CommandContext(context.Background(), "/bin/echo")
	cfg := &platform.WrapConfig{NeedsNetworkRestriction: false}
	if err := p.WrapCommand(context.Background(), cmd, cfg); err != nil {
		t.Fatalf("WrapCommand error: %v", err)
	}
	if cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWNET != 0 {
		t.Error("CLONE_NEWNET should NOT be set when NeedsNetworkRestriction=false")
	}
}
