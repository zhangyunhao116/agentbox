//go:build darwin

package platform

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// builtinDarwinPlatform: CheckDependencies with missing sandbox-exec
// ---------------------------------------------------------------------------

func TestBuiltinDarwinCheckDependencies_MissingSandboxExec(t *testing.T) {
	// Temporarily override SandboxExecPath to a nonexistent path.
	orig := SandboxExecPath
	SandboxExecPath = "/nonexistent/sandbox-exec"
	t.Cleanup(func() {
		SandboxExecPath = orig
	})

	p := &builtinDarwinPlatform{}
	dc := p.CheckDependencies()
	if dc == nil {
		t.Fatal("CheckDependencies() returned nil")
	}
	if dc.OK() {
		t.Fatal("CheckDependencies() should report errors when sandbox-exec is missing")
	}
	if len(dc.Errors) == 0 {
		t.Fatal("CheckDependencies() should have at least one error")
	}
	if !strings.Contains(dc.Errors[0], "sandbox-exec not found") {
		t.Errorf("error message should mention sandbox-exec not found, got: %s", dc.Errors[0])
	}
}

func TestBuiltinDarwinAvailable_MissingSandboxExec(t *testing.T) {
	// Temporarily override SandboxExecPath to a nonexistent path.
	orig := SandboxExecPath
	SandboxExecPath = "/nonexistent/sandbox-exec"
	t.Cleanup(func() {
		SandboxExecPath = orig
	})

	p := &builtinDarwinPlatform{}
	if p.Available() {
		t.Fatal("Available() should return false when sandbox-exec is missing")
	}
}

// Compile-time check that builtinDarwinPlatform implements Platform.
var _ Platform = (*builtinDarwinPlatform)(nil)
