package agentbox

import (
	"os"
	"runtime"
	"testing"
)

func TestMaybeSandboxInit_NonLinux(t *testing.T) {
	if runtime.GOOS == osLinux {
		t.Skip("this test is for non-Linux platforms")
	}
	if got := MaybeSandboxInit(); got {
		t.Errorf("MaybeSandboxInit() = true on %s, want false", runtime.GOOS)
	}
}

func TestMaybeSandboxInitLinux_Stub(t *testing.T) {
	// On non-Linux platforms, the stub should always return false.
	if runtime.GOOS == osLinux {
		t.Skip("this test is for non-Linux platforms")
	}
	if got := maybeSandboxInitLinux(); got {
		t.Errorf("maybeSandboxInitLinux() = true on %s, want false", runtime.GOOS)
	}
}

func TestMaybeSandboxInit_NoEnvVar(t *testing.T) {
	// t.Setenv registers cleanup to restore the original value after the test.
	// os.Unsetenv then actually removes it for the duration of the test.
	t.Setenv("_AGENTBOX_CONFIG", "")
	os.Unsetenv("_AGENTBOX_CONFIG")
	if MaybeSandboxInit() {
		t.Error("MaybeSandboxInit() should return false without _AGENTBOX_CONFIG")
	}
}
