//go:build windows

package windows

import "testing"

func TestHelperPath(t *testing.T) {
	if helperPath != "/opt/agentbox/helper" {
		t.Errorf("helperPath = %q, want /opt/agentbox/helper", helperPath)
	}
}

func TestHelperInstalledNoWSL(t *testing.T) {
	// A Platform with no wslPath should report helper as not installed.
	p := &Platform{wslPath: "", distroName: "test-distro"}
	if p.helperInstalled() {
		t.Error("helperInstalled() should return false when wslPath is empty")
	}
}
