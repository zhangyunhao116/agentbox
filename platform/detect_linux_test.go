//go:build linux

package platform

import (
	"testing"
)

// ---------------------------------------------------------------------------
// builtinLinuxPlatform: CheckDependencies returns warning
// ---------------------------------------------------------------------------

func TestBuiltinLinuxCheckDependencies_Warning(t *testing.T) {
	p := &builtinLinuxPlatform{}
	dc := p.CheckDependencies()
	if dc == nil {
		t.Fatal("CheckDependencies() returned nil")
	}
	// Should still be OK (no errors), but with a warning.
	if !dc.OK() {
		t.Fatalf("CheckDependencies() should be OK (no errors), got errors: %v", dc.Errors)
	}
	if len(dc.Warnings) == 0 {
		t.Fatal("CheckDependencies() should have at least one warning for the built-in stub")
	}
	found := false
	for _, w := range dc.Warnings {
		if w == "built-in stub: use platform/linux package for full sandbox support" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected stub warning, got warnings: %v", dc.Warnings)
	}
}

func TestBuiltinLinuxAvailable(t *testing.T) {
	p := &builtinLinuxPlatform{}
	if p.Available() {
		t.Fatal("builtinLinuxPlatform.Available() should return false")
	}
}
