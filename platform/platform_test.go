package platform

import (
	"context"
	"os/exec"
	"runtime"
	"testing"
)

// ---------------------------------------------------------------------------
// DependencyCheck tests
// ---------------------------------------------------------------------------

func TestDependencyCheckOK_NoErrors(t *testing.T) {
	d := &DependencyCheck{}
	if !d.OK() {
		t.Fatal("OK() should return true when Errors is empty")
	}
}

func TestDependencyCheckOK_NilSlices(t *testing.T) {
	d := &DependencyCheck{Errors: nil, Warnings: nil}
	if !d.OK() {
		t.Fatal("OK() should return true when Errors is nil")
	}
}

func TestDependencyCheckOK_WithWarningsOnly(t *testing.T) {
	d := &DependencyCheck{Warnings: []string{"minor issue"}}
	if !d.OK() {
		t.Fatal("OK() should return true when only Warnings are present")
	}
}

func TestDependencyCheckOK_WithErrors(t *testing.T) {
	d := &DependencyCheck{Errors: []string{"missing dependency"}}
	if d.OK() {
		t.Fatal("OK() should return false when Errors is non-empty")
	}
}

func TestDependencyCheckOK_WithErrorsAndWarnings(t *testing.T) {
	d := &DependencyCheck{
		Errors:   []string{"critical"},
		Warnings: []string{"minor"},
	}
	if d.OK() {
		t.Fatal("OK() should return false when Errors is non-empty, even with Warnings")
	}
}

func TestDependencyCheckOK_MultipleErrors(t *testing.T) {
	d := &DependencyCheck{Errors: []string{"err1", "err2", "err3"}}
	if d.OK() {
		t.Fatal("OK() should return false with multiple errors")
	}
}

// ---------------------------------------------------------------------------
// Capabilities tests
// ---------------------------------------------------------------------------

func TestCapabilitiesZeroValue(t *testing.T) {
	var caps Capabilities
	if caps.FileReadDeny || caps.FileWriteAllow || caps.NetworkDeny ||
		caps.NetworkProxy || caps.PIDIsolation || caps.SyscallFilter || caps.ProcessHarden {
		t.Fatal("zero-value Capabilities should have all fields false")
	}
}

func TestCapabilitiesAllTrue(t *testing.T) {
	caps := Capabilities{
		FileReadDeny:   true,
		FileWriteAllow: true,
		NetworkDeny:    true,
		NetworkProxy:   true,
		PIDIsolation:   true,
		SyscallFilter:  true,
		ProcessHarden:  true,
	}
	if !caps.FileReadDeny || !caps.FileWriteAllow || !caps.NetworkDeny ||
		!caps.NetworkProxy || !caps.PIDIsolation || !caps.SyscallFilter || !caps.ProcessHarden {
		t.Fatal("all capabilities should be true")
	}
}

// ---------------------------------------------------------------------------
// WrapConfig tests
// ---------------------------------------------------------------------------

func TestWrapConfigFields(t *testing.T) {
	cfg := &WrapConfig{
		WritableRoots:           []string{"/tmp", "/var/tmp"},
		DenyWrite:               []string{"/etc"},
		DenyRead:                []string{"/secret"},
		AllowGitConfig:          true,
		NeedsNetworkRestriction: true,
		HTTPProxyPort:           8080,
		SOCKSProxyPort:          1080,
		Shell:                   "/bin/bash",
		ResourceLimits: &ResourceLimits{
			MaxProcesses:       100,
			MaxMemoryBytes:     1 << 30,
			MaxFileDescriptors: 256,
			MaxCPUSeconds:      60,
		},
	}

	if len(cfg.WritableRoots) != 2 {
		t.Fatalf("WritableRoots: got %d, want 2", len(cfg.WritableRoots))
	}
	if cfg.WritableRoots[0] != "/tmp" {
		t.Fatalf("WritableRoots[0]: got %q, want /tmp", cfg.WritableRoots[0])
	}
	if len(cfg.DenyWrite) != 1 || cfg.DenyWrite[0] != "/etc" {
		t.Fatalf("DenyWrite: got %v, want [/etc]", cfg.DenyWrite)
	}
	if len(cfg.DenyRead) != 1 || cfg.DenyRead[0] != "/secret" {
		t.Fatalf("DenyRead: got %v, want [/secret]", cfg.DenyRead)
	}
	if !cfg.AllowGitConfig {
		t.Fatal("AllowGitConfig: got false, want true")
	}
	if !cfg.NeedsNetworkRestriction {
		t.Fatal("NeedsNetworkRestriction: got false, want true")
	}
	if cfg.HTTPProxyPort != 8080 {
		t.Fatalf("HTTPProxyPort: got %d, want 8080", cfg.HTTPProxyPort)
	}
	if cfg.SOCKSProxyPort != 1080 {
		t.Fatalf("SOCKSProxyPort: got %d, want 1080", cfg.SOCKSProxyPort)
	}
	if cfg.Shell != "/bin/bash" {
		t.Fatalf("Shell: got %q, want /bin/bash", cfg.Shell)
	}
	if cfg.ResourceLimits == nil {
		t.Fatal("ResourceLimits: got nil")
	}
	if cfg.ResourceLimits.MaxProcesses != 100 {
		t.Fatalf("MaxProcesses: got %d, want 100", cfg.ResourceLimits.MaxProcesses)
	}
	if cfg.ResourceLimits.MaxMemoryBytes != 1<<30 {
		t.Fatalf("MaxMemoryBytes: got %d, want %d", cfg.ResourceLimits.MaxMemoryBytes, int64(1<<30))
	}
	if cfg.ResourceLimits.MaxFileDescriptors != 256 {
		t.Fatalf("MaxFileDescriptors: got %d, want 256", cfg.ResourceLimits.MaxFileDescriptors)
	}
	if cfg.ResourceLimits.MaxCPUSeconds != 60 {
		t.Fatalf("MaxCPUSeconds: got %d, want 60", cfg.ResourceLimits.MaxCPUSeconds)
	}
}

func TestWrapConfigZeroValue(t *testing.T) {
	cfg := &WrapConfig{}
	if cfg.WritableRoots != nil {
		t.Fatal("zero-value WritableRoots should be nil")
	}
	if cfg.AllowGitConfig {
		t.Fatal("zero-value AllowGitConfig should be false")
	}
	if cfg.NeedsNetworkRestriction {
		t.Fatal("zero-value NeedsNetworkRestriction should be false")
	}
	if cfg.ResourceLimits != nil {
		t.Fatal("zero-value ResourceLimits should be nil")
	}
}

func TestWrapConfigNilResourceLimits(t *testing.T) {
	cfg := &WrapConfig{
		Shell:          "/bin/sh",
		ResourceLimits: nil,
	}
	if cfg.ResourceLimits != nil {
		t.Fatal("ResourceLimits should be nil")
	}
}

// ---------------------------------------------------------------------------
// ResourceLimits tests
// ---------------------------------------------------------------------------

func TestResourceLimitsZeroValue(t *testing.T) {
	rl := &ResourceLimits{}
	if rl.MaxProcesses != 0 || rl.MaxMemoryBytes != 0 ||
		rl.MaxFileDescriptors != 0 || rl.MaxCPUSeconds != 0 {
		t.Fatal("zero-value ResourceLimits should have all fields zero")
	}
}

func TestDefaultResourceLimits(t *testing.T) {
	rl := DefaultResourceLimits()
	if rl == nil {
		t.Fatal("DefaultResourceLimits() returned nil")
	}
	if rl.MaxProcesses != 1024 {
		t.Fatalf("MaxProcesses: got %d, want 1024", rl.MaxProcesses)
	}
	if rl.MaxMemoryBytes != 2*1024*1024*1024 {
		t.Fatalf("MaxMemoryBytes: got %d, want %d", rl.MaxMemoryBytes, int64(2*1024*1024*1024))
	}
	if rl.MaxFileDescriptors != 1024 {
		t.Fatalf("MaxFileDescriptors: got %d, want 1024", rl.MaxFileDescriptors)
	}
	if rl.MaxCPUSeconds != 0 {
		t.Fatalf("MaxCPUSeconds: got %d, want 0 (unlimited)", rl.MaxCPUSeconds)
	}
}

func TestDefaultResourceLimitsReturnsNewInstance(t *testing.T) {
	rl1 := DefaultResourceLimits()
	rl2 := DefaultResourceLimits()
	if rl1 == rl2 {
		t.Fatal("DefaultResourceLimits() should return a new instance each time")
	}
}

// ---------------------------------------------------------------------------
// Detect tests
// ---------------------------------------------------------------------------

func TestDetectReturnsNonNil(t *testing.T) {
	p := Detect()
	if p == nil {
		t.Fatal("Detect() returned nil")
	}
}

func TestDetectNameNonEmpty(t *testing.T) {
	p := Detect()
	if p.Name() == "" {
		t.Fatal("Detect().Name() returned empty string")
	}
}

func TestDetectPlatformMatchesOS(t *testing.T) {
	p := Detect()
	switch runtime.GOOS {
	case "darwin":
		if p.Name() != "darwin-seatbelt" {
			t.Fatalf("on darwin: got Name() = %q, want darwin-seatbelt", p.Name())
		}
		if !p.Available() {
			t.Fatal("on darwin: Available() should return true")
		}
	case "linux":
		if p.Name() != "linux-namespace" {
			t.Fatalf("on linux: got Name() = %q, want linux-namespace", p.Name())
		}
		if p.Available() {
			t.Fatal("on linux: builtin stub Available() should return false")
		}
	default:
		if p.Name() != "unsupported" {
			t.Fatalf("on %s: got Name() = %q, want unsupported", runtime.GOOS, p.Name())
		}
		if p.Available() {
			t.Fatalf("on %s: Available() should return false", runtime.GOOS)
		}
	}
}

func TestDetectCheckDependencies(t *testing.T) {
	p := Detect()
	dc := p.CheckDependencies()
	if dc == nil {
		t.Fatal("CheckDependencies() returned nil")
	}
	// On supported platforms, the stub should have no errors.
	switch runtime.GOOS {
	case "darwin", "linux":
		if !dc.OK() {
			t.Fatalf("on %s: CheckDependencies() should be OK, got errors: %v", runtime.GOOS, dc.Errors)
		}
	}
}

func TestDetectCapabilities(t *testing.T) {
	p := Detect()
	caps := p.Capabilities()
	// On darwin, the stub should report certain capabilities.
	if runtime.GOOS == "darwin" {
		if !caps.FileReadDeny {
			t.Fatal("darwin: FileReadDeny should be true")
		}
		if !caps.FileWriteAllow {
			t.Fatal("darwin: FileWriteAllow should be true")
		}
		if !caps.NetworkDeny {
			t.Fatal("darwin: NetworkDeny should be true")
		}
		if !caps.NetworkProxy {
			t.Fatal("darwin: NetworkProxy should be true")
		}
		if !caps.ProcessHarden {
			t.Fatal("darwin: ProcessHarden should be true")
		}
		// darwin stub does not support PID isolation or syscall filter.
		if caps.PIDIsolation {
			t.Fatal("darwin: PIDIsolation should be false")
		}
		if caps.SyscallFilter {
			t.Fatal("darwin: SyscallFilter should be false")
		}
	}
}

func TestDetectCleanup(t *testing.T) {
	p := Detect()
	if err := p.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() returned error: %v", err)
	}
}

func TestDetectWrapCommand(t *testing.T) {
	p := Detect()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "echo", "hello")
	cfg := &WrapConfig{}
	// Stub implementations return an error since they are not yet implemented.
	err := p.WrapCommand(ctx, cmd, cfg)
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		if err == nil {
			t.Fatal("stub WrapCommand() should return an error (not yet implemented)")
		}
	}
}

// ---------------------------------------------------------------------------
// unsupportedPlatform tests (via exported constructor)
// ---------------------------------------------------------------------------

func TestUnsupportedPlatformName(t *testing.T) {
	p := NewUnsupportedPlatform()
	if p.Name() != "unsupported" {
		t.Fatalf("Name(): got %q, want unsupported", p.Name())
	}
}

func TestUnsupportedPlatformAvailable(t *testing.T) {
	p := NewUnsupportedPlatform()
	if p.Available() {
		t.Fatal("Available() should return false for unsupported platform")
	}
}

func TestUnsupportedPlatformCheckDependencies(t *testing.T) {
	p := NewUnsupportedPlatform()
	dc := p.CheckDependencies()
	if dc == nil {
		t.Fatal("CheckDependencies() returned nil")
	}
	if dc.OK() {
		t.Fatal("unsupported platform CheckDependencies() should not be OK")
	}
	if len(dc.Errors) == 0 {
		t.Fatal("unsupported platform should have at least one error")
	}
}

func TestUnsupportedPlatformWrapCommand(t *testing.T) {
	p := NewUnsupportedPlatform()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "echo", "hello")
	err := p.WrapCommand(ctx, cmd, &WrapConfig{})
	if err == nil {
		t.Fatal("unsupported WrapCommand() should return an error")
	}
}

func TestUnsupportedPlatformCleanup(t *testing.T) {
	p := NewUnsupportedPlatform()
	if err := p.Cleanup(context.Background()); err != nil {
		t.Fatalf("unsupported Cleanup() should not return error, got: %v", err)
	}
}

func TestUnsupportedCapabilities(t *testing.T) {
	p := NewUnsupportedPlatform()
	caps := p.Capabilities()
	if caps.FileReadDeny || caps.FileWriteAllow || caps.NetworkDeny ||
		caps.NetworkProxy || caps.PIDIsolation || caps.SyscallFilter || caps.ProcessHarden {
		t.Fatal("unsupported platform should have all capabilities false")
	}
}

// ---------------------------------------------------------------------------
// Interface compliance
// ---------------------------------------------------------------------------

// Compile-time check that all stub types implement Platform.
var (
	_ Platform = (*unsupportedPlatform)(nil)
)

// ---------------------------------------------------------------------------
// WrapConfig new fields tests
// ---------------------------------------------------------------------------

func TestWrapConfigNewFieldsZeroValue(t *testing.T) {
	var cfg WrapConfig

	if cfg.AllowLocalBinding {
		t.Error("AllowLocalBinding should be false by default")
	}
	if cfg.AllowAllUnixSockets {
		t.Error("AllowAllUnixSockets should be false by default")
	}
	if cfg.AllowUnixSockets != nil {
		t.Error("AllowUnixSockets should be nil by default")
	}
}

func TestWrapConfigNewFieldsSet(t *testing.T) {
	cfg := WrapConfig{
		AllowLocalBinding:   true,
		AllowAllUnixSockets: true,
		AllowUnixSockets:    []string{"/var/run/docker.sock", "/tmp/test.sock"},
	}

	if !cfg.AllowLocalBinding {
		t.Error("AllowLocalBinding should be true when set")
	}
	if !cfg.AllowAllUnixSockets {
		t.Error("AllowAllUnixSockets should be true when set")
	}
	if len(cfg.AllowUnixSockets) != 2 {
		t.Fatalf("AllowUnixSockets: got %d entries, want 2", len(cfg.AllowUnixSockets))
	}
	if cfg.AllowUnixSockets[0] != "/var/run/docker.sock" {
		t.Errorf("AllowUnixSockets[0] = %q, want /var/run/docker.sock", cfg.AllowUnixSockets[0])
	}
}
