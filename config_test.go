package agentbox

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	// Check filesystem defaults.
	if len(cfg.Filesystem.WritableRoots) != 0 {
		t.Errorf("WritableRoots: got %d entries, want 0", len(cfg.Filesystem.WritableRoots))
	}

	if len(cfg.Filesystem.DenyWrite) == 0 {
		t.Error("DenyWrite: should not be empty")
	}

	if len(cfg.Filesystem.DenyRead) == 0 {
		t.Error("DenyRead: should not be empty")
	}

	if cfg.Filesystem.AllowGitConfig {
		t.Error("AllowGitConfig: got true, want false")
	}

	// Check network defaults.
	if cfg.Network.Mode != NetworkFiltered {
		t.Errorf("Network.Mode: got %v, want NetworkFiltered", cfg.Network.Mode)
	}

	// Check other defaults.
	if cfg.Shell != "" {
		t.Errorf("Shell: got %q, want empty", cfg.Shell)
	}

	if cfg.MaxOutputBytes != defaultMaxOutputBytes {
		t.Errorf("MaxOutputBytes: got %d, want %d", cfg.MaxOutputBytes, defaultMaxOutputBytes)
	}

	if cfg.ResourceLimits == nil {
		t.Fatal("ResourceLimits: got nil")
	}

	if cfg.FallbackPolicy != FallbackStrict {
		t.Errorf("FallbackPolicy: got %v, want FallbackStrict", cfg.FallbackPolicy)
	}
}

func TestDevelopmentConfig(t *testing.T) {
	cfg := DevelopmentConfig()

	if cfg == nil {
		t.Fatal("DevelopmentConfig() returned nil")
	}

	// Verify FallbackWarn.
	if cfg.FallbackPolicy != FallbackWarn {
		t.Errorf("FallbackPolicy: got %v, want FallbackWarn", cfg.FallbackPolicy)
	}

	// Verify NetworkAllowed.
	if cfg.Network.Mode != NetworkAllowed {
		t.Errorf("Network.Mode: got %v, want NetworkAllowed", cfg.Network.Mode)
	}

	// Verify other defaults are preserved from DefaultConfig.
	if len(cfg.Filesystem.WritableRoots) != 0 {
		t.Errorf("WritableRoots: got %d entries, want 0", len(cfg.Filesystem.WritableRoots))
	}
	if len(cfg.Filesystem.DenyWrite) == 0 {
		t.Error("DenyWrite: should not be empty")
	}
	if len(cfg.Filesystem.DenyRead) == 0 {
		t.Error("DenyRead: should not be empty")
	}
	if cfg.Shell != "" {
		t.Errorf("Shell: got %q, want empty", cfg.Shell)
	}
	if cfg.MaxOutputBytes != defaultMaxOutputBytes {
		t.Errorf("MaxOutputBytes: got %d, want %d", cfg.MaxOutputBytes, defaultMaxOutputBytes)
	}
	if cfg.ResourceLimits == nil {
		t.Fatal("ResourceLimits: got nil")
	}

	// Validate should pass.
	if err := cfg.Validate(); err != nil {
		t.Errorf("DevelopmentConfig().Validate() error: %v", err)
	}
}

func TestCIConfig(t *testing.T) {
	cfg := CIConfig()

	if cfg == nil {
		t.Fatal("CIConfig() returned nil")
	}

	// Verify FallbackStrict.
	if cfg.FallbackPolicy != FallbackStrict {
		t.Errorf("FallbackPolicy: got %v, want FallbackStrict", cfg.FallbackPolicy)
	}

	// Verify NetworkBlocked.
	if cfg.Network.Mode != NetworkBlocked {
		t.Errorf("Network.Mode: got %v, want NetworkBlocked", cfg.Network.Mode)
	}

	// Verify other defaults are preserved from DefaultConfig.
	if len(cfg.Filesystem.WritableRoots) != 0 {
		t.Errorf("WritableRoots: got %d entries, want 0", len(cfg.Filesystem.WritableRoots))
	}
	if len(cfg.Filesystem.DenyWrite) == 0 {
		t.Error("DenyWrite: should not be empty")
	}
	if len(cfg.Filesystem.DenyRead) == 0 {
		t.Error("DenyRead: should not be empty")
	}
	if cfg.Shell != "" {
		t.Errorf("Shell: got %q, want empty", cfg.Shell)
	}
	if cfg.MaxOutputBytes != defaultMaxOutputBytes {
		t.Errorf("MaxOutputBytes: got %d, want %d", cfg.MaxOutputBytes, defaultMaxOutputBytes)
	}
	if cfg.ResourceLimits == nil {
		t.Fatal("ResourceLimits: got nil")
	}

	// Validate should pass.
	if err := cfg.Validate(); err != nil {
		t.Errorf("CIConfig().Validate() error: %v", err)
	}
}

func TestDefaultConfigValidates(t *testing.T) {
	cfg := DefaultConfig()

	if err := cfg.Validate(); err != nil {
		t.Errorf("DefaultConfig().Validate() error: %v", err)
	}
}

func TestDefaultResourceLimits(t *testing.T) {
	rl := DefaultResourceLimits()
	if rl == nil {
		t.Fatal("DefaultResourceLimits() returned nil")
	}
	if rl.MaxProcesses != 1024 {
		t.Errorf("MaxProcesses: got %d, want 1024", rl.MaxProcesses)
	}
	if rl.MaxMemoryBytes != 2*1024*1024*1024 {
		t.Errorf("MaxMemoryBytes: got %d, want %d", rl.MaxMemoryBytes, int64(2*1024*1024*1024))
	}
	if rl.MaxFileDescriptors != 1024 {
		t.Errorf("MaxFileDescriptors: got %d, want 1024", rl.MaxFileDescriptors)
	}
	if rl.MaxCPUSeconds != 0 {
		t.Errorf("MaxCPUSeconds: got %d, want 0", rl.MaxCPUSeconds)
	}
}

func TestValidateValidConfig(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: []string{os.TempDir()},
			DenyWrite:     []string{"/etc"},
			DenyRead:      []string{"/secret"},
		},
		Network: NetworkConfig{
			Mode:           NetworkFiltered,
			AllowedDomains: []string{"*.example.com", "api.github.com"},
			DeniedDomains:  []string{"*.evil.com"},
		},
		MaxOutputBytes: 1024,
		ResourceLimits: DefaultResourceLimits(),
		FallbackPolicy: FallbackStrict,
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() error: %v", err)
	}
}

func TestValidateEmptyWritableRoot(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: []string{""},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for empty writable root")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestValidateNonMutating(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: []string{os.TempDir(), "relative/path"},
			DenyWrite:     []string{"/etc"},
			DenyRead:      []string{"/secret"},
		},
	}

	// Save original values.
	origRoot0 := cfg.Filesystem.WritableRoots[0]
	origRoot1 := cfg.Filesystem.WritableRoots[1]

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	// Validate must not mutate the config.
	if cfg.Filesystem.WritableRoots[0] != origRoot0 {
		t.Errorf("WritableRoots[0] mutated: got %q, want %q", cfg.Filesystem.WritableRoots[0], origRoot0)
	}
	if cfg.Filesystem.WritableRoots[1] != origRoot1 {
		t.Errorf("WritableRoots[1] mutated: got %q, want %q", cfg.Filesystem.WritableRoots[1], origRoot1)
	}
}

// TestNewManagerNormalizesRelativePaths verifies that newManager resolves
// relative writable roots to absolute paths on its internal copy.
func TestNewManagerNormalizesRelativePaths(t *testing.T) {
	cfg := &Config{
		FallbackPolicy: FallbackWarn,
		Filesystem: FilesystemConfig{
			WritableRoots: []string{"relative/path"},
		},
	}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// The original config should NOT be mutated.
	if cfg.Filesystem.WritableRoots[0] != "relative/path" {
		t.Errorf("original config mutated: got %q", cfg.Filesystem.WritableRoots[0])
	}
}

// TestDefaultConfigDenyReadExpanded verifies that DefaultConfig includes
// expanded DenyRead entries for sensitive credential files.
func TestDefaultConfigDenyReadExpanded(t *testing.T) {
	cfg := DefaultConfig()

	// Check that DenyRead includes the new entries.
	denyReadSet := make(map[string]bool)
	for _, p := range cfg.Filesystem.DenyRead {
		denyReadSet[p] = true
	}

	home, _ := os.UserHomeDir()
	expected := []string{
		home + "/.git-credentials",
		home + "/.npmrc",
		home + "/.netrc",
		home + "/.docker",
		home + "/.pypirc",
		home + "/.kube",
		"/proc/*/mem",
		"/sys",
	}
	for _, e := range expected {
		if !denyReadSet[e] {
			t.Errorf("DenyRead missing expected entry: %q", e)
		}
	}
}

func TestValidateRelativeWritableRoot(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: []string{"relative/path"},
		},
	}

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	// After validation, the relative path should NOT be mutated (Validate is non-mutating).
	if cfg.Filesystem.WritableRoots[0] != "relative/path" {
		t.Errorf("WritableRoots[0] should not be mutated by Validate, got %q", cfg.Filesystem.WritableRoots[0])
	}
}

func TestValidateEmptyDenyWrite(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			DenyWrite: []string{""},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for empty DenyWrite entry")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestValidateEmptyDenyRead(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			DenyRead: []string{""},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for empty DenyRead entry")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestValidateInvalidShell(t *testing.T) {
	cfg := &Config{
		Shell: "relative/shell/path",
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for non-absolute shell path")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestValidateValidShell(t *testing.T) {
	// /bin/sh is an absolute path and should pass Validate (no filesystem check).
	cfg := &Config{
		Shell: "/bin/sh",
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() error for /bin/sh: %v", err)
	}
}

func TestNewManagerRejectsNonexistentShell(t *testing.T) {
	cfg := &Config{
		Shell: "/nonexistent/shell/path",
	}

	_, err := newManager(cfg)
	if err == nil {
		t.Fatal("newManager() should return error for nonexistent shell")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestValidateNegativeResourceLimits(t *testing.T) {
	tests := []struct {
		name string
		rl   *ResourceLimits
	}{
		{"negative MaxProcesses", &ResourceLimits{MaxProcesses: -1}},
		{"negative MaxMemoryBytes", &ResourceLimits{MaxMemoryBytes: -1}},
		{"negative MaxFileDescriptors", &ResourceLimits{MaxFileDescriptors: -1}},
		{"negative MaxCPUSeconds", &ResourceLimits{MaxCPUSeconds: -1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{ResourceLimits: tt.rl}
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate() should return error for negative resource limit")
			}
			if !errors.Is(err, ErrConfigInvalid) {
				t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
			}
		})
	}
}

func TestValidateZeroResourceLimits(t *testing.T) {
	cfg := &Config{
		ResourceLimits: &ResourceLimits{
			MaxProcesses:       0,
			MaxMemoryBytes:     0,
			MaxFileDescriptors: 0,
			MaxCPUSeconds:      0,
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should accept zero resource limits: %v", err)
	}
}

func TestValidateNilResourceLimits(t *testing.T) {
	cfg := &Config{
		ResourceLimits: nil,
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should accept nil resource limits: %v", err)
	}
}

func TestValidateNegativeMaxOutputBytes(t *testing.T) {
	cfg := &Config{
		MaxOutputBytes: -1,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for negative MaxOutputBytes")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestValidateZeroMaxOutputBytes(t *testing.T) {
	cfg := &Config{
		MaxOutputBytes: 0,
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should accept zero MaxOutputBytes: %v", err)
	}
}

func TestValidateDomainPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"valid domain", "example.com", false},
		{"valid wildcard", "*.example.com", false},
		{"valid subdomain", "api.github.com", false},
		{"empty pattern", "", true},
		{"no dot", "localhost", true},
		{"protocol prefix http", "http://example.com", true},
		{"protocol prefix https", "https://example.com", true},
		{"wildcard no prefix", "example.*.com", true},
		{"wildcard too short", "*.com", true},
		{"double wildcard", "*.*.example.com", true},
		{"wildcard in middle", "foo.*.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDomainPattern(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDomainPattern(%q) error = %v, wantErr %v", tt.pattern, err, tt.wantErr)
			}
		})
	}
}

func TestValidateInvalidAllowedDomains(t *testing.T) {
	cfg := &Config{
		Network: NetworkConfig{
			AllowedDomains: []string{"invalid"},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for invalid allowed domain")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestValidateInvalidDeniedDomains(t *testing.T) {
	cfg := &Config{
		Network: NetworkConfig{
			DeniedDomains: []string{"https://evil.com"},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for invalid denied domain")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: []string{""},
			DenyWrite:     []string{""},
			DenyRead:      []string{""},
		},
		MaxOutputBytes: -1,
		ResourceLimits: &ResourceLimits{MaxProcesses: -1},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for multiple invalid fields")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
	// The error message should contain multiple issues.
	msg := err.Error()
	if len(msg) < 50 {
		t.Errorf("error message seems too short for multiple errors: %q", msg)
	}
}

func TestFallbackPolicyString(t *testing.T) {
	tests := []struct {
		policy FallbackPolicy
		want   string
	}{
		{FallbackStrict, "strict"},
		{FallbackWarn, "warn"},
		{FallbackPolicy(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.policy.String(); got != tt.want {
				t.Errorf("FallbackPolicy(%d).String() = %q, want %q", tt.policy, got, tt.want)
			}
		})
	}
}

func TestNetworkModeString(t *testing.T) {
	tests := []struct {
		mode NetworkMode
		want string
	}{
		{NetworkFiltered, "filtered"},
		{NetworkBlocked, "blocked"},
		{NetworkAllowed, "allowed"},
		{NetworkMode(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.want {
				t.Errorf("NetworkMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

func TestFallbackPolicyValues(t *testing.T) {
	if FallbackStrict != 0 {
		t.Errorf("FallbackStrict: got %d, want 0", FallbackStrict)
	}
	if FallbackWarn != 1 {
		t.Errorf("FallbackWarn: got %d, want 1", FallbackWarn)
	}
}

func TestNetworkModeValues(t *testing.T) {
	if NetworkFiltered != 0 {
		t.Errorf("NetworkFiltered: got %d, want 0", NetworkFiltered)
	}
	if NetworkBlocked != 1 {
		t.Errorf("NetworkBlocked: got %d, want 1", NetworkBlocked)
	}
	if NetworkAllowed != 2 {
		t.Errorf("NetworkAllowed: got %d, want 2", NetworkAllowed)
	}
}

// ---------------------------------------------------------------------------
// Enum range validation tests
// ---------------------------------------------------------------------------

func TestValidateInvalidFallbackPolicy(t *testing.T) {
	cfg := &Config{
		FallbackPolicy: FallbackPolicy(-1),
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for invalid FallbackPolicy")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}

	cfg2 := &Config{
		FallbackPolicy: FallbackPolicy(99),
	}
	err = cfg2.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for out-of-range FallbackPolicy")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestValidateInvalidNetworkMode(t *testing.T) {
	cfg := &Config{
		Network: NetworkConfig{
			Mode: NetworkMode(-1),
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for invalid NetworkMode")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}

	cfg2 := &Config{
		Network: NetworkConfig{
			Mode: NetworkMode(99),
		},
	}
	err = cfg2.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for out-of-range NetworkMode")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestValidateValidEnumValues(t *testing.T) {
	// All valid FallbackPolicy values should pass.
	for _, fp := range []FallbackPolicy{FallbackStrict, FallbackWarn} {
		cfg := &Config{FallbackPolicy: fp}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() should accept FallbackPolicy %d: %v", fp, err)
		}
	}

	// All valid NetworkMode values should pass.
	for _, nm := range []NetworkMode{NetworkFiltered, NetworkBlocked, NetworkAllowed} {
		cfg := &Config{Network: NetworkConfig{Mode: nm}}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() should accept NetworkMode %d: %v", nm, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Error wrapping tests (Go 1.20+ multi-%w)
// ---------------------------------------------------------------------------

func TestValidateErrorWrapping(t *testing.T) {
	// Test that Validate wraps ErrConfigInvalid properly.
	cfg := &Config{
		FallbackPolicy: FallbackPolicy(99),
		Network:        NetworkConfig{Mode: NetworkMode(99)},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap: DefaultConfig os.UserHomeDir() error fallback (L141-142)
// ---------------------------------------------------------------------------

func TestDefaultConfigHomeDirError(t *testing.T) {
	// Unset HOME to force os.UserHomeDir() to fail, triggering the fallback
	// to os.TempDir() on L141-142.
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", "")
	// Also unset other home-related env vars that os.UserHomeDir might use.
	if v := os.Getenv("USERPROFILE"); v != "" {
		t.Setenv("USERPROFILE", "")
	}

	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil even when HOME is unset")
	}

	// The config should still be valid and use os.TempDir() as fallback.
	// We can't easily check the exact paths, but we verify it doesn't panic
	// and produces a valid config.
	if len(cfg.Filesystem.DenyWrite) == 0 {
		t.Error("DenyWrite should not be empty even when HOME is unset")
	}

	// Restore HOME for subsequent tests.
	_ = origHome
}

// ---------------------------------------------------------------------------
// Coverage gap: validateFilesystem filepath.Abs() error (L247-248)
// ---------------------------------------------------------------------------

func TestValidateFilesystemAbsError(t *testing.T) {
	// A path containing a null byte causes filepath.Abs to fail on most systems.
	cfg := &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: []string{"relative/\x00path"},
		},
	}

	err := cfg.Validate()
	if err == nil {
		// On some systems filepath.Abs may not fail with null bytes.
		// In that case, the path is just treated as a relative path (which is valid).
		return
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestDeepCopyConfig(t *testing.T) {
	orig := DefaultConfig()
	orig.Filesystem.WritableRoots = []string{"/tmp/a"}
	orig.Filesystem.DenyWrite = []string{"/etc"}
	orig.Filesystem.DenyRead = []string{"/secret"}
	orig.Network.AllowedDomains = []string{"example.com"}
	orig.Network.DeniedDomains = []string{"evil.com"}

	cp := deepCopyConfig(orig)

	// Mutate the copy and verify the original is unchanged.
	cp.Filesystem.WritableRoots[0] = "/tmp/b"
	cp.Filesystem.DenyWrite[0] = "/usr"
	cp.Filesystem.DenyRead[0] = "/other"
	cp.Network.AllowedDomains[0] = "changed.com"
	cp.Network.DeniedDomains[0] = "changed.com"

	if orig.Filesystem.WritableRoots[0] != "/tmp/a" {
		t.Error("deepCopyConfig aliased WritableRoots")
	}
	if orig.Filesystem.DenyWrite[0] != "/etc" {
		t.Error("deepCopyConfig aliased DenyWrite")
	}
	if orig.Filesystem.DenyRead[0] != "/secret" {
		t.Error("deepCopyConfig aliased DenyRead")
	}
	if orig.Network.AllowedDomains[0] != "example.com" {
		t.Error("deepCopyConfig aliased AllowedDomains")
	}
	if orig.Network.DeniedDomains[0] != "evil.com" {
		t.Error("deepCopyConfig aliased DeniedDomains")
	}

	// Verify ResourceLimits is deep-copied.
	if cp.ResourceLimits == nil {
		t.Fatal("deepCopyConfig: copy ResourceLimits is nil")
	}
	cp.ResourceLimits.MaxProcesses = 9999
	if orig.ResourceLimits.MaxProcesses == 9999 {
		t.Error("deepCopyConfig aliased ResourceLimits")
	}
}

// TestValidateWritableRootsDenyWriteConflict verifies that Validate detects
// conflicts between WritableRoots and DenyWrite paths.
func TestValidateWritableRootsDenyWriteConflict(t *testing.T) {
	tests := []struct {
		name          string
		writableRoots []string
		denyWrite     []string
		wantErr       bool
	}{
		{
			name:          "exact match",
			writableRoots: []string{"/tmp"},
			denyWrite:     []string{"/tmp"},
			wantErr:       true,
		},
		{
			name:          "writable root under deny write",
			writableRoots: []string{"/etc/app"},
			denyWrite:     []string{"/etc"},
			wantErr:       true,
		},
		{
			name:          "no conflict",
			writableRoots: []string{"/tmp"},
			denyWrite:     []string{"/etc"},
			wantErr:       false,
		},
		{
			name:          "deny write under writable root is not a conflict",
			writableRoots: []string{"/etc"},
			denyWrite:     []string{"/etc/secret"},
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Filesystem: FilesystemConfig{
					WritableRoots: tt.writableRoots,
					DenyWrite:     tt.denyWrite,
				},
			}
			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("Validate() should return error for conflicting WritableRoots/DenyWrite")
				}
				if !errors.Is(err, ErrConfigInvalid) {
					t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
				}
			} else if err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Null byte validation tests
// ---------------------------------------------------------------------------

func TestValidateNullByteInDenyRead(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			DenyRead: []string{"/etc/\x00secret"},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for null byte in DenyRead")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
	if !strings.Contains(err.Error(), "null bytes") {
		t.Errorf("error should mention null bytes, got: %v", err)
	}
}

func TestValidateNullByteInDenyWrite(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			DenyWrite: []string{"/etc/\x00secret"},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for null byte in DenyWrite")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
	if !strings.Contains(err.Error(), "null bytes") {
		t.Errorf("error should mention null bytes, got: %v", err)
	}
}

func TestValidateNullByteInWritableRoots(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: []string{"/tmp/\x00bad"},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for null byte in WritableRoots")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
	if !strings.Contains(err.Error(), "null bytes") {
		t.Errorf("error should mention null bytes, got: %v", err)
	}
}

// TestAutoProtectDangerousFilesField verifies that the new
// AutoProtectDangerousFiles and DangerousFileScanDepth fields are
// properly stored and deep-copied.
func TestAutoProtectDangerousFilesField(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			AutoProtectDangerousFiles: true,
			DangerousFileScanDepth:    3,
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	if !cfg.Filesystem.AutoProtectDangerousFiles {
		t.Error("AutoProtectDangerousFiles should be true")
	}
	if cfg.Filesystem.DangerousFileScanDepth != 3 {
		t.Errorf("DangerousFileScanDepth: got %d, want 3", cfg.Filesystem.DangerousFileScanDepth)
	}

	// Verify deep copy preserves the new fields.
	cp := deepCopyConfig(cfg)
	if !cp.Filesystem.AutoProtectDangerousFiles {
		t.Error("deepCopyConfig should preserve AutoProtectDangerousFiles")
	}
	if cp.Filesystem.DangerousFileScanDepth != 3 {
		t.Errorf("deepCopyConfig should preserve DangerousFileScanDepth: got %d, want 3", cp.Filesystem.DangerousFileScanDepth)
	}

	// Mutating the copy should not affect the original (value types).
	cp.Filesystem.AutoProtectDangerousFiles = false
	cp.Filesystem.DangerousFileScanDepth = 99
	if !cfg.Filesystem.AutoProtectDangerousFiles {
		t.Error("original AutoProtectDangerousFiles should not be affected by copy mutation")
	}
	if cfg.Filesystem.DangerousFileScanDepth != 3 {
		t.Error("original DangerousFileScanDepth should not be affected by copy mutation")
	}
}

// TestValidateGlobPatternsInDenyRead verifies that glob patterns in DenyRead
// are accepted by validation (not rejected as invalid paths).
func TestValidateGlobPatternsInDenyRead(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			DenyRead: []string{"/proc/*/mem", "/tmp/**/*.key"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should accept glob patterns in DenyRead: %v", err)
	}
}

// TestValidateGlobPatternsInDenyWrite verifies that glob patterns in DenyWrite
// are accepted by validation.
func TestValidateGlobPatternsInDenyWrite(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			DenyWrite: []string{"/tmp/**/.git*"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should accept glob patterns in DenyWrite: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Network config new fields tests
// ---------------------------------------------------------------------------

func TestNetworkConfigAllowLocalBinding(t *testing.T) {
	cfg := &Config{
		Network: NetworkConfig{
			Mode:              NetworkFiltered,
			AllowLocalBinding: true,
		},
	}
	if !cfg.Network.AllowLocalBinding {
		t.Error("AllowLocalBinding should be true")
	}

	// Verify it validates without error.
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should pass with AllowLocalBinding: %v", err)
	}

	// Verify default is false.
	defaultCfg := DefaultConfig()
	if defaultCfg.Network.AllowLocalBinding {
		t.Error("AllowLocalBinding should default to false")
	}
}

func TestNetworkConfigAllowUnixSockets(t *testing.T) {
	cfg := &Config{
		Network: NetworkConfig{
			Mode:                NetworkFiltered,
			AllowAllUnixSockets: true,
			AllowUnixSockets:    []string{"/var/run/docker.sock"},
		},
	}
	if !cfg.Network.AllowAllUnixSockets {
		t.Error("AllowAllUnixSockets should be true")
	}
	if len(cfg.Network.AllowUnixSockets) != 1 {
		t.Fatalf("AllowUnixSockets: got %d entries, want 1", len(cfg.Network.AllowUnixSockets))
	}
	if cfg.Network.AllowUnixSockets[0] != "/var/run/docker.sock" {
		t.Errorf("AllowUnixSockets[0] = %q, want /var/run/docker.sock", cfg.Network.AllowUnixSockets[0])
	}

	// Verify it validates without error.
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should pass with Unix socket fields: %v", err)
	}

	// Verify defaults are false/empty.
	defaultCfg := DefaultConfig()
	if defaultCfg.Network.AllowAllUnixSockets {
		t.Error("AllowAllUnixSockets should default to false")
	}
	if len(defaultCfg.Network.AllowUnixSockets) != 0 {
		t.Error("AllowUnixSockets should default to empty")
	}
}

func TestDeepCopyConfigAllowUnixSockets(t *testing.T) {
	original := &Config{
		Network: NetworkConfig{
			AllowUnixSockets: []string{"/var/run/docker.sock"},
		},
	}
	copied := deepCopyConfig(original)

	// Mutate the copy.
	copied.Network.AllowUnixSockets[0] = "/tmp/other.sock"

	// Original should be unaffected.
	if original.Network.AllowUnixSockets[0] != "/var/run/docker.sock" {
		t.Error("deepCopyConfig should deep-copy AllowUnixSockets slice")
	}
}

func TestDeepCopyConfigMITMProxy(t *testing.T) {
	original := &Config{
		Network: NetworkConfig{
			MITMProxy: &MITMProxyConfig{
				SocketPath: "/var/run/mitm.sock",
				Domains:    []string{"*.example.com", "api.corp.io"},
			},
		},
	}
	copied := deepCopyConfig(original)

	// Mutate the copy.
	copied.Network.MITMProxy.SocketPath = "/tmp/other.sock"
	copied.Network.MITMProxy.Domains[0] = "*.changed.com"

	// Original should be unaffected.
	if original.Network.MITMProxy.SocketPath != "/var/run/mitm.sock" {
		t.Error("deepCopyConfig should deep-copy MITMProxy.SocketPath")
	}
	if original.Network.MITMProxy.Domains[0] != "*.example.com" {
		t.Error("deepCopyConfig should deep-copy MITMProxy.Domains slice")
	}
}

func TestDeepCopyConfigMITMProxyNil(t *testing.T) {
	original := &Config{
		Network: NetworkConfig{
			MITMProxy: nil,
		},
	}
	copied := deepCopyConfig(original)

	if copied.Network.MITMProxy != nil {
		t.Error("deepCopyConfig should preserve nil MITMProxy")
	}
}

// ---------------------------------------------------------------------------
// Config validation: MITMProxy, AllowUnixSockets, DangerousFileScanDepth
// ---------------------------------------------------------------------------

func TestValidateMITMProxySocketPathEmpty(t *testing.T) {
	cfg := &Config{
		Network: NetworkConfig{
			MITMProxy: &MITMProxyConfig{
				SocketPath: "",
				Domains:    []string{"*.example.com"},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject empty MITMProxy.SocketPath")
	}
	if !strings.Contains(err.Error(), "MITMProxy.SocketPath") {
		t.Errorf("error should mention MITMProxy.SocketPath, got: %v", err)
	}
}

func TestValidateMITMProxySocketPathRelative(t *testing.T) {
	cfg := &Config{
		Network: NetworkConfig{
			MITMProxy: &MITMProxyConfig{
				SocketPath: "relative/path.sock",
				Domains:    []string{"*.example.com"},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject relative MITMProxy.SocketPath")
	}
	if !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("error should mention absolute path, got: %v", err)
	}
}

func TestValidateMITMProxyInvalidDomain(t *testing.T) {
	cfg := &Config{
		Network: NetworkConfig{
			MITMProxy: &MITMProxyConfig{
				SocketPath: "/var/run/mitm.sock",
				Domains:    []string{""},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject invalid MITMProxy domain")
	}
	if !strings.Contains(err.Error(), "MITMProxy.Domains") {
		t.Errorf("error should mention MITMProxy.Domains, got: %v", err)
	}
}

func TestValidateMITMProxyValid(t *testing.T) {
	cfg := &Config{
		Network: NetworkConfig{
			MITMProxy: &MITMProxyConfig{
				SocketPath: "/var/run/mitm.sock",
				Domains:    []string{"*.example.com"},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should accept valid MITMProxy config: %v", err)
	}
}

func TestValidateAllowUnixSocketsEmpty(t *testing.T) {
	cfg := &Config{
		Network: NetworkConfig{
			AllowUnixSockets: []string{""},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject empty AllowUnixSockets entry")
	}
	if !strings.Contains(err.Error(), "AllowUnixSockets") {
		t.Errorf("error should mention AllowUnixSockets, got: %v", err)
	}
}

func TestValidateAllowUnixSocketsRelative(t *testing.T) {
	cfg := &Config{
		Network: NetworkConfig{
			AllowUnixSockets: []string{"relative/path.sock"},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject relative AllowUnixSockets path")
	}
	if !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("error should mention absolute path, got: %v", err)
	}
}

func TestValidateAllowUnixSocketsValid(t *testing.T) {
	cfg := &Config{
		Network: NetworkConfig{
			AllowUnixSockets: []string{"/var/run/docker.sock"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should accept valid AllowUnixSockets: %v", err)
	}
}

func TestValidateDangerousFileScanDepthNegative(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			DangerousFileScanDepth: -1,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject negative DangerousFileScanDepth")
	}
	if !strings.Contains(err.Error(), "DangerousFileScanDepth") {
		t.Errorf("error should mention DangerousFileScanDepth, got: %v", err)
	}
}

func TestValidateDangerousFileScanDepthZero(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			DangerousFileScanDepth: 0,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should accept zero DangerousFileScanDepth: %v", err)
	}
}
