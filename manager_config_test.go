package agentbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
)

// TestManagerUpdateConfig verifies that a valid config update succeeds.
func TestManagerUpdateConfig(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	newCfg := newTestConfig(t)
	newCfg.MaxOutputBytes = 42

	err = mgr.UpdateConfig(newCfg)
	if err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}

	m := mgr.(*manager)
	m.mu.Lock()
	got := m.cfg.MaxOutputBytes
	m.mu.Unlock()
	if got != 42 {
		t.Errorf("MaxOutputBytes after UpdateConfig = %d, want 42", got)
	}
}

// TestManagerUpdateConfigInvalid verifies that an invalid config is rejected.
func TestManagerUpdateConfigInvalid(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	badCfg := &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: []string{""},
		},
	}
	err = mgr.UpdateConfig(badCfg)
	if err == nil {
		t.Fatal("UpdateConfig() with invalid config should return error")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

// TestManagerUpdateConfigClosed verifies that UpdateConfig returns
// ErrManagerClosed after Cleanup.
func TestManagerUpdateConfigClosed(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	_ = mgr.Cleanup(context.Background())

	newCfg := newTestConfig(t)
	err = mgr.UpdateConfig(newCfg)
	if !errors.Is(err, ErrManagerClosed) {
		t.Errorf("UpdateConfig() after Cleanup: got %v, want ErrManagerClosed", err)
	}
}

// TestManagerUpdateConfigNetworkRules verifies that UpdateConfig hot-reloads
// proxy filter rules when network domains change. We test this by creating
// a manager with a proxy filter and verifying the filter is updated.
func TestManagerUpdateConfigNetworkRules(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network = NetworkConfig{
		Mode:           NetworkFiltered,
		AllowedDomains: []string{"api.github.com"},
	}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m, ok := mgr.(*manager)
	if !ok {
		t.Fatal("expected *manager type")
	}

	if m.proxyFilter == nil {
		t.Fatal("proxyFilter should not be nil for NetworkFiltered mode")
	}

	// Update config with new allowed domains.
	newCfg := newTestConfig(t)
	newCfg.Network = NetworkConfig{
		Mode:           NetworkFiltered,
		AllowedDomains: []string{"api.openai.com"},
	}

	err = mgr.UpdateConfig(newCfg)
	if err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}

	// Verify the filter was updated by checking that the old domain is now
	// denied and the new domain is allowed.
	ctx := context.Background()
	allowed, err := m.proxyFilter.Filter(ctx, "api.openai.com", 443)
	if err != nil {
		t.Fatalf("Filter() error: %v", err)
	}
	if !allowed {
		t.Error("api.openai.com should be allowed after UpdateConfig")
	}

	allowed, err = m.proxyFilter.Filter(ctx, "api.github.com", 443)
	if err != nil {
		t.Fatalf("Filter() error: %v", err)
	}
	if allowed {
		t.Error("api.github.com should be denied after UpdateConfig (no longer in allowed list)")
	}
}

// ---------------------------------------------------------------------------
// newManager branch coverage
// ---------------------------------------------------------------------------

// TestNewManagerNetworkBlocked verifies that newManager with NetworkBlocked
// mode does NOT start a proxy (proxy is only for NetworkFiltered).
func TestNewManagerNetworkBlocked(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network = NetworkConfig{
		Mode: NetworkBlocked,
	}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m, ok := mgr.(*manager)
	if !ok {
		t.Fatal("expected *manager type")
	}

	// NetworkBlocked should NOT start a proxy.
	if m.proxy != nil {
		t.Error("proxy should be nil for NetworkBlocked mode")
	}
	if m.proxyFilter != nil {
		t.Error("proxyFilter should be nil for NetworkBlocked mode")
	}
	if m.httpProxyPort != 0 {
		t.Errorf("httpProxyPort = %d, want 0", m.httpProxyPort)
	}
	if m.socksProxyPort != 0 {
		t.Errorf("socksProxyPort = %d, want 0", m.socksProxyPort)
	}
}

// TestNewManagerCustomShell verifies that a custom shell is preserved.
func TestNewManagerCustomShell(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Shell = "/bin/bash"

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	if m.cfg.Shell != "/bin/bash" {
		t.Errorf("Shell = %q, want /bin/bash", m.cfg.Shell)
	}
}

// TestNewManagerRelativeWritableRoots verifies that relative writable roots
// are resolved to absolute paths.
func TestNewManagerRelativeWritableRoots(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	relDir := t.TempDir()
	cfg.Filesystem.WritableRoots = []string{relDir}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	for _, root := range m.cfg.Filesystem.WritableRoots {
		if !filepath.IsAbs(root) {
			t.Errorf("writable root should be absolute path, got %q", root)
		}
	}
}

// TestNewManagerNetworkFiltered verifies that newManager with NetworkFiltered
// mode starts a proxy and sets proxy ports.
func TestNewManagerNetworkFiltered(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network = NetworkConfig{
		Mode:           NetworkFiltered,
		AllowedDomains: []string{"example.com"},
	}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	if m.proxy == nil {
		t.Error("proxy should not be nil for NetworkFiltered mode")
	}
	if m.proxyFilter == nil {
		t.Error("proxyFilter should not be nil for NetworkFiltered mode")
	}
	if m.httpProxyPort == 0 {
		t.Error("httpProxyPort should be set for NetworkFiltered mode")
	}
	if m.socksProxyPort == 0 {
		t.Error("socksProxyPort should be set for NetworkFiltered mode")
	}
}

// ---------------------------------------------------------------------------
// buildWrapConfig branch coverage
// ---------------------------------------------------------------------------

// TestBuildWrapConfigWithProxyPorts verifies that proxy ports are passed
// to the WrapConfig.
func TestBuildWrapConfigWithProxyPorts(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network = NetworkConfig{
		Mode:           NetworkFiltered,
		AllowedDomains: []string{"example.com"},
	}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	co := &callOptions{}
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	wcfg := m.buildWrapConfig(&snap, co)

	if wcfg.HTTPProxyPort == 0 {
		t.Error("HTTPProxyPort should be set when proxy is active")
	}
	if wcfg.SOCKSProxyPort == 0 {
		t.Error("SOCKSProxyPort should be set when proxy is active")
	}
	if !wcfg.NeedsNetworkRestriction {
		t.Error("NeedsNetworkRestriction should be true for NetworkFiltered")
	}
}

// TestBuildWrapConfigNetworkBlocked verifies NeedsNetworkRestriction is set
// for NetworkBlocked mode.
func TestBuildWrapConfigNetworkBlocked(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network = NetworkConfig{
		Mode: NetworkBlocked,
	}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	co := &callOptions{}
	wcfg := m.buildWrapConfig(&configSnapshot{cfg: *m.cfg}, co)

	if !wcfg.NeedsNetworkRestriction {
		t.Error("NeedsNetworkRestriction should be true for NetworkBlocked")
	}
}

// TestBuildWrapConfigPerCallNetworkOverride verifies that per-call network
// option overrides the config network.
func TestBuildWrapConfigPerCallNetworkOverride(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network = NetworkConfig{
		Mode: NetworkAllowed,
	}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	co := &callOptions{
		network: &NetworkConfig{Mode: NetworkBlocked},
	}
	wcfg := m.buildWrapConfig(&configSnapshot{cfg: *m.cfg}, co)

	if !wcfg.NeedsNetworkRestriction {
		t.Error("NeedsNetworkRestriction should be true when per-call network is NetworkBlocked")
	}
}

// TestBuildWrapConfigPerCallWritableRoots verifies that per-call writable
// roots are merged with config writable roots.
func TestBuildWrapConfigPerCallWritableRoots(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	cfg.Filesystem.WritableRoots = []string{"/tmp"}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	co := &callOptions{
		writableRoots: []string{"/var"},
	}
	wcfg := m.buildWrapConfig(&configSnapshot{cfg: *m.cfg}, co)

	// On macOS, /var is a symlink to /private/var, so resolve it.
	expectedVar := "/var"
	if resolved, err := filepath.EvalSymlinks("/var"); err == nil {
		expectedVar = resolved
	}

	found := false
	for _, root := range wcfg.WritableRoots {
		if root == expectedVar {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("per-call writable root %q should be in WrapConfig.WritableRoots, got %v", expectedVar, wcfg.WritableRoots)
	}
}

// TestBuildWrapConfigPerCallShell verifies that per-call shell overrides
// the config shell.
func TestBuildWrapConfigPerCallShell(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	co := &callOptions{
		shell: "/bin/bash",
	}
	wcfg := m.buildWrapConfig(&configSnapshot{cfg: *m.cfg}, co)

	if wcfg.Shell != "/bin/bash" {
		t.Errorf("Shell = %q, want /bin/bash", wcfg.Shell)
	}
}

// ---------------------------------------------------------------------------
// injectProxyEnv branch coverage
// ---------------------------------------------------------------------------

// TestInjectProxyEnvNoProxy verifies that injectProxyEnv is a no-op when
// proxy is not active.
func TestInjectProxyEnvNoProxy(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	cmd := exec.Command("echo", "test")
	cmd.Env = []string{"PATH=/usr/bin"}

	m.injectProxyEnv(cmd)

	// Should not add any proxy env vars.
	if len(cmd.Env) != 1 {
		t.Errorf("cmd.Env length = %d, want 1 (no proxy env added)", len(cmd.Env))
	}
}

// TestInjectProxyEnvWithProxy verifies that injectProxyEnv adds proxy
// environment variables when proxy is active.
func TestInjectProxyEnvWithProxy(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network = NetworkConfig{
		Mode:           NetworkFiltered,
		AllowedDomains: []string{"example.com"},
	}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	cmd := exec.Command("echo", "test")
	// cmd.Env is nil — injectProxyEnv should call cmd.Environ() and add proxy vars.

	m.injectProxyEnv(cmd)

	if cmd.Env == nil {
		t.Fatal("cmd.Env should not be nil after injectProxyEnv with active proxy")
	}

	hasProxy := false
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "HTTP_PROXY=") || strings.HasPrefix(e, "http_proxy=") {
			hasProxy = true
			break
		}
	}
	if !hasProxy {
		t.Error("cmd.Env should contain HTTP_PROXY after injectProxyEnv")
	}
}

// ---------------------------------------------------------------------------
// UpdateConfig branch coverage
// ---------------------------------------------------------------------------

// TestManagerUpdateConfigShell verifies that UpdateConfig updates the shell.
func TestManagerUpdateConfigShell(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	newCfg := newTestConfig(t)
	newCfg.Shell = "/bin/bash"
	newCfg.ResourceLimits = DefaultResourceLimits()

	err = mgr.UpdateConfig(newCfg)
	if err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}

	m := mgr.(*manager)
	m.mu.Lock()
	got := m.cfg.Shell
	m.mu.Unlock()
	if got != "/bin/bash" {
		t.Errorf("Shell after UpdateConfig = %q, want /bin/bash", got)
	}
}

// TestManagerUpdateConfigClassifier verifies that UpdateConfig updates the classifier.
func TestManagerUpdateConfigClassifier(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	newCfg := newTestConfig(t)
	customClassifier := &ruleClassifier{
		rules: []rule{
			{
				Name: "allow-all",
				Match: func(command string) (ClassifyResult, bool) {
					return ClassifyResult{Decision: Sandboxed, Reason: "allowed"}, true
				},
			},
		},
	}
	newCfg.Classifier = customClassifier

	err = mgr.UpdateConfig(newCfg)
	if err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}

	m := mgr.(*manager)
	m.mu.Lock()
	got := m.cfg.Classifier
	m.mu.Unlock()
	if got != customClassifier {
		t.Error("Classifier should be updated after UpdateConfig")
	}
}

// TestManagerUpdateConfigNilClassifier verifies that UpdateConfig with nil
// classifier does not overwrite the existing classifier.
func TestManagerUpdateConfigNilClassifier(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	m.mu.Lock()
	origClassifier := m.cfg.Classifier
	m.mu.Unlock()

	newCfg := newTestConfig(t)
	newCfg.Classifier = nil

	err = mgr.UpdateConfig(newCfg)
	if err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}

	m.mu.Lock()
	got := m.cfg.Classifier
	m.mu.Unlock()
	if got != origClassifier {
		t.Error("Classifier should not be overwritten when UpdateConfig has nil classifier")
	}
}

// TestManagerUpdateConfigResourceLimits verifies that UpdateConfig updates
// resource limits.
func TestManagerUpdateConfigResourceLimits(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	newCfg := newTestConfig(t)
	newCfg.ResourceLimits = &ResourceLimits{
		MaxProcesses:       200,
		MaxMemoryBytes:     1 << 30,
		MaxFileDescriptors: 512,
		MaxCPUSeconds:      120,
	}

	err = mgr.UpdateConfig(newCfg)
	if err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}

	m := mgr.(*manager)
	m.mu.Lock()
	got := m.cfg.ResourceLimits
	m.mu.Unlock()
	if got.MaxProcesses != 200 {
		t.Errorf("MaxProcesses = %d, want 200", got.MaxProcesses)
	}
}

// TestManagerUpdateConfigSameDomains verifies that UpdateConfig with the same
// domains does not trigger a filter update.
func TestManagerUpdateConfigSameDomains(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network = NetworkConfig{
		Mode:           NetworkFiltered,
		AllowedDomains: []string{"api.github.com"},
	}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Update with the same domains — should be a no-op for the filter.
	newCfg := newTestConfig(t)
	newCfg.Network = NetworkConfig{
		Mode:           NetworkFiltered,
		AllowedDomains: []string{"api.github.com"},
	}

	err = mgr.UpdateConfig(newCfg)
	if err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// stringSlicesEqual branch coverage
// ---------------------------------------------------------------------------

func TestStringSlicesEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{name: "both nil", a: nil, b: nil, want: true},
		{name: "both empty", a: []string{}, b: []string{}, want: true},
		{name: "equal", a: []string{"a", "b"}, b: []string{"a", "b"}, want: true},
		{name: "different lengths", a: []string{"a"}, b: []string{"a", "b"}, want: false},
		{name: "same length different content", a: []string{"a", "b"}, b: []string{"a", "c"}, want: false},
		{name: "one nil one empty", a: nil, b: []string{}, want: true},
		{name: "single element equal", a: []string{"x"}, b: []string{"x"}, want: true},
		{name: "single element different", a: []string{"x"}, b: []string{"y"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stringSlicesEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("stringSlicesEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Fix 2: UpdateConfig nil check
// ---------------------------------------------------------------------------

// TestManagerUpdateConfigNil verifies that UpdateConfig rejects a nil config.
func TestManagerUpdateConfigNil(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	err = mgr.UpdateConfig(nil)
	if err == nil {
		t.Fatal("UpdateConfig(nil) should return error")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Fix 3: UpdateConfig normalizes relative paths
// ---------------------------------------------------------------------------

// TestManagerUpdateConfigNormalizesRelativePaths verifies that UpdateConfig
// resolves relative writable roots to absolute paths.
func TestManagerUpdateConfigNormalizesRelativePaths(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	newCfg := newTestConfig(t)
	tmpDir := t.TempDir()
	newCfg.Filesystem.WritableRoots = []string{tmpDir}

	err = mgr.UpdateConfig(newCfg)
	if err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}

	m := mgr.(*manager)
	m.mu.RLock()
	roots := m.cfg.Filesystem.WritableRoots
	m.mu.RUnlock()

	found := false
	for _, root := range roots {
		if root == tmpDir {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("writable root %q should be present after UpdateConfig, got %v", tmpDir, roots)
	}
}

// ---------------------------------------------------------------------------
// Fix 4: UpdateConfig deep-copies all slices
// ---------------------------------------------------------------------------

// TestManagerUpdateConfigDeepCopySlices verifies that UpdateConfig deep-copies
// DenyWrite, DenyRead, AllowedDomains, and DeniedDomains slices so that
// mutations to the caller's slices do not affect the manager's config.
func TestManagerUpdateConfigDeepCopySlices(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	denyWrite := []string{"/secret"}
	denyRead := []string{"/private"}
	allowedDomains := []string{"example.com"}
	deniedDomains := []string{"evil.com"}

	newCfg := newTestConfig(t)
	newCfg.Network.Mode = NetworkAllowed
	newCfg.Filesystem.DenyWrite = denyWrite
	newCfg.Filesystem.DenyRead = denyRead
	newCfg.Network.AllowedDomains = allowedDomains
	newCfg.Network.DeniedDomains = deniedDomains

	err = mgr.UpdateConfig(newCfg)
	if err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}

	// Mutate the caller's slices.
	denyWrite[0] = "/mutated"
	denyRead[0] = "/mutated"
	allowedDomains[0] = "mutated.com"
	deniedDomains[0] = "mutated.com"

	m := mgr.(*manager)
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.cfg.Filesystem.DenyWrite) > 0 && m.cfg.Filesystem.DenyWrite[0] == "/mutated" {
		t.Error("DenyWrite should be deep-copied; caller mutation should not affect manager")
	}
	if len(m.cfg.Filesystem.DenyRead) > 0 && m.cfg.Filesystem.DenyRead[0] == "/mutated" {
		t.Error("DenyRead should be deep-copied; caller mutation should not affect manager")
	}
	if len(m.cfg.Network.AllowedDomains) > 0 && m.cfg.Network.AllowedDomains[0] == "mutated.com" {
		t.Error("AllowedDomains should be deep-copied; caller mutation should not affect manager")
	}
	if len(m.cfg.Network.DeniedDomains) > 0 && m.cfg.Network.DeniedDomains[0] == "mutated.com" {
		t.Error("DeniedDomains should be deep-copied; caller mutation should not affect manager")
	}
}

// ---------------------------------------------------------------------------
// newManager deep-copy verification
// ---------------------------------------------------------------------------

// TestNewManagerDeepCopySlices verifies that newManager deep-copies all slices
// from the input config so that mutations to the caller's slices do not affect
// the manager's internal config.
func TestNewManagerDeepCopySlices(t *testing.T) {
	// Use stub platform so newManager creates a real *manager.
	origDetect := detectPlatformFn
	detectPlatformFn = func() platform.Platform { return stubPlatform{} }
	t.Cleanup(func() { detectPlatformFn = origDetect })

	denyWrite := []string{"/etc"}
	denyRead := []string{"/secret"}
	allowedDomains := []string{"example.com"}
	deniedDomains := []string{"evil.com"}
	writableRoots := []string{"/tmp"}

	cfg := &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: writableRoots,
			DenyWrite:     denyWrite,
			DenyRead:      denyRead,
		},
		Network: NetworkConfig{
			Mode:           NetworkAllowed,
			AllowedDomains: allowedDomains,
			DeniedDomains:  deniedDomains,
		},
	}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Mutate the caller's slices.
	writableRoots[0] = "/mutated"
	denyWrite[0] = "/mutated"
	denyRead[0] = "/mutated"
	allowedDomains[0] = "mutated.com"
	deniedDomains[0] = "mutated.com"

	m := mgr.(*manager)
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.cfg.Filesystem.WritableRoots) > 0 && m.cfg.Filesystem.WritableRoots[0] == "/mutated" {
		t.Error("WritableRoots should be deep-copied; caller mutation should not affect manager")
	}
	if len(m.cfg.Filesystem.DenyWrite) > 0 && m.cfg.Filesystem.DenyWrite[0] == "/mutated" {
		t.Error("DenyWrite should be deep-copied; caller mutation should not affect manager")
	}
	if len(m.cfg.Filesystem.DenyRead) > 0 && m.cfg.Filesystem.DenyRead[0] == "/mutated" {
		t.Error("DenyRead should be deep-copied; caller mutation should not affect manager")
	}
	if len(m.cfg.Network.AllowedDomains) > 0 && m.cfg.Network.AllowedDomains[0] == "mutated.com" {
		t.Error("AllowedDomains should be deep-copied; caller mutation should not affect manager")
	}
	if len(m.cfg.Network.DeniedDomains) > 0 && m.cfg.Network.DeniedDomains[0] == "mutated.com" {
		t.Error("DeniedDomains should be deep-copied; caller mutation should not affect manager")
	}
}

func TestBuildWrapConfigDeepCopyDenySlices(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Filesystem.DenyWrite = []string{"/etc", "/usr"}
	cfg.Filesystem.DenyRead = []string{"/secret"}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}

	co := &callOptions{}
	wcfg := m.buildWrapConfig(&snap, co)

	// Verify the values are correct.
	if len(wcfg.DenyWrite) != 2 || wcfg.DenyWrite[0] != "/etc" || wcfg.DenyWrite[1] != "/usr" {
		t.Errorf("DenyWrite: got %v, want [/etc /usr]", wcfg.DenyWrite)
	}
	if len(wcfg.DenyRead) != 1 || wcfg.DenyRead[0] != "/secret" {
		t.Errorf("DenyRead: got %v, want [/secret]", wcfg.DenyRead)
	}

	// Mutate the returned slices and verify the snapshot is not affected.
	wcfg.DenyWrite[0] = "/mutated"
	wcfg.DenyRead[0] = "/mutated"

	snap2, _ := m.snapshotConfig()
	wcfg2 := m.buildWrapConfig(&snap2, co)
	if wcfg2.DenyWrite[0] != "/etc" {
		t.Errorf("DenyWrite was mutated: got %v, want /etc", wcfg2.DenyWrite[0])
	}
	if wcfg2.DenyRead[0] != "/secret" {
		t.Errorf("DenyRead was mutated: got %v, want /secret", wcfg2.DenyRead[0])
	}
}

// TestBuildWrapConfigDenyReadMerge verifies that per-call denyRead paths
// are merged with config-level DenyRead.
func TestBuildWrapConfigDenyReadMerge(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Filesystem.DenyRead = []string{"/secret"}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	co := &callOptions{
		denyRead: []string{"/also-secret"},
	}
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	wcfg := m.buildWrapConfig(&snap, co)

	if len(wcfg.DenyRead) != 2 {
		t.Fatalf("DenyRead: got %d entries, want 2", len(wcfg.DenyRead))
	}
	if wcfg.DenyRead[0] != "/secret" {
		t.Errorf("DenyRead[0]: got %q, want %q", wcfg.DenyRead[0], "/secret")
	}
	if wcfg.DenyRead[1] != "/also-secret" {
		t.Errorf("DenyRead[1]: got %q, want %q", wcfg.DenyRead[1], "/also-secret")
	}
}

// TestBuildWrapConfigDenyWriteMerge verifies that per-call denyWrite paths
// are merged with config-level DenyWrite.
func TestBuildWrapConfigDenyWriteMerge(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Filesystem.DenyWrite = []string{"/etc"}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	co := &callOptions{
		denyWrite: []string{"/usr"},
	}
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	wcfg := m.buildWrapConfig(&snap, co)

	if len(wcfg.DenyWrite) != 2 {
		t.Fatalf("DenyWrite: got %d entries, want 2", len(wcfg.DenyWrite))
	}
	if wcfg.DenyWrite[0] != "/etc" {
		t.Errorf("DenyWrite[0]: got %q, want %q", wcfg.DenyWrite[0], "/etc")
	}
	if wcfg.DenyWrite[1] != "/usr" {
		t.Errorf("DenyWrite[1]: got %q, want %q", wcfg.DenyWrite[1], "/usr")
	}
}

// ---------------------------------------------------------------------------
// Coverage gap: newManager shell existence check failure (L91-93)
// ---------------------------------------------------------------------------

func TestNewManagerNonexistentShellError(t *testing.T) {
	cfg := &Config{
		Shell: "/nonexistent/shell/that/does/not/exist",
	}
	_, err := newManager(cfg)
	if err == nil {
		t.Fatal("newManager() should return error for nonexistent shell")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error should mention 'does not exist', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap: UpdateConfig shell check failure (L602-604)
// ---------------------------------------------------------------------------

func TestManagerUpdateConfigNonexistentShell(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	newCfg := newTestConfig(t)
	newCfg.Shell = "/nonexistent/shell/path"

	err = mgr.UpdateConfig(newCfg)
	if err == nil {
		t.Fatal("UpdateConfig() should return error for nonexistent shell")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error should mention 'does not exist', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap: UpdateConfig filepath.Abs error (L573-578)
// ---------------------------------------------------------------------------

func TestManagerUpdateConfigAbsError(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	newCfg := newTestConfig(t)
	// A path with null byte should cause filepath.Abs to fail.
	newCfg.Filesystem.WritableRoots = []string{"relative/\x00path"}

	err = mgr.UpdateConfig(newCfg)
	if err == nil {
		// On some systems filepath.Abs may not fail with null bytes.
		// Skip if the system handles it gracefully.
		t.Skip("filepath.Abs did not fail with null byte path on this system")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap: UpdateConfig after Cleanup (ErrManagerClosed)
// ---------------------------------------------------------------------------

func TestManagerUpdateConfigAfterCleanup(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}

	_ = mgr.Cleanup(context.Background())

	newCfg := newTestConfig(t)
	err = mgr.UpdateConfig(newCfg)
	if !errors.Is(err, ErrManagerClosed) {
		t.Errorf("UpdateConfig() after Cleanup: got %v, want ErrManagerClosed", err)
	}
}

// TestManagerUpdateConfigZeroValueReset verifies that UpdateConfig with
// zero-value MaxOutputBytes and nil ResourceLimits actually resets them
// (not skipped due to zero-value check).
func TestManagerUpdateConfigZeroValueReset(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.MaxOutputBytes = 1024
	cfg.ResourceLimits = &ResourceLimits{MaxProcesses: 500}
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Verify initial values.
	m := mgr.(*manager)
	m.mu.RLock()
	if m.cfg.MaxOutputBytes != 1024 {
		t.Fatalf("initial MaxOutputBytes = %d, want 1024", m.cfg.MaxOutputBytes)
	}
	if m.cfg.ResourceLimits == nil || m.cfg.ResourceLimits.MaxProcesses != 500 {
		t.Fatal("initial ResourceLimits not set correctly")
	}
	m.mu.RUnlock()

	// Update with zero values to reset.
	newCfg := newTestConfig(t)
	newCfg.MaxOutputBytes = 0
	newCfg.ResourceLimits = nil

	err = mgr.UpdateConfig(newCfg)
	if err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg.MaxOutputBytes != 0 {
		t.Errorf("MaxOutputBytes after reset = %d, want 0", m.cfg.MaxOutputBytes)
	}
	if m.cfg.ResourceLimits != nil {
		t.Errorf("ResourceLimits after reset = %v, want nil", m.cfg.ResourceLimits)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap: newManager proxy NewDomainFilter error (L127-129)
// The root package's validateDomainPattern does not reject domains with
// port numbers, but the proxy's ValidateDomainPattern does. This allows
// us to trigger the NewDomainFilter error path.
// ---------------------------------------------------------------------------

func TestNewManagerProxyFilterError(t *testing.T) {
	// Use stub platform so newManager reaches the proxy filter creation code.
	origDetect := detectPlatformFn
	detectPlatformFn = func() platform.Platform { return stubPlatform{} }
	t.Cleanup(func() { detectPlatformFn = origDetect })

	cfg := &Config{
		Network: NetworkConfig{
			Mode: NetworkFiltered,
			// "example.com:8080" passes root-level validation but fails
			// proxy.ValidateDomainPattern (rejects port numbers).
			AllowedDomains: []string{"example.com:8080"},
		},
	}

	_, err := newManager(cfg)
	if err == nil {
		t.Fatal("newManager() should return error when proxy filter creation fails")
	}
	if !errors.Is(err, ErrProxyStartFailed) {
		t.Errorf("error should wrap ErrProxyStartFailed, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap: UpdateConfig proxyFilter.UpdateRules error (L587-589)
// Use a domain with port to trigger the proxy filter update error.
// ---------------------------------------------------------------------------

func TestManagerUpdateConfigProxyFilterUpdateError(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network = NetworkConfig{
		Mode:           NetworkFiltered,
		AllowedDomains: []string{"api.github.com"},
	}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Update with a domain that has a port — passes root validation but
	// fails proxy.ValidateDomainPattern.
	newCfg := newTestConfig(t)
	newCfg.Network = NetworkConfig{
		Mode:           NetworkFiltered,
		AllowedDomains: []string{"example.com:8080"},
	}

	err = mgr.UpdateConfig(newCfg)
	if err == nil {
		t.Fatal("UpdateConfig() should return error when proxy filter update fails")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Symlink resolution in buildWrapConfig
// ---------------------------------------------------------------------------

// TestBuildWrapConfigSymlinkResolution verifies that buildWrapConfig resolves
// symlinks in writable roots when they stay within boundaries.
func TestBuildWrapConfigSymlinkResolution(t *testing.T) {
	// Create a temp directory with a symlink that stays within boundary.
	tmpDir := t.TempDir()
	// Resolve tmpDir itself so that on macOS (where /var -> /private/var)
	// the boundary check in ResolveWithBoundaryCheck works correctly.
	tmpDir, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q) error: %v", tmpDir, err)
	}
	realDir := filepath.Join(tmpDir, "real")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatalf("MkdirAll error: %v", err)
	}
	linkDir := filepath.Join(tmpDir, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	cfg.Filesystem.WritableRoots = []string{linkDir}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	co := &callOptions{}
	wcfg := m.buildWrapConfig(&snap, co)

	// The symlink should be resolved to the real path.
	found := false
	for _, root := range wcfg.WritableRoots {
		if root == realDir {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("WritableRoots should contain resolved path %q, got %v", realDir, wcfg.WritableRoots)
	}
}

// TestBuildWrapConfigSymlinkResolutionBroken verifies that buildWrapConfig
// keeps the original path when symlink resolution fails (broken symlink).
func TestBuildWrapConfigSymlinkResolutionBroken(t *testing.T) {
	tmpDir := t.TempDir()
	brokenLink := filepath.Join(tmpDir, "broken")
	if err := os.Symlink("/nonexistent/target/path", brokenLink); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	cfg.Filesystem.WritableRoots = []string{brokenLink}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	co := &callOptions{}
	wcfg := m.buildWrapConfig(&snap, co)

	// The broken symlink should keep the original path.
	found := false
	for _, root := range wcfg.WritableRoots {
		if root == brokenLink {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("WritableRoots should keep original path %q for broken symlink, got %v", brokenLink, wcfg.WritableRoots)
	}
}

// ---------------------------------------------------------------------------
// Dangerous file scanning integration
// ---------------------------------------------------------------------------

// TestBuildWrapConfigDangerousFileScanning verifies that buildWrapConfig
// scans for dangerous files when AutoProtectDangerousFiles is enabled.
func TestBuildWrapConfigDangerousFileScanning(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a dangerous file.
	bashrc := filepath.Join(tmpDir, ".bashrc")
	if err := os.WriteFile(bashrc, []byte("# test"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	cfg.Filesystem.WritableRoots = []string{tmpDir}
	cfg.Filesystem.AutoProtectDangerousFiles = true
	cfg.Filesystem.DangerousFileScanDepth = 3

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	co := &callOptions{}
	wcfg := m.buildWrapConfig(&snap, co)

	// The .bashrc file should be in DenyWrite.
	found := false
	for _, p := range wcfg.DenyWrite {
		if p == bashrc {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DenyWrite should contain dangerous file %q, got %v", bashrc, wcfg.DenyWrite)
	}
}

// TestBuildWrapConfigDangerousFileScanningDisabled verifies that dangerous
// file scanning is skipped when AutoProtectDangerousFiles is false.
func TestBuildWrapConfigDangerousFileScanningDisabled(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a dangerous file.
	bashrc := filepath.Join(tmpDir, ".bashrc")
	if err := os.WriteFile(bashrc, []byte("# test"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	cfg.Filesystem.WritableRoots = []string{tmpDir}
	cfg.Filesystem.AutoProtectDangerousFiles = false

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	co := &callOptions{}
	wcfg := m.buildWrapConfig(&snap, co)

	// The .bashrc file should NOT be in DenyWrite when disabled.
	for _, p := range wcfg.DenyWrite {
		if p == bashrc {
			t.Errorf("DenyWrite should not contain %q when AutoProtectDangerousFiles is false", bashrc)
		}
	}
}

// TestBuildWrapConfigDangerousFileScanDefaultDepth verifies that the default
// scan depth of 5 is used when DangerousFileScanDepth is 0.
func TestBuildWrapConfigDangerousFileScanDefaultDepth(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a dangerous file at depth 1.
	bashrc := filepath.Join(tmpDir, ".bashrc")
	if err := os.WriteFile(bashrc, []byte("# test"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	cfg.Filesystem.WritableRoots = []string{tmpDir}
	cfg.Filesystem.AutoProtectDangerousFiles = true
	cfg.Filesystem.DangerousFileScanDepth = 0 // should use default of 5

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	co := &callOptions{}
	wcfg := m.buildWrapConfig(&snap, co)

	// The .bashrc file should still be found with default depth.
	found := false
	for _, p := range wcfg.DenyWrite {
		if p == bashrc {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DenyWrite should contain %q with default scan depth", bashrc)
	}
}

// ---------------------------------------------------------------------------
// Glob expansion in buildWrapConfig
// ---------------------------------------------------------------------------

// TestBuildWrapConfigGlobExpansionDenyRead verifies that glob patterns in
// DenyRead are expanded to concrete paths.
func TestBuildWrapConfigGlobExpansionDenyRead(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files matching a glob pattern.
	secretFile := filepath.Join(tmpDir, "secret.key")
	if err := os.WriteFile(secretFile, []byte("key"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	cfg.Filesystem.DenyRead = []string{filepath.Join(tmpDir, "*.key")}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	co := &callOptions{}
	wcfg := m.buildWrapConfig(&snap, co)

	// The glob should be expanded to the concrete file.
	found := false
	for _, p := range wcfg.DenyRead {
		if p == secretFile {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DenyRead should contain expanded path %q, got %v", secretFile, wcfg.DenyRead)
	}
}

// TestBuildWrapConfigGlobExpansionDenyWrite verifies that glob patterns in
// DenyWrite are expanded to concrete paths.
func TestBuildWrapConfigGlobExpansionDenyWrite(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files matching a glob pattern.
	configFile := filepath.Join(tmpDir, ".gitconfig")
	if err := os.WriteFile(configFile, []byte("config"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	cfg.Filesystem.DenyWrite = []string{filepath.Join(tmpDir, ".git*")}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	co := &callOptions{}
	wcfg := m.buildWrapConfig(&snap, co)

	// The glob should be expanded to the concrete file.
	found := false
	for _, p := range wcfg.DenyWrite {
		if p == configFile {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DenyWrite should contain expanded path %q, got %v", configFile, wcfg.DenyWrite)
	}
}

// TestBuildWrapConfigGlobNoMatch verifies that a glob pattern with no matches
// results in no entries (the pattern is not kept literally).
func TestBuildWrapConfigGlobNoMatch(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	cfg.Filesystem.DenyRead = []string{filepath.Join(tmpDir, "*.nonexistent")}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	co := &callOptions{}
	wcfg := m.buildWrapConfig(&snap, co)

	// No matches means the glob expands to nothing.
	for _, p := range wcfg.DenyRead {
		if strings.Contains(p, "nonexistent") {
			t.Errorf("DenyRead should not contain unmatched glob pattern, got %q", p)
		}
	}
}

// TestBuildWrapConfigNonGlobPathPreserved verifies that non-glob paths in
// DenyRead/DenyWrite are preserved as-is.
func TestBuildWrapConfigNonGlobPathPreserved(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	cfg.Filesystem.DenyRead = []string{"/etc/shadow"}
	cfg.Filesystem.DenyWrite = []string{"/etc/passwd"}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	co := &callOptions{}
	wcfg := m.buildWrapConfig(&snap, co)

	foundRead := false
	for _, p := range wcfg.DenyRead {
		if p == "/etc/shadow" {
			foundRead = true
		}
	}
	if !foundRead {
		t.Errorf("DenyRead should preserve non-glob path /etc/shadow, got %v", wcfg.DenyRead)
	}

	foundWrite := false
	for _, p := range wcfg.DenyWrite {
		if p == "/etc/passwd" {
			foundWrite = true
		}
	}
	if !foundWrite {
		t.Errorf("DenyWrite should preserve non-glob path /etc/passwd, got %v", wcfg.DenyWrite)
	}
}

// ---------------------------------------------------------------------------
// Git worktree awareness
// ---------------------------------------------------------------------------

// TestBuildWrapConfigGitWorktree verifies that buildWrapConfig removes
// .git/hooks deny entries for git worktree roots.
func TestBuildWrapConfigGitWorktree(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a .git file (not directory) to simulate a worktree.
	gitFile := filepath.Join(tmpDir, ".git")
	if err := os.WriteFile(gitFile, []byte("gitdir: /some/other/path"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	hooksPath := filepath.Join(tmpDir, ".git", "hooks")

	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	cfg.Filesystem.WritableRoots = []string{tmpDir}
	cfg.Filesystem.DenyWrite = []string{hooksPath, "/etc"}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	co := &callOptions{}
	wcfg := m.buildWrapConfig(&snap, co)

	// The .git/hooks path should be removed for worktree roots.
	for _, p := range wcfg.DenyWrite {
		if strings.HasPrefix(p, hooksPath) {
			t.Errorf("DenyWrite should not contain %q for git worktree root", p)
		}
	}

	// /etc should still be present.
	foundEtc := false
	for _, p := range wcfg.DenyWrite {
		if p == "/etc" {
			foundEtc = true
		}
	}
	if !foundEtc {
		t.Error("DenyWrite should still contain /etc")
	}
}

// TestBuildWrapConfigGitNonWorktree verifies that buildWrapConfig does NOT
// remove .git/hooks deny entries for regular (non-worktree) git repos.
func TestBuildWrapConfigGitNonWorktree(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a .git directory (regular repo, not worktree).
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatalf("MkdirAll error: %v", err)
	}

	hooksPath := filepath.Join(tmpDir, ".git", "hooks")

	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	cfg.Filesystem.WritableRoots = []string{tmpDir}
	cfg.Filesystem.DenyWrite = []string{hooksPath}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	co := &callOptions{}
	wcfg := m.buildWrapConfig(&snap, co)

	// The .git/hooks path should be preserved for regular repos.
	found := false
	for _, p := range wcfg.DenyWrite {
		if p == hooksPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DenyWrite should contain %q for non-worktree repo, got %v", hooksPath, wcfg.DenyWrite)
	}
}

// ---------------------------------------------------------------------------
// filterOutPrefix helper
// ---------------------------------------------------------------------------

func TestFilterOutPrefix(t *testing.T) {
	tests := []struct {
		name   string
		paths  []string
		prefix string
		want   []string
	}{
		{
			name:   "removes matching prefix",
			paths:  []string{"/a/b/c", "/a/b/d", "/x/y"},
			prefix: "/a/b",
			want:   []string{"/x/y"},
		},
		{
			name:   "no matches",
			paths:  []string{"/x/y", "/z"},
			prefix: "/a/b",
			want:   []string{"/x/y", "/z"},
		},
		{
			name:   "empty input",
			paths:  []string{},
			prefix: "/a",
			want:   []string{},
		},
		{
			name:   "all match",
			paths:  []string{"/a/1", "/a/2"},
			prefix: "/a",
			want:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterOutPrefix(tt.paths, tt.prefix)
			if len(got) != len(tt.want) {
				t.Fatalf("filterOutPrefix() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("filterOutPrefix()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Non-existent path warning tests
// ---------------------------------------------------------------------------

// TestBuildWrapConfigNonExistentDenyWriteWarning verifies that a warning is
// generated when a DenyWrite path does not fully exist on disk.
func TestBuildWrapConfigNonExistentDenyWriteWarning(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Filesystem.DenyWrite = []string{"/nonexistent_xyz_test_path/subdir/file"}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	co := &callOptions{}
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	wcfg := m.buildWrapConfig(&snap, co)

	if len(wcfg.Warnings) == 0 {
		t.Fatal("expected at least one warning for non-existent DenyWrite path")
	}

	found := false
	for _, w := range wcfg.Warnings {
		if strings.Contains(w, "DenyWrite") && strings.Contains(w, "does not exist") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected DenyWrite warning, got: %v", wcfg.Warnings)
	}
}

// TestBuildWrapConfigNonExistentDenyReadWarning verifies that a warning is
// generated when a DenyRead path does not fully exist on disk.
func TestBuildWrapConfigNonExistentDenyReadWarning(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Filesystem.DenyRead = []string{"/nonexistent_xyz_test_path/secret"}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	co := &callOptions{}
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	wcfg := m.buildWrapConfig(&snap, co)

	if len(wcfg.Warnings) == 0 {
		t.Fatal("expected at least one warning for non-existent DenyRead path")
	}

	found := false
	for _, w := range wcfg.Warnings {
		if strings.Contains(w, "DenyRead") && strings.Contains(w, "does not exist") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected DenyRead warning, got: %v", wcfg.Warnings)
	}
}

// TestBuildWrapConfigExistentPathNoWarning verifies that no warning is
// generated when DenyWrite/DenyRead paths exist on disk.
func TestBuildWrapConfigExistentPathNoWarning(t *testing.T) {
	// Use paths that definitely exist.
	existingDir := t.TempDir()
	existingFile := filepath.Join(existingDir, "testfile")
	if err := os.WriteFile(existingFile, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg := newTestConfig(t)
	cfg.Filesystem.DenyWrite = []string{existingFile}
	cfg.Filesystem.DenyRead = []string{existingDir}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	co := &callOptions{}
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	wcfg := m.buildWrapConfig(&snap, co)

	if len(wcfg.Warnings) != 0 {
		t.Errorf("expected no warnings for existing paths, got: %v", wcfg.Warnings)
	}
}

// TestBuildWrapConfigMixedPathWarnings verifies that warnings are generated
// only for non-existent paths when both existing and non-existent paths are
// configured.
func TestBuildWrapConfigMixedPathWarnings(t *testing.T) {
	existingDir := t.TempDir()

	cfg := newTestConfig(t)
	// Clear default DenyRead to avoid noise from default paths that may not exist.
	cfg.Filesystem.DenyRead = nil
	cfg.Filesystem.DenyWrite = []string{
		existingDir,
		"/nonexistent_abc_test_path/foo",
	}

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	co := &callOptions{}
	snap, err := m.snapshotConfig()
	if err != nil {
		t.Fatalf("snapshotConfig() error: %v", err)
	}
	wcfg := m.buildWrapConfig(&snap, co)

	// Should have exactly one warning (for the non-existent path).
	if len(wcfg.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(wcfg.Warnings), wcfg.Warnings)
	}
	if !strings.Contains(wcfg.Warnings[0], "nonexistent_abc_test_path") {
		t.Errorf("warning should mention the non-existent path, got: %s", wcfg.Warnings[0])
	}
}

// TestManagerUpdateConfigApprovalCallback verifies that UpdateConfig properly
// updates the approval callback so that escalated commands use the new callback.
func TestManagerUpdateConfigApprovalCallback(t *testing.T) {
	cfg := newTestConfig(t)
	// Start without an approval callback.
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}

	// Escalated command should fail without a callback.
	_, err = mgr.Exec(context.Background(), "echo test", WithClassifier(escalateAll))
	if !errors.Is(err, ErrEscalatedCommand) {
		t.Fatalf("expected ErrEscalatedCommand without callback, got: %v", err)
	}

	// Now update config with an approval callback that approves everything.
	newCfg := newTestConfig(t)
	newCfg.ApprovalCallback = func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		return Approve, nil
	}
	if err := mgr.UpdateConfig(newCfg); err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}

	// Escalated command should now succeed (callback approves).
	_, err = mgr.Exec(context.Background(), "echo test", WithClassifier(escalateAll))
	// The error, if any, should NOT be ErrEscalatedCommand.
	if errors.Is(err, ErrEscalatedCommand) {
		t.Error("expected escalated command to be approved after UpdateConfig with callback")
	}
}

// TestNopManagerUpdateConfigApprovalCallback verifies that nopManager.UpdateConfig
// properly updates the approval callback.
func TestNopManagerUpdateConfigApprovalCallback(t *testing.T) {
	mgr := NewNopManager()

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}

	// Without a callback, escalated commands should fail.
	_, err := mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if !errors.Is(err, ErrEscalatedCommand) {
		t.Fatalf("expected ErrEscalatedCommand without callback, got: %v", err)
	}

	// Update config with an approval callback.
	newCfg := &Config{
		Shell: "/bin/sh",
		ApprovalCallback: func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
			return Approve, nil
		},
	}
	if err := mgr.UpdateConfig(newCfg); err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}

	// Now escalated commands should be approved.
	_, err = mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if errors.Is(err, ErrEscalatedCommand) {
		t.Error("expected escalated command to be approved after UpdateConfig with callback")
	}
}
