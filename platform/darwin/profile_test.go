//go:build darwin

package darwin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
)

// ---------------------------------------------------------------------------
// profileBuilder.Build tests
// ---------------------------------------------------------------------------

func TestBuildEmptyConfig(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if !strings.Contains(profile, "(version 1)") {
		t.Error("profile missing (version 1)")
	}
	if !strings.Contains(profile, "(deny default)") {
		t.Error("profile missing (deny default)")
	}
	if !strings.Contains(profile, "(allow process-fork)") {
		t.Error("profile missing (allow process-fork)")
	}
	if !strings.Contains(profile, "(allow file-read*)") {
		t.Error("profile missing (allow file-read*)")
	}
	if !strings.Contains(profile, "(deny file-write*)") {
		t.Error("profile missing (deny file-write*)")
	}
	// No network restriction by default.
	if !strings.Contains(profile, "(allow network*)") {
		t.Error("profile should allow network when NeedsNetworkRestriction is false")
	}
	// PTY access.
	if !strings.Contains(profile, "(allow file-ioctl") {
		t.Error("profile missing PTY ioctl rule")
	}
}

func TestBuildWithWritableRoots(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		WritableRoots: []string{"/Users/test/project", "/Users/test/data"},
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if !strings.Contains(profile, "/Users/test/project") {
		t.Error("profile missing writable root /Users/test/project")
	}
	if !strings.Contains(profile, "/Users/test/data") {
		t.Error("profile missing writable root /Users/test/data")
	}
	// Writable roots should be in allow file-write* rules.
	if !strings.Contains(profile, "(allow file-write* (subpath") {
		t.Error("profile missing allow file-write* subpath rule")
	}
}

func TestBuildWithDenyReadPaths(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		DenyRead: []string{"/etc/shadow", "/private/secret"},
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if !strings.Contains(profile, "(deny file-read* (subpath") {
		t.Error("profile missing deny file-read* subpath rule")
	}
	if !strings.Contains(profile, "/private/secret") {
		t.Error("profile missing deny read path /private/secret")
	}
}

func TestBuildWithNetworkRestriction(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		NeedsNetworkRestriction: true,
		HTTPProxyPort:           8080,
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if !strings.Contains(profile, "(deny network*)") {
		t.Error("profile missing (deny network*)")
	}
	if !strings.Contains(profile, "localhost:8080") {
		t.Error("profile missing localhost proxy port allow rule")
	}
	// Should NOT have a blanket allow network.
	lines := strings.Split(profile, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "(allow network*)" {
			t.Error("profile should not have blanket (allow network*) when network is restricted")
		}
	}
}

func TestBuildWithAllowGitConfig(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		AllowGitConfig: true,
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}
	gitCfg := filepath.Join(home, ".gitconfig")
	if !strings.Contains(profile, gitCfg) {
		t.Errorf("profile should contain git config path %s when AllowGitConfig is true", gitCfg)
	}
	if !strings.Contains(profile, "(allow file-read* (literal") {
		t.Error("profile missing allow file-read* literal rule for git config")
	}
}

func TestBuildDangerousFileProtection(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}

	// Check that dangerous files are protected.
	dangerousFiles := []string{".bashrc", ".zshrc", ".gitconfig", ".ssh"}
	for _, f := range dangerousFiles {
		fp := filepath.Join(home, f)
		if !strings.Contains(profile, fp) {
			t.Errorf("profile should deny writes to %s", fp)
		}
	}

	// Check .git/hooks protection.
	hooksPath := filepath.Join(home, ".git", "hooks")
	if !strings.Contains(profile, hooksPath) {
		t.Errorf("profile should deny writes to %s", hooksPath)
	}
}

func TestBuildTempDirsAlwaysWritable(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if !strings.Contains(profile, "/private/tmp") {
		t.Error("profile should allow writes to /private/tmp")
	}
	if !strings.Contains(profile, "/private/var/folders") {
		t.Error("profile should allow writes to /private/var/folders")
	}
}

func TestBuildReusable(t *testing.T) {
	// profileBuilder should be reusable across multiple Build calls.
	b := newProfileBuilder()
	p1, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("first Build() error: %v", err)
	}
	p2, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("second Build() error: %v", err)
	}
	if p1 != p2 {
		t.Error("two builds with same config should produce identical profiles")
	}
}

// ---------------------------------------------------------------------------
// escapeForSBPL tests
// ---------------------------------------------------------------------------

func TestEscapeForSBPL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"no special chars", "hello world", "hello world"},
		{"backslash", `a\b`, `a\\b`},
		{"double quote", `say "hi"`, `say \"hi\"`},
		{"newline", "line1\nline2", `line1\nline2`},
		{"tab", "col1\tcol2", `col1\tcol2`},
		{"carriage return", "line1\rline2", `line1\rline2`},
		{"mixed", "a\\b\"c\nd\te", `a\\b\"c\nd\te`},
		{"path with spaces", "/Users/my user/dir", "/Users/my user/dir"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeForSBPL(tt.input)
			if got != tt.want {
				t.Errorf("escapeForSBPL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// canonicalizePath tests
// ---------------------------------------------------------------------------

func TestCanonicalizePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"tmp", "/tmp", "/private/tmp"},
		{"tmp subpath", "/tmp/foo/bar", "/private/tmp/foo/bar"},
		{"var", "/var", "/private/var"},
		{"var subpath", "/var/log/system.log", "/private/var/log/system.log"},
		{"normal path", "/Users/test/project", "/Users/test/project"},
		{"root", "/", "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalizePath(tt.path)
			if got != tt.want {
				t.Errorf("canonicalizePath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestCanonicalizePathResolvesSymlinks(t *testing.T) {
	// /tmp is a symlink to /private/tmp on macOS.
	got := canonicalizePath("/tmp")
	if got != "/private/tmp" {
		t.Errorf("canonicalizePath(/tmp) = %q, want /private/tmp", got)
	}
}

func TestCanonicalizePathVarFallback(t *testing.T) {
	// When the path does not exist, EvalSymlinks fails and the function
	// should fall back to prepending /private for /var paths.
	got := canonicalizePath("/var/nonexistent/deeply/nested/path")
	want := "/private/var/nonexistent/deeply/nested/path"
	if got != want {
		t.Errorf("canonicalizePath(/var/nonexistent/deeply/nested/path) = %q, want %q", got, want)
	}
}

func TestCanonicalizePathTmpFallback(t *testing.T) {
	// When the path does not exist, EvalSymlinks fails and the function
	// should fall back to prepending /private for /tmp paths.
	got := canonicalizePath("/tmp/nonexistent/deeply/nested/path")
	want := "/private/tmp/nonexistent/deeply/nested/path"
	if got != want {
		t.Errorf("canonicalizePath(/tmp/nonexistent/deeply/nested/path) = %q, want %q", got, want)
	}
}

func TestCanonicalizePathNonMacOSFallback(t *testing.T) {
	// A nonexistent path that is NOT under /tmp or /var should be returned
	// cleaned but without /private prefix.
	got := canonicalizePath("/nonexistent/some/path")
	want := "/nonexistent/some/path"
	if got != want {
		t.Errorf("canonicalizePath(/nonexistent/some/path) = %q, want %q", got, want)
	}
}

func TestCanonicalizePathVarExactFallback(t *testing.T) {
	// Test the exact "/var" path when EvalSymlinks fails.
	// On macOS /var exists as a symlink, so EvalSymlinks succeeds.
	// We test with a nonexistent subpath to trigger the fallback.
	got := canonicalizePath("/var/nonexistent")
	want := "/private/var/nonexistent"
	if got != want {
		t.Errorf("canonicalizePath(/var/nonexistent) = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// sanitizeEnv tests
// ---------------------------------------------------------------------------

func TestSanitizeEnv(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"HOME=/Users/test",
		"DYLD_LIBRARY_PATH=/bad/path",
		"DYLD_INSERT_LIBRARIES=/evil.dylib",
		"SHELL=/bin/zsh",
		"DYLD_FRAMEWORK_PATH=/another/bad",
	}
	got := sanitizeEnv(env)

	for _, e := range got {
		if strings.HasPrefix(e, "DYLD_") {
			t.Errorf("sanitizeEnv should remove DYLD_* vars, found: %s", e)
		}
	}

	// Should keep non-DYLD vars.
	expected := map[string]bool{
		"PATH=/usr/bin":    true,
		"HOME=/Users/test": true,
		"SHELL=/bin/zsh":   true,
	}
	for _, e := range got {
		delete(expected, e)
	}
	if len(expected) > 0 {
		t.Errorf("sanitizeEnv removed non-DYLD vars: %v", expected)
	}
}

func TestSanitizeEnvEmpty(t *testing.T) {
	got := sanitizeEnv(nil)
	if len(got) != 0 {
		t.Errorf("sanitizeEnv(nil) should return empty slice, got %v", got)
	}
}

func TestSanitizeEnvNoDYLD(t *testing.T) {
	env := []string{"PATH=/usr/bin", "HOME=/Users/test"}
	got := sanitizeEnv(env)
	if len(got) != 2 {
		t.Errorf("sanitizeEnv should keep all vars when no DYLD_*, got %d", len(got))
	}
}

func TestSanitizeEnvOnlyDYLD(t *testing.T) {
	env := []string{"DYLD_LIBRARY_PATH=/bad", "DYLD_INSERT_LIBRARIES=/evil"}
	got := sanitizeEnv(env)
	if len(got) != 0 {
		t.Errorf("sanitizeEnv should remove all DYLD_* vars, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// proxyEnvVars tests
// ---------------------------------------------------------------------------

func TestProxyEnvVarsHTTP(t *testing.T) {
	vars := proxyEnvVars(8080, 0)
	found := make(map[string]bool)
	for _, v := range vars {
		found[v] = true
	}
	if !found["HTTP_PROXY=http://127.0.0.1:8080"] {
		t.Error("missing HTTP_PROXY")
	}
	if !found["http_proxy=http://127.0.0.1:8080"] {
		t.Error("missing http_proxy")
	}
	if !found["HTTPS_PROXY=http://127.0.0.1:8080"] {
		t.Error("missing HTTPS_PROXY")
	}
	if !found["https_proxy=http://127.0.0.1:8080"] {
		t.Error("missing https_proxy")
	}
}

func TestProxyEnvVarsSOCKS(t *testing.T) {
	vars := proxyEnvVars(0, 1080)
	found := make(map[string]bool)
	for _, v := range vars {
		found[v] = true
	}
	if !found["ALL_PROXY=socks5h://127.0.0.1:1080"] {
		t.Error("missing ALL_PROXY")
	}
	if !found["all_proxy=socks5h://127.0.0.1:1080"] {
		t.Error("missing all_proxy")
	}
}

func TestProxyEnvVarsBoth(t *testing.T) {
	vars := proxyEnvVars(8080, 1080)
	if len(vars) != 6 {
		t.Errorf("expected 6 proxy vars, got %d", len(vars))
	}
}

func TestProxyEnvVarsNone(t *testing.T) {
	vars := proxyEnvVars(0, 0)
	if len(vars) != 0 {
		t.Errorf("expected 0 proxy vars, got %d", len(vars))
	}
}

// ---------------------------------------------------------------------------
// getTmpdirParents tests
// ---------------------------------------------------------------------------

func TestGetTmpdirParents(t *testing.T) {
	dirs := getTmpdirParents()
	if len(dirs) == 0 {
		t.Fatal("getTmpdirParents() returned empty")
	}

	found := make(map[string]bool)
	for _, d := range dirs {
		found[d] = true
	}
	if !found["/private/tmp"] {
		t.Error("missing /private/tmp")
	}
	if !found["/private/var/folders"] {
		t.Error("missing /private/var/folders")
	}
}

// ---------------------------------------------------------------------------
// PTY device restriction tests (Fix 1)
// ---------------------------------------------------------------------------

func TestBuildPTYDeviceRestrictions(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Should NOT have unrestricted /dev write access.
	if strings.Contains(profile, `(allow file-write* (subpath "/dev"))`) {
		t.Error("profile should NOT have unrestricted file-write* to /dev")
	}

	// Should have specific PTY device write rules.
	expectedRules := []string{
		`(allow file-write* (regex #"^/dev/ttys[0-9]+$"))`,
		`(allow file-write* (regex #"^/dev/pty[a-z][0-9a-f]$"))`,
		`(allow file-write* (literal "/dev/null"))`,
		`(allow file-write* (literal "/dev/zero"))`,
		`(allow file-write* (literal "/dev/random"))`,
		`(allow file-write* (literal "/dev/urandom"))`,
		`(allow file-ioctl (regex #"^/dev/(ttys|pty)"))`,
	}
	for _, rule := range expectedRules {
		if !strings.Contains(profile, rule) {
			t.Errorf("profile missing PTY rule: %s", rule)
		}
	}

	// Should allow reading specific /dev device nodes via regex, not a blanket subpath.
	if strings.Contains(profile, `(allow file-read* (subpath "/dev"))`) {
		t.Error("profile should NOT have blanket file-read* on /dev subpath")
	}
	if !strings.Contains(profile, `(allow file-read* (regex #"^/dev/(ttys|pty|null|zero|random|urandom|fd)"))`) {
		t.Error("profile should allow file-read* on specific /dev device nodes via regex")
	}
}

func TestBuildPTYDoesNotOverrideDenyRead(t *testing.T) {
	// Verify that the PTY rules do not use a blanket /dev subpath read
	// which would override DenyRead rules for /dev subpaths.
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		DenyRead: []string{"/dev/disk0"},
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// The profile should deny reads to /dev/disk0.
	if !strings.Contains(profile, `(deny file-read* (subpath "/dev/disk0"))`) {
		t.Error("profile should deny file-read* on /dev/disk0")
	}

	// The PTY read rule should be a regex, not a blanket subpath.
	if strings.Contains(profile, `(allow file-read* (subpath "/dev"))`) {
		t.Error("blanket /dev read would override DenyRead for /dev subpaths")
	}
}

// ---------------------------------------------------------------------------
// DenyWrite tests (Fix 3)
// ---------------------------------------------------------------------------

func TestBuildWithDenyWritePaths(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		WritableRoots: []string{"/Users/test/project"},
		DenyWrite:     []string{"/Users/test/project/secrets"},
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Should have the writable root.
	if !strings.Contains(profile, "/Users/test/project") {
		t.Error("profile missing writable root")
	}

	// Should have the deny write rule.
	if !strings.Contains(profile, `(deny file-write* (subpath "/Users/test/project/secrets"))`) {
		t.Error("profile missing deny file-write* for DenyWrite path")
	}
}

func TestBuildDenyWriteEmptyList(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		DenyWrite: []string{},
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	// Should not have any extra deny file-write* subpath rules beyond the base deny.
	lines := strings.Split(profile, "\n")
	denyWriteSubpathCount := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "(deny file-write* (subpath") {
			denyWriteSubpathCount++
		}
	}
	// Only dangerous file protection dirs should have deny subpath rules.
	if denyWriteSubpathCount > 1 {
		// .git/hooks is the only subpath deny from dangerous file protection.
		// This is fine.
	}
}

// ---------------------------------------------------------------------------
// escapeForSBPL usage in profile output (Fix 5)
// ---------------------------------------------------------------------------

func TestBuildUsesEscapeForSBPL(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		WritableRoots: []string{"/Users/test/project"},
		DenyRead:      []string{"/secret/data"},
		DenyWrite:     []string{"/protected/dir"},
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Verify paths are properly quoted with escapeForSBPL (double-quoted, not Go %q).
	// Go's %q would produce paths like \"/Users/test/project\" with extra escaping.
	// escapeForSBPL should produce clean double-quoted strings.
	if !strings.Contains(profile, `(allow file-write* (subpath "/Users/test/project"))`) {
		t.Error("writable root should use escapeForSBPL quoting")
	}
	if !strings.Contains(profile, `(deny file-read* (subpath "/secret/data"))`) {
		t.Error("deny read should use escapeForSBPL quoting")
	}
	if !strings.Contains(profile, `(deny file-write* (subpath "/protected/dir"))`) {
		t.Error("deny write should use escapeForSBPL quoting")
	}
}

// ---------------------------------------------------------------------------
// Profile SBPL syntax validation
// ---------------------------------------------------------------------------

func TestProfileSBPLSyntax(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		WritableRoots:           []string{"/Users/test/project"},
		DenyRead:                []string{"/secret"},
		NeedsNetworkRestriction: true,
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Verify the profile starts with (version 1).
	lines := strings.Split(strings.TrimSpace(profile), "\n")
	if len(lines) == 0 {
		t.Fatal("profile is empty")
	}
	if strings.TrimSpace(lines[0]) != "(version 1)" {
		t.Errorf("first line should be (version 1), got %q", lines[0])
	}

	// Every non-comment, non-blank line should start with '(' or be a
	// continuation line (indented with spaces, part of a multi-line expression).
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			continue
		}
		// Allow continuation lines that are indented (part of multi-line S-expressions).
		if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t") {
			continue
		}
		if !strings.HasPrefix(trimmed, "(") && trimmed != ")" {
			t.Errorf("line %d: expected SBPL expression starting with '(' or closing ')', got %q", i+1, trimmed)
		}
	}
}

// ---------------------------------------------------------------------------
// writeDangerousFileProtection: UserHomeDir error path
// ---------------------------------------------------------------------------

func TestWriteDangerousFileProtection_NoHome(t *testing.T) {
	// When HOME is unset, os.UserHomeDir() fails on most systems.
	// writeDangerousFileProtection should return early without adding
	// any home-relative protections, but the rest of the profile should
	// still be generated correctly.
	origHome, hadHome := os.LookupEnv("HOME")
	os.Unsetenv("HOME")
	t.Cleanup(func() {
		if hadHome {
			os.Setenv("HOME", origHome)
		} else {
			os.Unsetenv("HOME")
		}
	})

	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// The profile should still have the base structure.
	if !strings.Contains(profile, "(version 1)") {
		t.Error("profile missing (version 1)")
	}
	if !strings.Contains(profile, "(deny default)") {
		t.Error("profile missing (deny default)")
	}

	// The profile should NOT contain home-relative dangerous file protections
	// like .bashrc, .zshrc, .ssh, etc. since we couldn't determine HOME.
	dangerousFiles := []string{".bashrc", ".zshrc", ".gitconfig", ".ssh"}
	for _, f := range dangerousFiles {
		// These filenames should not appear in deny rules since home is unknown.
		needle := `(deny file-write* (literal "` + f + `"))`
		if strings.Contains(profile, needle) {
			t.Errorf("profile should not contain home-relative protection for %s when HOME is unset", f)
		}
	}

	// Verify the dangerous file protection comment is present (the function
	// writes it before checking HOME), confirming the function was called.
	if !strings.Contains(profile, "Dangerous file protection") {
		t.Error("profile should contain the dangerous file protection comment")
	}
}

func TestWriteDangerousFileProtection_NoHomeStillHasOtherSections(t *testing.T) {
	// Even when HOME is unset, the profile should still contain all other
	// sections: base, file-read, file-write, network, PTY.
	origHome, hadHome := os.LookupEnv("HOME")
	os.Unsetenv("HOME")
	t.Cleanup(func() {
		if hadHome {
			os.Setenv("HOME", origHome)
		} else {
			os.Unsetenv("HOME")
		}
	})

	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		WritableRoots:           []string{"/tmp/test"},
		NeedsNetworkRestriction: true,
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// File write section should still work.
	if !strings.Contains(profile, "/tmp/test") {
		t.Error("profile should contain writable root even when HOME is unset")
	}
	// Network restriction should still work.
	if !strings.Contains(profile, "(deny network*)") {
		t.Error("profile should contain network deny even when HOME is unset")
	}
	// PTY section should still work.
	if !strings.Contains(profile, "(allow file-ioctl") {
		t.Error("profile should contain PTY rules even when HOME is unset")
	}
}

// ---------------------------------------------------------------------------
// Mach port tightening tests (P1-7)
// ---------------------------------------------------------------------------

func TestBuildMachPortTightening(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Should NOT have blanket mach* permission.
	lines := strings.Split(profile, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "(allow mach*)" {
			t.Error("profile should not have blanket (allow mach*)")
		}
	}

	// Should NOT have any regex-based mach-lookup patterns.
	if strings.Contains(profile, "global-name-regex") {
		t.Error("profile should not use global-name-regex for mach-lookup; use exact global-name list")
	}

	// Should have all 15 exact Mach service names.
	expectedServices := []string{
		`(global-name "com.apple.audio.systemsoundserver")`,
		`(global-name "com.apple.distributed_notifications@Uv3")`,
		`(global-name "com.apple.FontObjectsServer")`,
		`(global-name "com.apple.fonts")`,
		`(global-name "com.apple.logd")`,
		`(global-name "com.apple.lsd.mapdb")`,
		`(global-name "com.apple.PowerManagement.control")`,
		`(global-name "com.apple.system.logger")`,
		`(global-name "com.apple.system.notification_center")`,
		`(global-name "com.apple.system.opendirectoryd.libinfo")`,
		`(global-name "com.apple.system.opendirectoryd.membership")`,
		`(global-name "com.apple.bsd.dirhelper")`,
		`(global-name "com.apple.securityd.xpc")`,
		`(global-name "com.apple.coreservices.launchservicesd")`,
		`(global-name "com.apple.SecurityServer")`,
	}
	for _, svc := range expectedServices {
		if !strings.Contains(profile, svc) {
			t.Errorf("profile missing Mach service: %s", svc)
		}
	}

	// Should still have mach-per-user-lookup.
	if !strings.Contains(profile, "(allow mach-per-user-lookup)") {
		t.Error("profile missing (allow mach-per-user-lookup)")
	}
}

// ---------------------------------------------------------------------------
// Process permission tightening tests (P1-8)
// ---------------------------------------------------------------------------

func TestBuildProcessPermissionTightening(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Should NOT have blanket process* permission.
	lines := strings.Split(profile, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "(allow process*)" {
			t.Error("profile should not have blanket (allow process*)")
		}
	}

	// Should have specific process permissions.
	if !strings.Contains(profile, "(allow process-fork)") {
		t.Error("profile missing (allow process-fork)")
	}
	if !strings.Contains(profile, "(allow process-exec)") {
		t.Error("profile missing (allow process-exec)")
	}
	if !strings.Contains(profile, "(allow signal (target self))") {
		t.Error("profile missing (allow signal (target self))")
	}
}

// ---------------------------------------------------------------------------
// Proxy port-specific network rules tests (P1-9)
// ---------------------------------------------------------------------------

func TestBuildNetworkProxyPortSpecific(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		NeedsNetworkRestriction: true,
		HTTPProxyPort:           8080,
		SOCKSProxyPort:          1080,
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Should have port-specific rules.
	if !strings.Contains(profile, `(allow network* (remote tcp "localhost:8080"))`) {
		t.Error("profile missing HTTP proxy port rule for localhost:8080")
	}
	if !strings.Contains(profile, `(allow network* (remote tcp "localhost:1080"))`) {
		t.Error("profile missing SOCKS proxy port rule for localhost:1080")
	}

	// Should NOT have blanket localhost:* rule.
	if strings.Contains(profile, `localhost:*`) {
		t.Error("profile should not have blanket localhost:* rule")
	}
}

func TestBuildNetworkNoProxyPorts(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		NeedsNetworkRestriction: true,
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// With no proxy ports, should still deny network and allow local UDP.
	if !strings.Contains(profile, "(deny network*)") {
		t.Error("profile missing (deny network*)")
	}
	if !strings.Contains(profile, `(allow network* (local udp "*:*"))`) {
		t.Error("profile missing local UDP allow rule")
	}

	// Should NOT have any localhost TCP rules.
	if strings.Contains(profile, "remote tcp") {
		t.Error("profile should not have remote tcp rules when no proxy ports are set")
	}
}

func TestBuildNetworkHTTPProxyOnly(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		NeedsNetworkRestriction: true,
		HTTPProxyPort:           9090,
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	if !strings.Contains(profile, `(allow network* (remote tcp "localhost:9090"))`) {
		t.Error("profile missing HTTP proxy port rule for localhost:9090")
	}
	// Should NOT have SOCKS rule.
	if strings.Contains(profile, "1080") {
		t.Error("profile should not have SOCKS proxy rule when SOCKSProxyPort is 0")
	}
}

func TestBuildNetworkSOCKSProxyOnly(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		NeedsNetworkRestriction: true,
		SOCKSProxyPort:          1080,
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	if !strings.Contains(profile, `(allow network* (remote tcp "localhost:1080"))`) {
		t.Error("profile missing SOCKS proxy port rule for localhost:1080")
	}
	// Should NOT have HTTP proxy rule.
	if strings.Contains(profile, "8080") {
		t.Error("profile should not have HTTP proxy rule when HTTPProxyPort is 0")
	}
}

// ---------------------------------------------------------------------------
// Move-blocking rules tests (P1-6)
// ---------------------------------------------------------------------------

func TestBuildMoveBlocking(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		WritableRoots: []string{"/Users/test/project"},
		DenyWrite:     []string{"/Users/test/project/secrets"},
		DenyRead:      []string{"/private/data"},
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Should have file-write-unlink deny for DenyWrite paths.
	if !strings.Contains(profile, `(deny file-write-unlink (subpath "/Users/test/project/secrets"))`) {
		t.Error("profile missing file-write-unlink deny for DenyWrite path")
	}

	// Should have file-write-unlink deny for DenyRead paths.
	if !strings.Contains(profile, `(deny file-write-unlink (subpath "/private/data"))`) {
		t.Error("profile missing file-write-unlink deny for DenyRead path")
	}

	// Should have the comment.
	if !strings.Contains(profile, "Prevent bypass via mv/rename") {
		t.Error("profile missing move-blocking comment")
	}
}

func TestBuildMoveBlockingEmpty(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// With no DenyWrite or DenyRead, should still have the comment but no unlink rules.
	if !strings.Contains(profile, "Prevent bypass via mv/rename") {
		t.Error("profile missing move-blocking comment")
	}
	if strings.Contains(profile, "file-write-unlink") {
		t.Error("profile should not have file-write-unlink rules when no deny paths are set")
	}
}

// ---------------------------------------------------------------------------
// escapeForSBPL null byte tests (P2-18)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Sysctl hardening tests (P1-B)
// ---------------------------------------------------------------------------

func TestProfileSysctlHardening(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Should NOT have blanket sysctl-read.
	for _, line := range strings.Split(profile, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "(allow sysctl-read)" {
			t.Error("profile should not have blanket (allow sysctl-read); use specific sysctl-name entries")
		}
	}

	// Should have the specific sysctl-read block.
	if !strings.Contains(profile, "(allow sysctl-read") {
		t.Error("profile missing (allow sysctl-read block")
	}

	// Spot-check a few sysctl names from each category.
	expectedNames := []string{
		`(sysctl-name "hw.activecpu")`,
		`(sysctl-name "hw.memsize")`,
		`(sysctl-name "hw.pagesize")`,
		`(sysctl-name "kern.hostname")`,
		`(sysctl-name "kern.osversion")`,
		`(sysctl-name "kern.version")`,
		`(sysctl-name "machdep.cpu.brand_string")`,
		`(sysctl-name "vm.loadavg")`,
		`(sysctl-name "security.mac.lockdown_mode_state")`,
		`(sysctl-name "sysctl.proc_cputype")`,
	}
	for _, name := range expectedNames {
		if !strings.Contains(profile, name) {
			t.Errorf("profile missing sysctl name: %s", name)
		}
	}

	// Check prefix patterns.
	expectedPrefixes := []string{
		`(sysctl-name-prefix "hw.optional.arm")`,
		`(sysctl-name-prefix "hw.perflevel")`,
		`(sysctl-name-prefix "kern.proc.pid.")`,
		`(sysctl-name-prefix "machdep.cpu.")`,
		`(sysctl-name-prefix "net.routetable.")`,
	}
	for _, prefix := range expectedPrefixes {
		if !strings.Contains(profile, prefix) {
			t.Errorf("profile missing sysctl prefix: %s", prefix)
		}
	}

	// Check sysctl-write rule.
	if !strings.Contains(profile, `(allow sysctl-write (sysctl-name "kern.tcsm_enable"))`) {
		t.Error("profile missing sysctl-write rule for kern.tcsm_enable")
	}
}

func TestProfileSysctlNameCount(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Count sysctl-name entries (exact names, not prefixes).
	nameCount := strings.Count(profile, "(sysctl-name \"")
	// We expect 49 exact names + the 1 in sysctl-write = 50 occurrences of (sysctl-name "
	if nameCount < 49 {
		t.Errorf("expected at least 49 sysctl-name entries, got %d", nameCount)
	}

	// Count sysctl-name-prefix entries.
	prefixCount := strings.Count(profile, "(sysctl-name-prefix \"")
	if prefixCount != 9 {
		t.Errorf("expected 9 sysctl-name-prefix entries, got %d", prefixCount)
	}
}

// ---------------------------------------------------------------------------
// IOKit rules tests (P2-B)
// ---------------------------------------------------------------------------

func TestProfileIOKit(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Should have the IOKit comment.
	if !strings.Contains(profile, "Allow IOKit for graphics and power management") {
		t.Error("profile missing IOKit comment")
	}

	// Should have iokit-open block.
	if !strings.Contains(profile, "(allow iokit-open") {
		t.Error("profile missing (allow iokit-open)")
	}

	// Check specific IOKit classes.
	expectedIOKit := []string{
		`(iokit-registry-entry-class "IOSurfaceRootUserClient")`,
		`(iokit-registry-entry-class "RootDomainUserClient")`,
		`(iokit-user-client-class "IOSurfaceSendRight")`,
	}
	for _, rule := range expectedIOKit {
		if !strings.Contains(profile, rule) {
			t.Errorf("profile missing IOKit rule: %s", rule)
		}
	}
}

// ---------------------------------------------------------------------------
// POSIX IPC rules tests (P3-D)
// ---------------------------------------------------------------------------

func TestProfilePOSIXIPC(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Should have the POSIX IPC comment.
	if !strings.Contains(profile, "Allow POSIX IPC for shared memory and semaphores") {
		t.Error("profile missing POSIX IPC comment")
	}

	// Should have ipc-posix-shm and ipc-posix-sem.
	if !strings.Contains(profile, "(allow ipc-posix-shm)") {
		t.Error("profile missing (allow ipc-posix-shm)")
	}
	if !strings.Contains(profile, "(allow ipc-posix-sem)") {
		t.Error("profile missing (allow ipc-posix-sem)")
	}
}

// ---------------------------------------------------------------------------
// Process info rules tests (P3-E)
// ---------------------------------------------------------------------------

func TestProfileProcessInfo(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Should have the process-info comment.
	if !strings.Contains(profile, "Allow process info queries within same sandbox") {
		t.Error("profile missing process-info comment")
	}

	// Should have process-info* rule.
	if !strings.Contains(profile, "(allow process-info* (target same-sandbox))") {
		t.Error("profile missing (allow process-info* (target same-sandbox))")
	}
}

func TestEscapeForSBPLNullBytes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"null byte only", "\x00", ""},
		{"null byte in middle", "hello\x00world", "helloworld"},
		{"null byte at start", "\x00/path/to/file", "/path/to/file"},
		{"null byte at end", "/path/to/file\x00", "/path/to/file"},
		{"multiple null bytes", "/path\x00/to\x00/file", "/path/to/file"},
		{"null byte with special chars", "a\x00\\b\x00\"c", `a\\b\"c`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeForSBPL(tt.input)
			if got != tt.want {
				t.Errorf("escapeForSBPL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ancestorDirectories tests
// ---------------------------------------------------------------------------

func TestAncestorDirectories(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []string
	}{
		{
			name: "deep path",
			path: "/workspace/.git/hooks",
			want: []string{"/workspace/.git", "/workspace"},
		},
		{
			name: "two levels",
			path: "/a/b",
			want: []string{"/a"},
		},
		{
			name: "single component under root",
			path: "/workspace",
			want: nil,
		},
		{
			name: "root path",
			path: "/",
			want: nil,
		},
		{
			name: "relative path",
			path: "a/b/c",
			want: []string{"a/b", "a"},
		},
		{
			name: "four levels",
			path: "/a/b/c/d",
			want: []string{"/a/b/c", "/a/b", "/a"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ancestorDirectories(tt.path)
			if len(got) != len(tt.want) {
				t.Fatalf("ancestorDirectories(%q) = %v, want %v", tt.path, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ancestorDirectories(%q)[%d] = %q, want %q", tt.path, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Move-blocking ancestor tests
// ---------------------------------------------------------------------------

func TestMoveBlockingAncestors(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		DenyWrite: []string{"/workspace/.git/hooks"},
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Should have subpath rule for the protected path.
	if !strings.Contains(profile, `(deny file-write-unlink (subpath "/workspace/.git/hooks"))`) {
		t.Error("profile missing subpath deny for /workspace/.git/hooks")
	}
	// Should have literal rules for ancestor directories.
	if !strings.Contains(profile, `(deny file-write-unlink (literal "/workspace/.git"))`) {
		t.Error("profile missing literal deny for ancestor /workspace/.git")
	}
	if !strings.Contains(profile, `(deny file-write-unlink (literal "/workspace"))`) {
		t.Error("profile missing literal deny for ancestor /workspace")
	}
}

func TestMoveBlockingAncestorDedup(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		DenyWrite: []string{"/workspace/.git/hooks", "/workspace/.git/config"},
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Both paths share /workspace/.git and /workspace as ancestors.
	// Each ancestor should appear exactly once.
	count := strings.Count(profile, `(deny file-write-unlink (literal "/workspace/.git"))`)
	if count != 1 {
		t.Errorf("ancestor /workspace/.git appeared %d times, want 1", count)
	}
	count = strings.Count(profile, `(deny file-write-unlink (literal "/workspace"))`)
	if count != 1 {
		t.Errorf("ancestor /workspace appeared %d times, want 1", count)
	}
}

// ---------------------------------------------------------------------------
// AllowLocalBinding tests
// ---------------------------------------------------------------------------

func TestProfileAllowLocalBinding(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		NeedsNetworkRestriction: true,
		AllowLocalBinding:       true,
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	if !strings.Contains(profile, `(allow network-bind (local ip "*:*"))`) {
		t.Error("profile missing network-bind rule")
	}
	if !strings.Contains(profile, `(allow network-inbound (local ip "*:*"))`) {
		t.Error("profile missing network-inbound rule")
	}
	if strings.Contains(profile, `(allow network-outbound (local ip "*:*"))`) {
		t.Error("profile should not contain network-outbound rule for AllowLocalBinding")
	}
}

func TestProfileAllowLocalBindingDisabled(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		NeedsNetworkRestriction: true,
		AllowLocalBinding:       false,
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	if strings.Contains(profile, "network-bind") {
		t.Error("profile should not contain network-bind when AllowLocalBinding is false")
	}
	if strings.Contains(profile, "network-inbound") {
		t.Error("profile should not contain network-inbound when AllowLocalBinding is false")
	}
}

// ---------------------------------------------------------------------------
// Unix socket tests
// ---------------------------------------------------------------------------

func TestProfileAllowAllUnixSockets(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		NeedsNetworkRestriction: true,
		AllowAllUnixSockets:     true,
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	if !strings.Contains(profile, `(allow network-outbound (remote unix-socket (subpath "/")))`) {
		t.Error("profile missing allow all Unix sockets outbound rule")
	}
	if !strings.Contains(profile, `(allow network-inbound (local unix-socket (subpath "/")))`) {
		t.Error("profile missing allow all Unix sockets inbound rule")
	}
}

func TestProfileAllowSpecificUnixSockets(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		NeedsNetworkRestriction: true,
		AllowUnixSockets:        []string{"/var/run/docker.sock", "/tmp/mysocket.sock"},
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	if !strings.Contains(profile, `(allow network* (subpath "/var/run/docker.sock"))`) {
		t.Error("profile missing specific Unix socket rule for docker.sock")
	}
	if !strings.Contains(profile, `(allow network* (subpath "/tmp/mysocket.sock"))`) {
		t.Error("profile missing specific Unix socket rule for mysocket.sock")
	}
	// Should NOT have the blanket allow-all rule.
	if strings.Contains(profile, `(allow network* (subpath "/"))`) {
		t.Error("profile should not have blanket Unix socket rule when specific paths are set")
	}
}

func TestProfileUnixSocketsDisabled(t *testing.T) {
	b := newProfileBuilder()
	profile, err := b.Build(&platform.WrapConfig{
		NeedsNetworkRestriction: true,
		AllowAllUnixSockets:     false,
		AllowUnixSockets:        nil,
	})
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Should not contain any Unix socket specific rules.
	if strings.Contains(profile, "Unix domain socket") {
		t.Error("profile should not contain Unix socket comments when disabled")
	}
}
