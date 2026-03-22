package agentbox

import (
	"testing"
)

// --- protectedPathClassifier direct tests ---

func TestProtectedPathClassifier_DirectWrite(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// rm targeting git hooks → Forbidden
	r := c.Classify("rm .git/hooks/pre-commit")
	if r.Decision != Forbidden {
		t.Errorf("rm .git/hooks/pre-commit: got %v, want Forbidden", r.Decision)
	}

	// rm targeting agent config → Forbidden
	r = c.Classify("rm .agent/config.yaml")
	if r.Decision != Forbidden {
		t.Errorf("rm .agent/config.yaml: got %v, want Forbidden", r.Decision)
	}

	// rm targeting claude config → Forbidden
	r = c.Classify("rm .claude/settings.json")
	if r.Decision != Forbidden {
		t.Errorf("rm .claude/settings.json: got %v, want Forbidden", r.Decision)
	}
}

func TestProtectedPathClassifier_RedirectDetection(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// Redirect to git hooks → Forbidden
	r := c.Classify("echo malicious > .git/hooks/pre-commit")
	if r.Decision != Forbidden {
		t.Errorf("echo > .git/hooks/pre-commit: got %v, want Forbidden", r.Decision)
	}

	// Append redirect to .env → Escalated
	r = c.Classify("echo SECRET=val >> .env")
	if r.Decision != Escalated {
		t.Errorf("echo >> .env: got %v, want Escalated", r.Decision)
	}

	// Redirect to .env.production → Escalated
	r = c.Classify("echo x > .env.production")
	if r.Decision != Escalated {
		t.Errorf("echo > .env.production: got %v, want Escalated", r.Decision)
	}
}

func TestProtectedPathClassifier_MoveToProtected(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// mv to agent config → Forbidden
	r := c.Classify("mv script.sh .agent/config")
	if r.Decision != Forbidden {
		t.Errorf("mv to .agent/config: got %v, want Forbidden", r.Decision)
	}

	// mv to vscode settings → Escalated
	r = c.Classify("mv settings.json .vscode/settings.json")
	if r.Decision != Escalated {
		t.Errorf("mv to .vscode/settings.json: got %v, want Escalated", r.Decision)
	}
}

func TestProtectedPathClassifier_MoveFromProtected(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// mv FROM a protected path is destructive (removes the source).
	r := c.Classify("mv .git/hooks/pre-commit /tmp/backup")
	if r.Decision != Forbidden {
		t.Errorf("mv from .git/hooks/pre-commit: got %v, want Forbidden", r.Decision)
	}
}

func TestProtectedPathClassifier_EscalatedPaths(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// Write to .env → Escalated
	r := c.Classify("echo x > .env")
	if r.Decision != Escalated {
		t.Errorf("echo > .env: got %v, want Escalated", r.Decision)
	}

	// Write to .git/config → Escalated
	r = c.Classify("echo x > .git/config")
	if r.Decision != Escalated {
		t.Errorf("echo > .git/config: got %v, want Escalated", r.Decision)
	}

	// Write to .idea settings → Escalated
	r = c.Classify("rm .idea/workspace.xml")
	if r.Decision != Escalated {
		t.Errorf("rm .idea/workspace.xml: got %v, want Escalated", r.Decision)
	}
}

func TestProtectedPathClassifier_ReadIsOK(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// cat is not a write command → no match
	r := c.Classify("cat .git/hooks/pre-commit")
	if r.Decision != Sandboxed {
		t.Errorf("cat .git/hooks/pre-commit: got %v, want Sandboxed (nil)", r.Decision)
	}

	// ls is not a write command → no match
	r = c.Classify("ls .agent/")
	if r.Decision != Sandboxed {
		t.Errorf("ls .agent/: got %v, want Sandboxed (nil)", r.Decision)
	}

	// head is not a write command → no match
	r = c.Classify("head -1 .env")
	if r.Decision != Sandboxed {
		t.Errorf("head .env: got %v, want Sandboxed (nil)", r.Decision)
	}
}

func TestProtectedPathClassifier_NonProtectedPath(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// rm normal file → no match
	r := c.Classify("rm normal_file.txt")
	if r.Decision != Sandboxed {
		t.Errorf("rm normal_file.txt: got %v, want Sandboxed (nil)", r.Decision)
	}

	// Redirect to normal file → no match
	r = c.Classify("echo x > output.txt")
	if r.Decision != Sandboxed {
		t.Errorf("echo > output.txt: got %v, want Sandboxed (nil)", r.Decision)
	}
}

func TestProtectedPathClassifier_SedInPlace(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// sed -i on protected path → match
	r := c.Classify("sed -i 's/old/new/' .git/config")
	if r.Decision != Escalated {
		t.Errorf("sed -i .git/config: got %v, want Escalated", r.Decision)
	}

	// sed without -i → no match (read-only)
	r = c.Classify("sed 's/old/new/' .git/config")
	if r.Decision != Sandboxed {
		t.Errorf("sed (no -i) .git/config: got %v, want Sandboxed (nil)", r.Decision)
	}
}

func TestProtectedPathClassifier_TeeCommand(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	r := c.Classify("tee .agent/config.yaml")
	if r.Decision != Forbidden {
		t.Errorf("tee .agent/config.yaml: got %v, want Forbidden", r.Decision)
	}
}

func TestProtectedPathClassifier_TruncateCommand(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	r := c.Classify("truncate -s 0 .env")
	if r.Decision != Escalated {
		t.Errorf("truncate .env: got %v, want Escalated", r.Decision)
	}
}

func TestProtectedPathClassifier_ChmodCommand(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	r := c.Classify("chmod +x .git/hooks/pre-commit")
	if r.Decision != Forbidden {
		t.Errorf("chmod .git/hooks/pre-commit: got %v, want Forbidden", r.Decision)
	}
}

func TestProtectedPathClassifier_ChownCommand(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	r := c.Classify("chown root .claude/settings.json")
	if r.Decision != Forbidden {
		t.Errorf("chown .claude/settings.json: got %v, want Forbidden", r.Decision)
	}
}

func TestProtectedPathClassifier_CPDestination(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// cp to protected destination → match
	r := c.Classify("cp malicious.sh .git/hooks/pre-commit")
	if r.Decision != Forbidden {
		t.Errorf("cp to .git/hooks/pre-commit: got %v, want Forbidden", r.Decision)
	}

	// cp from protected source (non-write) → no match
	r = c.Classify("cp .git/hooks/pre-commit /tmp/backup")
	if r.Decision != Sandboxed {
		t.Errorf("cp from .git/hooks/pre-commit: got %v, want Sandboxed (nil)", r.Decision)
	}
}

func TestProtectedPathClassifier_GitCheckout(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// git checkout -- <protected path> → match
	r := c.Classify("git checkout -- .env")
	if r.Decision != Escalated {
		t.Errorf("git checkout -- .env: got %v, want Escalated", r.Decision)
	}

	// git checkout without -- → no match (branch checkout)
	r = c.Classify("git checkout main")
	if r.Decision != Sandboxed {
		t.Errorf("git checkout main: got %v, want Sandboxed (nil)", r.Decision)
	}
}

func TestProtectedPathClassifier_DotSlashPrefix(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// ./ prefix should be normalized
	r := c.Classify("rm ./.git/hooks/pre-commit")
	if r.Decision != Forbidden {
		t.Errorf("rm ./.git/hooks/pre-commit: got %v, want Forbidden", r.Decision)
	}
}

// --- ClassifyArgs tests ---

func TestProtectedPathClassifier_ClassifyArgs(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// rm with protected path arg
	r := c.ClassifyArgs("rm", []string{"-f", ".git/hooks/pre-commit"})
	if r.Decision != Forbidden {
		t.Errorf("ClassifyArgs rm .git/hooks/pre-commit: got %v, want Forbidden", r.Decision)
	}

	// cat (non-write) with protected path arg → no match
	r = c.ClassifyArgs("cat", []string{".git/hooks/pre-commit"})
	if r.Decision != Sandboxed {
		t.Errorf("ClassifyArgs cat .git/hooks: got %v, want Sandboxed", r.Decision)
	}

	// sed -i with protected path
	r = c.ClassifyArgs("sed", []string{"-i", "s/old/new/", ".env"})
	if r.Decision != Escalated {
		t.Errorf("ClassifyArgs sed -i .env: got %v, want Escalated", r.Decision)
	}

	// sed without -i → no match
	r = c.ClassifyArgs("sed", []string{"s/old/new/", ".env"})
	if r.Decision != Sandboxed {
		t.Errorf("ClassifyArgs sed .env: got %v, want Sandboxed", r.Decision)
	}

	// cp to protected destination
	r = c.ClassifyArgs("cp", []string{"source.sh", ".agent/config"})
	if r.Decision != Forbidden {
		t.Errorf("ClassifyArgs cp to .agent/config: got %v, want Forbidden", r.Decision)
	}

	// git checkout -- protected path
	r = c.ClassifyArgs("git", []string{"checkout", "--", ".env"})
	if r.Decision != Escalated {
		t.Errorf("ClassifyArgs git checkout -- .env: got %v, want Escalated", r.Decision)
	}
}

func TestProtectedPathClassifier_ClassifyArgs_NoArgs(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// Non-write command → Sandboxed
	r := c.ClassifyArgs("ls", nil)
	if r.Decision != Sandboxed {
		t.Errorf("ClassifyArgs ls nil: got %v, want Sandboxed", r.Decision)
	}
}

// --- Option integration tests ---

func TestWithProtectedPaths_Integration(t *testing.T) {
	custom := []ProtectedPath{
		{Pattern: "secret/*", Decision: Forbidden, Description: "secret directory"},
	}
	co := mergeCallOptions(WithProtectedPaths(custom...))

	if len(co.protectedPaths) != 1 {
		t.Fatalf("expected 1 protected path, got %d", len(co.protectedPaths))
	}
	if co.protectedPaths[0].Pattern != "secret/*" {
		t.Errorf("expected pattern 'secret/*', got %q", co.protectedPaths[0].Pattern)
	}

	// Test via resolveClassifier chain
	base := DefaultClassifier()
	cl := resolveClassifier(base, co)
	r := cl.Classify("rm secret/key.pem")
	if r.Decision != Forbidden {
		t.Errorf("rm secret/key.pem: got %v, want Forbidden", r.Decision)
	}
}

func TestWithDefaultProtectedPaths_Integration(t *testing.T) {
	co := mergeCallOptions(WithDefaultProtectedPaths())

	if len(co.protectedPaths) != len(defaultProtectedPaths) {
		t.Fatalf("expected %d protected paths, got %d",
			len(defaultProtectedPaths), len(co.protectedPaths))
	}

	// Test via resolveClassifier chain
	base := DefaultClassifier()
	cl := resolveClassifier(base, co)

	// Write to .git/hooks → Forbidden
	r := cl.Classify("rm .git/hooks/pre-commit")
	if r.Decision != Forbidden {
		t.Errorf("rm .git/hooks/pre-commit: got %v, want Forbidden", r.Decision)
	}

	// Read from .git/hooks → passes through to base classifier
	r = cl.Classify("cat .git/hooks/pre-commit")
	if r.Decision == Forbidden {
		t.Errorf("cat .git/hooks: should not be Forbidden (read is ok)")
	}
}

func TestWithProtectedPaths_CustomOverridesDefaults(t *testing.T) {
	// User can define custom rules that override protected paths
	// (because custom rules come first in the chain).
	customAllow := UserRule{
		Pattern:     "rm .env",
		Decision:    Allow,
		Description: "allow rm .env",
	}
	co := mergeCallOptions(
		WithDefaultProtectedPaths(),
		WithCustomRules(customAllow),
	)

	base := DefaultClassifier()
	cl := resolveClassifier(base, co)

	// Custom rule allows "rm .env" even though protected paths would escalate.
	r := cl.Classify("rm .env")
	if r.Decision != Allow {
		t.Errorf("rm .env with custom allow: got %v, want Allow", r.Decision)
	}
}

func TestWithProtectedPaths_MultipleCallsAppend(t *testing.T) {
	co := mergeCallOptions(
		WithProtectedPaths(ProtectedPath{Pattern: "a/*", Decision: Forbidden, Description: "a"}),
		WithProtectedPaths(ProtectedPath{Pattern: "b/*", Decision: Escalated, Description: "b"}),
	)

	if len(co.protectedPaths) != 2 {
		t.Fatalf("expected 2 protected paths, got %d", len(co.protectedPaths))
	}
}

// --- resolveClassifier chain order tests ---

func TestResolveClassifier_ChainOrder(t *testing.T) {
	// Chain order: custom rules → protected paths → base
	// Custom rules should take priority over protected paths.
	customRule := UserRule{
		Pattern:     "echo * > .env",
		Decision:    Allow,
		Description: "allow echo to .env",
	}
	pp := []ProtectedPath{
		{Pattern: ".env", Decision: Forbidden, Description: "env file"},
	}

	co := mergeCallOptions(
		WithCustomRules(customRule),
		WithProtectedPaths(pp...),
	)

	base := DefaultClassifier()
	cl := resolveClassifier(base, co)

	// Custom rule matches first → Allow
	r := cl.Classify("echo test > .env")
	if r.Decision != Allow {
		t.Errorf("custom rule should override protected path: got %v, want Allow", r.Decision)
	}
}

func TestResolveClassifier_ProtectedPathsBeforeBase(t *testing.T) {
	// Protected paths should take priority over base classifier.
	pp := []ProtectedPath{
		{Pattern: ".env", Decision: Forbidden, Description: "env file"},
	}

	co := mergeCallOptions(WithProtectedPaths(pp...))
	base := DefaultClassifier()
	cl := resolveClassifier(base, co)

	// "echo x > .env" — protected path should catch this as Forbidden.
	r := cl.Classify("echo x > .env")
	if r.Decision != Forbidden {
		t.Errorf("protected path should override base: got %v, want Forbidden", r.Decision)
	}
}

// --- matchPath tests ---

func TestMatchPath_InvalidPattern(t *testing.T) {
	c := &protectedPathClassifier{
		paths: []ProtectedPath{
			{Pattern: "[invalid", Decision: Forbidden, Description: "bad pattern"},
		},
	}

	// Invalid glob pattern should be skipped (no match).
	r := c.matchPath("anything")
	if r.Decision != Sandboxed {
		t.Errorf("invalid pattern: got %v, want Sandboxed", r.Decision)
	}
}

func TestMatchPath_NestedDirectory(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	// path.Match(".agent/*", ".agent/sub/config.yaml") returns false
	// because * does not match '/'. Our prefix-based fallback must handle this.
	tests := []struct {
		name string
		path string
		want Decision
	}{
		{"shallow agent path", ".agent/config", Forbidden},
		{"nested agent path", ".agent/sub/config.yaml", Forbidden},
		{"deeply nested agent path", ".agent/a/b/c/deep.txt", Forbidden},
		{"nested vscode path", ".vscode/extensions/ext/settings.json", Escalated},
		{"nested claude path", ".claude/sub/file", Forbidden},
		{"nested idea path", ".idea/modules/mod.iml", Escalated},
		{"unrelated path", "src/main.go", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.matchPath(tt.path)
			if r.Decision != tt.want {
				t.Errorf("matchPath(%q) = %v, want %v", tt.path, r.Decision, tt.want)
			}
		})
	}
}

// --- Result metadata tests ---

func TestProtectedPathClassifier_ResultMetadata(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	r := c.Classify("rm .git/hooks/pre-commit")
	if r.Rule == "" {
		t.Error("expected non-empty Rule")
	}
	if r.Reason == "" {
		t.Error("expected non-empty Reason")
	}
	if r.Rule != "protected-path: .git/hooks/*" {
		t.Errorf("unexpected Rule: %q", r.Rule)
	}
}

// --- Edge cases ---

func TestProtectedPathClassifier_EmptyCommand(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	r := c.Classify("")
	if r.Decision != Sandboxed {
		t.Errorf("empty command: got %v, want Sandboxed", r.Decision)
	}
}

func TestProtectedPathClassifier_NoPaths(t *testing.T) {
	c := &protectedPathClassifier{paths: nil}

	r := c.Classify("rm .git/hooks/pre-commit")
	if r.Decision != Sandboxed {
		t.Errorf("no paths: got %v, want Sandboxed", r.Decision)
	}
}

func TestProtectedPathClassifier_InstallCommand(t *testing.T) {
	c := &protectedPathClassifier{paths: defaultProtectedPaths}

	r := c.Classify("install -m 755 script.sh .git/hooks/pre-commit")
	if r.Decision != Forbidden {
		t.Errorf("install to .git/hooks: got %v, want Forbidden", r.Decision)
	}
}

// --- containsFlagPrefix tests ---

func TestContainsFlagPrefix(t *testing.T) {
	tests := []struct {
		args []string
		flag string
		want bool
	}{
		{[]string{"-i", "file"}, "-i", true},
		{[]string{"-i.bak", "file"}, "-i", true},
		{[]string{"-n", "file"}, "-i", false},
		{nil, "-i", false},
	}
	for _, tt := range tests {
		got := containsFlagPrefix(tt.args, tt.flag)
		if got != tt.want {
			t.Errorf("containsFlagPrefix(%v, %q) = %v, want %v",
				tt.args, tt.flag, got, tt.want)
		}
	}
}

// --- isWriteCommand tests ---

func TestIsWriteCommand(t *testing.T) {
	writes := []string{"rm", "mv", "chmod", "chown", "tee", "truncate", "install"}
	for _, cmd := range writes {
		if !isWriteCommand(cmd) {
			t.Errorf("isWriteCommand(%q) = false, want true", cmd)
		}
	}

	nonWrites := []string{"cat", "ls", "echo", "grep", "head", "tail"}
	for _, cmd := range nonWrites {
		if isWriteCommand(cmd) {
			t.Errorf("isWriteCommand(%q) = true, want false", cmd)
		}
	}
}
