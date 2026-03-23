package agentbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"
)

// --- Compile-time interface checks ---
// These are placed at package level to fail at compile time, not test time.
// The production code already has them; these test-file assertions provide
// additional coverage and serve as documentation.

var (
	_ Classifier    = (*ruleClassifier)(nil)
	_ Classifier    = (*chainClassifier)(nil)
	_ Classifier    = (*customRuleClassifier)(nil)
	_ Classifier    = (*protectedPathClassifier)(nil)
	_ Classifier    = (*overrideClassifier)(nil)
	_ ApprovalCache = (*MemoryApprovalCache)(nil)
	_ io.Closer     = (Manager)(nil)
)

// --- JSON round-trip tests ---

func TestExecResultJSONRoundTrip(t *testing.T) {
	r := ExecResult{
		ExitCode:  42,
		Stdout:    "hello",
		Stderr:    "err",
		Duration:  2 * time.Second,
		Sandboxed: true,
		Truncated: true,
		Violations: []Violation{
			{Operation: ViolationFileWrite, Path: "/etc/passwd", Detail: "blocked", Process: "cat", Raw: "raw msg"},
		},
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	// Verify expected JSON keys are present.
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"exitCode", "stdout", "stderr", "duration", "sandboxed", "truncated", "violations"} {
		if _, ok := m[key]; !ok {
			t.Errorf("ExecResult JSON missing key %q", key)
		}
	}
	// Verify round-trip.
	var r2 ExecResult
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if r2.ExitCode != r.ExitCode {
		t.Errorf("ExitCode: got %d, want %d", r2.ExitCode, r.ExitCode)
	}
	if r2.Stdout != r.Stdout {
		t.Errorf("Stdout: got %q, want %q", r2.Stdout, r.Stdout)
	}
	if r2.Sandboxed != r.Sandboxed {
		t.Errorf("Sandboxed: got %v, want %v", r2.Sandboxed, r.Sandboxed)
	}
}

func TestExecResultJSONOmitsEmptyViolations(t *testing.T) {
	r := ExecResult{ExitCode: 0}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["violations"]; ok {
		t.Error("expected violations to be omitted when nil")
	}
}

func TestViolationJSONOmitsEmptyFields(t *testing.T) {
	v := Violation{Operation: ViolationNetwork}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	// "operation" should be present.
	if _, ok := m["operation"]; !ok {
		t.Error("expected operation to be present")
	}
	// "path", "detail", "process", "raw" should be omitted.
	for _, key := range []string{"path", "detail", "process", "raw"} {
		if _, ok := m[key]; ok {
			t.Errorf("expected %q to be omitted when empty", key)
		}
	}
}

func TestUserRuleJSONRoundTrip(t *testing.T) {
	rule := UserRule{
		Pattern:     "npm test",
		Decision:    Allow,
		Description: "safe test command",
	}
	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"pattern", "decision", "description"} {
		if _, ok := m[key]; !ok {
			t.Errorf("UserRule JSON missing key %q", key)
		}
	}
}

func TestUserRuleJSONOmitsEmptyDescription(t *testing.T) {
	rule := UserRule{Pattern: "ls", Decision: Allow}
	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["description"]; ok {
		t.Error("expected description to be omitted when empty")
	}
}

func TestProtectedPathJSONRoundTrip(t *testing.T) {
	pp := ProtectedPath{
		Pattern:     ".git/*",
		Decision:    Forbidden,
		Description: "git directory",
	}
	data, err := json.Marshal(pp)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"pattern", "decision", "description"} {
		if _, ok := m[key]; !ok {
			t.Errorf("ProtectedPath JSON missing key %q", key)
		}
	}
}

func TestConfigJSONExcludesCallbackFields(t *testing.T) {
	cfg := Config{
		Shell:            "/bin/sh",
		MaxOutputBytes:   1024,
		FallbackPolicy:   FallbackWarn,
		Classifier:       DefaultClassifier(),                                                                          // should be excluded
		Logger:           nil,                                                                                          // should be excluded
		ApprovalCallback: func(_ context.Context, _ ApprovalRequest) (ApprovalDecision, error) { return Approve, nil }, // should be excluded
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	// Verify json:"-" fields are excluded.
	for _, key := range []string{"classifier", "Classifier", "logger", "Logger", "approvalCallback", "ApprovalCallback", "approvalCache", "ApprovalCache"} {
		if _, ok := m[key]; ok {
			t.Errorf("Config JSON should exclude %q", key)
		}
	}
	// Verify included fields.
	if _, ok := m["shell"]; !ok {
		t.Error("expected shell to be present")
	}
}

func TestFilesystemConfigJSONRoundTrip(t *testing.T) {
	fs := FilesystemConfig{
		WritableRoots:             []string{"/tmp"},
		DenyWrite:                 []string{"/etc"},
		DenyRead:                  []string{"/secret"},
		AllowGitConfig:            true,
		AutoProtectDangerousFiles: true,
		DangerousFileScanDepth:    3,
	}
	data, err := json.Marshal(fs)
	if err != nil {
		t.Fatal(err)
	}
	var fs2 FilesystemConfig
	if err := json.Unmarshal(data, &fs2); err != nil {
		t.Fatal(err)
	}
	if len(fs2.WritableRoots) != 1 || fs2.WritableRoots[0] != "/tmp" {
		t.Errorf("WritableRoots round-trip failed: %v", fs2.WritableRoots)
	}
	if !fs2.AllowGitConfig {
		t.Error("AllowGitConfig should be true")
	}
}

func TestNetworkConfigJSONExcludesOnRequest(t *testing.T) {
	nc := NetworkConfig{
		Mode:           NetworkFiltered,
		AllowedDomains: []string{"example.com"},
		OnRequest:      func(_ context.Context, _ string, _ int) (bool, error) { return true, nil },
	}
	data, err := json.Marshal(nc)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["onRequest"]; ok {
		t.Error("OnRequest should be excluded from JSON")
	}
	if _, ok := m["OnRequest"]; ok {
		t.Error("OnRequest should be excluded from JSON")
	}
}

func TestMITMProxyConfigJSONRoundTrip(t *testing.T) {
	mc := MITMProxyConfig{
		SocketPath: "/tmp/mitm.sock",
		Domains:    []string{"*.example.com"},
	}
	data, err := json.Marshal(mc)
	if err != nil {
		t.Fatal(err)
	}
	var mc2 MITMProxyConfig
	if err := json.Unmarshal(data, &mc2); err != nil {
		t.Fatal(err)
	}
	if mc2.SocketPath != mc.SocketPath {
		t.Errorf("SocketPath: got %q, want %q", mc2.SocketPath, mc.SocketPath)
	}
}

// --- P1-6: Manager Close() tests ---

func TestNopManagerClose(t *testing.T) {
	mgr := NewNopManager()
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	// After Close, operations should fail.
	_, err := mgr.Exec(context.Background(), "echo hello")
	if !errors.Is(err, ErrManagerClosed) {
		t.Errorf("expected ErrManagerClosed after Close, got: %v", err)
	}
}

func TestNopManagerCloseIdempotent(t *testing.T) {
	mgr := NewNopManager()
	if err := mgr.Close(); err != nil {
		t.Fatalf("first Close() error: %v", err)
	}
	// Second Close should not error (same as Cleanup behavior).
	if err := mgr.Close(); err != nil {
		t.Fatalf("second Close() error: %v", err)
	}
}

func TestManagerCloseEquivalentToCleanup(t *testing.T) {
	// Verify Close() delegates to Cleanup(context.Background()).
	mgr := NewNopManager()
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	// Cleanup after Close should also succeed (idempotent).
	if err := mgr.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup after Close error: %v", err)
	}
}

// --- P1-7: Empty UserRule.Pattern tests ---

func TestMatchPatternEmptyMatchesNothing(t *testing.T) {
	// Empty pattern should match nothing (only matches empty string).
	if matchPattern("", "ls") {
		t.Error("empty pattern should not match 'ls'")
	}
	if matchPattern("", "echo hello") {
		t.Error("empty pattern should not match 'echo hello'")
	}
	if matchPattern("", "") {
		// Empty pattern == empty command is technically true, but
		// in practice commands are never empty strings.
		// This test documents the behavior.
		t.Log("empty pattern matches empty command (expected edge case)")
	}
}

func TestCustomRuleClassifierEmptyPatternSkipped(t *testing.T) {
	c := &customRuleClassifier{
		rules: []UserRule{
			{Pattern: "", Decision: Forbidden, Description: "should not match"},
			{Pattern: "ls", Decision: Allow, Description: "allow ls"},
		},
	}
	// The empty pattern should not match anything, so "ls" should match the second rule.
	result := c.Classify("ls")
	if result.Decision != Allow {
		t.Errorf("expected Allow, got %v", result.Decision)
	}
	// A random command should fall through both rules (empty doesn't match).
	result = c.Classify("cat /etc/hosts")
	if result.Decision != Sandboxed {
		t.Errorf("expected Sandboxed for unmatched command, got %v", result.Decision)
	}
}

// --- Batch C: Additional JSON tag tests ---

func TestClassifyResultJSONRoundTrip(t *testing.T) {
	cr := ClassifyResult{
		Decision: Escalated,
		Reason:   "needs approval",
		Rule:     RuleSudo,
	}
	data, err := json.Marshal(cr)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"decision", "reason", "rule"} {
		if _, ok := m[key]; !ok {
			t.Errorf("ClassifyResult JSON missing key %q", key)
		}
	}
	// Round-trip.
	var cr2 ClassifyResult
	if err := json.Unmarshal(data, &cr2); err != nil {
		t.Fatal(err)
	}
	if cr2.Decision != cr.Decision {
		t.Errorf("Decision: got %v, want %v", cr2.Decision, cr.Decision)
	}
	if cr2.Reason != cr.Reason {
		t.Errorf("Reason: got %q, want %q", cr2.Reason, cr.Reason)
	}
	if cr2.Rule != cr.Rule {
		t.Errorf("Rule: got %q, want %q", cr2.Rule, cr.Rule)
	}
}

func TestClassifyResultJSONOmitsEmpty(t *testing.T) {
	cr := ClassifyResult{Decision: Sandboxed}
	data, err := json.Marshal(cr)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"reason", "rule"} {
		if _, ok := m[key]; ok {
			t.Errorf("expected %q to be omitted when empty", key)
		}
	}
}

func TestRuleOverrideJSONRoundTrip(t *testing.T) {
	ro := RuleOverride{
		Rule:     RuleDockerRuntime,
		Decision: Allow,
	}
	data, err := json.Marshal(ro)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"rule", "decision"} {
		if _, ok := m[key]; !ok {
			t.Errorf("RuleOverride JSON missing key %q", key)
		}
	}
	var ro2 RuleOverride
	if err := json.Unmarshal(data, &ro2); err != nil {
		t.Fatal(err)
	}
	if ro2.Rule != ro.Rule {
		t.Errorf("Rule: got %q, want %q", ro2.Rule, ro.Rule)
	}
	if ro2.Decision != ro.Decision {
		t.Errorf("Decision: got %v, want %v", ro2.Decision, ro.Decision)
	}
}

func TestApprovalRequestJSONRoundTrip(t *testing.T) {
	ar := ApprovalRequest{
		Command:  "sudo rm -rf /",
		Reason:   "privilege escalation",
		Decision: Escalated,
	}
	data, err := json.Marshal(ar)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"command", "decision"} {
		if _, ok := m[key]; !ok {
			t.Errorf("ApprovalRequest JSON missing key %q", key)
		}
	}
	var ar2 ApprovalRequest
	if err := json.Unmarshal(data, &ar2); err != nil {
		t.Fatal(err)
	}
	if ar2.Command != ar.Command {
		t.Errorf("Command: got %q, want %q", ar2.Command, ar.Command)
	}
}

func TestApprovalRequestJSONOmitsEmptyReason(t *testing.T) {
	ar := ApprovalRequest{Command: "ls", Decision: Escalated}
	data, err := json.Marshal(ar)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["reason"]; ok {
		t.Error("expected reason to be omitted when empty")
	}
}

func TestForbiddenCommandErrorJSONRoundTrip(t *testing.T) {
	e := ForbiddenCommandError{Command: "rm -rf /", Reason: "dangerous"}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"command", "reason"} {
		if _, ok := m[key]; !ok {
			t.Errorf("ForbiddenCommandError JSON missing key %q", key)
		}
	}
}

func TestEscalatedCommandErrorJSONRoundTrip(t *testing.T) {
	e := EscalatedCommandError{Command: "sudo su", Reason: "needs approval"}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"command", "reason"} {
		if _, ok := m[key]; !ok {
			t.Errorf("EscalatedCommandError JSON missing key %q", key)
		}
	}
}

func TestApprovalRequestRuleField(t *testing.T) {
	ar := ApprovalRequest{
		Command:  "sudo rm -rf /",
		Reason:   "privilege escalation",
		Decision: Escalated,
		Rule:     RuleSudo,
	}
	if ar.Rule != RuleSudo {
		t.Errorf("Rule: got %q, want %q", ar.Rule, RuleSudo)
	}
}

func TestApprovalRequestRuleJSONRoundTrip(t *testing.T) {
	ar := ApprovalRequest{
		Command:  "docker run ubuntu",
		Reason:   "docker runtime",
		Decision: Escalated,
		Rule:     RuleDockerRuntime,
	}
	data, err := json.Marshal(ar)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["rule"]; !ok {
		t.Error("expected 'rule' key in JSON when Rule is set")
	}
	var ar2 ApprovalRequest
	if err := json.Unmarshal(data, &ar2); err != nil {
		t.Fatal(err)
	}
	if ar2.Rule != ar.Rule {
		t.Errorf("Rule: got %q, want %q", ar2.Rule, ar.Rule)
	}
}

func TestApprovalRequestRuleOmittedWhenEmpty(t *testing.T) {
	ar := ApprovalRequest{Command: "ls", Decision: Escalated}
	data, err := json.Marshal(ar)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["rule"]; ok {
		t.Error("expected 'rule' to be omitted when empty")
	}
}

func TestNewManagerNilConfigUsesDefault(t *testing.T) {
	// NewManager(nil) should use DefaultConfig and succeed.
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager(nil) should not error, got: %v", err)
	}
	defer mgr.Close()
	// Verify manager is functional by checking availability.
	_ = mgr.Available()
}
