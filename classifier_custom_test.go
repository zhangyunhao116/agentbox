package agentbox

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zhangyunhao116/agentbox/testutil"
)

// ---------------------------------------------------------------------------
// customRuleClassifier unit tests
// ---------------------------------------------------------------------------

func TestCustomRuleExactMatch(t *testing.T) {
	c := &customRuleClassifier{rules: []UserRule{
		{Pattern: "npm test", Decision: Allow, Description: "allow npm test"},
	}}

	r := c.Classify("npm test")
	if r.Decision != Allow {
		t.Errorf("expected Allow for exact match, got %v", r.Decision)
	}
	if r.Rule != "custom: allow npm test" {
		t.Errorf("expected rule 'custom: allow npm test', got %q", r.Rule)
	}

	// Must not match a different command.
	r = c.Classify("npm run test")
	if r.Decision != Sandboxed {
		t.Errorf("expected Sandboxed for non-match, got %v", r.Decision)
	}
}

func TestCustomRuleGlobMatch(t *testing.T) {
	c := &customRuleClassifier{rules: []UserRule{
		{Pattern: "git push *", Decision: Forbidden, Description: "block git push"},
	}}

	r := c.Classify("git push origin")
	if r.Decision != Forbidden {
		t.Errorf("expected Forbidden for glob match, got %v", r.Decision)
	}

	// path.Match * matches any non-separator character sequence, including spaces.
	// So "git push *" matches "git push origin main" (spaces are not separators).
	r = c.Classify("git push origin main")
	if r.Decision != Forbidden {
		t.Errorf("expected Forbidden for multi-word glob match, got %v", r.Decision)
	}

	// But * does NOT match path separators (/), so paths won't match.
	r = c.Classify("git push /some/path")
	if r.Decision != Sandboxed {
		t.Errorf("expected Sandboxed for path with separators, got %v", r.Decision)
	}
}

func TestCustomRuleGlobQuestionMark(t *testing.T) {
	c := &customRuleClassifier{rules: []UserRule{
		{Pattern: "ls -?", Decision: Allow},
	}}

	r := c.Classify("ls -l")
	if r.Decision != Allow {
		t.Errorf("expected Allow for ? match, got %v", r.Decision)
	}

	r = c.Classify("ls -la")
	if r.Decision != Sandboxed {
		t.Errorf("expected Sandboxed for ? non-match, got %v", r.Decision)
	}
}

func TestCustomRuleDecisionOverrideAllowToForbidden(t *testing.T) {
	// User Forbidden rule should override built-in Allow.
	custom := &customRuleClassifier{rules: []UserRule{
		{Pattern: "ls", Decision: Forbidden, Description: "deny ls"},
	}}
	chain := ChainClassifier(custom, DefaultClassifier())

	r := chain.Classify("ls")
	if r.Decision != Forbidden {
		t.Errorf("expected user Forbidden to override built-in Allow, got %v", r.Decision)
	}
	if r.Rule != "custom: deny ls" {
		t.Errorf("expected rule 'custom: deny ls', got %q", r.Rule)
	}
}

func TestCustomRuleDecisionOverrideEscalatedToAllow(t *testing.T) {
	// User Allow rule should override built-in Escalated.
	custom := &customRuleClassifier{rules: []UserRule{
		{Pattern: "sudo apt update", Decision: Allow, Description: "trusted apt update"},
	}}
	chain := ChainClassifier(custom, DefaultClassifier())

	r := chain.Classify("sudo apt update")
	if r.Decision != Allow {
		t.Errorf("expected user Allow to override built-in Escalated, got %v", r.Decision)
	}
}

func TestCustomRuleOrdering(t *testing.T) {
	// First matching rule wins.
	c := &customRuleClassifier{rules: []UserRule{
		{Pattern: "npm *", Decision: Allow, Description: "first rule"},
		{Pattern: "npm *", Decision: Forbidden, Description: "second rule"},
	}}

	r := c.Classify("npm test")
	if r.Decision != Allow {
		t.Errorf("expected first matching rule (Allow), got %v", r.Decision)
	}
	if r.Rule != "custom: first rule" {
		t.Errorf("expected rule 'custom: first rule', got %q", r.Rule)
	}
}

func TestCustomRuleNoMatchFallsThrough(t *testing.T) {
	// When no custom rule matches, ChainClassifier falls through to built-in.
	custom := &customRuleClassifier{rules: []UserRule{
		{Pattern: "npm test", Decision: Allow},
	}}
	chain := ChainClassifier(custom, DefaultClassifier())

	// "ls" should not match the custom rule and should be classified by built-in.
	r := chain.Classify("ls")
	if r.Decision == Sandboxed {
		// Built-in should classify ls as Allow, not Sandboxed.
		t.Errorf("expected built-in classifier to handle ls (Allow), got Sandboxed")
	}
	if r.Decision != Allow {
		t.Errorf("expected Allow from built-in for ls, got %v", r.Decision)
	}
}

func TestCustomRuleClassifyArgs(t *testing.T) {
	c := &customRuleClassifier{rules: []UserRule{
		{Pattern: "git push origin", Decision: Escalated, Description: "review push"},
	}}

	r := c.ClassifyArgs("git", []string{"push", "origin"})
	if r.Decision != Escalated {
		t.Errorf("expected Escalated from ClassifyArgs, got %v", r.Decision)
	}

	// No args — just the command name.
	r = c.ClassifyArgs("git", nil)
	if r.Decision != Sandboxed {
		t.Errorf("expected Sandboxed for non-match ClassifyArgs, got %v", r.Decision)
	}
}

func TestCustomRuleEmptyRules(t *testing.T) {
	c := &customRuleClassifier{rules: nil}

	r := c.Classify("anything")
	if r.Decision != Sandboxed {
		t.Errorf("expected Sandboxed from empty rules, got %v", r.Decision)
	}

	r = c.ClassifyArgs("anything", []string{"here"})
	if r.Decision != Sandboxed {
		t.Errorf("expected Sandboxed from empty rules ClassifyArgs, got %v", r.Decision)
	}
}

func TestCustomRuleNameWithoutDescription(t *testing.T) {
	c := &customRuleClassifier{rules: []UserRule{
		{Pattern: "npm test", Decision: Allow},
	}}

	r := c.Classify("npm test")
	if r.Rule != "custom: npm test" {
		t.Errorf("expected rule name 'custom: npm test' (pattern fallback), got %q", r.Rule)
	}
}

func TestCustomRuleInvalidPattern(t *testing.T) {
	// path.Match returns an error for malformed patterns like "[\".
	c := &customRuleClassifier{rules: []UserRule{
		{Pattern: "[", Decision: Forbidden},
	}}

	r := c.Classify("anything")
	if r.Decision != Sandboxed {
		t.Errorf("expected Sandboxed for invalid pattern, got %v", r.Decision)
	}
}

// ---------------------------------------------------------------------------
// matchPattern unit tests
// ---------------------------------------------------------------------------

func TestMatchPatternExact(t *testing.T) {
	if !matchPattern("npm test", "npm test") {
		t.Error("expected exact match")
	}
	if matchPattern("npm test", "npm test ") {
		t.Error("expected no match with trailing space")
	}
}

func TestMatchPatternGlob(t *testing.T) {
	if !matchPattern("git push *", "git push origin") {
		t.Error("expected glob match")
	}
	if matchPattern("git push *", "git push") {
		t.Error("expected no match without argument")
	}
}

// ---------------------------------------------------------------------------
// resolveClassifier tests
// ---------------------------------------------------------------------------

func TestResolveClassifierNoOverrides(t *testing.T) {
	base := &mockClassifier{result: ClassifyResult{Decision: Allow, Reason: "base"}}
	co := &callOptions{}

	cl := resolveClassifier(base, co)
	r := cl.Classify("test")
	if r.Decision != Allow {
		t.Errorf("expected base classifier Allow, got %v", r.Decision)
	}
}

func TestResolveClassifierWithOverride(t *testing.T) {
	base := &mockClassifier{result: ClassifyResult{Decision: Allow, Reason: "base"}}
	override := &mockClassifier{result: ClassifyResult{Decision: Forbidden, Reason: "override"}}
	co := &callOptions{classifier: override}

	cl := resolveClassifier(base, co)
	r := cl.Classify("test")
	if r.Decision != Forbidden {
		t.Errorf("expected override Forbidden, got %v", r.Decision)
	}
}

func TestResolveClassifierWithCustomRules(t *testing.T) {
	base := &mockClassifier{result: ClassifyResult{Decision: Allow, Reason: "base"}}
	co := &callOptions{
		customRules: []UserRule{
			{Pattern: "blocked", Decision: Forbidden, Description: "block it"},
		},
	}

	cl := resolveClassifier(base, co)

	// Custom rule matches.
	r := cl.Classify("blocked")
	if r.Decision != Forbidden {
		t.Errorf("expected custom Forbidden, got %v", r.Decision)
	}

	// Custom rule does not match — falls through to base.
	r = cl.Classify("something else")
	if r.Decision != Allow {
		t.Errorf("expected base Allow for non-match, got %v", r.Decision)
	}
}

func TestResolveClassifierCustomRulesWithOverride(t *testing.T) {
	base := &mockClassifier{result: ClassifyResult{Decision: Allow, Reason: "base"}}
	override := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "override"}}
	co := &callOptions{
		classifier: override,
		customRules: []UserRule{
			{Pattern: "special", Decision: Forbidden},
		},
	}

	cl := resolveClassifier(base, co)

	// Custom rule matches.
	r := cl.Classify("special")
	if r.Decision != Forbidden {
		t.Errorf("expected custom Forbidden, got %v", r.Decision)
	}

	// Falls through custom, uses override (not base).
	r = cl.Classify("other")
	if r.Decision != Escalated {
		t.Errorf("expected override Escalated, got %v", r.Decision)
	}
}

// ---------------------------------------------------------------------------
// WithCustomRules option tests
// ---------------------------------------------------------------------------

func TestWithCustomRulesOption(t *testing.T) {
	opts := &callOptions{}
	WithCustomRules(
		UserRule{Pattern: "npm test", Decision: Allow, Description: "safe test"},
		UserRule{Pattern: "rm *", Decision: Forbidden},
	)(opts)

	if len(opts.customRules) != 2 {
		t.Fatalf("expected 2 custom rules, got %d", len(opts.customRules))
	}
	if opts.customRules[0].Pattern != "npm test" {
		t.Errorf("expected pattern 'npm test', got %q", opts.customRules[0].Pattern)
	}
	if opts.customRules[1].Decision != Forbidden {
		t.Errorf("expected Forbidden for second rule, got %v", opts.customRules[1].Decision)
	}
}

func TestWithCustomRulesAppends(t *testing.T) {
	opts := &callOptions{}
	WithCustomRules(UserRule{Pattern: "a", Decision: Allow})(opts)
	WithCustomRules(UserRule{Pattern: "b", Decision: Forbidden})(opts)

	if len(opts.customRules) != 2 {
		t.Fatalf("expected 2 custom rules after two calls, got %d", len(opts.customRules))
	}
}

func TestWithCustomRulesEmpty(t *testing.T) {
	opts := &callOptions{}
	WithCustomRules()(opts)

	if len(opts.customRules) != 0 {
		t.Errorf("expected 0 custom rules, got %d", len(opts.customRules))
	}
}

// ---------------------------------------------------------------------------
// Integration test with nopManager (NopManager is the fallback Manager)
// ---------------------------------------------------------------------------

func TestWithCustomRulesNopManagerExec(t *testing.T) {
	mgr := NewNopManager()
	defer mgr.Cleanup(context.Background())

	// "ls" is normally Allow by built-in rules.
	// Override it to Forbidden with a custom rule.
	_, err := mgr.Exec(context.Background(), "ls",
		WithCustomRules(UserRule{Pattern: "ls", Decision: Forbidden, Description: "deny ls"}),
	)
	if err == nil {
		t.Fatal("expected error for Forbidden command, got nil")
	}
	// Should get ErrForbiddenCommand.
	if !isForbiddenErr(err) {
		t.Errorf("expected ErrForbiddenCommand, got %v", err)
	}
}

func TestWithCustomRulesNopManagerExecArgs(t *testing.T) {
	mgr := NewNopManager()
	defer mgr.Cleanup(context.Background())

	// Use testutil.EchoCommand for cross-platform compatibility (echo is a
	// cmd.exe builtin on Windows, not a standalone executable).
	name, args := testutil.EchoCommand("hello")

	// ClassifyArgs builds "name arg0 arg1 ..." so we construct the exact
	// pattern that will match the platform-specific command string.
	pattern := name + " " + strings.Join(args, " ")

	_, err := mgr.ExecArgs(context.Background(), name, args,
		WithCustomRules(UserRule{Pattern: pattern, Decision: Allow}),
	)
	if err != nil {
		t.Fatalf("expected Allow for custom rule, got error: %v", err)
	}
}

// isForbiddenErr checks if err wraps ForbiddenCommandError.
func isForbiddenErr(err error) bool {
	var fce *ForbiddenCommandError
	return errors.As(err, &fce)
}
