package agentbox

import (
	"testing"
)

// ---------------------------------------------------------------------------
// BuiltinRuleNames tests
// ---------------------------------------------------------------------------

func TestBuiltinRuleNamesCount(t *testing.T) {
	names := BuiltinRuleNames()
	// There are 44 built-in rules: 17 forbidden + 21 escalated + 6 allow.
	const wantCount = 44
	if got := len(names); got != wantCount {
		t.Errorf("BuiltinRuleNames() returned %d names, want %d", got, wantCount)
	}
}

func TestBuiltinRuleNamesNoDuplicates(t *testing.T) {
	names := BuiltinRuleNames()
	seen := make(map[RuleName]bool, len(names))
	for _, n := range names {
		if seen[n] {
			t.Errorf("duplicate rule name: %s", n)
		}
		seen[n] = true
	}
}

func TestBuiltinRuleNamesMatchDefaultRules(t *testing.T) {
	// Verify that every RuleName constant corresponds to an actual rule in
	// defaultRules(). This catches typos in the constants.
	rules := defaultRules()
	ruleSet := make(map[RuleName]bool, len(rules))
	for _, r := range rules {
		ruleSet[r.Name] = true
	}

	for _, name := range BuiltinRuleNames() {
		if !ruleSet[name] {
			t.Errorf("RuleName constant %q does not match any rule in defaultRules()", name)
		}
	}

	// Also verify the reverse: every default rule has a corresponding constant.
	nameSet := make(map[RuleName]bool, len(BuiltinRuleNames()))
	for _, n := range BuiltinRuleNames() {
		nameSet[n] = true
	}
	for _, r := range rules {
		if !nameSet[r.Name] {
			t.Errorf("defaultRules() contains rule %q with no corresponding RuleName constant", r.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// RuleOverride / overrideClassifier unit tests
// ---------------------------------------------------------------------------

func TestOverrideEscalatedToAllow(t *testing.T) {
	// docker run ubuntu is normally Escalated by the docker-runtime rule.
	base := DefaultClassifier()
	result := base.Classify("docker run ubuntu")
	if result.Decision != Escalated {
		t.Fatalf("precondition: expected Escalated for 'docker run ubuntu', got %v", result.Decision)
	}

	// Override docker-runtime → Allow.
	oc := &overrideClassifier{
		base:      base,
		overrides: map[RuleName]Decision{RuleDockerRuntime: Allow},
	}
	result = oc.Classify("docker run ubuntu")
	if result.Decision != Allow {
		t.Errorf("expected Allow after override, got %v", result.Decision)
	}
	if result.Rule != RuleDockerRuntime {
		t.Errorf("expected Rule=%q, got %q", RuleDockerRuntime, result.Rule)
	}
}

func TestOverrideForbiddenToSandboxed(t *testing.T) {
	// fork bomb is Forbidden.
	base := DefaultClassifier()
	result := base.Classify(":(){ :|:& };:")
	if result.Decision != Forbidden {
		t.Fatalf("precondition: expected Forbidden for fork bomb, got %v", result.Decision)
	}

	// Override fork-bomb → Sandboxed (effectively disable it).
	oc := &overrideClassifier{
		base:      base,
		overrides: map[RuleName]Decision{RuleForkBomb: Sandboxed},
	}
	result = oc.Classify(":(){ :|:& };:")
	if result.Decision != Sandboxed {
		t.Errorf("expected Sandboxed after override, got %v", result.Decision)
	}
}

func TestOverrideAllowToEscalated(t *testing.T) {
	// "ls" is normally Allow via common-safe-commands.
	base := DefaultClassifier()
	result := base.Classify("ls")
	if result.Decision != Allow {
		t.Fatalf("precondition: expected Allow for 'ls', got %v", result.Decision)
	}

	// Override common-safe-commands → Escalated.
	oc := &overrideClassifier{
		base:      base,
		overrides: map[RuleName]Decision{RuleCommonSafeCommands: Escalated},
	}
	result = oc.Classify("ls")
	if result.Decision != Escalated {
		t.Errorf("expected Escalated after override, got %v", result.Decision)
	}
}

func TestOverrideToSandboxedDisablesRule(t *testing.T) {
	// "sudo apt-get install nginx" matches the sudo rule (Escalated).
	base := DefaultClassifier()
	result := base.Classify("sudo apt-get install nginx")
	if result.Decision != Escalated {
		t.Fatalf("precondition: expected Escalated, got %v", result.Decision)
	}

	// Override sudo → Sandboxed. Since the chain sees Sandboxed it continues
	// to subsequent rules. No other rule matches "sudo apt-get install nginx"
	// individually (sudo is the first matching rule), but after override, the
	// base classifier returns Sandboxed for the sudo rule so that's what we get
	// from the overrideClassifier. If wrapped in a chain, later rules would run.
	oc := &overrideClassifier{
		base:      base,
		overrides: map[RuleName]Decision{RuleSudo: Sandboxed},
	}
	result = oc.Classify("sudo apt-get install nginx")
	if result.Decision != Sandboxed {
		t.Errorf("expected Sandboxed after override, got %v", result.Decision)
	}
}

func TestOverrideUnknownRuleIgnored(t *testing.T) {
	// An override for a non-existent rule should be silently ignored.
	base := DefaultClassifier()
	oc := &overrideClassifier{
		base:      base,
		overrides: map[RuleName]Decision{RuleName("non-existent-rule"): Allow},
	}

	// Normal commands still work.
	result := oc.Classify("ls")
	if result.Decision != Allow {
		t.Errorf("expected Allow for 'ls', got %v", result.Decision)
	}

	result = oc.Classify("sudo rm -rf /")
	if result.Decision != Escalated {
		t.Errorf("expected Escalated for 'sudo rm -rf /', got %v", result.Decision)
	}
}

func TestOverrideDoesNotAffectOtherRules(t *testing.T) {
	// Override docker-runtime but NOT ssh-command.
	base := DefaultClassifier()
	oc := &overrideClassifier{
		base:      base,
		overrides: map[RuleName]Decision{RuleDockerRuntime: Allow},
	}

	// docker run → overridden to Allow.
	result := oc.Classify("docker run ubuntu")
	if result.Decision != Allow {
		t.Errorf("docker run: expected Allow, got %v", result.Decision)
	}

	// ssh → still Escalated.
	result = oc.Classify("ssh user@host")
	if result.Decision != Escalated {
		t.Errorf("ssh: expected Escalated, got %v", result.Decision)
	}
}

func TestOverrideMultiple(t *testing.T) {
	base := DefaultClassifier()
	oc := &overrideClassifier{
		base: base,
		overrides: map[RuleName]Decision{
			RuleDockerRuntime: Allow,
			RuleSSHCommand:    Allow,
			RuleForkBomb:      Sandboxed,
		},
	}

	result := oc.Classify("docker run ubuntu")
	if result.Decision != Allow {
		t.Errorf("docker run: expected Allow, got %v", result.Decision)
	}
	result = oc.Classify("ssh user@host")
	if result.Decision != Allow {
		t.Errorf("ssh: expected Allow, got %v", result.Decision)
	}
	result = oc.Classify(":(){ :|:& };:")
	if result.Decision != Sandboxed {
		t.Errorf("fork bomb: expected Sandboxed, got %v", result.Decision)
	}
	// Unaffected rule.
	result = oc.Classify("sudo ls")
	if result.Decision != Escalated {
		t.Errorf("sudo: expected Escalated, got %v", result.Decision)
	}
}

func TestOverrideClassifyArgs(t *testing.T) {
	// Verify ClassifyArgs path also applies overrides.
	base := DefaultClassifier()
	oc := &overrideClassifier{
		base:      base,
		overrides: map[RuleName]Decision{RuleDockerRuntime: Allow},
	}

	result := oc.ClassifyArgs("docker", []string{"run", "ubuntu"})
	if result.Decision != Allow {
		t.Errorf("ClassifyArgs docker run: expected Allow, got %v", result.Decision)
	}
}

// ---------------------------------------------------------------------------
// Integration: WithRuleOverrides via resolveClassifier
// ---------------------------------------------------------------------------

func TestWithRuleOverridesIntegration(t *testing.T) {
	// Simulate what happens when WithRuleOverrides is used with resolveClassifier.
	co := &callOptions{}
	WithRuleOverrides(RuleOverride{
		Rule:     RuleDockerRuntime,
		Decision: Allow,
	})(co)

	cl := resolveClassifier(DefaultClassifier(), co)
	result := cl.Classify("docker run ubuntu")
	if result.Decision != Allow {
		t.Errorf("expected Allow via WithRuleOverrides, got %v", result.Decision)
	}
}

func TestWithRuleOverridesAndCustomRules(t *testing.T) {
	// Custom rules take priority over rule overrides because they are chained
	// on top. Here we override ssh-command to Allow, but add a custom rule
	// that forbids "ssh badhost".
	co := &callOptions{}
	WithRuleOverrides(RuleOverride{
		Rule:     RuleSSHCommand,
		Decision: Allow,
	})(co)
	WithCustomRules(UserRule{
		Pattern:     "ssh badhost",
		Decision:    Forbidden,
		Description: "block bad host",
	})(co)

	cl := resolveClassifier(DefaultClassifier(), co)

	// Custom rule matches first → Forbidden.
	result := cl.Classify("ssh badhost")
	if result.Decision != Forbidden {
		t.Errorf("ssh badhost: expected Forbidden (custom rule), got %v", result.Decision)
	}

	// Other ssh commands → Allow (override).
	result = cl.Classify("ssh goodhost")
	if result.Decision != Allow {
		t.Errorf("ssh goodhost: expected Allow (override), got %v", result.Decision)
	}
}

func TestWithRuleOverridesAndProtectedPaths(t *testing.T) {
	// Protected paths take priority over rule overrides because they are
	// chained on top.
	co := &callOptions{}
	// Override common-safe-commands → Escalated won't matter for protected paths
	// because the protected path classifier fires first.
	WithRuleOverrides(RuleOverride{
		Rule:     RuleCommonSafeCommands,
		Decision: Escalated,
	})(co)
	WithProtectedPaths(ProtectedPath{
		Pattern:  ".secret/*",
		Decision: Forbidden,
	})(co)

	cl := resolveClassifier(DefaultClassifier(), co)

	// Writing to a protected path → Forbidden from protectedPathClassifier.
	result := cl.Classify("rm .secret/key")
	if result.Decision != Forbidden {
		t.Errorf("rm .secret/key: expected Forbidden (protected), got %v", result.Decision)
	}

	// "ls" hits override → Escalated.
	result = cl.Classify("ls")
	if result.Decision != Escalated {
		t.Errorf("ls: expected Escalated (override), got %v", result.Decision)
	}
}

func TestWithRuleOverridesLastWins(t *testing.T) {
	// If WithRuleOverrides is called multiple times with the same rule,
	// the last override wins (map semantics).
	co := &callOptions{}
	WithRuleOverrides(RuleOverride{
		Rule:     RuleDockerRuntime,
		Decision: Forbidden,
	})(co)
	WithRuleOverrides(RuleOverride{
		Rule:     RuleDockerRuntime,
		Decision: Allow,
	})(co)

	cl := resolveClassifier(DefaultClassifier(), co)
	result := cl.Classify("docker run ubuntu")
	if result.Decision != Allow {
		t.Errorf("expected Allow (last override wins), got %v", result.Decision)
	}
}

func TestWithRuleOverridesEmpty(t *testing.T) {
	// WithRuleOverrides with no arguments should not affect classification.
	co := &callOptions{}
	WithRuleOverrides()(co)

	cl := resolveClassifier(DefaultClassifier(), co)
	result := cl.Classify("docker run ubuntu")
	if result.Decision != Escalated {
		t.Errorf("expected Escalated (no overrides), got %v", result.Decision)
	}
}

// ---------------------------------------------------------------------------
// RuleName type safety
// ---------------------------------------------------------------------------

func TestRuleNameStringConversion(t *testing.T) {
	// Verify that RuleName → string conversion works for ClassifyResult.Rule.
	var r ClassifyResult
	r.Rule = RuleDockerRuntime
	if r.Rule != "docker-runtime" {
		t.Errorf("expected 'docker-runtime', got %q", r.Rule)
	}
}
