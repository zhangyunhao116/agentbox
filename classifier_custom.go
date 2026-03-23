package agentbox

import (
	"path"
	"strings"
)

// UserRule defines a user-specified command classification rule.
// User rules are evaluated before built-in rules, giving users full control
// over how specific commands are classified. This is inspired by Claude Code's
// permission rules and Codex CLI's approval policy.
type UserRule struct {
	// Pattern is a glob pattern to match against the command string.
	// Supports exact matching and path.Match glob syntax (* and ?).
	// An empty pattern matches nothing.
	// Examples: "npm test", "git push *", "rm -rf *"
	Pattern string `json:"pattern"`

	// Decision is the classification result when the pattern matches.
	Decision Decision `json:"decision"`

	// Description explains why this rule exists (for logging/display).
	Description string `json:"description,omitempty"`
}

// Compile-time interface check.
var _ Classifier = (*customRuleClassifier)(nil)

// customRuleClassifier evaluates user-defined rules against commands.
// It implements the Classifier interface and returns a zero-value
// ClassifyResult (Sandboxed) when no rule matches, allowing ChainClassifier
// to fall through to subsequent classifiers.
type customRuleClassifier struct {
	rules []UserRule
}

// Classify inspects a shell command string against user-defined rules.
// Returns the first matching rule's decision, or a zero-value ClassifyResult
// (Sandboxed) if no rule matches.
func (c *customRuleClassifier) Classify(command string) ClassifyResult {
	return c.match(command)
}

// ClassifyArgs inspects a command specified as program name and argument list.
// The full command is reconstructed by joining name and args with spaces,
// then matched against user-defined rules.
func (c *customRuleClassifier) ClassifyArgs(name string, args []string) ClassifyResult {
	full := name
	if len(args) > 0 {
		full = name + " " + strings.Join(args, " ")
	}
	return c.match(full)
}

// match evaluates user rules against the given command string.
// Rules are evaluated in order; the first match wins.
func (c *customRuleClassifier) match(command string) ClassifyResult {
	for _, rule := range c.rules {
		if matchPattern(rule.Pattern, command) {
			return ClassifyResult{
				Decision: rule.Decision,
				Reason:   "matched custom rule: " + rule.Pattern,
				Rule:     customRuleName(rule),
			}
		}
	}
	return ClassifyResult{}
}

// matchPattern checks if command matches the given pattern.
// For patterns without glob metacharacters (* and ?), it does exact string
// comparison. Otherwise it uses path.Match for glob matching.
// path.Match is used instead of filepath.Match because command strings always
// use forward slashes, regardless of the host OS.
func matchPattern(pattern, command string) bool {
	// Fast path: exact match for patterns without glob characters.
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == command
	}
	matched, err := path.Match(pattern, command)
	if err != nil {
		// Invalid pattern; treat as no match.
		return false
	}
	return matched
}

// customRuleName returns the Rule identifier for a matched user rule.
func customRuleName(rule UserRule) RuleName {
	if rule.Description != "" {
		return RuleName("custom: " + rule.Description)
	}
	return RuleName("custom: " + rule.Pattern)
}

// resolveClassifier returns the effective classifier for a call, considering
// per-call overrides, rule overrides, custom user rules, and protected path
// rules. The resolve chain is:
//
//	custom rules → protected paths → overrideClassifier(base)
//
// Rule overrides wrap the base classifier so that built-in rule decisions can
// be changed without writing glob patterns. Custom rules and protected paths
// are chained on top, meaning they take precedence over overrides.
func resolveClassifier(base Classifier, co *callOptions) Classifier {
	cl := base
	if co.classifier != nil {
		cl = co.classifier
	}
	// Rule overrides wrap the built-in (or per-call) classifier.
	if len(co.ruleOverrides) > 0 {
		m := make(map[RuleName]Decision, len(co.ruleOverrides))
		for _, o := range co.ruleOverrides {
			m[o.Rule] = o.Decision
		}
		cl = &overrideClassifier{base: cl, overrides: m}
	}
	// Protected paths and custom rules chain on top.
	if len(co.protectedPaths) > 0 {
		cl = ChainClassifier(&protectedPathClassifier{paths: co.protectedPaths}, cl)
	}
	if len(co.customRules) > 0 {
		cl = ChainClassifier(&customRuleClassifier{rules: co.customRules}, cl)
	}
	return cl
}
