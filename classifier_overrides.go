package agentbox

// Compile-time interface check.
var _ Classifier = (*overrideClassifier)(nil)

// RuleOverride changes the decision of a specific built-in rule.
// When a rule identified by [RuleName] matches a command, the classifier
// replaces its original decision with the one specified here.
//
// Use Decision: [Sandboxed] to effectively disable a rule — the overridden
// result will be treated as "no match" by [ChainClassifier].
// Note that this disables the specific rule, but does not cause other
// built-in rules to re-evaluate for the same command. Built-in rules are
// evaluated in priority order and only the first matching rule fires;
// overriding it to Sandboxed skips the entire built-in result.
type RuleOverride struct {
	Rule     RuleName `json:"rule"`
	Decision Decision `json:"decision"`
}

// overrideClassifier wraps a base [Classifier] and post-processes results
// by replacing the decision of any rule whose name appears in the overrides
// map.
type overrideClassifier struct {
	base      Classifier
	overrides map[RuleName]Decision
}

// Classify delegates to the base classifier and applies any rule override.
func (c *overrideClassifier) Classify(command string) ClassifyResult {
	return c.apply(c.base.Classify(command))
}

// ClassifyArgs delegates to the base classifier and applies any rule override.
func (c *overrideClassifier) ClassifyArgs(name string, args []string) ClassifyResult {
	return c.apply(c.base.ClassifyArgs(name, args))
}

// apply replaces the decision if the result's rule name is in the overrides map.
// When overriding, the Reason field is updated to indicate the override.
func (c *overrideClassifier) apply(result ClassifyResult) ClassifyResult {
	if d, ok := c.overrides[result.Rule]; ok {
		result.Reason = result.Reason + " (overridden to " + d.String() + ")"
		result.Decision = d
	}
	return result
}
