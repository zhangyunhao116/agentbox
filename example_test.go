package agentbox_test

import (
	"context"
	"fmt"

	"github.com/zhangyunhao116/agentbox"
)

// ExampleNewManager demonstrates creating a sandbox manager with the default
// configuration.
func ExampleNewManager() {
	mgr, err := agentbox.NewManager(agentbox.DefaultConfig())
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer mgr.Close()
	fmt.Println("manager created")
	// Output: manager created
}

// ExampleDefaultClassifier shows how the default classifier categorises
// commands into Allow, Forbidden, Escalated, or Sandboxed decisions.
func ExampleDefaultClassifier() {
	c := agentbox.DefaultClassifier()

	fmt.Println(c.Classify("ls -la").Decision)
	fmt.Println(c.Classify("rm -rf /").Decision)
	fmt.Println(c.Classify("sudo apt install vim").Decision)
	fmt.Println(c.Classify("python3 main.py").Decision)
	// Output:
	// allow
	// forbidden
	// escalated
	// sandboxed
}

// ExampleWithCustomRules demonstrates adding user-defined classification
// rules via WithCustomRules, a per-call Option for Exec, ExecArgs, and Wrap.
// Custom rules are evaluated before built-in rules; the first match wins.
func ExampleWithCustomRules() {
	cfg := agentbox.DefaultConfig()
	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer mgr.Close()

	// WithCustomRules overrides the built-in classifier on a per-call basis.
	// For example, explicitly allow "npm test" and forbid "npm publish *":
	_, _ = mgr.Exec(context.Background(), "npm test",
		agentbox.WithCustomRules(
			agentbox.UserRule{Pattern: "npm test", Decision: agentbox.Allow, Description: "CI test runner"},
			agentbox.UserRule{Pattern: "npm publish *", Decision: agentbox.Forbidden, Description: "no publishing"},
		),
	)
}

// ExampleWithRuleOverrides shows how to change the decision of a specific
// built-in rule using WithRuleOverrides. Here the docker-container rule is
// relaxed from Escalated to Allow so docker commands execute without
// approval prompts.
func ExampleWithRuleOverrides() {
	cfg := agentbox.DefaultConfig()
	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer mgr.Close()

	// Override docker-container from Escalated → Allow for this call only.
	_, _ = mgr.Exec(context.Background(), "docker run --rm ubuntu echo hello",
		agentbox.WithRuleOverrides(agentbox.RuleOverride{
			Rule:     agentbox.RuleDockerContainer,
			Decision: agentbox.Allow,
		}),
	)
}

// ExampleBuiltinRuleNames lists all built-in rule identifiers in evaluation
// order (forbidden → escalated → allow). Use these names with
// WithRuleOverrides to selectively change rule decisions.
func ExampleBuiltinRuleNames() {
	names := agentbox.BuiltinRuleNames()
	fmt.Println("total rules:", len(names))
	fmt.Println("first rule:", names[0])
	// Output:
	// total rules: 45
	// first rule: fork-bomb
}
