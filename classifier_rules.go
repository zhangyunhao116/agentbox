// classifier_rules.go provides the rule-based classifier infrastructure.
// Rule functions and helpers are split across companion files:
//   - classifier_rules_forbidden.go  — Forbidden-category rules
//   - classifier_rules_escalated.go  — Escalated-category rules
//   - classifier_rules_allow.go      — Allow-category rules
//   - classifier_helpers.go          — Shared utility functions

package agentbox

import (
	"strings"
	"sync"
)

const (
	// homeEnvVar is the $HOME environment variable reference used in rule matching.
	homeEnvVar = "$HOME"
	// homeBraceEnvVar is the ${HOME} environment variable reference used in rule matching.
	homeBraceEnvVar = "${HOME}"
	// flagHelp is the long-form --help flag used in rule matching.
	flagHelp = "--help"
	// flagVersion is the long-form --version flag used in rule matching.
	flagVersion = "--version"
	// flagList is the long-form --list flag used in rule matching.
	flagList = "--list"
	// flagRecursive is the long-form --recursive flag used in rule matching.
	flagRecursive = "--recursive"
	// cmdPython is the interpreter name used to exempt safe python pipe targets.
	cmdPython = "python"
	// cmdPython3 is the interpreter name used to exempt safe python3 pipe targets.
	cmdPython3 = "python3"
	// ruleSudo is the rule name for the sudo/doas privilege escalation rule.
	// It is also used for command matching (cmd == "sudo"), so it stays as
	// an untyped string constant rather than RuleName.
	ruleSudo = "sudo"
	// cmdGit is the git command name used in git-read and git-write rules.
	cmdGit = "git"
	// cmdCurl is the curl command name used in download and pipe rules.
	cmdCurl = "curl"
	// cmdWget is the wget command name used in download and pipe rules.
	cmdWget = "wget"
	// cmdRedisCLI is the redis-cli command name used in database rules.
	cmdRedisCLI = "redis-cli"
	// subStash is the git stash subcommand name.
	subStash = "stash"
)

// Compile-time interface checks for classifier types in this file.
var (
	_ Classifier = (*ruleClassifier)(nil)
	_ Classifier = (*chainClassifier)(nil)
)

// rule defines a single classification rule. Each rule has a Name and one or
// both match functions. Match operates on a raw shell command string while
// MatchArgs operates on a parsed program name and argument list.
type rule struct {
	// Name is a short, unique identifier for this rule (e.g. "fork-bomb").
	Name RuleName

	// Match inspects a raw shell command string. It returns a ClassifyResult
	// and true if the rule matches, or a zero value and false otherwise.
	Match func(command string) (ClassifyResult, bool)

	// MatchArgs inspects a parsed command (program name + args). It returns a
	// ClassifyResult and true if the rule matches, or a zero value and false
	// otherwise.
	MatchArgs func(name string, args []string) (ClassifyResult, bool)
}

// ruleClassifier implements Classifier by evaluating an ordered list of Rules.
type ruleClassifier struct {
	rules []rule
}

// Classify iterates through rules in order and returns the first match.
// If no rule matches the command is classified as Sandboxed.
func (c *ruleClassifier) Classify(command string) ClassifyResult {
	for _, r := range c.rules {
		if r.Match != nil {
			if result, ok := r.Match(command); ok {
				return result
			}
		}
	}
	return ClassifyResult{
		Decision: Sandboxed,
		Reason:   "no rule matched; defaulting to sandboxed execution",
	}
}

// ClassifyArgs iterates through rules in order using MatchArgs, falling back
// to Match with a reconstructed command string. If no rule matches the command
// is classified as Sandboxed.
func (c *ruleClassifier) ClassifyArgs(name string, args []string) ClassifyResult {
	// Build a command string for rules that only implement Match.
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, name)
	parts = append(parts, args...)
	command := strings.Join(parts, " ")

	for _, r := range c.rules {
		if r.MatchArgs != nil {
			if result, ok := r.MatchArgs(name, args); ok {
				return result
			}
		}
		if r.Match != nil {
			if result, ok := r.Match(command); ok {
				return result
			}
		}
	}
	return ClassifyResult{
		Decision: Sandboxed,
		Reason:   "no rule matched; defaulting to sandboxed execution",
	}
}

// chainClassifier chains multiple Classifier implementations. The first
// non-Sandboxed result wins; if all return Sandboxed the last Sandboxed
// result is returned.
type chainClassifier struct {
	classifiers []Classifier
}

// Classify delegates to each chained classifier in order.
func (c *chainClassifier) Classify(command string) ClassifyResult {
	var last ClassifyResult
	if len(c.classifiers) == 0 {
		return ClassifyResult{
			Decision: Sandboxed,
			Reason:   "no classifiers in chain; defaulting to sandboxed execution",
		}
	}
	for _, cl := range c.classifiers {
		result := cl.Classify(command)
		if result.Decision != Sandboxed {
			return result
		}
		last = result
	}
	return last
}

// ClassifyArgs delegates to each chained classifier in order.
func (c *chainClassifier) ClassifyArgs(name string, args []string) ClassifyResult {
	var last ClassifyResult
	if len(c.classifiers) == 0 {
		return ClassifyResult{
			Decision: Sandboxed,
			Reason:   "no classifiers in chain; defaulting to sandboxed execution",
		}
	}
	for _, cl := range c.classifiers {
		result := cl.ClassifyArgs(name, args)
		if result.Decision != Sandboxed {
			return result
		}
		last = result
	}
	return last
}

// ChainClassifier returns a Classifier that evaluates multiple classifiers in
// order. The first non-Sandboxed result wins. If every classifier returns
// Sandboxed the final Sandboxed result is returned.
func ChainClassifier(classifiers ...Classifier) Classifier {
	return &chainClassifier{classifiers: classifiers}
}

// defaultClassifier caches the singleton DefaultClassifier instance.
var (
	defaultClassifierOnce sync.Once
	defaultClassifierInst Classifier
)

// DefaultClassifier returns a Classifier pre-loaded with the built-in rules.
// Rules are evaluated in priority order: forbidden, escalated, allow.
// The classifier is stateless and immutable, so it is cached after first creation.
func DefaultClassifier() Classifier {
	defaultClassifierOnce.Do(func() {
		defaultClassifierInst = &ruleClassifier{rules: defaultRules()}
	})
	return defaultClassifierInst
}

// defaultRules returns the built-in rules in priority order.
func defaultRules() []rule {
	forbidden := forbiddenRules()
	escalated := escalatedRules()
	allow := allowRules()
	rules := make([]rule, 0, len(forbidden)+len(escalated)+len(allow))
	rules = append(rules, forbidden...)
	rules = append(rules, escalated...)
	rules = append(rules, allow...)
	return rules
}

// ---------------------------------------------------------------------------
// Forbidden rules (highest priority)
// ---------------------------------------------------------------------------

func forbiddenRules() []rule {
	return []rule{
		forkBombRule(),
		recursiveDeleteRootRule(),
		diskWipeRule(),
		reverseShellRule(),
		recursivePermRootRule(),
		filesystemFormatRule(),
		pipeToShellRule(),
		ifsBypassRule(),
		shutdownRebootRule(),
		kernelModuleRule(),
		partitionManagementRule(),
		historyExecRule(),
		destructiveFindRule(),
		destructiveXargsRule(),
		outputRedirectSystemRule(),
	}
}

// ---------------------------------------------------------------------------
// Allow rules (safe commands)
// ---------------------------------------------------------------------------

func allowRules() []rule {
	return []rule{
		commonSafeCommandsRule(),
		gitReadCommandsRule(),
		versionCheckRule(),
		windowsSafeCommandsRule(),
		cdSleepRule(),
		processListRule(),
	}
}

// ---------------------------------------------------------------------------
// Escalated rules
// ---------------------------------------------------------------------------

func escalatedRules() []rule {
	return []rule{
		sudoRule(),
		suPrivilegeRule(),
		credentialAccessRule(),
		userManagementRule(),
		globalInstallRule(),
		dockerBuildRule(),
		dockerContainerRule(),
		dockerComposeRule(),
		kubernetesRule(),
		systemPackageInstallRule(),
		processKillRule(),
		gitWriteRule(),
		sshCommandRule(),
		fileTransferRule(),
		downloadToFileRule(),
		serviceManagementRule(),
		crontabAtRule(),
		filePermissionRule(),
		firewallManagementRule(),
		networkScanRule(),
		databaseBackupRule(),
		databaseClientRule(),
		gitStashDropRule(),
		evalExecRule(),
	}
}
