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
	// flagForce is the long-form --force flag used in rule matching.
	flagForce = "--force"
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
	// cmdDocker is the docker command name used in container and build rules.
	cmdDocker = "docker"
	// cmdPodman is the podman command name used in container and build rules.
	cmdPodman = "podman"
	// subStash is the git stash subcommand name.
	subStash = "stash"
	// cmdDoas is the doas command name used in privilege escalation rules.
	cmdDoas = "doas"
	// cmdEnv is the env command name used as a prefix wrapper.
	cmdEnv = "env"
	// cmdFind is the find command name used in safe-command and destructive-find rules.
	cmdFind = "find"
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

	// MatchCtx is an optional alternative to Match that receives precomputed
	// command fields (lower, fields, base). When non-nil, classifyOnce calls
	// MatchCtx instead of Match, avoiding redundant strings.Fields /
	// strings.ToLower / baseCommand calls across rules.
	MatchCtx func(ctx *classifyCtx) (ClassifyResult, bool)
}

// ruleClassifier implements Classifier by evaluating an ordered list of Rules.
type ruleClassifier struct {
	rules []rule
}

// classifyOnce runs all rules against a single command string and returns
// the first match. If no rule matches it returns Sandboxed.
// When a rule provides MatchCtx, it is called with a precomputed classifyCtx
// (fields, lower, base) to avoid redundant string operations.
func (c *ruleClassifier) classifyOnce(command string) ClassifyResult {
	ctx := acquireCtx(command)
	defer releaseCtx(ctx)
	for _, r := range c.rules {
		if r.MatchCtx != nil {
			if result, ok := r.MatchCtx(ctx); ok {
				return result
			}
		} else if r.Match != nil {
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

// Classify iterates through rules in order and returns the first match.
// If no rule matches the original command, a normalized form (stripping cd
// prefixes, comments, env vars, safe pipes/redirects) is tried. This
// dual-pass approach improves classification of real-world compound commands
// while preserving safety: forbidden results are always returned immediately.
func (c *ruleClassifier) Classify(command string) ClassifyResult {
	result := c.classifyOnce(command)
	if result.Decision != Sandboxed {
		return result
	}

	// Attempt classification on the normalized form.
	normalized := normalizeForClassification(command)
	if normalized != command {
		normResult := c.classifyOnce(normalized)
		if normResult.Decision == Forbidden {
			return normResult // safety: always honour Forbidden
		}
		if normResult.Decision != Sandboxed {
			normResult.Reason += " (normalized)"
			return normResult
		}
	}

	// Pass 3: try compound chain analysis on the normalized command
	// (which equals the original if normalization was a no-op).
	chainResult := c.classifyCompoundChain(normalized)
	if chainResult.Decision != Sandboxed {
		return chainResult
	}
	return result // all three passes returned Sandboxed
}

// classifyCompoundChain splits a compound command on "&&" and ";" separators,
// classifies each segment independently, and returns an aggregate result.
// If ALL segments are Allow → Allow. If ANY is Forbidden → Forbidden.
// If ANY is Escalated (and none Forbidden) → Escalated. Otherwise → Sandboxed.
// The "||" operator is NOT split because its short-circuit semantics differ.
//
// For single-segment commands that contain quoted metacharacters (e.g.
// echo "a && b"), it attempts classification with quoted content replaced
// by a placeholder so that isSimpleCommand does not reject the harmless
// metacharacters inside quotes.
func (c *ruleClassifier) classifyCompoundChain(command string) ClassifyResult {
	segments := splitCompoundCommand(command)
	if len(segments) <= 1 {
		// Not a compound chain — but the command may contain quoted
		// metacharacters that isSimpleCommand conservatively rejects.
		// Try classifying a quote-sanitized version, but skip sanitize
		// when the command is a scripting runtime executing inline code
		// (the semicolons inside the quoted code ARE significant).
		cleaned := sanitizeQuotedContent(command)
		if cleaned != command && !isInlineCodeExecution(command) {
			r := c.classifyOnce(cleaned)
			if r.Decision == Allow {
				r.Reason += " (quoted metacharacters sanitized)"
				return r
			}
		}
		return ClassifyResult{Decision: Sandboxed, Reason: "not a compound command"}
	}

	// Guard: if splitting may have broken a find -exec ... ; construct,
	// bail out — the ";" was a find terminator, not a command separator.
	if hasExecSemicolonArtifact(segments) {
		return ClassifyResult{Decision: Sandboxed, Reason: "compound split may have broken -exec terminator"}
	}

	highest := Allow // start optimistic
	hasSandboxed := false
	var highestResult ClassifyResult

	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}

		// Safety: if a segment contains command substitution ($() or
		// backticks) or is a subshell (parentheses), the inner command
		// will be executed by the shell but is invisible to our
		// classifier. Treat such segments as unclassifiable.
		if containsCommandSubstitution(seg) {
			hasSandboxed = true
			continue
		}

		// Classify each segment (use classifyOnce, not full Classify to
		// avoid recursion). Also try the normalized form of each segment.
		result := c.classifyOnce(seg)
		if result.Decision == Sandboxed {
			norm := normalizeForClassification(seg)
			if norm != seg {
				result = c.classifyOnce(norm)
			}
		}

		switch result.Decision {
		case Forbidden:
			return result // immediate: any Forbidden → whole chain Forbidden
		case Escalated:
			if highest < Escalated {
				highest = Escalated
				highestResult = result
			}
		case Sandboxed:
			// Mark that we can't fully classify the chain, but continue
			// scanning remaining segments so that Forbidden is still caught.
			hasSandboxed = true
		case Allow:
			if highest == Allow && highestResult.Reason == "" {
				highestResult = result
			}
		}
	}

	// If any segment was unclassified, we can't promote the whole chain.
	if hasSandboxed {
		return ClassifyResult{Decision: Sandboxed, Reason: "compound chain contains unclassified segment"}
	}

	if highest == Allow {
		return ClassifyResult{
			Decision: Allow,
			Reason:   "all segments of compound command are allowed (chain analysis)",
			Rule:     RuleCompoundChainAllow,
		}
	}
	highestResult.Reason += " (compound chain)"
	return highestResult
}

// classifyArgsOnce runs all rules against a parsed command (name + args) and
// falls back to MatchCtx (or Match) with the reconstructed command string.
// Returns the first match or Sandboxed.
func (c *ruleClassifier) classifyArgsOnce(name string, args []string, command string) ClassifyResult {
	// Lazily-initialized: only created when a rule has MatchCtx but no MatchArgs.
	var ctx *classifyCtx
	defer func() {
		if ctx != nil {
			releaseCtx(ctx)
		}
	}()
	for _, r := range c.rules {
		if r.MatchArgs != nil {
			if result, ok := r.MatchArgs(name, args); ok {
				return result
			}
		}
		if r.MatchCtx != nil {
			if ctx == nil {
				ctx = acquireCtx(command)
			}
			if result, ok := r.MatchCtx(ctx); ok {
				return result
			}
		} else if r.Match != nil {
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
// to Match with a reconstructed command string. If no rule matches, a
// normalized form is tried (same dual-pass as Classify).
func (c *ruleClassifier) ClassifyArgs(name string, args []string) ClassifyResult {
	// Build a command string for rules that only implement Match.
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, name)
	parts = append(parts, args...)
	command := strings.Join(parts, " ")

	result := c.classifyArgsOnce(name, args, command)
	if result.Decision != Sandboxed {
		return result
	}

	// Attempt classification on the normalized form.
	normalized := normalizeForClassification(command)
	if normalized == command {
		return result
	}
	normResult := c.classifyOnce(normalized)
	if normResult.Decision == Forbidden {
		return normResult
	}
	if normResult.Decision != Sandboxed {
		normResult.Reason += " (normalized)"
		return normResult
	}
	return result
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
// The shell-wrapper-unwrap rule is placed first among forbidden rules so that
// wrapped commands (e.g. "bash -c 'rm -rf /'") are unwrapped before other
// rules evaluate them. It receives the full rule set (including itself) so
// that double-wrapped commands (e.g. "bash -c 'sh -c \"rm -rf /\"'") are also
// unwrapped. Infinite recursion is prevented by extractShellWrapperInner
// returning false when the inner command is not a shell wrapper.
func defaultRules() []rule {
	core := coreForbiddenRules()
	escalated := escalatedRules()
	allow := allowRules()

	// Pre-allocate the final list: unwrap + core forbidden + escalated + allow.
	rules := make([]rule, 0, 1+len(core)+len(escalated)+len(allow))

	// Placeholder for the unwrap rule at index 0; we'll fill it in after
	// the slice is built so the unwrap rule can reference the full list.
	rules = append(rules, rule{Name: "shell-wrapper-unwrap"})
	rules = append(rules, core...)
	rules = append(rules, escalated...)
	rules = append(rules, allow...)

	// Now create the unwrap rule that re-classifies against the full list.
	rules[0] = shellWrapperUnwrapRule(rules)
	return rules
}

// ---------------------------------------------------------------------------
// Forbidden rules (highest priority)
// ---------------------------------------------------------------------------

// coreForbiddenRules returns all forbidden rules except shell-wrapper-unwrap.
func coreForbiddenRules() []rule {
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
		windowsRecursiveDeleteRule(),
		windowsDelRecursiveRule(),
		windowsFormatRule(),
		powershellDestructiveRule(),
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
		devToolRunRule(),
		buildToolRule(),
		goToolRule(),
		fileManagementRule(),
		textProcessingRule(),
		networkDiagnosticRule(),
		archiveToolRule(),
		shellBuiltinRule(),
		openCommandRule(),
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
		packageInstallRule(),
		backgroundProcessRule(),
		inPlaceEditRule(),
		containerEscapeRule(),
	}
}
