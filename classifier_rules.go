package agentbox

import (
	"path"
	"strings"
	"sync"
)

const (
	// homeEnvVar is the $HOME environment variable reference used in rule matching.
	homeEnvVar = "$HOME"
	// homeBraceEnvVar is the ${HOME} environment variable reference used in rule matching.
	homeBraceEnvVar = "${HOME}"
	// flagRecursive is the long-form --recursive flag used in rule matching.
	flagRecursive = "--recursive"
)

// rule defines a single classification rule. Each rule has a Name and one or
// both match functions. Match operates on a raw shell command string while
// MatchArgs operates on a parsed program name and argument list.
type rule struct {
	// Name is a short, unique identifier for this rule (e.g. "fork-bomb").
	Name string

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
// Rules are evaluated in priority order: forbidden, allow, escalated.
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
	allow := allowRules()
	escalated := escalatedRules()
	rules := make([]rule, 0, len(forbidden)+len(allow)+len(escalated))
	rules = append(rules, forbidden...)
	rules = append(rules, allow...)
	rules = append(rules, escalated...)
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
		chmodRecursiveRootRule(),
		chownRecursiveRootRule(),
		filesystemFormatRule(),
		curlPipeShellRule(),
	}
}

func forkBombRule() rule {
	forkBombMatch := func(command string) (ClassifyResult, bool) {
		// Classic fork bomb patterns with various spacing.
		if strings.Contains(command, ":(){ :|:& };:") ||
			strings.Contains(command, ":(){ :|: & };:") {
			return ClassifyResult{
				Decision: Forbidden,
				Reason:   "fork bomb detected",
				Rule:     "fork-bomb",
			}, true
		}
		// Detect renamed fork bomb functions: <name>(){ <name>|<name>& };<name>
		// Normalize whitespace for matching.
		normalized := strings.Join(strings.Fields(command), " ")
		if (strings.Contains(normalized, "(){") || strings.Contains(normalized, "() {")) &&
			(strings.Contains(normalized, "& };") || strings.Contains(normalized, "&};")) {
			// Look for pattern: X(){ X|X& };X or X(){ X | X & };X
			for _, seg := range strings.Split(normalized, ";") {
				seg = strings.TrimSpace(seg)
				// Try both "() {" and "(){" patterns.
				idx := strings.Index(seg, "() {")
				if idx <= 0 {
					idx = strings.Index(seg, "(){")
				}
				if idx > 0 {
					fname := strings.TrimSpace(seg[:idx])
					// Skip past the "(){" or "() {" to get the body.
					bodyStart := strings.Index(seg[idx:], "{")
					if bodyStart < 0 {
						continue
					}
					body := seg[idx+bodyStart+1:]
					body = strings.TrimSuffix(strings.TrimSpace(body), "}")
					body = strings.TrimSpace(body)
					// Check body contains fname|fname pattern.
					if strings.Contains(body, fname+"|"+fname) ||
						strings.Contains(body, fname+" | "+fname) ||
						strings.Contains(body, fname+" |"+fname) ||
						strings.Contains(body, fname+"| "+fname) {
						return ClassifyResult{
							Decision: Forbidden,
							Reason:   "fork bomb detected",
							Rule:     "fork-bomb",
						}, true
					}
				}
			}
		}
		return ClassifyResult{}, false
	}

	return rule{
		Name:  "fork-bomb",
		Match: forkBombMatch,
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			// Fork bombs are inherently string-based; reconstruct and delegate.
			parts := make([]string, 0, 1+len(args))
			parts = append(parts, name)
			parts = append(parts, args...)
			return forkBombMatch(strings.Join(parts, " "))
		},
	}
}

//nolint:gocyclo // complexity is inherent to matching multiple rm flag combinations
func recursiveDeleteRootRule() rule {
	return rule{
		Name: "recursive-delete-root",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if baseCommand(fields[0]) != "rm" {
				return ClassifyResult{}, false
			}
			// Check for recursive+force flags.
			hasRecursive := false
			hasForce := false
			for _, f := range fields[1:] {
				if f == "--" {
					break
				}
				if strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "--") {
					if strings.Contains(f, "r") || strings.Contains(f, "R") {
						hasRecursive = true
					}
					if strings.Contains(f, "f") {
						hasForce = true
					}
				}
				if f == flagRecursive {
					hasRecursive = true
				}
				if f == "--force" {
					hasForce = true
				}
			}
			if !hasRecursive || !hasForce {
				return ClassifyResult{}, false
			}
			// Check for dangerous targets using path normalization.
			for _, f := range fields[1:] {
				if isDangerousTarget(f) {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "recursive deletion of root or home directory",
						Rule:     "recursive-delete-root",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if base != "rm" {
				return ClassifyResult{}, false
			}
			hasRecursive := false
			hasForce := false
			for _, a := range args {
				if a == "--" {
					break
				}
				if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
					if strings.Contains(a, "r") || strings.Contains(a, "R") {
						hasRecursive = true
					}
					if strings.Contains(a, "f") {
						hasForce = true
					}
				}
				if a == flagRecursive {
					hasRecursive = true
				}
				if a == "--force" {
					hasForce = true
				}
			}
			if !hasRecursive || !hasForce {
				return ClassifyResult{}, false
			}
			for _, a := range args {
				if isDangerousTarget(a) {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "recursive deletion of root or home directory",
						Rule:     "recursive-delete-root",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
	}
}

func diskWipeRule() rule {
	return rule{
		Name: "disk-wipe",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if baseCommand(fields[0]) != "dd" {
				return ClassifyResult{}, false
			}
			for _, f := range fields {
				if isDangerousDDTarget(f) {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "dd writing to block device detected",
						Rule:     "disk-wipe",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if base != "dd" {
				return ClassifyResult{}, false
			}
			for _, a := range args {
				if isDangerousDDTarget(a) {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "dd writing to block device detected",
						Rule:     "disk-wipe",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
	}
}

func reverseShellRule() rule {
	return rule{
		Name: "reverse-shell",
		Match: func(command string) (ClassifyResult, bool) {
			lower := strings.ToLower(command)
			checkers := []func() (ClassifyResult, bool){
				func() (ClassifyResult, bool) { return rsDevTCP(command) },
				func() (ClassifyResult, bool) { return rsNC(lower) },
				func() (ClassifyResult, bool) { return rsNcat(lower) },
				func() (ClassifyResult, bool) { return rsPythonSocket(lower) },
				func() (ClassifyResult, bool) { return rsPerlSocket(lower) },
				func() (ClassifyResult, bool) { return rsSocat(lower) },
				func() (ClassifyResult, bool) { return rsRuby(lower) },
				func() (ClassifyResult, bool) { return rsPHP(lower) },
				func() (ClassifyResult, bool) { return rsTelnetPipe(lower, command) },
				func() (ClassifyResult, bool) { return rsOpenSSLPipe(lower, command) },
			}
			for _, check := range checkers {
				if res, ok := check(); ok {
					return res, true
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			allArgs := strings.Join(args, " ")
			lower := strings.ToLower(allArgs)
			base := baseCommand(name)
			baseLower := strings.ToLower(base)
			checkers := []func() (ClassifyResult, bool){
				func() (ClassifyResult, bool) { return rsArgsDevTCP(args) },
				func() (ClassifyResult, bool) { return rsArgsNCExec(baseLower, args) },
				func() (ClassifyResult, bool) { return rsArgsSocat(baseLower, args) },
				func() (ClassifyResult, bool) { return rsArgsRuby(baseLower, lower) },
				func() (ClassifyResult, bool) { return rsArgsPHP(baseLower, lower) },
				func() (ClassifyResult, bool) { return rsArgsPython(baseLower, lower) },
				func() (ClassifyResult, bool) { return rsArgsPerl(baseLower, lower) },
			}
			for _, check := range checkers {
				if res, ok := check(); ok {
					return res, true
				}
			}
			return ClassifyResult{}, false
		},
	}
}

// rsResult is a convenience constructor for forbidden reverse-shell results.
func rsResult(reason string) (ClassifyResult, bool) {
	return ClassifyResult{
		Decision: Forbidden,
		Reason:   reason,
		Rule:     "reverse-shell",
	}, true
}

// rsDevTCP detects /dev/tcp and /dev/udp reverse shells in a command string.
func rsDevTCP(command string) (ClassifyResult, bool) {
	if strings.Contains(command, "/dev/tcp/") || strings.Contains(command, "/dev/udp/") {
		return rsResult("reverse shell via /dev/tcp or /dev/udp detected")
	}
	return ClassifyResult{}, false
}

// rsNC detects nc -e or nc -c (netcat execute) reverse shells.
func rsNC(lower string) (ClassifyResult, bool) {
	if strings.Contains(lower, "nc ") && (strings.Contains(lower, " -e") || strings.Contains(lower, " -c")) {
		return rsResult("reverse shell via nc detected")
	}
	return ClassifyResult{}, false
}

// rsNcat detects ncat -e, ncat -c, or ncat --exec reverse shells.
func rsNcat(lower string) (ClassifyResult, bool) {
	if strings.Contains(lower, "ncat ") && (strings.Contains(lower, " -e") || strings.Contains(lower, " -c") || strings.Contains(lower, " --exec")) {
		return rsResult("reverse shell via ncat detected")
	}
	return ClassifyResult{}, false
}

// rsPythonSocket detects Python socket-based reverse shells.
func rsPythonSocket(lower string) (ClassifyResult, bool) {
	if strings.Contains(lower, "python") && strings.Contains(lower, "import socket") {
		return rsResult("reverse shell via python socket detected")
	}
	return ClassifyResult{}, false
}

// rsPerlSocket detects Perl socket-based reverse shells.
func rsPerlSocket(lower string) (ClassifyResult, bool) {
	if strings.Contains(lower, "perl") && strings.Contains(lower, "use socket") {
		return rsResult("reverse shell via perl socket detected")
	}
	return ClassifyResult{}, false
}

// rsSocat detects socat with exec and tcp/ssl patterns.
func rsSocat(lower string) (ClassifyResult, bool) {
	if strings.Contains(lower, "socat") &&
		(strings.Contains(lower, "exec") || strings.Contains(lower, "system")) &&
		(strings.Contains(lower, "tcp") || strings.Contains(lower, "ssl")) {
		return rsResult("reverse shell via socat detected")
	}
	return ClassifyResult{}, false
}

// rsRuby detects Ruby reverse shells using -rsocket or TCPSocket.
func rsRuby(lower string) (ClassifyResult, bool) {
	if strings.Contains(lower, "ruby") &&
		(strings.Contains(lower, "-rsocket") || strings.Contains(lower, "tcpsocket")) {
		return rsResult("reverse shell via ruby detected")
	}
	return ClassifyResult{}, false
}

// rsPHP detects PHP reverse shells using fsockopen.
func rsPHP(lower string) (ClassifyResult, bool) {
	if strings.Contains(lower, "php") && strings.Contains(lower, "fsockopen") {
		return rsResult("reverse shell via php detected")
	}
	return ClassifyResult{}, false
}

// rsTelnetPipe detects telnet piped to a shell.
func rsTelnetPipe(lower, command string) (ClassifyResult, bool) {
	if strings.Contains(lower, "telnet") && strings.Contains(command, "|") && containsPipeToShell(command) {
		return rsResult("reverse shell via telnet pipe detected")
	}
	return ClassifyResult{}, false
}

// rsOpenSSLPipe detects openssl s_client piped to a shell.
func rsOpenSSLPipe(lower, command string) (ClassifyResult, bool) {
	if strings.Contains(lower, "openssl") && strings.Contains(lower, "s_client") &&
		strings.Contains(command, "|") && containsPipeToShell(command) {
		return rsResult("reverse shell via openssl pipe detected")
	}
	return ClassifyResult{}, false
}

// rsArgsDevTCP detects /dev/tcp and /dev/udp patterns in argument list.
func rsArgsDevTCP(args []string) (ClassifyResult, bool) {
	for _, a := range args {
		if strings.Contains(a, "/dev/tcp/") || strings.Contains(a, "/dev/udp/") {
			return rsResult("reverse shell via /dev/tcp or /dev/udp detected")
		}
	}
	return ClassifyResult{}, false
}

// rsArgsNCExec detects nc/ncat/netcat -e/-c/--exec patterns in arguments.
func rsArgsNCExec(baseLower string, args []string) (ClassifyResult, bool) {
	if baseLower == "nc" || baseLower == "ncat" || baseLower == "netcat" {
		for _, a := range args {
			if a == "-e" || a == "-c" || a == "--exec" {
				return rsResult("reverse shell via " + baseLower + " detected")
			}
		}
	}
	return ClassifyResult{}, false
}

// rsArgsSocat detects socat with exec and tcp/ssl in arguments.
func rsArgsSocat(baseLower string, args []string) (ClassifyResult, bool) {
	if baseLower != "socat" {
		return ClassifyResult{}, false
	}
	hasExec := false
	hasTCP := false
	for _, a := range args {
		la := strings.ToLower(a)
		if strings.Contains(la, "exec") || strings.Contains(la, "system") {
			hasExec = true
		}
		if strings.Contains(la, "tcp") || strings.Contains(la, "ssl") {
			hasTCP = true
		}
	}
	if hasExec && hasTCP {
		return rsResult("reverse shell via socat detected")
	}
	return ClassifyResult{}, false
}

// rsArgsRuby detects Ruby reverse shells in arguments.
func rsArgsRuby(baseLower, lower string) (ClassifyResult, bool) {
	if baseLower == "ruby" && (strings.Contains(lower, "-rsocket") || strings.Contains(lower, "tcpsocket")) {
		return rsResult("reverse shell via ruby detected")
	}
	return ClassifyResult{}, false
}

// rsArgsPHP detects PHP reverse shells in arguments.
func rsArgsPHP(baseLower, lower string) (ClassifyResult, bool) {
	if baseLower == "php" && strings.Contains(lower, "fsockopen") {
		return rsResult("reverse shell via php detected")
	}
	return ClassifyResult{}, false
}

// rsArgsPython detects Python socket reverse shells in arguments.
func rsArgsPython(baseLower, lower string) (ClassifyResult, bool) {
	if strings.Contains(baseLower, "python") && strings.Contains(lower, "import socket") {
		return rsResult("reverse shell via python socket detected")
	}
	return ClassifyResult{}, false
}

// rsArgsPerl detects Perl socket reverse shells in arguments.
func rsArgsPerl(baseLower, lower string) (ClassifyResult, bool) {
	if baseLower == "perl" && strings.Contains(lower, "use socket") {
		return rsResult("reverse shell via perl socket detected")
	}
	return ClassifyResult{}, false
}

func chmodRecursiveRootRule() rule {
	return rule{
		Name: "chmod-recursive-root",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if baseCommand(fields[0]) != "chmod" {
				return ClassifyResult{}, false
			}
			cmd := strings.Join(fields, " ")
			if !strings.Contains(cmd, "-R") && !strings.Contains(cmd, flagRecursive) {
				return ClassifyResult{}, false
			}
			// Check for root or home targets.
			for _, f := range fields {
				if isDangerousTarget(f) {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "recursive chmod on root or home directory",
						Rule:     "chmod-recursive-root",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if base != "chmod" {
				return ClassifyResult{}, false
			}
			hasRecursive := false
			for _, a := range args {
				if a == "-R" || a == flagRecursive {
					hasRecursive = true
				} else if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
					// Check for R in bundled short flags like -vR, -Rv.
					if strings.Contains(a, "R") {
						hasRecursive = true
					}
				}
			}
			if !hasRecursive {
				return ClassifyResult{}, false
			}
			for _, a := range args {
				if isDangerousTarget(a) {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "recursive chmod on root or home directory",
						Rule:     "chmod-recursive-root",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
	}
}

func chownRecursiveRootRule() rule {
	return rule{
		Name: "chown-recursive-root",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if baseCommand(fields[0]) != "chown" {
				return ClassifyResult{}, false
			}
			cmd := strings.Join(fields, " ")
			if !strings.Contains(cmd, "-R") && !strings.Contains(cmd, flagRecursive) {
				return ClassifyResult{}, false
			}
			// Check for root or home targets.
			for _, f := range fields {
				if isDangerousTarget(f) {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "recursive chown on root or home directory",
						Rule:     "chown-recursive-root",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if base != "chown" {
				return ClassifyResult{}, false
			}
			hasRecursive := false
			for _, a := range args {
				if a == "-R" || a == flagRecursive {
					hasRecursive = true
				} else if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
					// Check for R in bundled short flags like -vR, -Rv.
					if strings.Contains(a, "R") {
						hasRecursive = true
					}
				}
			}
			if !hasRecursive {
				return ClassifyResult{}, false
			}
			for _, a := range args {
				if isDangerousTarget(a) {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "recursive chown on root or home directory",
						Rule:     "chown-recursive-root",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
	}
}

func filesystemFormatRule() rule {
	return rule{
		Name: "filesystem-format",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			return checkFilesystemFormat(base, fields[1:])
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			return checkFilesystemFormat(base, args)
		},
	}
}

func checkFilesystemFormat(base string, args []string) (ClassifyResult, bool) {
	result := ClassifyResult{
		Decision: Forbidden,
		Rule:     "filesystem-format",
	}
	// shred is always destructive.
	if base == "shred" {
		result.Reason = "shred command detected"
		return result, true
	}
	// mkfs and variants (mkfs.ext4, mkfs.xfs, etc.)
	if base == "mkfs" || strings.HasPrefix(base, "mkfs.") {
		result.Reason = "filesystem format command detected"
		return result, true
	}
	// fdisk and parted: only read-only usage (-l/--list) is safe.
	// The -l/--list flag makes the entire invocation read-only regardless of
	// other arguments, so its presence alone is sufficient to allow the command.
	if base == "fdisk" || base == "parted" {
		for _, a := range args {
			if a == "-l" || a == "--list" {
				return ClassifyResult{}, false
			}
		}
		result.Reason = base + " partition manipulation detected"
		return result, true
	}
	return ClassifyResult{}, false
}

func curlPipeShellRule() rule {
	shells := []string{"sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "node"}
	return rule{
		Name: "curl-pipe-shell",
		Match: func(command string) (ClassifyResult, bool) {
			lower := strings.ToLower(command)
			hasFetcher := strings.Contains(lower, "curl") || strings.Contains(lower, "wget")
			if !hasFetcher {
				return ClassifyResult{}, false
			}
			if !strings.Contains(command, "|") {
				return ClassifyResult{}, false
			}
			// Check if the pipe target is a shell.
			parts := strings.Split(command, "|")
			for _, part := range parts[1:] {
				trimmed := strings.TrimSpace(part)
				fields := strings.Fields(trimmed)
				if len(fields) == 0 {
					continue
				}
				target := baseCommand(fields[0])
				for _, sh := range shells {
					if target == sh {
						return ClassifyResult{
							Decision: Forbidden,
							Reason:   "piping remote content to a shell is dangerous",
							Rule:     "curl-pipe-shell",
						}, true
					}
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			// Reconstruct the command and delegate to Match-style logic,
			// since pipes are shell constructs that appear in the raw string.
			base := baseCommand(name)
			lower := strings.ToLower(base)
			isFetcher := lower == "curl" || lower == "wget"
			if !isFetcher {
				return ClassifyResult{}, false
			}
			// Check if any arg contains a pipe to a shell.
			full := base + " " + strings.Join(args, " ")
			if !strings.Contains(full, "|") {
				return ClassifyResult{}, false
			}
			parts := strings.Split(full, "|")
			for _, part := range parts[1:] {
				trimmed := strings.TrimSpace(part)
				fields := strings.Fields(trimmed)
				if len(fields) == 0 {
					continue
				}
				target := baseCommand(fields[0])
				for _, sh := range shells {
					if target == sh {
						return ClassifyResult{
							Decision: Forbidden,
							Reason:   "piping remote content to a shell is dangerous",
							Rule:     "curl-pipe-shell",
						}, true
					}
				}
			}
			return ClassifyResult{}, false
		},
	}
}

// ---------------------------------------------------------------------------
// Allow rules (safe commands)
// ---------------------------------------------------------------------------

// commonSafeCommands is the set of commands considered safe for Allow.
var commonSafeCommands = map[string]bool{
	"ls": true, "cat": true, "echo": true, "pwd": true,
	"whoami": true, "date": true, "head": true, "tail": true,
	"wc": true, "sort": true, "uniq": true, "grep": true,
	"which": true, "file": true, "basename": true,
	"dirname": true, "realpath": true, "stat": true, "du": true,
	"df": true, "printenv": true, "id": true,
	"uname": true, "hostname": true, "true": true, "false": true,
}

// gitReadSubcommands lists git subcommands that are read-only.
var gitReadSubcommands = map[string]bool{
	"status": true, "log": true, "diff": true, "show": true,
	"branch": true, "tag": true,
}

func allowRules() []rule {
	return []rule{
		commonSafeCommandsRule(),
		gitReadCommandsRule(),
	}
}

func commonSafeCommandsRule() rule {
	return rule{
		Name: "common-safe-commands",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(fields[0])
			if commonSafeCommands[cmd] {
				return ClassifyResult{
					Decision: Allow,
					Reason:   "command is in the safe-commands list",
					Rule:     "common-safe-commands",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if commonSafeCommands[cmd] {
				return ClassifyResult{
					Decision: Allow,
					Reason:   "command is in the safe-commands list",
					Rule:     "common-safe-commands",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

func gitReadCommandsRule() rule {
	return rule{
		Name: "git-read-commands",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			if baseCommand(fields[0]) != "git" {
				return ClassifyResult{}, false
			}
			sub := fields[1]
			if gitReadSubcommands[sub] {
				return ClassifyResult{
					Decision: Allow,
					Reason:   "git read-only command",
					Rule:     "git-read-commands",
				}, true
			}
			// git remote -v
			if sub == "remote" && len(fields) >= 3 && fields[2] == "-v" {
				return ClassifyResult{
					Decision: Allow,
					Reason:   "git read-only command",
					Rule:     "git-read-commands",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if baseCommand(name) != "git" {
				return ClassifyResult{}, false
			}
			if len(args) == 0 {
				return ClassifyResult{}, false
			}
			sub := args[0]
			if gitReadSubcommands[sub] {
				return ClassifyResult{
					Decision: Allow,
					Reason:   "git read-only command",
					Rule:     "git-read-commands",
				}, true
			}
			if sub == "remote" && len(args) >= 2 && args[1] == "-v" {
				return ClassifyResult{
					Decision: Allow,
					Reason:   "git read-only command",
					Rule:     "git-read-commands",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

// ---------------------------------------------------------------------------
// Escalated rules
// ---------------------------------------------------------------------------

func escalatedRules() []rule {
	return []rule{
		globalInstallRule(),
		dockerBuildRule(),
		systemPackageInstallRule(),
	}
}

//nolint:gocyclo // complexity is inherent to matching multiple package manager patterns
func globalInstallRule() rule {
	return rule{
		Name: "global-install",
		Match: func(command string) (ClassifyResult, bool) {
			cmd := strings.Join(strings.Fields(command), " ")

			// npm install -g / npm i -g
			if (strings.Contains(cmd, "npm install") || strings.Contains(cmd, "npm i ")) &&
				strings.Contains(cmd, " -g") {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "global npm install requires approval",
					Rule:     "global-install",
				}, true
			}

			// yarn global add
			if strings.Contains(cmd, "yarn global add") {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "global yarn install requires approval",
					Rule:     "global-install",
				}, true
			}

			// pip install (without --user or venv indicators)
			if strings.Contains(cmd, "pip install") || strings.Contains(cmd, "pip3 install") {
				if !strings.Contains(cmd, "--user") &&
					!strings.Contains(cmd, "venv") &&
					!strings.Contains(cmd, "virtualenv") {
					return ClassifyResult{
						Decision: Escalated,
						Reason:   "pip install without --user or virtualenv requires approval",
						Rule:     "global-install",
					}, true
				}
			}

			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)

			// npm install -g
			if base == "npm" && len(args) >= 2 {
				hasInstall := args[0] == "install" || args[0] == "i"
				hasGlobal := false
				for _, a := range args {
					if a == "-g" || a == "--global" {
						hasGlobal = true
					}
				}
				if hasInstall && hasGlobal {
					return ClassifyResult{
						Decision: Escalated,
						Reason:   "global npm install requires approval",
						Rule:     "global-install",
					}, true
				}
			}

			// yarn global add
			if base == "yarn" && len(args) >= 2 && args[0] == "global" && args[1] == "add" {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "global yarn install requires approval",
					Rule:     "global-install",
				}, true
			}

			// pip install
			if (base == "pip" || base == "pip3") && len(args) >= 1 && args[0] == "install" {
				hasUser := false
				hasVenv := false
				for _, a := range args {
					if a == "--user" {
						hasUser = true
					}
					if strings.Contains(a, "venv") || strings.Contains(a, "virtualenv") {
						hasVenv = true
					}
				}
				if !hasUser && !hasVenv {
					return ClassifyResult{
						Decision: Escalated,
						Reason:   "pip install without --user or virtualenv requires approval",
						Rule:     "global-install",
					}, true
				}
			}

			return ClassifyResult{}, false
		},
	}
}

func dockerBuildRule() rule {
	return rule{
		Name: "docker-build",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if base != "docker" {
				return ClassifyResult{}, false
			}
			sub := fields[1]
			if sub == "build" || sub == "push" || sub == "pull" {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "docker " + sub + " requires approval",
					Rule:     "docker-build",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if baseCommand(name) != "docker" || len(args) == 0 {
				return ClassifyResult{}, false
			}
			sub := args[0]
			if sub == "build" || sub == "push" || sub == "pull" {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "docker " + sub + " requires approval",
					Rule:     "docker-build",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

func systemPackageInstallRule() rule {
	// Map of package manager base command to the subcommand(s) that trigger escalation.
	type pkgMgr struct {
		cmd  string
		subs []string
	}
	managers := []pkgMgr{
		{"brew", []string{"install"}},
		{"apt", []string{"install"}},
		{"apt-get", []string{"install"}},
		{"yum", []string{"install"}},
		{"dnf", []string{"install"}},
	}

	return rule{
		Name: "system-package-install",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			for _, m := range managers {
				if base == m.cmd {
					for _, sub := range m.subs {
						if fields[1] == sub {
							return ClassifyResult{
								Decision: Escalated,
								Reason:   base + " " + sub + " requires approval",
								Rule:     "system-package-install",
							}, true
						}
					}
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if len(args) == 0 {
				return ClassifyResult{}, false
			}
			for _, m := range managers {
				if base == m.cmd {
					for _, sub := range m.subs {
						if args[0] == sub {
							return ClassifyResult{
								Decision: Escalated,
								Reason:   base + " " + sub + " requires approval",
								Rule:     "system-package-install",
							}, true
						}
					}
				}
			}
			return ClassifyResult{}, false
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// baseCommand extracts the base name from a possibly path-qualified command.
// Trailing slashes are stripped before extracting the base name.
func baseCommand(cmd string) string {
	cmd = strings.TrimRight(cmd, "/")
	if cmd == "" {
		return ""
	}
	idx := strings.LastIndex(cmd, "/")
	if idx >= 0 {
		return cmd[idx+1:]
	}
	return cmd
}

// isDangerousDDTarget returns true if the argument is a dd of= parameter
// targeting a block device. Safe pseudo-devices (/dev/null, /dev/zero,
// /dev/stdout, /dev/stderr) are excluded.
func isDangerousDDTarget(arg string) bool {
	if !strings.HasPrefix(arg, "of=/dev/") {
		return false
	}
	// Allow safe pseudo-devices.
	safeTargets := []string{
		"of=/dev/null",
		"of=/dev/zero",
		"of=/dev/stdout",
		"of=/dev/stderr",
	}
	for _, safe := range safeTargets {
		if arg == safe {
			return false
		}
	}
	return strings.HasPrefix(arg, "of=/dev/sd") ||
		strings.HasPrefix(arg, "of=/dev/nvme") ||
		strings.HasPrefix(arg, "of=/dev/hd") ||
		strings.HasPrefix(arg, "of=/dev/vd") ||
		strings.HasPrefix(arg, "of=/dev/xvd") ||
		strings.HasPrefix(arg, "of=/dev/loop") ||
		strings.HasPrefix(arg, "of=/dev/dm-") ||
		strings.HasPrefix(arg, "of=/dev/mmcblk") ||
		strings.HasPrefix(arg, "of=/dev/md")
}

// isDangerousTarget returns true if the argument, after path normalization,
// matches a dangerous root or home directory target.
// path.Clean normalizes patterns like "///", "/./", etc.
// Glob patterns like "/*" and "~/*" are checked explicitly since
// path.Clean does not reduce the trailing wildcard.
func isDangerousTarget(arg string) bool {
	cleaned := path.Clean(arg)
	switch cleaned {
	case "/", "~", "/*", "~/*", homeEnvVar, homeBraceEnvVar:
		return true
	}
	// Traversal from home-like prefixes is dangerous because the classifier
	// cannot resolve ~ or $HOME. "~/../" could escape to the parent of the
	// home directory; treat conservatively as dangerous.
	// We check for ".." as a path segment (not substring) to avoid false
	// positives on names like "~/..cache" or "$HOME_DIR/..".
	for _, prefix := range []string{"~", homeEnvVar, homeBraceEnvVar} {
		if strings.HasPrefix(arg, prefix) {
			tail := strings.TrimPrefix(arg, prefix)
			if tail == "" || tail[0] != '/' {
				continue
			}
			for _, seg := range strings.Split(tail, "/") {
				if seg == ".." {
					return true
				}
			}
		}
	}
	return false
}

// containsPipeToShell checks whether a command string contains a pipe to a
// common shell or interpreter.
func containsPipeToShell(command string) bool {
	shells := []string{"sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "node"}
	parts := strings.Split(command, "|")
	for _, part := range parts[1:] {
		trimmed := strings.TrimSpace(part)
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		target := baseCommand(fields[0])
		for _, sh := range shells {
			if target == sh {
				return true
			}
		}
	}
	return false
}
