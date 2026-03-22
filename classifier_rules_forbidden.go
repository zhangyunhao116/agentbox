// classifier_rules_forbidden.go contains all Forbidden-category rule functions
// and their helpers. Forbidden rules block commands unconditionally — they are
// evaluated at the highest priority before escalated or allow rules.

package agentbox

import "strings"

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
// It requires "nc" to appear as a standalone command word (not a substring of
// "rsync", "func", "scutil --nc", etc.) and that the -e/-c flag appears in the
// SAME compound-command segment (split by && ; || or top-level pipes) so that
// "nc -zuv host && ping -c 3 host" does not false-positive on "-c".
func rsNC(lower string) (ClassifyResult, bool) {
	if ncSegmentHasExecFlag(lower, "nc") {
		return rsResult("reverse shell via nc detected")
	}
	if ncSegmentHasExecFlag(lower, "netcat") {
		return rsResult("reverse shell via netcat detected")
	}
	return ClassifyResult{}, false
}

// rsNcat detects ncat -e, ncat -c, or ncat --exec reverse shells.
// It requires "ncat" to appear as a standalone command word.
func rsNcat(lower string) (ClassifyResult, bool) {
	if ncSegmentHasExecFlag(lower, "ncat") {
		return rsResult("reverse shell via ncat detected")
	}
	return ClassifyResult{}, false
}

// ncSegmentHasExecFlag splits a command on compound operators (&&, ||, ;, |)
// and checks whether any segment contains a standalone occurrence of cmd (e.g.
// "nc" or "ncat") together with an -e, -c, or --exec flag. This prevents
// flags from unrelated segments (like "ping -c 3") from triggering the rule.
func ncSegmentHasExecFlag(lower, cmd string) bool {
	if !hasStandaloneCommand(lower, cmd) {
		return false
	}
	// Quick path: if there are no compound operators, check the whole string.
	if !strings.ContainsAny(lower, "&;|") {
		return strings.Contains(lower, " -e") || strings.Contains(lower, " -c") || strings.Contains(lower, " --exec")
	}
	for _, seg := range splitCompoundSegments(lower) {
		if hasStandaloneCommand(seg, cmd) &&
			(strings.Contains(seg, " -e") || strings.Contains(seg, " -c") || strings.Contains(seg, " --exec")) {
			return true
		}
	}
	return false
}

// splitCompoundSegments splits a command string on shell compound operators
// (&&, ||, ;) and top-level pipes. This is a rough split for checking flag
// locality and does not need full quote awareness.
func splitCompoundSegments(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			if i+1 < len(s) && s[i+1] == '&' {
				result = append(result, s[start:i])
				i++
				start = i + 1
			}
		case '|':
			if i+1 < len(s) && s[i+1] == '|' {
				result = append(result, s[start:i])
				i++
				start = i + 1
			} else {
				result = append(result, s[start:i])
				start = i + 1
			}
		case ';':
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	return append(result, s[start:])
}

// rsPythonSocket detects Python socket-based reverse shells.
// When the code is inline (python -c "..."), a bare "import socket" is
// almost always port scanning or HTTP testing — not a reverse shell.
// We only flag inline code when it also contains shell-exec indicators
// (dup2, subprocess.call, subprocess.popen, pty.spawn, os.system,
// /bin/sh, /bin/bash) that are hallmarks of a real reverse shell.
func rsPythonSocket(lower string) (ClassifyResult, bool) {
	if !strings.Contains(lower, "python") || !strings.Contains(lower, "import socket") {
		return ClassifyResult{}, false
	}
	// Inline code via -c: require additional reverse-shell indicators.
	if strings.Contains(lower, "python -c") || strings.Contains(lower, "python3 -c") {
		if strings.Contains(lower, "dup2") ||
			strings.Contains(lower, "subprocess.call") ||
			strings.Contains(lower, "subprocess.popen") ||
			strings.Contains(lower, "pty.spawn") ||
			strings.Contains(lower, "os.system") ||
			strings.Contains(lower, "/bin/sh") ||
			strings.Contains(lower, "/bin/bash") {
			return rsResult("reverse shell via python socket detected")
		}
		return ClassifyResult{}, false
	}
	return rsResult("reverse shell via python socket detected")
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
			hasFetcher := strings.Contains(lower, cmdCurl) || strings.Contains(lower, cmdWget)
			if !hasFetcher {
				return ClassifyResult{}, false
			}
			if !strings.Contains(command, "|") {
				return ClassifyResult{}, false
			}
			// Split on top-level pipes only (ignoring pipes inside $(), backticks, quotes).
			parts := splitTopLevelPipes(command)
			for _, part := range parts[1:] {
				trimmed := strings.TrimSpace(part)
				fields := strings.Fields(trimmed)
				if len(fields) == 0 {
					continue
				}
				target := baseCommand(fields[0])
				for _, sh := range shells {
					if target == sh {
						// python/python3 with -c or -m is safe (inline code, not stdin eval).
						if (target == cmdPython || target == cmdPython3) && isPipeTargetSafePython(fields) {
							continue
						}
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
			isFetcher := lower == cmdCurl || lower == cmdWget
			if !isFetcher {
				return ClassifyResult{}, false
			}
			// Check if any arg contains a pipe to a shell.
			full := base + " " + strings.Join(args, " ")
			if !strings.Contains(full, "|") {
				return ClassifyResult{}, false
			}
			parts := splitTopLevelPipes(full)
			for _, part := range parts[1:] {
				trimmed := strings.TrimSpace(part)
				fields := strings.Fields(trimmed)
				if len(fields) == 0 {
					continue
				}
				target := baseCommand(fields[0])
				for _, sh := range shells {
					if target == sh {
						if (target == cmdPython || target == cmdPython3) && isPipeTargetSafePython(fields) {
							continue
						}
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

// segmentHasBase64Decode checks whether a pipe segment contains a base64
// command with a decode flag (-d, --decode, or combined short flags like -di).
// It tokenizes the segment so that extra flags between "base64" and "-d" are
// handled correctly (e.g. "base64 -w 0 -d").
func segmentHasBase64Decode(segLower string) bool {
	fields := strings.Fields(segLower)
	if len(fields) == 0 {
		return false
	}
	cmd := fields[0]
	if cmd != "base64" && !strings.HasSuffix(cmd, "/base64") {
		return false
	}
	for _, arg := range fields[1:] {
		if arg == "-d" || arg == "--decode" {
			return true
		}
		// Handle combined short flags like -di, -wd, etc.
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg, "d") {
			return true
		}
	}
	return false
}

// base64PipeShells lists the shell interpreters that matchBase64PipeShell
// considers dangerous when receiving piped base64-decoded output.
var base64PipeShells = []string{"sh", "bash", "zsh", "dash", "ksh", "eval"}

// matchBase64PipeShell returns a Forbidden result if the command pipes
// base64-decoded output to a shell interpreter.
func matchBase64PipeShell(command string) (ClassifyResult, bool) {
	lower := strings.ToLower(command)
	// Must contain base64 with a decode flag.
	if !strings.Contains(lower, "base64") {
		return ClassifyResult{}, false
	}
	if !strings.Contains(command, "|") {
		return ClassifyResult{}, false
	}
	// Walk pipe segments: find the segment with base64 decode,
	// then check if any subsequent segment is a shell.
	parts := splitTopLevelPipes(command)
	decodeSeen := false
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		partLower := strings.ToLower(trimmed)
		if segmentHasBase64Decode(partLower) {
			decodeSeen = true
			continue
		}
		if decodeSeen {
			fields := strings.Fields(trimmed)
			if len(fields) == 0 {
				continue
			}
			target := strings.ToLower(baseCommand(fields[0]))
			for _, sh := range base64PipeShells {
				if target == sh {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "piping base64-decoded content to a shell is dangerous",
						Rule:     "base64-pipe-shell",
					}, true
				}
			}
		}
	}
	return ClassifyResult{}, false
}

// base64PipeShellRule detects base64 decode output piped to a shell.
// Attackers encode malicious payloads as base64 strings and pipe the decoded
// output to a shell interpreter to bypass command-string classifiers.
// Examples: echo "cm0gLXJmIC8=" | base64 -d | sh
//
//	base64 --decode payload.txt | bash
func base64PipeShellRule() rule {
	return rule{
		Name:  "base64-pipe-shell",
		Match: matchBase64PipeShell,
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			// Pipes are shell constructs; reconstruct and delegate.
			full := name + " " + strings.Join(args, " ")
			return matchBase64PipeShell(full)
		},
	}
}

// ifsBypassRule detects $IFS used as a word-splitting bypass in commands.
// Attackers use $IFS (Internal Field Separator) to replace spaces and evade
// simple string matching. For example: cat$IFS/etc/passwd, rm$IFS-rf$IFS/
// Legitimate uses of $IFS (e.g. "echo $IFS") are not flagged because the
// variable appears as a standalone token rather than concatenated with a command.
func ifsBypassRule() rule {
	return rule{
		Name:  "ifs-bypass",
		Match: matchIFSBypass,
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			full := name + " " + strings.Join(args, " ")
			return matchIFSBypass(full)
		},
	}
}

// isIFSSeparator returns true if c is a character that would naturally
// separate a $IFS token from adjacent text.
func isIFSSeparator(c byte) bool {
	return c == ' ' || c == '\t' || c == '|' || c == ';' || c == '"' || c == '\'' || c == '\n'
}

// matchIFSBypass returns a Forbidden result if the command contains $IFS or
// ${IFS} concatenated with adjacent text (i.e., used as a word-splitting
// bypass). A standalone "$IFS" token (like "echo $IFS") is not flagged.
func matchIFSBypass(command string) (ClassifyResult, bool) {
	// Check for both $IFS and ${IFS} forms.
	for _, marker := range []string{"${IFS}", "$IFS"} {
		idx := strings.Index(command, marker)
		if idx < 0 {
			continue
		}
		// Walk all occurrences.
		for idx >= 0 {
			before := idx > 0 && !isIFSSeparator(command[idx-1])
			end := idx + len(marker)
			after := end < len(command) && !isIFSSeparator(command[end])
			if before || after {
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "$IFS word-splitting bypass detected",
					Rule:     "ifs-bypass",
				}, true
			}
			// Search for next occurrence after current.
			next := strings.Index(command[end:], marker)
			if next < 0 {
				break
			}
			idx = end + next
		}
	}
	return ClassifyResult{}, false
}

// shutdownRebootRule matches commands that shut down or reboot the system.
func shutdownRebootRule() rule {
	powerCmds := map[string]bool{
		"shutdown": true,
		"reboot":   true,
		"halt":     true,
		"poweroff": true,
	}
	return rule{
		Name: "shutdown-reboot",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(fields[0])
			if powerCmds[cmd] {
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "system shutdown/reboot is forbidden",
					Rule:     "shutdown-reboot",
				}, true
			}
			// "init 0" and "init 6" trigger a shutdown/reboot.
			if cmd == "init" && len(fields) >= 2 && (fields[1] == "0" || fields[1] == "6") {
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "system shutdown/reboot is forbidden",
					Rule:     "shutdown-reboot",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if powerCmds[cmd] {
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "system shutdown/reboot is forbidden",
					Rule:     "shutdown-reboot",
				}, true
			}
			if cmd == "init" && len(args) >= 1 && (args[0] == "0" || args[0] == "6") {
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "system shutdown/reboot is forbidden",
					Rule:     "shutdown-reboot",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

// kernelModuleRule matches commands that manipulate kernel modules.
func kernelModuleRule() rule {
	kmodCmds := map[string]bool{
		"insmod": true, "rmmod": true, "modprobe": true, "depmod": true,
	}
	return rule{
		Name: "kernel-module",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if kmodCmds[baseCommand(fields[0])] {
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "kernel module manipulation is forbidden",
					Rule:     "kernel-module",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, _ []string) (ClassifyResult, bool) {
			if kmodCmds[baseCommand(name)] {
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "kernel module manipulation is forbidden",
					Rule:     "kernel-module",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

// partitionManagementRule matches commands that manage disk partitions.
// fdisk and parted are handled by filesystemFormatRule (which already exempts
// their -l/--list read-only modes), so they are not duplicated here.
func partitionManagementRule() rule {
	partCmds := map[string]bool{
		"gdisk": true, "cfdisk": true, "sfdisk": true,
	}
	return rule{
		Name: "partition-management",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if partCmds[baseCommand(fields[0])] {
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "disk partition management is forbidden",
					Rule:     "partition-management",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, _ []string) (ClassifyResult, bool) {
			if partCmds[baseCommand(name)] {
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "disk partition management is forbidden",
					Rule:     "partition-management",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

// historyExecRule matches commands that re-execute shell history, such as
// "history | sh", "history | bash", "fc -s", and "fc -e".
func historyExecRule() rule {
	shellInterpreters := map[string]bool{
		"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	}
	return rule{
		Name: "history-exec",
		Match: func(command string) (ClassifyResult, bool) {
			// Check "history | <shell>" pattern.
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(fields[0])
			if cmd == "history" {
				// Check for pipe to shell.
				parts := splitTopLevelPipes(command)
				for _, p := range parts[1:] {
					trimmed := strings.TrimSpace(p)
					pfields := strings.Fields(trimmed)
					if len(pfields) > 0 && shellInterpreters[baseCommand(pfields[0])] {
						return ClassifyResult{
							Decision: Forbidden,
							Reason:   "history re-execution is forbidden",
							Rule:     "history-exec",
						}, true
					}
				}
			}
			// Check "fc -s" or "fc -e" pattern.
			if cmd == "fc" {
				for _, f := range fields[1:] {
					if f == "-s" || f == "-e" {
						return ClassifyResult{
							Decision: Forbidden,
							Reason:   "history re-execution is forbidden",
							Rule:     "history-exec",
						}, true
					}
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if cmd == "fc" {
				for _, a := range args {
					if a == "-s" || a == "-e" {
						return ClassifyResult{
							Decision: Forbidden,
							Reason:   "history re-execution is forbidden",
							Rule:     "history-exec",
						}, true
					}
				}
			}
			// "history | sh" is only detectable via Match (raw command string),
			// not MatchArgs, since the pipe is part of the shell syntax.
			return ClassifyResult{}, false
		},
	}
}

func destructiveFindRule() rule {
	return rule{
		Name: "destructive-find",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			if baseCommand(fields[0]) != "find" {
				return ClassifyResult{}, false
			}
			for i, f := range fields {
				if f == "-delete" {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "find with destructive action is forbidden",
						Rule:     "destructive-find",
					}, true
				}
				if (f == "-exec" || f == "-execdir" || f == "-ok" || f == "-okdir") && i+1 < len(fields) {
					execCmd := baseCommand(fields[i+1])
					if execCmd == "rm" {
						return ClassifyResult{
							Decision: Forbidden,
							Reason:   "find with destructive action is forbidden",
							Rule:     "destructive-find",
						}, true
					}
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if baseCommand(name) != "find" || len(args) == 0 {
				return ClassifyResult{}, false
			}
			for i, a := range args {
				if a == "-delete" {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "find with destructive action is forbidden",
						Rule:     "destructive-find",
					}, true
				}
				if (a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir") && i+1 < len(args) {
					execCmd := baseCommand(args[i+1])
					if execCmd == "rm" {
						return ClassifyResult{
							Decision: Forbidden,
							Reason:   "find with destructive action is forbidden",
							Rule:     "destructive-find",
						}, true
					}
				}
			}
			return ClassifyResult{}, false
		},
	}
}

func destructiveXargsRule() rule {
	return rule{
		Name: "destructive-xargs",
		Match: func(command string) (ClassifyResult, bool) {
			// Split on pipe to find segments where xargs is the command.
			segments := strings.Split(command, "|")
			for _, seg := range segments {
				fields := strings.Fields(strings.TrimSpace(seg))
				if len(fields) < 2 {
					continue
				}
				if baseCommand(fields[0]) != "xargs" {
					continue
				}
				// xargs is the command in this segment; check if any arg is rm.
				for _, f := range fields[1:] {
					if baseCommand(f) == "rm" {
						return ClassifyResult{
							Decision: Forbidden,
							Reason:   "xargs with rm is forbidden",
							Rule:     "destructive-xargs",
						}, true
					}
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if baseCommand(name) != "xargs" {
				return ClassifyResult{}, false
			}
			for _, a := range args {
				base := baseCommand(a)
				if base == "rm" {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "xargs with rm is forbidden",
						Rule:     "destructive-xargs",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
	}
}

// outputRedirectSystemRule detects commands that redirect output to critical
// system paths (/etc/, /dev/ block devices, /boot/, /proc/, /sys/). This is a
// Match-only rule since redirections appear in the raw command string.
func outputRedirectSystemRule() rule {
	// systemWritePrefixes are path prefixes that must not be overwritten
	// via shell redirection.
	systemWritePrefixes := []string{"/etc/", "/dev/", "/boot/", "/proc/", "/sys/"}

	return rule{
		Name: "output-redirect-system",
		Match: func(command string) (ClassifyResult, bool) {
			// Scan for > or >> followed by a system path.
			// Use pipeScanner to track quoting state so that
			// '>' inside quotes is not treated as a redirect.
			var ps pipeScanner
			for i := 0; i < len(command); i++ {
				advance, _ := ps.feed(command, i)
				ch := command[i]
				i += advance
				// Ignore '>' inside quotes or subshells.
				if ps.inSingle || ps.inDouble || ps.inBtick || ps.depth > 0 {
					continue
				}
				if ch != '>' {
					continue
				}
				// Skip >> (still a redirect).
				j := i + 1
				if j < len(command) && command[j] == '>' {
					j++
				}
				// Skip whitespace (spaces and tabs) after the redirect operator.
				for j < len(command) && (command[j] == ' ' || command[j] == '\t') {
					j++
				}
				if j >= len(command) {
					continue
				}
				// Extract the target path token (until next whitespace or end).
				end := j
				for end < len(command) && command[end] != ' ' && command[end] != '\t' {
					end++
				}
				target := command[j:end]
				for _, prefix := range systemWritePrefixes {
					if strings.HasPrefix(target, prefix) {
						return ClassifyResult{
							Decision: Forbidden,
							Reason:   "redirecting output to a system path is forbidden",
							Rule:     "output-redirect-system",
						}, true
					}
				}
			}
			return ClassifyResult{}, false
		},
		// No MatchArgs — redirections are shell constructs, not parsed args.
	}
}
