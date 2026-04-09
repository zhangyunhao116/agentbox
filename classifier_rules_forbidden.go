// classifier_rules_forbidden.go contains all Forbidden-category rule functions
// and their helpers. Forbidden rules block commands unconditionally — they are
// evaluated at the highest priority before escalated or allow rules.

package agentbox

import "strings"

// shutdownPowerCmds is the set of commands that shut down or reboot the system.
var shutdownPowerCmds = map[string]struct{}{
	"shutdown": {}, "reboot": {}, "halt": {}, "poweroff": {},
}

// kernelModuleCmds matches commands that manipulate kernel modules.
var kernelModuleCmds = map[string]struct{}{
	"insmod": {}, "rmmod": {}, "modprobe": {}, "depmod": {},
}

// partitionCmds matches commands that manage disk partitions.
var partitionCmds = map[string]struct{}{
	"gdisk": {}, "cfdisk": {}, "sfdisk": {},
}

// shellInterpreterCmds are shell interpreters for history execution detection.
var shellInterpreterCmds = map[string]struct{}{
	"sh": {}, "bash": {}, "zsh": {}, "dash": {}, "ksh": {},
}

// windowsRmdirCmds are Windows rmdir/rd commands for recursive delete detection.
var windowsRmdirCmds = map[string]struct{}{"rmdir": {}, "rd": {}}

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

// rmHasRecursiveForce checks whether an rm argument list contains both a
// recursive flag (-r, -R, or --recursive) and a force flag (-f or --force).
// It stops scanning at "--" or any command separator.
func rmHasRecursiveForce(args []string) bool {
	hasRecursive := false
	hasForce := false
	for _, a := range args {
		if a == "--" || isCommandSeparator(a) {
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
		if a == flagForce {
			hasForce = true
		}
	}
	return hasRecursive && hasForce
}

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
			if !rmHasRecursiveForce(fields[1:]) {
				return ClassifyResult{}, false
			}
			// Check for dangerous targets using path normalization.
			// Stop at command separators (&&, ||, ;, |) — tokens beyond
			// a separator belong to a different command.
			for _, f := range fields[1:] {
				if isCommandSeparator(f) {
					break
				}
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
			if !rmHasRecursiveForce(args) {
				return ClassifyResult{}, false
			}
			for _, a := range args {
				if isCommandSeparator(a) {
					break
				}
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
				func() (ClassifyResult, bool) { return rsNcat(command) },
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
				func() (ClassifyResult, bool) { return rsArgsDevTCP(name, args) },
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
//
// Simple connectivity tests like "echo > /dev/tcp/host/port" or
// "timeout 5 < /dev/tcp/host/port" are NOT reverse shells.
// Actual reverse shells use fd redirection: "exec 3<>/dev/tcp/host/port",
// ">&3", "0>&1", "/bin/sh", "/bin/bash", etc.
//
// We require the command to contain BOTH /dev/tcp (or /dev/udp) AND at
// least one reverse-shell indicator.
func rsDevTCP(command string) (ClassifyResult, bool) {
	if !strings.Contains(command, "/dev/tcp/") && !strings.Contains(command, "/dev/udp/") {
		return ClassifyResult{}, false
	}
	lower := strings.ToLower(command)
	// A timeout-wrapped /dev/tcp probe without interactive-shell redirects
	// (0>&1, >& followed by space or EOL) is a connectivity test, not a
	// reverse shell. Example: "timeout 3 bash -c 'exec 3<>/dev/tcp/h/p'"
	if isTimeoutConnectivityProbe(lower) {
		return ClassifyResult{}, false
	}
	if rsDevTCPHasIndicator(lower) {
		return rsResult("reverse shell via /dev/tcp or /dev/udp detected")
	}
	return ClassifyResult{}, false
}

// isTimeoutConnectivityProbe reports whether a lowered command looks like a
// timeout-wrapped port connectivity test using /dev/tcp or /dev/udp. These
// open a fd to test reachability but do not redirect stdin/stdout for an
// interactive shell session. We require:
//  1. The command starts with "timeout" (to bound execution time).
//  2. The command does NOT contain "0>&1" (stdin→stdout reverse shell pattern).
//  3. The command does NOT contain bare ">&" followed by space or end-of-string
//     (stdout+stderr redirect for interactive shell).
//  4. The command does NOT invoke a shell (/bin/sh, /bin/bash) outside the
//     wrapper itself.
func isTimeoutConnectivityProbe(lower string) bool {
	fields := strings.Fields(lower)
	if len(fields) == 0 || baseCommand(fields[0]) != "timeout" {
		return false
	}
	// Reject if interactive-shell redirect patterns are present.
	if strings.Contains(lower, "0>&1") {
		return false
	}
	if strings.Contains(lower, ">& ") || strings.HasSuffix(lower, ">&") {
		return false
	}
	// Reject if non-standard fd redirects are present (e.g. >&3, <&5).
	// These indicate data exfiltration like "cat /etc/shadow >&3".
	if hasNonStdFDRedirect(lower) {
		return false
	}
	// Reject if a shell is invoked as a payload (not just as the -c wrapper).
	// "bash -c 'exec 3<>/dev/tcp/...'" is a wrapper; look for shell AFTER
	// /dev/tcp which would indicate piping to a shell.
	if idx := strings.Index(lower, "/dev/tcp/"); idx >= 0 {
		tail := lower[idx:]
		if strings.Contains(tail, "/bin/sh") || strings.Contains(tail, "/bin/bash") {
			return false
		}
	}
	if idx := strings.Index(lower, "/dev/udp/"); idx >= 0 {
		tail := lower[idx:]
		if strings.Contains(tail, "/bin/sh") || strings.Contains(tail, "/bin/bash") {
			return false
		}
	}
	return true
}

// rsDevTCPHasIndicator reports whether a (lowered) command string contains
// indicators of an actual /dev/tcp reverse shell rather than a simple
// connectivity test.
func rsDevTCPHasIndicator(lower string) bool {
	// exec with fd redirection: "exec 3<>/dev/tcp/..."
	if strings.Contains(lower, "exec ") {
		return true
	}
	// Shell execution via the socket.
	if strings.Contains(lower, "/bin/sh") || strings.Contains(lower, "/bin/bash") {
		return true
	}
	// Python/C fd duplication.
	if strings.Contains(lower, "dup2") {
		return true
	}
	// Bare >& (stdout+stderr redirect without a preceding fd digit) is a
	// reverse shell indicator. "bash -i >& /dev/tcp/host/port" is a classic
	// reverse shell pattern. Check for ">& " (followed by space) or trailing ">&".
	if strings.Contains(lower, ">& ") || strings.HasSuffix(lower, ">&") {
		return true
	}
	// Look for fd redirection operators: >&N, <&N, N>&M where N >= 3
	// but exclude the common stderr redirect "2>&1" and "1>&2".
	return hasNonStdFDRedirect(lower)
}

// hasNonStdFDRedirect reports whether s contains a file-descriptor redirect
// that is NOT the standard "2>&1" or "1>&2" patterns. Non-standard fd
// redirects like ">&3", "0>&1", "1>&0", "<&5" are indicators of reverse
// shell fd piping.
func hasNonStdFDRedirect(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '>' && i+1 < len(s) && s[i+1] == '&' {
			if isOutputFDRedirectSuspicious(s, i) {
				return true
			}
			i += 2 // skip past >&
			continue
		}
		if s[i] == '<' && i+1 < len(s) && s[i+1] == '&' {
			if isInputFDRedirectSuspicious(s, i) {
				return true
			}
			i += 2 // skip past <&
			continue
		}
	}
	return false
}

// digitFDBefore returns the single-digit fd number immediately before
// position i, or -1 if none.
func digitFDBefore(s string, i int) int {
	if i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		return int(s[i-1] - '0')
	}
	return -1
}

// digitFDAfter returns the single-digit fd number at position i+2
// (after the two-character operator >&/<&), or -1 if none.
func digitFDAfter(s string, i int) int {
	if i+2 < len(s) && s[i+2] >= '0' && s[i+2] <= '9' {
		return int(s[i+2] - '0')
	}
	return -1
}

// isOutputFDRedirectSuspicious checks whether the >& at position i is a
// suspicious (non-standard) fd redirect. Standard patterns "2>&1" and "1>&2"
// are not suspicious.
func isOutputFDRedirectSuspicious(s string, i int) bool {
	fdBefore := digitFDBefore(s, i)
	fdAfter := digitFDAfter(s, i)
	// "2>&1" or "1>&2" are standard stderr/stdout swaps — not suspicious.
	if (fdBefore == 2 && fdAfter == 1) || (fdBefore == 1 && fdAfter == 2) {
		return false
	}
	// Redirect to fd > 2 is suspicious (>&3, 1>&3).
	if fdAfter > 2 {
		return true
	}
	// "0>&1" is a reverse shell pattern (redirect stdin to stdout).
	if fdBefore == 0 && fdAfter == 1 {
		return true
	}
	// "1>&0" is also suspicious.
	return fdBefore == 1 && fdAfter == 0
}

// isInputFDRedirectSuspicious checks whether the <& at position i is a
// suspicious (non-standard) fd input redirect. Redirects like "<&3" indicate
// reverse shell fd piping. "0<&1" (redirect stdin from stdout) is also a
// classic reverse shell pattern.
func isInputFDRedirectSuspicious(s string, i int) bool {
	fdBefore := digitFDBefore(s, i)
	fdAfter := digitFDAfter(s, i)
	// <&3, <&4, etc. — input from non-standard fd.
	if fdAfter > 2 {
		return true
	}
	// 0<&1 — redirect stdin from stdout (classic reverse shell pattern).
	return fdBefore == 0 && fdAfter == 1
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
//
// It passes the ORIGINAL (non-lowered) command to ncSegmentHasExecFlag so
// that ncat's -C flag (CRLF line endings) is not confused with -c (execute).
// ncSegmentHasExecFlag lowercases internally for command matching but uses
// original case for flag matching.
func rsNcat(command string) (ClassifyResult, bool) {
	// Use original case: ncSegmentHasExecFlag lowercases for command matching
	// but preserves case for flag matching (-C ≠ -c).
	if ncSegmentHasExecFlag(command, "ncat") {
		return rsResult("reverse shell via ncat detected")
	}
	return ClassifyResult{}, false
}

// ncSegmentHasExecFlag splits a command on compound operators (&&, ||, ;, |)
// and checks whether any segment contains a standalone occurrence of cmd (e.g.
// "nc" or "ncat") together with an -e, -c, or --exec flag. This prevents
// flags from unrelated segments (like "ping -c 3") from triggering the rule.
//
// It also rejects the match when the segment contains a -z flag (zero-I/O
// scan mode) because nc -z is always a connectivity test, never a reverse
// shell. Likewise, PowerShell "Get-Command" listing nc is not a shell.
//
// The first parameter may be original-case or already lowered. The function
// lowercases it internally for command matching (hasStandaloneCommand) so
// that mixed-case commands like "Ncat" are found. Flag matching (-c vs -C)
// uses the original string so that ncat's -C (CRLF) is not confused with
// -c (execute).
func ncSegmentHasExecFlag(s, cmd string) bool {
	lower := strings.ToLower(s)
	if !hasStandaloneCommand(lower, cmd) {
		return false
	}
	// PowerShell Get-Command just lists available commands — never dangerous.
	if strings.Contains(lower, "get-command") {
		return false
	}
	// Quick path: if there are no compound operators, check the whole string.
	if !strings.ContainsAny(lower, "&;|") {
		return ncSegmentExecNoScan(s)
	}
	for _, seg := range splitCompoundSegments(s) {
		segLower := strings.ToLower(seg)
		if hasStandaloneCommand(segLower, cmd) && ncSegmentExecNoScan(seg) {
			return true
		}
	}
	return false
}

// ncSegmentExecNoScan reports whether a command segment contains an nc/ncat
// exec flag (-e, -c, --exec) as a whole flag AND does not contain the -z
// (zero-I/O / scan) flag. The -z flag indicates a port scan or connectivity
// test, which is never a reverse shell.
//
// The -z flag may appear combined (e.g., -zv, -zuv) so we check for -z
// anywhere in short-flag groups in addition to standalone -z.
func ncSegmentExecNoScan(seg string) bool {
	if ncHasScanFlag(seg) {
		return false
	}
	return hasWholeFlag(seg, "-e") || hasWholeFlag(seg, "-c") || hasWholeFlag(seg, "--exec")
}

// ncHasScanFlag reports whether s contains nc/ncat -z flag (zero-I/O mode).
// The flag may appear standalone (-z) or combined with other short flags
// (-zv, -zuv, -vz, etc.).
func ncHasScanFlag(s string) bool {
	for _, f := range strings.Fields(s) {
		if f == "-z" {
			return true
		}
		// Combined short flags: -zv, -zuv, -vz, etc.
		// Must start with '-', not be '--', and contain 'z'.
		if len(f) > 2 && f[0] == '-' && f[1] != '-' && strings.ContainsRune(f, 'z') {
			return true
		}
	}
	return false
}

// hasWholeFlag reports whether s contains the given flag as a whole word.
// The flag must be preceded by whitespace (or start-of-string) and followed
// by whitespace, end-of-string, or another flag prefix '-'.
// Example: hasWholeFlag("nc -e /bin/sh", "-e") => true
//
//	hasWholeFlag("wget -ErrorAction ...", "-e") => false
func hasWholeFlag(s, flag string) bool {
	// Normalise: if the caller passed " --exec" strip the leading space so
	// the boundary check below works correctly.
	flag = strings.TrimLeft(flag, " ")
	for off := 0; off < len(s); {
		idx := strings.Index(s[off:], flag)
		if idx < 0 {
			return false
		}
		pos := off + idx
		end := pos + len(flag)
		// Left boundary: must be preceded by whitespace or start-of-string.
		leftOK := pos == 0 || s[pos-1] == ' ' || s[pos-1] == '\t'
		// Right boundary: must be followed by whitespace, EOF, or '-' (next flag).
		rightOK := end >= len(s) || s[end] == ' ' || s[end] == '\t' || s[end] == '-'
		if leftOK && rightOK {
			return true
		}
		off = pos + 1
	}
	return false
}

// splitCompoundSegments splits a command string on shell compound operators
// (&&, ||, ;) and top-level pipes, respecting quoting and subshell nesting.
// This is used for checking flag locality in reverse-shell rules.
func splitCompoundSegments(s string) []string {
	var (
		result []string
		ps     pipeScanner
		start  int
	)
	for i := 0; i < len(s); i++ {
		advance, _ := ps.feed(s, i)
		if ps.inSingle || ps.inDouble || ps.inBtick || ps.depth > 0 {
			i += advance
			continue
		}
		ch := s[i]
		switch ch {
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
		i += advance
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

// rsArgsDevTCP detects /dev/tcp and /dev/udp reverse shell patterns in
// argument list. Like rsDevTCP, it requires additional reverse-shell
// indicators (exec, fd redirection, shell invocation) to avoid flagging
// simple connectivity tests.
func rsArgsDevTCP(name string, args []string) (ClassifyResult, bool) {
	hasDevTCP := false
	for _, a := range args {
		if strings.Contains(a, "/dev/tcp/") || strings.Contains(a, "/dev/udp/") {
			hasDevTCP = true
			break
		}
	}
	if !hasDevTCP {
		return ClassifyResult{}, false
	}
	// Reuse rsDevTCPHasIndicator for consistent indicator checking.
	joined := strings.ToLower(strings.Join(args, " "))
	// Exempt timeout-wrapped connectivity probes (consistent with Classify path).
	// Prepend the command name since isTimeoutConnectivityProbe expects the
	// full command string starting with "timeout".
	fullCmd := strings.ToLower(name) + " " + joined
	if isTimeoutConnectivityProbe(fullCmd) {
		return ClassifyResult{}, false
	}
	if rsDevTCPHasIndicator(joined) {
		return rsResult("reverse shell via /dev/tcp or /dev/udp detected")
	}
	return ClassifyResult{}, false
}

// rsArgsNCExec detects nc/ncat/netcat -e/-c/--exec patterns in arguments.
// It skips if -z (scan mode) is present, since that is a connectivity test.
func rsArgsNCExec(baseLower string, args []string) (ClassifyResult, bool) {
	if baseLower == "nc" || baseLower == "ncat" || baseLower == "netcat" {
		hasExec := false
		hasScan := false
		for _, a := range args {
			switch a {
			case "-e", "-c", "--exec":
				hasExec = true
			case "-z":
				hasScan = true
			}
		}
		if hasExec && !hasScan {
			return rsResult("reverse shell via " + baseLower + " detected")
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

// argsHaveRecursiveFlag checks whether an argument list contains a recursive
// flag (-R, bundled short flags containing R, or --recursive). It stops
// scanning at "--" or any command separator.
func argsHaveRecursiveFlag(args []string) bool {
	for _, a := range args {
		if a == "--" || isCommandSeparator(a) {
			break
		}
		if a == "-R" || a == flagRecursive {
			return true
		}
		// Check for R in bundled short flags like -vR, -Rv.
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
			if strings.Contains(a, "R") {
				return true
			}
		}
	}
	return false
}

// recursivePermRootRule detects recursive chmod or chown targeting dangerous
// paths (root, home directory, etc.). This is a combined rule that replaces the
// former chmod-recursive-root and chown-recursive-root rules.
func recursivePermRootRule() rule {
	permCmds := map[string]string{
		"chmod": "recursive chmod on root or home directory",
		"chown": "recursive chown on root or home directory",
	}
	const ruleName = "recursive-perm-root"

	return rule{
		Name: ruleName,
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			reason, ok := permCmds[baseCommand(fields[0])]
			if !ok {
				return ClassifyResult{}, false
			}
			// Check for recursive flag by iterating fields rather than
			// using strings.Contains on the full string, which could
			// false-positive on substrings like "file-README".
			if !argsHaveRecursiveFlag(fields[1:]) {
				return ClassifyResult{}, false
			}
			// Check for root or home targets. Stop at command separators.
			for _, f := range fields {
				if isCommandSeparator(f) {
					break
				}
				if isDangerousTarget(f) {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   reason,
						Rule:     ruleName,
					}, true
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			reason, ok := permCmds[baseCommand(name)]
			if !ok {
				return ClassifyResult{}, false
			}
			if !argsHaveRecursiveFlag(args) {
				return ClassifyResult{}, false
			}
			for _, a := range args {
				if isCommandSeparator(a) {
					break
				}
				if isDangerousTarget(a) {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   reason,
						Rule:     ruleName,
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
	// Help/version queries are safe for all commands in this rule.
	// -V is only safe when it is the sole argument (no device target).
	if hasHelpOrVersionFlag(args) || hasVersionOnlyFlag(args) {
		return ClassifyResult{}, false
	}
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
			if a == "-l" || a == flagList {
				return ClassifyResult{}, false
			}
		}
		result.Reason = base + " partition manipulation detected"
		return result, true
	}
	return ClassifyResult{}, false
}

// matchAnyPipeToShell checks for ANY content piped to a shell interpreter.
// This is broader than the curl/wget-specific check — piping arbitrary content
// to bash/sh/zsh/etc. is dangerous regardless of the source.
func matchAnyPipeToShell(command, ruleName string) (ClassifyResult, bool) {
	if !strings.Contains(command, "|") {
		return ClassifyResult{}, false
	}
	parts := splitTopLevelPipes(command)
	if len(parts) < 2 {
		return ClassifyResult{}, false
	}
	for _, part := range parts[1:] {
		trimmed := strings.TrimSpace(part)
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		target := baseCommand(fields[0])
		for _, sh := range pipeShells {
			if target == sh {
				// python/python3 with -c or -m is safe (inline code, not stdin eval).
				if (target == cmdPython || target == cmdPython3) && isPipeTargetSafePython(fields) {
					continue
				}
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "piping content to a shell interpreter is dangerous",
					Rule:     RuleName(ruleName),
				}, true
			}
		}
	}
	return ClassifyResult{}, false
}

// pipeToShellRule detects piping untrusted content to a shell interpreter.
// This is a combined rule that replaces the former curl-pipe-shell and
// base64-pipe-shell rules. It checks for both curl/wget piping to shells and
// base64-decoded content piping to shells.
func pipeToShellRule() rule {
	const ruleName = "pipe-to-shell"

	// matchCurlPipe checks for curl/wget output piped to a shell.
	matchCurlPipe := func(command string) (ClassifyResult, bool) {
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
			for _, sh := range pipeShells {
				if target == sh {
					// python/python3 with -c or -m is safe (inline code, not stdin eval).
					if (target == cmdPython || target == cmdPython3) && isPipeTargetSafePython(fields) {
						continue
					}
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "piping remote content to a shell is dangerous",
						Rule:     ruleName,
					}, true
				}
			}
		}
		return ClassifyResult{}, false
	}

	return rule{
		Name: ruleName,
		Match: func(command string) (ClassifyResult, bool) {
			// Check curl/wget pipe to shell first.
			if r, ok := matchCurlPipe(command); ok {
				return r, true
			}
			// Check base64 decode pipe to shell.
			if r, ok := matchPipeToShellBase64(command, ruleName); ok {
				return r, true
			}
			// Check any content piped to a shell interpreter.
			return matchAnyPipeToShell(command, ruleName)
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			lower := strings.ToLower(base)
			isFetcher := lower == cmdCurl || lower == cmdWget
			if isFetcher {
				// Reconstruct the command and delegate to Match-style logic,
				// since pipes are shell constructs that appear in the raw string.
				full := base + " " + strings.Join(args, " ")
				if r, ok := matchCurlPipe(full); ok {
					return r, true
				}
			}
			// Check base64 decode pipe to shell.
			full := name + " " + strings.Join(args, " ")
			if r, ok := matchPipeToShellBase64(full, ruleName); ok {
				return r, true
			}
			// Check any content piped to a shell interpreter.
			return matchAnyPipeToShell(full, ruleName)
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

// base64PipeShells lists the shell interpreters that matchPipeToShellBase64
// considers dangerous when receiving piped base64-decoded output.
var base64PipeShells = []string{"sh", "bash", "zsh", "dash", "ksh", "eval"}

// matchPipeToShellBase64 returns a Forbidden result if the command pipes
// base64-decoded output to a shell interpreter. The ruleName parameter
// allows the caller to specify the rule name for the result.
func matchPipeToShellBase64(command string, ruleName RuleName) (ClassifyResult, bool) {
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
						Rule:     ruleName,
					}, true
				}
			}
		}
	}
	return ClassifyResult{}, false
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
	return rule{
		Name: "shutdown-reboot",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(fields[0])
			if _, ok := shutdownPowerCmds[cmd]; ok {
				// Windows "shutdown /a" aborts a pending shutdown — safe.
				if cmd == "shutdown" && containsShutdownAbort(fields[1:]) {
					return ClassifyResult{}, false
				}
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
			if _, ok := shutdownPowerCmds[cmd]; ok {
				// Windows "shutdown /a" aborts a pending shutdown — safe.
				if cmd == "shutdown" && containsShutdownAbort(args) {
					return ClassifyResult{}, false
				}
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

// containsShutdownAbort reports whether args contain the Windows shutdown
// abort flag "/a". "shutdown /a" cancels a pending shutdown and is safe.
func containsShutdownAbort(args []string) bool {
	for _, a := range args {
		if strings.EqualFold(a, "/a") {
			return true
		}
	}
	return false
}

// isModprobeReadOnly reports whether the argument list contains flags that
// make modprobe a read-only query: --show-*, --dump-*, --dry-run, or -n.
func isModprobeReadOnly(args []string) bool {
	// If a command separator is present, this is a compound command.
	// Don't exempt it — a subsequent command may be destructive
	// (e.g. "modprobe --show-depends x && modprobe x").
	for _, a := range args {
		if isCommandSeparator(a) {
			return false
		}
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--show-") || strings.HasPrefix(a, "--dump-") {
			return true
		}
		if a == "--dry-run" || a == "-n" {
			return true
		}
	}
	return false
}

// kernelModuleRule matches commands that manipulate kernel modules.
// Read-only modprobe queries (--show-*, --dump-*, --dry-run, -n) are exempt.
func kernelModuleRule() rule {
	return rule{
		Name: "kernel-module",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if _, ok := kernelModuleCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			// Help/version queries are safe.
			if hasHelpOrVersionFlag(fields[1:]) || hasVersionOnlyFlag(fields[1:]) {
				return ClassifyResult{}, false
			}
			// Read-only modprobe queries (--show-*, --dump-*, --dry-run, -n).
			if base == "modprobe" && isModprobeReadOnly(fields[1:]) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Forbidden,
				Reason:   "kernel module manipulation is forbidden",
				Rule:     "kernel-module",
			}, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if _, ok := kernelModuleCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			if hasHelpOrVersionFlag(args) || hasVersionOnlyFlag(args) {
				return ClassifyResult{}, false
			}
			if base == "modprobe" && isModprobeReadOnly(args) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Forbidden,
				Reason:   "kernel module manipulation is forbidden",
				Rule:     "kernel-module",
			}, true
		},
	}
}

// partitionManagementRule matches commands that manage disk partitions.
// fdisk and parted are handled by filesystemFormatRule (which already exempts
// their -l/--list read-only modes), so they are not duplicated here.
func partitionManagementRule() rule {
	return rule{
		Name: "partition-management",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if _, ok := partitionCmds[baseCommand(fields[0])]; ok {
				// Help/version queries are safe.
				if hasHelpOrVersionFlag(fields[1:]) || hasVersionOnlyFlag(fields[1:]) {
					return ClassifyResult{}, false
				}
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "disk partition management is forbidden",
					Rule:     "partition-management",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if _, ok := partitionCmds[baseCommand(name)]; ok {
				// Help/version queries are safe.
				if hasHelpOrVersionFlag(args) || hasVersionOnlyFlag(args) {
					return ClassifyResult{}, false
				}
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
					if len(pfields) > 0 {
						if _, ok := shellInterpreterCmds[baseCommand(pfields[0])]; ok {
							return ClassifyResult{
								Decision: Forbidden,
								Reason:   "history re-execution is forbidden",
								Rule:     "history-exec",
							}, true
						}
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

// findHasDestructiveAction checks whether a find argument list contains a
// destructive action such as -delete or -exec/-execdir/-ok/-okdir invoking rm.
func findHasDestructiveAction(args []string) bool {
	for i, a := range args {
		if a == "-delete" {
			return true
		}
		if (a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir") && i+1 < len(args) {
			execCmd := baseCommand(args[i+1])
			if execCmd == "rm" {
				return true
			}
		}
	}
	return false
}

// findHasActionFlag checks whether a find argument list contains any action
// flag that could execute arbitrary commands or modify the filesystem.
// This is broader than findHasDestructiveAction — it catches ALL exec-style
// actions (not just rm), so the blanket "allow" for find can be skipped and
// deeper rules (destructive-find, sandbox) can handle them properly.
func findHasActionFlag(args []string) bool {
	for _, a := range args {
		switch a {
		case "-exec", "-execdir", "-ok", "-okdir", "-delete":
			return true
		}
	}
	return false
}

func destructiveFindRule() rule {
	return rule{
		Name: "destructive-find",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			if baseCommand(fields[0]) != cmdFind {
				return ClassifyResult{}, false
			}
			if !findHasDestructiveAction(fields) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Forbidden,
				Reason:   "find with destructive action is forbidden",
				Rule:     "destructive-find",
			}, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if baseCommand(name) != cmdFind || len(args) == 0 {
				return ClassifyResult{}, false
			}
			if !findHasDestructiveAction(args) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Forbidden,
				Reason:   "find with destructive action is forbidden",
				Rule:     "destructive-find",
			}, true
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
				// Find the command xargs will execute (first non-xargs-flag arg).
				cmd := xargsTargetCommand(fields[1:])
				if cmd != "" && baseCommand(cmd) == "rm" {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "xargs with rm is forbidden",
						Rule:     "destructive-xargs",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if baseCommand(name) != "xargs" {
				return ClassifyResult{}, false
			}
			// Find the command xargs will execute (first non-xargs-flag arg).
			cmd := xargsTargetCommand(args)
			if cmd != "" && baseCommand(cmd) == "rm" {
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "xargs with rm is forbidden",
					Rule:     "destructive-xargs",
				}, true
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
				// Extract the target path token. Stop at shell
				// metacharacters that cannot be part of a path.
				end := j
				for end < len(command) && !isRedirectTerminator(command[end]) {
					end++
				}
				target := command[j:end]
				// Skip known-safe /dev/ targets (e.g. /dev/null, /dev/zero)
				// that are commonly used in shell redirections like 2>/dev/null.
				if isSafeDevTarget(target) {
					continue
				}
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

// safeDevTargets lists exact /dev/ paths that are safe redirection targets.
// Redirecting to these devices (e.g. 2>/dev/null) is normal shell usage and
// should not be flagged by output-redirect-system.
var safeDevTargets = map[string]struct{}{
	"/dev/null":    {},
	"/dev/zero":    {},
	"/dev/stdout":  {},
	"/dev/stderr":  {},
	"/dev/stdin":   {},
	"/dev/tty":     {},
	"/dev/random":  {},
	"/dev/urandom": {},
}

// safeDevPrefixes lists /dev/ subdirectory prefixes that are safe redirection
// targets (e.g. /dev/fd/3, /dev/pts/0, /dev/tcp/ for connectivity tests).
var safeDevPrefixes = []string{"/dev/fd/", "/dev/pts/", "/dev/tcp/", "/dev/udp/"}

// safeProcPrefixes lists /proc/ subdirectory prefixes that are safe
// redirection targets (e.g. /proc/self/fd/3 which is equivalent to /dev/fd/3).
var safeProcPrefixes = []string{"/proc/self/fd/"}

// isSafeDevTarget returns true if the redirect target is a known-safe /dev/
// or /proc/ path. This prevents false positives such as "2>/dev/null" or
// "> /proc/self/fd/1" being flagged as a dangerous system write.
func isSafeDevTarget(target string) bool {
	// Reject paths with traversal components that could escape safe prefixes.
	if strings.Contains(target, "..") {
		return false
	}
	if _, ok := safeDevTargets[target]; ok {
		return true
	}
	for _, prefix := range safeDevPrefixes {
		if strings.HasPrefix(target, prefix) {
			return true
		}
	}
	for _, prefix := range safeProcPrefixes {
		if strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return false
}

// hasHelpOrVersionFlag returns true if args contains --help, -h, or --version.
// Commands invoked with these flags only display usage information and are safe.
func hasHelpOrVersionFlag(args []string) bool {
	for _, a := range args {
		switch a {
		case flagHelp, "-h", flagVersion:
			return true
		}
	}
	return false
}

// hasVersionOnlyFlag returns true when args consist solely of "-V" with no
// other arguments. This prevents "-V" from exempting commands that also have
// a device/target argument (e.g. "mkfs.ext4 -V /dev/sda1").
func hasVersionOnlyFlag(args []string) bool {
	return len(args) == 1 && args[0] == "-V"
}

// xargsNoValFlags are xargs flags that take no argument value.
//
// Boolean flags: -0, -t, -p, -r, --no-run-if-empty, --verbose, --null, -x, --exit
var xargsNoValFlags = map[string]struct{}{
	"-0": {}, "-t": {}, "-p": {}, "-r": {}, "-x": {},
	"--no-run-if-empty": {}, "--verbose": {}, "--null": {}, "--exit": {},
}

// xargsValFlags are xargs flags that consume the next argument as a value.
//
// Key-value flags (GNU + BSD/macOS):
//
//	-I, -J, -L, -n, -P, -R, -S, -s, -d, -E, -a
//	--arg-file, --delimiter, --max-args, --max-procs, --max-lines, --replace
var xargsValFlags = map[string]struct{}{
	"-I": {}, "-J": {}, "-L": {}, "-n": {}, "-P": {},
	"-R": {}, "-S": {}, "-s": {}, "-d": {}, "-E": {},
	"-a": {},
	"--arg-file": {}, "--delimiter": {}, "--max-args": {},
	"--max-procs": {}, "--max-lines": {}, "--replace": {},
}

// shellWrapperUnwrapRule detects shell wrapper commands (sh -c, bash -c,
// cmd /c, cmd.exe /c, powershell -Command, etc.) and recursively classifies
// the inner command. This prevents bypassing forbidden rules by wrapping
// dangerous commands inside a shell invocation.
//
// The rule extracts the inner command string and re-classifies it using the
// same rule set. It preserves the original rule name from the inner match so
// that "bash -c 'rm -rf /'" reports as "recursive-delete-root", not a generic
// "shell-wrapper" rule.
func shellWrapperUnwrapRule(rules []rule) rule {
	return rule{
		Name: "shell-wrapper-unwrap",
		Match: func(command string) (ClassifyResult, bool) {
			inner, ok := extractShellWrapperInner(command)
			if !ok || inner == "" {
				return ClassifyResult{}, false
			}
			return classifyWithRules(inner, rules)
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			inner, ok := extractShellWrapperInnerArgs(name, args)
			if !ok || inner == "" {
				return ClassifyResult{}, false
			}
			return classifyWithRules(inner, rules)
		},
	}
}

// classifyWithRules evaluates a command against the given rule set.
func classifyWithRules(command string, rules []rule) (ClassifyResult, bool) {
	for _, r := range rules {
		if r.Match != nil {
			if result, ok := r.Match(command); ok {
				return result, true
			}
		}
	}
	return ClassifyResult{}, false
}

// unixShellWrappers are Unix shell commands that accept -c to run an inline
// command string.
var unixShellWrappers = map[string]struct{}{
	"sh": {}, "bash": {}, "zsh": {}, "dash": {}, "ksh": {},
}

// windowsShellWrappers maps Windows shell commands to their "execute"
// flag. cmd.exe uses /c (or /C), powershell uses -Command (or -c).
var windowsShellWrappers = map[string]string{
	"cmd": "/c", "cmd.exe": "/c",
}

// psWrappers are PowerShell executable names.
var psWrappers = map[string]struct{}{
	"powershell": {}, "powershell.exe": {},
	"pwsh": {}, "pwsh.exe": {},
}

// extractShellWrapperInner extracts the inner command from a shell wrapper
// command string. Returns ("", false) if the command is not a shell wrapper.
func extractShellWrapperInner(command string) (string, bool) {
	fields := strings.Fields(command)
	if len(fields) < 3 {
		return "", false
	}

	// Skip prefix commands like env, nice, nohup, sudo, etc.
	idx := 0
	for idx < len(fields)-2 && isPrefixCommand(strings.ToLower(baseCommand(fields[idx]))) {
		idx++
	}
	if idx >= len(fields)-2 {
		return "", false
	}
	base := strings.ToLower(baseCommand(fields[idx]))

	// Unix: sh -c "...", bash -c "..."
	if _, ok := unixShellWrappers[base]; ok {
		if idx+2 < len(fields) && fields[idx+1] == "-c" {
			inner := strings.Join(fields[idx+2:], " ")
			return stripOuterQuotes(inner), true
		}
		return "", false
	}

	// Windows: cmd /c "...", cmd.exe /C "..."
	if _, ok := windowsShellWrappers[base]; ok {
		if idx+2 < len(fields) && strings.EqualFold(fields[idx+1], "/c") {
			inner := strings.Join(fields[idx+2:], " ")
			return stripOuterQuotes(inner), true
		}
		// cmd /c"rmdir ..." (no space between /c and command)
		if idx+1 < len(fields) {
			arg := fields[idx+1]
			if len(arg) > 2 && strings.EqualFold(arg[:2], "/c") {
				rest := arg[2:]
				if len(fields) > idx+2 {
					rest += " " + strings.Join(fields[idx+2:], " ")
				}
				return stripOuterQuotes(rest), true
			}
		}
		return "", false
	}

	// PowerShell: powershell -Command "...", powershell -c "..."
	if _, ok := psWrappers[base]; ok {
		for j := idx + 1; j < len(fields)-1; j++ {
			lower := strings.ToLower(fields[j])
			if lower == "-command" || lower == "-c" {
				inner := strings.Join(fields[j+1:], " ")
				return stripOuterQuotes(inner), true
			}
			// Skip other PowerShell flags (e.g. -NoProfile, -ExecutionPolicy)
			if strings.HasPrefix(fields[j], "-") {
				// If the flag takes a value, skip the value too.
				if isPowerShellValueFlag(lower) && j+1 < len(fields) {
					j++ // skip value
				}
				continue
			}
			break
		}
		return "", false
	}

	return "", false
}

// extractShellWrapperInnerArgs is the MatchArgs variant of extractShellWrapperInner.
func extractShellWrapperInnerArgs(name string, args []string) (string, bool) {
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, name)
	parts = append(parts, args...)
	return extractShellWrapperInner(strings.Join(parts, " "))
}

// isPrefixCommand returns true for commands that act as wrappers/prefixes
// (e.g. env, nice, nohup, sudo, doas) before the actual command.
func isPrefixCommand(cmd string) bool {
	switch cmd {
	case cmdEnv, "nice", "nohup", ruleSudo, cmdDoas, "strace", "ltrace", "time":
		return true
	}
	return false
}

// isPowerShellValueFlag returns true for PowerShell flags that consume a
// following argument as their value.
func isPowerShellValueFlag(flag string) bool {
	switch flag {
	case "-executionpolicy", "-inputformat", "-outputformat", "-encodedcommand",
		"-file", "-configurationname", "-windowstyle":
		return true
	}
	return false
}

// stripOuterQuotes removes a matching pair of outer quotes (single or double)
// from a string. It handles the common case where shell wrapper inner commands
// are quoted: bash -c "rm -rf /" → rm -rf /
func stripOuterQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// windowsRecursiveDeleteRule detects Windows recursive directory deletion
// commands: rmdir /s /q and rd /s /q targeting dangerous paths.
func windowsRecursiveDeleteRule() rule {
	const ruleName = "windows-recursive-delete"
	matchInner := func(fields []string) (ClassifyResult, bool) {
		if len(fields) < 2 {
			return ClassifyResult{}, false
		}
		cmd := strings.ToLower(baseCommand(fields[0]))
		if _, ok := windowsRmdirCmds[cmd]; !ok {
			return ClassifyResult{}, false
		}
		// Check for /s flag (recursive) — case-insensitive.
		hasS := false
		for _, f := range fields[1:] {
			if isCommandSeparator(f) {
				break
			}
			if strings.EqualFold(f, "/s") {
				hasS = true
				break
			}
		}
		if !hasS {
			return ClassifyResult{}, false
		}
		// Check targets for dangerous paths.
		for _, f := range fields[1:] {
			if isCommandSeparator(f) {
				break
			}
			if strings.HasPrefix(f, "/") && !isWindowsFlag(f) {
				// Could be a Unix-style path like "/"
				if isDangerousTarget(f) {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "recursive directory deletion targeting dangerous path",
						Rule:     ruleName,
					}, true
				}
			}
			if isWindowsDangerousTarget(f) {
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "recursive directory deletion targeting dangerous path",
					Rule:     ruleName,
				}, true
			}
		}
		return ClassifyResult{}, false
	}

	return rule{
		Name: ruleName,
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			return matchInner(fields)
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			fields := make([]string, 0, 1+len(args))
			fields = append(fields, name)
			fields = append(fields, args...)
			return matchInner(fields)
		},
	}
}

// isWindowsFlag returns true if the token looks like a Windows-style flag
// (e.g. /s, /q, /f, /y) rather than a path.
func isWindowsFlag(s string) bool {
	if len(s) < 2 || s[0] != '/' {
		return false
	}
	// Single-letter flags: /s, /q, /f, /y, /a, etc.
	if len(s) == 2 && ((s[1] >= 'a' && s[1] <= 'z') || (s[1] >= 'A' && s[1] <= 'Z')) {
		return true
	}
	return false
}

// isWindowsDangerousTarget returns true if the path is a dangerous Windows
// deletion target: current directory ".", drive roots ("C:\", "D:\"), or
// system directories.
func isWindowsDangerousTarget(arg string) bool {
	if arg == "." || arg == ".." {
		return true
	}
	upper := strings.ToUpper(arg)
	// Drive root: "C:\", "D:\", etc.
	if len(upper) >= 2 && upper[0] >= 'A' && upper[0] <= 'Z' && upper[1] == ':' {
		rest := upper[2:]
		if rest == "" || rest == `\` || rest == "/" || rest == `\*` || rest == "/*" {
			return true
		}
	}
	// Windows system directories
	systemPaths := []string{
		`C:\WINDOWS`, `C:\WINDOWS\SYSTEM32`, `C:\PROGRAM FILES`,
		`C:\PROGRAM FILES (X86)`, `%SYSTEMROOT%`, `%WINDIR%`,
	}
	for _, sp := range systemPaths {
		if upper == sp || strings.HasPrefix(upper, sp+`\`) {
			return true
		}
	}
	// Also check Unix-style dangerous targets
	return isDangerousTarget(arg)
}

// windowsDelRecursiveRule detects Windows "del /f /s /q" targeting dangerous
// paths or wildcard patterns in dangerous locations.
func windowsDelRecursiveRule() rule {
	const ruleName = "windows-del-recursive"

	matchInner := func(fields []string) (ClassifyResult, bool) {
		if len(fields) < 2 {
			return ClassifyResult{}, false
		}
		cmd := strings.ToLower(baseCommand(fields[0]))
		if cmd != "del" && cmd != "erase" {
			return ClassifyResult{}, false
		}
		// Check for /s (recursive) flag.
		hasS := false
		for _, f := range fields[1:] {
			if isCommandSeparator(f) {
				break
			}
			if strings.EqualFold(f, "/s") {
				hasS = true
				break
			}
		}
		if !hasS {
			return ClassifyResult{}, false
		}
		// Check targets.
		for _, f := range fields[1:] {
			if isCommandSeparator(f) {
				break
			}
			if isWindowsFlag(f) {
				continue
			}
			// "del /f /s /q *" in any directory, or targeting dangerous paths.
			if f == "*" || f == "*.*" || isWindowsDangerousTarget(f) {
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "recursive file deletion targeting dangerous path or wildcard",
					Rule:     ruleName,
				}, true
			}
		}
		return ClassifyResult{}, false
	}

	return rule{
		Name: ruleName,
		Match: func(command string) (ClassifyResult, bool) {
			return matchInner(strings.Fields(command))
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			fields := make([]string, 0, 1+len(args))
			fields = append(fields, name)
			fields = append(fields, args...)
			return matchInner(fields)
		},
	}
}

// windowsFormatRule detects the Windows "format" command targeting drives.
func windowsFormatRule() rule {
	const ruleName = "windows-format"

	return rule{
		Name: ruleName,
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			if strings.ToLower(baseCommand(fields[0])) != "format" {
				return ClassifyResult{}, false
			}
			// "format C:" or "format C: /y /fs:ntfs" etc.
			for _, f := range fields[1:] {
				if isCommandSeparator(f) {
					break
				}
				upper := strings.ToUpper(f)
				if len(upper) >= 2 && upper[0] >= 'A' && upper[0] <= 'Z' && upper[1] == ':' {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "formatting a drive is forbidden",
						Rule:     ruleName,
					}, true
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if strings.ToLower(baseCommand(name)) != "format" {
				return ClassifyResult{}, false
			}
			for _, a := range args {
				if isCommandSeparator(a) {
					break
				}
				upper := strings.ToUpper(a)
				if len(upper) >= 2 && upper[0] >= 'A' && upper[0] <= 'Z' && upper[1] == ':' {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "formatting a drive is forbidden",
						Rule:     ruleName,
					}, true
				}
			}
			return ClassifyResult{}, false
		},
	}
}

// powershellDestructiveRule detects PowerShell commands that recursively delete
// files or directories: Remove-Item -Recurse -Force targeting dangerous paths.
func powershellDestructiveRule() rule {
	const ruleName = "powershell-destructive"

	matchInner := func(fields []string) (ClassifyResult, bool) {
		if len(fields) < 2 {
			return ClassifyResult{}, false
		}
		cmd := strings.ToLower(fields[0])
		// Match Remove-Item and ri (PowerShell cmdlet and its shortest alias).
		// Other PowerShell aliases (rm, del, erase, rmdir, rd) are handled by
		// dedicated Windows rules: windowsRecursiveDeleteRule and
		// windowsDelRecursiveRule.
		if cmd != "remove-item" && cmd != "ri" {
			return ClassifyResult{}, false
		}
		hasRecurse := false
		for _, f := range fields[1:] {
			lower := strings.ToLower(f)
			if lower == "-recurse" || lower == "-r" {
				hasRecurse = true
			}
		}
		if !hasRecurse {
			return ClassifyResult{}, false
		}
		// Check path arguments for dangerous targets.
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "-") {
				continue
			}
			if isWindowsDangerousTarget(f) || isDangerousTarget(f) {
				return ClassifyResult{
					Decision: Forbidden,
					Reason:   "PowerShell recursive deletion targeting dangerous path",
					Rule:     ruleName,
				}, true
			}
		}
		return ClassifyResult{}, false
	}

	return rule{
		Name: ruleName,
		Match: func(command string) (ClassifyResult, bool) {
			return matchInner(strings.Fields(command))
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			fields := make([]string, 0, 1+len(args))
			fields = append(fields, name)
			fields = append(fields, args...)
			return matchInner(fields)
		},
	}
}

// xargsTargetCommand returns the command that xargs will execute, skipping over
// xargs' own flags. Returns "" if no target command is found.
func xargsTargetCommand(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if _, ok := xargsNoValFlags[a]; ok {
			continue
		}
		if _, ok := xargsValFlags[a]; ok {
			i++ // skip the value
			continue
		}
		// Handle --flag=value syntax (e.g., --delimiter=,).
		if strings.HasPrefix(a, "--") && strings.Contains(a, "=") {
			continue
		}
		// Handle short flags with attached values (e.g., -I{}, -n1, -d,).
		if len(a) > 2 && a[0] == '-' && a[1] != '-' {
			short := a[:2]
			if _, ok := xargsValFlags[short]; ok {
				continue // value is attached
			}
		}
		// Not a recognized xargs flag — this is the target command.
		return a
	}
	return ""
}
