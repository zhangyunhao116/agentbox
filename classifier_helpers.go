// classifier_helpers.go contains shared utility functions used by multiple
// classifier rule files (forbidden, escalated, allow). These helpers handle
// command parsing, pipe scanning, path analysis, and other cross-cutting
// concerns.

package agentbox

import (
	"path"
	"strings"
)

// pipeShells is the canonical list of shell and interpreter names used to
// detect dangerous pipe-to-shell patterns across multiple rules.
var pipeShells = [...]string{"sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "node"}

// baseCommand extracts the base name from a possibly path-qualified command.
// Trailing slashes are stripped before extracting the base name. Windows
// executable suffixes (.exe, .cmd, .bat) are removed so that "python.exe"
// normalizes to "python" and all rules match uniformly.
func baseCommand(cmd string) string {
	cmd = strings.TrimRight(cmd, "/")
	if cmd == "" {
		return ""
	}
	// Also handle Windows backslash paths (e.g. C:\Python39\python.exe).
	idx := strings.LastIndex(cmd, "/")
	if bIdx := strings.LastIndex(cmd, `\`); bIdx > idx {
		idx = bIdx
	}
	if idx >= 0 {
		cmd = cmd[idx+1:]
	}
	// Strip common Windows executable suffixes.
	lower := strings.ToLower(cmd)
	for _, suffix := range []string{".exe", ".cmd", ".bat"} {
		if strings.HasSuffix(lower, suffix) {
			cmd = cmd[:len(cmd)-len(suffix)]
			break
		}
	}
	return cmd
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

// containsPipeToShell checks whether a command string contains a top-level
// pipe to a common shell or interpreter. Pipes inside subshells ($(...)),
// backticks, or quotes are ignored. Python/python3 with -c or -m flags is
// considered safe (inline code, not stdin eval).
func containsPipeToShell(command string) bool {
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
				if (target == cmdPython || target == cmdPython3) && isPipeTargetSafePython(fields) {
					continue
				}
				return true
			}
		}
	}
	return false
}

// splitTopLevelPipes splits a command string on pipe '|' characters that are
// NOT inside single quotes, double quotes, $(...) subshells, $((...))
// arithmetic, or backtick groups. This prevents subshell pipes (e.g. inside
// $(echo|shasum)) from being treated as top-level pipes.
func splitTopLevelPipes(command string) []string {
	var (
		result []string
		ps     pipeScanner
		start  int
	)
	for i := 0; i < len(command); i++ {
		advance, isSplit := ps.feed(command, i)
		if isSplit {
			// Distinguish pipe '|' from logical OR '||'.
			if i+1 < len(command) && command[i+1] == '|' {
				i++ // skip the second '|'; this is '||', not a pipe
			} else {
				result = append(result, command[start:i])
				start = i + 1
			}
		}
		i += advance
	}
	return append(result, command[start:])
}

// pipeScanner tracks quoting and subshell nesting while scanning a command
// string for top-level pipe characters.
type pipeScanner struct {
	depth    int  // $(...) nesting
	inSingle bool // inside '...'
	inDouble bool // inside "..."
	inBtick  bool // inside `...`
}

// feed processes command[i] and returns (advance, isSplit). advance is the
// number of extra characters to skip (e.g. 1 for escapes or "$(" pairs).
// isSplit is true when the character is a top-level pipe.
func (ps *pipeScanner) feed(cmd string, i int) (advance int, isSplit bool) {
	ch := cmd[i]
	if ch == '\\' && !ps.inSingle && i+1 < len(cmd) {
		return 1, false // skip escaped char
	}
	if ps.toggleQuote(ch) {
		return 0, false
	}
	if ch == '$' && !ps.inSingle && !ps.inBtick && i+1 < len(cmd) && cmd[i+1] == '(' {
		ps.depth++
		return 1, false
	}
	if ch == ')' && !ps.inSingle && !ps.inBtick && ps.depth > 0 {
		ps.depth--
		return 0, false
	}
	if ch == '|' && !ps.inSingle && !ps.inDouble && !ps.inBtick && ps.depth == 0 {
		return 0, true
	}
	return 0, false
}

// toggleQuote toggles the appropriate quote state flag and reports whether ch
// was a quote character that was handled.
func (ps *pipeScanner) toggleQuote(ch byte) bool {
	switch {
	case ch == '\'' && !ps.inDouble && !ps.inBtick:
		ps.inSingle = !ps.inSingle
		return true
	case ch == '"' && !ps.inSingle && !ps.inBtick:
		ps.inDouble = !ps.inDouble
		return true
	case ch == '`' && !ps.inSingle && !ps.inDouble:
		ps.inBtick = !ps.inBtick
		return true
	}
	return false
}

// isPipeTargetSafePython reports whether a pipe segment whose base command is
// "python" or "python3" is safe. It is safe when the interpreter is invoked
// with -c (inline code), -m (module), or a heredoc (<<) because it does not
// read arbitrary code from stdin. Bare `python3` (no args) reads stdin and is
// dangerous.
func isPipeTargetSafePython(fields []string) bool {
	if len(fields) < 2 {
		return false // bare python — reads from stdin
	}
	for _, f := range fields[1:] {
		if f == "-c" || f == "-m" {
			return true
		}
		// A heredoc marker (e.g. `<< 'PYEOF'`) means the script body is
		// embedded in the command, not read from the pipe — safe.
		if strings.HasPrefix(f, "<<") {
			return true
		}
		// Stop at first non-flag argument.
		if len(f) > 0 && f[0] != '-' {
			break
		}
	}
	return false
}

// hasStandaloneCommand reports whether cmd appears as a standalone command word
// inside the lower-cased string s. "Standalone" means preceded by
// start-of-string, whitespace, pipe '|', semicolon ';', ampersand '&', or '/'
// and followed by end-of-string or whitespace. This prevents substring matches
// like "rsync" containing "nc" or "func" containing "nc".
func hasStandaloneCommand(s, cmd string) bool {
	for i := 0; i < len(s); {
		idx := strings.Index(s[i:], cmd)
		if idx < 0 {
			return false
		}
		pos := i + idx
		end := pos + len(cmd)
		// Check left boundary: start-of-string or a non-alphanumeric separator.
		leftOK := pos == 0 || !isWordChar(s[pos-1])
		// Check right boundary: end-of-string or a non-alphanumeric char.
		rightOK := end >= len(s) || !isWordChar(s[end])
		if leftOK && rightOK {
			return true
		}
		i = pos + 1
	}
	return false
}

// isRedirectTerminator reports whether c is a shell metacharacter that
// terminates a redirect target path. Redirect targets end at whitespace,
// newlines, shell operators like ; & | ) < >, and brace group delimiters { }.
func isRedirectTerminator(c byte) bool {
	switch c {
	case ' ', '\t', '\n', ';', '&', '|', ')', '<', '>', '{', '}':
		return true
	}
	return false
}

// isCommandSeparator reports whether a shell token is a command separator
// (&&, ||, ;, |) or contains an embedded separator character. When
// strings.Fields splits a raw command, semicolons without surrounding spaces
// remain attached to the preceding token (e.g. "~/x;" from "rm -rf ~/x; ls").
// Detecting these embedded separators prevents rules from scanning into the
// next command.
func isCommandSeparator(token string) bool {
	switch token {
	case "&&", "||", ";", "|":
		return true
	}
	// Check for embedded shell metacharacters that signal a command boundary.
	for i := 0; i < len(token); i++ {
		switch token[i] {
		case ';', '|':
			return true
		case '&':
			// A single & (background) is also a command boundary.
			return true
		}
	}
	return false
}

// isWordChar reports whether b is an ASCII letter, digit, underscore, or
// hyphen. Hyphens are included so that flag-like tokens such as "--nc" are
// treated as a single word and do not produce a false word boundary.
func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-'
}

// isSimpleCommand reports whether command is a simple command — i.e. it does
// NOT contain top-level compound operators (&&, ||, ;), pipes (|, |&), or
// I/O redirections (>, >>, <, <<). Operators inside single quotes, double
// quotes, $(...) subshells, or backticks are ignored.
//
// Redirects are rejected because "echo payload > /etc/cron.d/job" would
// otherwise pass as a simple echo. The one safe redirect family — fd-to-fd
// merges like 2>&1 and >&2 — is explicitly allowed: any ">" immediately
// followed by "&" and a digit is kept.
//
// Allow rules use this to prevent compound/redirect abuse.
func isSimpleCommand(command string) bool {
	return isSimpleScan(command, false, false, false)
}

// isSimpleScan performs the character-level scan for isSimpleCommand.
// The ignore* parameters tell the scanner to treat the corresponding quote
// character as a literal (not a quote delimiter). This is used to recover
// from unmatched quotes — common in user-supplied paths such as "Mia's dir".
func isSimpleScan(command string, ignoreSingle, ignoreDouble, ignoreBtick bool) bool {
	var ps pipeScanner
	for i := 0; i < len(command); i++ {
		ch := command[i]
		pos := i // save position before advance

		// When an unmatched-quote retry tells us to ignore a specific
		// quote type, skip past it so the pipeScanner sees it as a
		// literal character (it never toggles that quote state).
		isIgnored := (ch == '\'' && ignoreSingle) ||
			(ch == '"' && ignoreDouble) ||
			(ch == '`' && ignoreBtick)
		if !isIgnored {
			// Let the pipe scanner handle escapes and quoting state.
			advance, _ := ps.feed(command, i)
			i += advance
		}

		// Outside quotes/subshells, check for compound operators,
		// pipes, and redirections.
		if ps.inSingle || ps.inDouble || ps.inBtick || ps.depth > 0 {
			continue
		}
		if _, reject := isSimpleCheck(ch, command, pos); reject {
			return false
		}
	}

	// If a quote was opened but never closed, the command contains an
	// unmatched quote (e.g. an apostrophe in a file-path like "Mia's").
	// In a real shell this would be a syntax error, but IDE-submitted
	// commands contain literal apostrophes in paths routinely. Re-scan
	// while treating the unmatched quote type as a literal so that
	// operators hidden behind the false quote context are detected.
	if ps.inSingle || ps.inDouble || ps.inBtick {
		return isSimpleScan(command,
			ignoreSingle || ps.inSingle,
			ignoreDouble || ps.inDouble,
			ignoreBtick || ps.inBtick,
		)
	}

	// Paranoid check: even-count stray quotes can pair up and hide
	// operators.  Re-scan with all quotes as literals — if operators are
	// found, the command is not simple regardless of apparent quoting.
	// In our classifier context commands come from IDEs, not real shells,
	// so legitimate quoting of operators (e.g. echo "a && b") should
	// still be treated conservatively.
	if !ignoreSingle || !ignoreDouble || !ignoreBtick {
		if !isSimpleScan(command, true, true, true) {
			return false
		}
	}
	return true
}

// isSimpleCheck inspects a single top-level character at position pos in
// command and reports whether it should be (safe=continue, reject=false).
// If both are false the caller continues scanning normally.
func isSimpleCheck(ch byte, command string, pos int) (safe, reject bool) {
	n := len(command)
	switch ch {
	case ';':
		return false, true
	case '&':
		return isSimpleAmpersand(command, pos, n)
	case '|':
		return isSimplePipe()
	case '>':
		return isSimpleOutputRedirect(command, pos, n)
	case '<':
		return isSimpleInputRedirect()
	}
	return false, false
}

// isSimpleAmpersand handles '&' in isSimpleCommand.
func isSimpleAmpersand(command string, pos, n int) (safe, reject bool) {
	// Double && is a compound operator.
	if pos+1 < n && command[pos+1] == '&' {
		return false, true
	}
	// Skip & when it is part of a redirect operator (>&, &>).
	// Examples: 2>&1, &>/dev/null.
	if pos > 0 && command[pos-1] == '>' {
		return true, false
	}
	if pos+1 < n && command[pos+1] == '>' {
		return true, false
	}
	// Bare & (not part of && or redirect) is a Windows command
	// separator and Unix background operator — treat as compound.
	return false, true
}

// isSimplePipe handles '|' in isSimpleCommand. All pipe variants are rejected.
func isSimplePipe() (safe, reject bool) {
	// || (logical OR), |& (bash stderr pipe), or single | — all rejected.
	return false, true
}

// isSimpleOutputRedirect handles '>' in isSimpleCommand.
// Safe fd-to-fd merges (>&N, e.g. 2>&1, >&2) return safe=true.
func isSimpleOutputRedirect(command string, pos, n int) (safe, reject bool) {
	next := pos + 1
	// >> (append) — reject.
	if next < n && command[next] == '>' {
		return false, true
	}
	// >& followed by a digit is an fd-to-fd merge (safe).
	if next < n && command[next] == '&' {
		if next+1 < n && command[next+1] >= '0' && command[next+1] <= '9' {
			return true, false
		}
		// >& without a digit (e.g. >&file) — reject.
		return false, true
	}
	// Plain > (output redirect to file) — reject.
	return false, true
}

// isSimpleInputRedirect handles '<' in isSimpleCommand. All input redirects
// (< and << heredoc) are rejected.
func isSimpleInputRedirect() (safe, reject bool) {
	return false, true
}

// clipboardTools lists commands that modify the system clipboard.
var clipboardTools = map[string]bool{
	"pbcopy": true, "xclip": true, "xsel": true, "clip": true,
}

// hasOutputRedirectOrClipboardPipe scans command (outside quotes and
// subshells) for output redirection (> or >>) or a pipe to a clipboard
// tool (pbcopy, xclip, xsel, clip).  It returns true if either pattern
// is found.  This is used by allow rules to reject commands like
// "printf '...' > file" or "printf ... | pbcopy".
func hasOutputRedirectOrClipboardPipe(command string) bool {
	var ps pipeScanner
	for i := 0; i < len(command); i++ {
		ch := command[i]
		pos := i
		advance, _ := ps.feed(command, i)
		i += advance
		if ps.inSingle || ps.inDouble || ps.inBtick || ps.depth > 0 {
			continue
		}
		// Detect > or >> outside quotes (but not >&, which is stderr merge).
		if ch == '>' {
			next := byte(0)
			if pos+1 < len(command) {
				next = command[pos+1]
			}
			// Skip >& (stderr redirect merge like >&2, 2>&1).
			if next == '&' {
				continue
			}
			return true
		}
		// Detect pipe to clipboard tool.
		if ch == '|' {
			rest := strings.TrimLeft(command[pos+1:], " \t")
			word := rest
			if idx := strings.IndexAny(rest, " \t"); idx >= 0 {
				word = rest[:idx]
			}
			if clipboardTools[baseCommand(word)] {
				return true
			}
		}
	}
	return false
}

// containsWordToken reports whether s contains token as a standalone word
// delimited by common separators (_, -, .) or string boundaries.
func containsWordToken(s, token string) bool {
	for i := 0; i < len(s); {
		idx := strings.Index(s[i:], token)
		if idx < 0 {
			return false
		}
		pos := i + idx
		end := pos + len(token)
		leftOK := pos == 0 || s[pos-1] == '_' || s[pos-1] == '-' || s[pos-1] == '.'
		rightOK := end >= len(s) || s[end] == '_' || s[end] == '-' || s[end] == '.'
		if leftOK && rightOK {
			return true
		}
		i = pos + 1
	}
	return false
}

// findGitSubcommand returns the first non-flag argument in fields,
// skipping flags and their consumed values.  It is shared by
// gitReadCommandsRule and gitWriteRule.
func findGitSubcommand(fields []string) string {
	skip := false
	for _, f := range fields {
		if skip {
			skip = false
			continue
		}
		if strings.HasPrefix(f, "-") {
			// Check if this flag consumes the next token.
			// For --key=value forms, no skip needed.
			if strings.Contains(f, "=") {
				continue
			}
			if gitValueFlags[f] {
				skip = true
			}
			continue
		}
		return f
	}
	return ""
}

// containsFlag reports whether flag appears in the given slice.
func containsFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// gitValueFlags lists git global flags that consume the next argument as a value.
var gitValueFlags = map[string]bool{
	"-C":              true,
	"-c":              true,
	"--git-dir":       true,
	"--work-tree":     true,
	"--namespace":     true,
	"--super-prefix":  true,
	"--exec-path":     true,
	"--config-env":    true,
	"--list-cmds":     true,
	"--attr-source":   true,
	"--glob-pathspec": true,
}
