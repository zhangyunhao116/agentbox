package agentbox

import (
	"path"
	"path/filepath"
	"strings"
)

// Command names used in protected path detection.
const (
	cmdSed = "sed"
	cmdCP  = "cp"
)

// ProtectedPath defines a path pattern that should be protected from writes.
// When a write operation targeting a matching path is detected, the command
// is classified with the specified Decision (typically Forbidden or Escalated).
type ProtectedPath struct {
	// Pattern is a glob pattern matched against file paths in commands.
	// Examples: ".git/*", ".agent/*", "/etc/*"
	Pattern string `json:"pattern"`

	// Decision is the classification when a write to this path is detected.
	// Typically Forbidden or Escalated.
	Decision Decision `json:"decision"`

	// Description explains why this path is protected.
	Description string `json:"description,omitempty"`
}

// defaultProtectedPaths defines the built-in set of protected path rules.
// Inspired by Claude Code's protected dirs (.git, .claude, .vscode) and
// Codex CLI's protected paths (.git, .codex, .agents).
var defaultProtectedPaths = []ProtectedPath{
	{Pattern: ".git/hooks/*", Decision: Forbidden, Description: "git hooks directory"},
	{Pattern: ".git/config", Decision: Escalated, Description: "git config file"},
	{Pattern: ".agent/*", Decision: Forbidden, Description: "agent configuration directory"},
	{Pattern: ".claude/*", Decision: Forbidden, Description: "claude configuration directory"},
	{Pattern: ".vscode/*", Decision: Escalated, Description: "vscode settings directory"},
	{Pattern: ".idea/*", Decision: Escalated, Description: "jetbrains settings directory"},
	{Pattern: ".env", Decision: Escalated, Description: "environment file"},
	{Pattern: ".env.*", Decision: Escalated, Description: "environment file variants"},
}

// writeCommands are commands that perform write operations on file paths.
var writeCommands = map[string]bool{
	"rm": true, "mv": true, "chmod": true, "chown": true,
	"tee": true, "truncate": true, "install": true,
}

// Compile-time interface check.
var _ Classifier = (*protectedPathClassifier)(nil)

// protectedPathClassifier detects write operations targeting protected paths.
// It implements the Classifier interface.
type protectedPathClassifier struct {
	paths []ProtectedPath
}

// Classify inspects a shell command string to detect writes to protected paths.
// Returns a zero-value ClassifyResult (Sandboxed) when no protected path is
// affected, allowing ChainClassifier to fall through.
func (c *protectedPathClassifier) Classify(command string) ClassifyResult {
	// Check for output redirect: > or >> targeting a protected path.
	if r := c.checkRedirects(command); r.Decision != Sandboxed {
		return r
	}
	// Check for write commands with protected path arguments.
	return c.checkWriteCommand(command)
}

// ClassifyArgs inspects a command specified as program name and argument list.
func (c *protectedPathClassifier) ClassifyArgs(name string, args []string) ClassifyResult {
	base := baseCommand(name)
	if !isWriteCommand(base) && base != cmdSed && base != cmdGit && base != cmdCP {
		return ClassifyResult{}
	}
	// sed -i is a write; plain sed is not.
	if base == cmdSed && !containsFlagPrefix(args, "-i") {
		return ClassifyResult{}
	}
	// git checkout -- <path> is a write (overwrites working tree).
	if base == cmdGit {
		return c.checkGitArgs(args)
	}
	// For cp, only the last arg (destination) is a write target.
	if base == cmdCP {
		return c.checkCPArgs(args)
	}
	// For other write commands, check all non-flag arguments.
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if r := c.matchPath(arg); r.Decision != Sandboxed {
			return r
		}
	}
	return ClassifyResult{}
}

// checkRedirects detects > and >> redirects to protected paths.
func (c *protectedPathClassifier) checkRedirects(command string) ClassifyResult {
	for _, op := range []string{">>", ">"} {
		idx := strings.Index(command, op)
		if idx < 0 {
			continue
		}
		target := strings.TrimSpace(command[idx+len(op):])
		// Take only the first token as the target path.
		if sp := strings.IndexAny(target, " \t;|&"); sp >= 0 {
			target = target[:sp]
		}
		if target == "" {
			continue
		}
		if r := c.matchPath(target); r.Decision != Sandboxed {
			return r
		}
	}
	return ClassifyResult{}
}

// checkWriteCommand parses a command string to detect write commands with
// protected path arguments.
func (c *protectedPathClassifier) checkWriteCommand(command string) ClassifyResult {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ClassifyResult{}
	}
	cmd := baseCommand(fields[0])
	// Handle "sed -i" as a write command.
	if cmd == cmdSed {
		hasDashI := false
		for _, f := range fields[1:] {
			if f == "-i" || strings.HasPrefix(f, "-i") {
				hasDashI = true
				break
			}
		}
		if !hasDashI {
			return ClassifyResult{}
		}
		// Check remaining args for protected paths.
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "-") {
				continue
			}
			if r := c.matchPath(f); r.Decision != Sandboxed {
				return r
			}
		}
		return ClassifyResult{}
	}
	// Handle "cp" — destination is the last non-flag argument.
	if cmd == cmdCP {
		return c.checkCPFields(fields[1:])
	}
	// Handle "git checkout -- <path>".
	if cmd == cmdGit {
		return c.checkGitFields(fields[1:])
	}
	if !writeCommands[cmd] {
		return ClassifyResult{}
	}
	// Check all non-flag arguments for protected path matches.
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "-") {
			continue
		}
		if r := c.matchPath(f); r.Decision != Sandboxed {
			return r
		}
	}
	return ClassifyResult{}
}

// checkCPFields checks cp command fields for writes to protected destinations.
func (c *protectedPathClassifier) checkCPFields(fields []string) ClassifyResult {
	// The destination is the last non-flag argument.
	var nonFlags []string
	for _, f := range fields {
		if !strings.HasPrefix(f, "-") {
			nonFlags = append(nonFlags, f)
		}
	}
	if len(nonFlags) < 2 {
		return ClassifyResult{}
	}
	return c.matchPath(nonFlags[len(nonFlags)-1])
}

// checkCPArgs checks cp args for writes to protected destinations.
func (c *protectedPathClassifier) checkCPArgs(args []string) ClassifyResult {
	return c.checkCPFields(args)
}

// checkGitFields checks git checkout -- <path> patterns.
func (c *protectedPathClassifier) checkGitFields(fields []string) ClassifyResult {
	// Look for "checkout" followed by "--" then a path.
	for i, f := range fields {
		if f != "checkout" {
			continue
		}
		for j := i + 1; j < len(fields); j++ {
			if fields[j] == "--" {
				// Everything after "--" is a path.
				for _, p := range fields[j+1:] {
					if r := c.matchPath(p); r.Decision != Sandboxed {
						return r
					}
				}
				return ClassifyResult{}
			}
		}
	}
	return ClassifyResult{}
}

// checkGitArgs checks git args for checkout -- <path> pattern.
func (c *protectedPathClassifier) checkGitArgs(args []string) ClassifyResult {
	return c.checkGitFields(args)
}

// matchPath checks if a path matches any protected path pattern.
// Paths are normalized with path.Clean to prevent traversal bypasses
// (e.g. "foo/../.git/hooks/pre-commit" → ".git/hooks/pre-commit").
func (c *protectedPathClassifier) matchPath(p string) ClassifyResult {
	// Normalize: clean traversal sequences and strip leading "./" for consistent matching.
	clean := path.Clean(p)
	clean = strings.TrimPrefix(clean, "./")
	for _, pp := range c.paths {
		matched, err := filepath.Match(pp.Pattern, clean)
		if err != nil {
			continue
		}
		if !matched {
			// filepath.Match("dir/*", "dir/sub/file") returns false
			// because * does not match '/'. Use prefix matching for
			// patterns ending in /* to handle arbitrary nesting.
			if strings.HasSuffix(pp.Pattern, "/*") {
				prefix := pp.Pattern[:len(pp.Pattern)-1] // "dir/*" → "dir/"
				matched = strings.HasPrefix(clean, prefix)
			}
		}
		if matched {
			return ClassifyResult{
				Decision: pp.Decision,
				Reason:   "write to protected path: " + pp.Description,
				Rule:     RuleName("protected-path: " + pp.Pattern),
			}
		}
	}
	return ClassifyResult{}
}

// isWriteCommand returns true if the command name is a known write operation.
func isWriteCommand(cmd string) bool {
	return writeCommands[cmd]
}

// containsFlagPrefix checks if a flag (or a flag with a value suffix) is
// present in the argument list. For example, containsFlagPrefix(args, "-i")
// matches both "-i" and "-i.bak".
func containsFlagPrefix(args []string, flag string) bool {
	for _, a := range args {
		if a == flag || strings.HasPrefix(a, flag) {
			return true
		}
	}
	return false
}
