// Package pathutil provides path security utilities for sandbox isolation.
// It includes symlink boundary checking, glob pattern support, dangerous file
// scanning, git worktree detection, and various path helper functions.
package pathutil

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Symlink Boundary Check
// ---------------------------------------------------------------------------

// IsSymlinkOutsideBoundary checks if resolving a symlink would broaden access
// scope. Returns true if the resolved path escapes the expected boundary.
//
// The boundary is defined as the directory containing the original path. If the
// resolved path does not start with that boundary prefix, it is considered an
// escape.
//
// Examples:
//   - /tmp/link -> /            : returns true  (resolves to root)
//   - /tmp/link -> /tmp/real    : returns false  (stays within)
//   - /workspace/link -> /etc   : returns true   (escapes workspace)
func IsSymlinkOutsideBoundary(originalPath, resolvedPath string) bool {
	boundary := filepath.Dir(filepath.Clean(originalPath))
	resolved := filepath.Clean(resolvedPath)

	// The resolved path must be the boundary itself or a child of it.
	if resolved == boundary {
		return false
	}
	// When boundary is root "/", every absolute path is within it.
	if boundary == "/" {
		return !strings.HasPrefix(resolved, "/")
	}
	return !strings.HasPrefix(resolved, boundary+string(filepath.Separator))
}

// ResolveWithBoundaryCheck resolves a path (following symlinks) and checks
// that the resolution stays within acceptable boundaries. The boundary is the
// directory containing the original path. Returns the resolved path or an
// error if the resolution would escape boundaries.
func ResolveWithBoundaryCheck(path string) (string, error) {
	absPath, _ := filepath.Abs(path)

	resolved, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", fmt.Errorf("pathutil: cannot resolve symlinks: %w", err)
	}

	if IsSymlinkOutsideBoundary(absPath, resolved) {
		return "", fmt.Errorf("pathutil: resolved path %q escapes boundary of %q", resolved, filepath.Dir(absPath))
	}
	return resolved, nil
}

// ---------------------------------------------------------------------------
// Glob Pattern Support
// ---------------------------------------------------------------------------

// GlobToRegex converts a glob pattern to a regexp string.
// Supports: * (any non-separator), ** (any including separator),
// ? (single non-separator char), [...] (character class).
func GlobToRegex(pattern string) string {
	var b strings.Builder
	b.WriteString("^")
	i := 0
	for i < len(pattern) {
		ch := pattern[i]
		switch ch {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				// ** matches everything including separators.
				i += 2
				// Skip a trailing separator after **.
				if i < len(pattern) && pattern[i] == '/' {
					i++
				}
				// Match any prefix (including empty) that ends at a boundary.
				b.WriteString("(?:.*/)?")
				continue
			}
			// Single * matches anything except separator.
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '[':
			// Pass through character class [...] verbatim.
			j := i + 1
			if j < len(pattern) && pattern[j] == ']' {
				j++ // allow ] as first char in class
			}
			for j < len(pattern) && pattern[j] != ']' {
				j++
			}
			if j < len(pattern) {
				// Found closing ], pass through as regex character class.
				b.WriteString(pattern[i : j+1])
				i = j + 1
				continue
			}
			// No closing bracket — escape the [ literally.
			b.WriteString("\\[")
		case '.', '+', '^', '$', '|', '(', ')', '{', '}', ']', '\\':
			b.WriteByte('\\')
			b.WriteByte(ch)
		default:
			b.WriteByte(ch)
		}
		i++
	}
	b.WriteString("$")
	return b.String()
}

// ExpandGlob expands a glob pattern to concrete filesystem paths.
// maxDepth limits directory traversal depth (0 = default of 20).
// Returns only paths that exist on the filesystem.
func ExpandGlob(pattern string, maxDepth int) ([]string, error) {
	if maxDepth == 0 {
		maxDepth = 20
	}

	// If the pattern has no glob metacharacters, just check existence.
	if !IsGlobPattern(pattern) {
		if _, err := os.Stat(pattern); err == nil {
			return []string{pattern}, nil
		}
		return nil, nil
	}

	// Determine the root: walk up until we find a component without globs.
	// filepath.Dir always converges to "." or "/" which contain no glob chars,
	// so this loop always terminates.
	root := pattern
	for IsGlobPattern(root) {
		root = filepath.Dir(root)
	}

	re := regexp.MustCompile(GlobToRegex(pattern))

	var matches []string
	rootDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))

	// filepath.Walk never returns an error when the callback returns nil.
	_ = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil //nolint:nilerr // intentionally skip inaccessible entries
		}
		if maxDepth > 0 {
			depth := strings.Count(filepath.Clean(path), string(filepath.Separator)) - rootDepth
			if depth > maxDepth {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if re.MatchString(path) {
			matches = append(matches, path)
		}
		return nil
	})
	return matches, nil
}

// IsGlobPattern returns true if the string contains glob metacharacters.
func IsGlobPattern(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// ---------------------------------------------------------------------------
// Dangerous File Scanning
// ---------------------------------------------------------------------------

// dangerousFiles is the list of filenames that should be write-protected.
var dangerousFiles = []string{
	".gitconfig", ".gitmodules", ".bashrc", ".bash_profile",
	".zshrc", ".zprofile", ".profile", ".ripgreprc", ".mcp.json",
	".npmrc", ".yarnrc", ".netrc", ".pypirc",
}

// dangerousDirectories is the list of directory names that need protection.
var dangerousDirectories = []string{".git/hooks", ".vscode", ".idea"}

// GetDangerousFiles returns a copy of the dangerous files list.
func GetDangerousFiles() []string {
	return append([]string(nil), dangerousFiles...)
}

// GetDangerousDirectories returns a copy of the dangerous directories list.
func GetDangerousDirectories() []string {
	return append([]string(nil), dangerousDirectories...)
}

// dangerousFileSet is a pre-built lookup set for O(1) filename checks.
var dangerousFileSet map[string]struct{}

func init() {
	dangerousFileSet = make(map[string]struct{}, len(dangerousFiles))
	for _, f := range dangerousFiles {
		dangerousFileSet[f] = struct{}{}
	}
}

// ScanDangerousFiles scans a directory tree for dangerous files and
// directories, returning their absolute paths. maxDepth limits traversal
// (0 = unlimited, recommended: 5).
func ScanDangerousFiles(root string, maxDepth int) ([]string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("pathutil: cannot resolve root: %w", err)
	}

	rootDepth := strings.Count(filepath.Clean(absRoot), string(filepath.Separator))
	var found []string

	// filepath.Walk never returns an error when the callback returns nil.
	_ = filepath.Walk(absRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil //nolint:nilerr // intentionally skip inaccessible entries
		}

		if maxDepth > 0 {
			depth := strings.Count(filepath.Clean(path), string(filepath.Separator)) - rootDepth
			if depth > maxDepth {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		name := filepath.Base(path)

		// Check dangerous files.
		if !info.IsDir() {
			if _, ok := dangerousFileSet[name]; ok {
				found = append(found, path)
			}
		}

		// Check dangerous directories.
		if info.IsDir() && path != absRoot {
			rel, relErr := filepath.Rel(absRoot, path)
			if relErr == nil {
				for _, dd := range dangerousDirectories {
					// Match if the relative path ends with the dangerous dir pattern.
					if rel == dd || strings.HasSuffix(rel, string(filepath.Separator)+dd) {
						found = append(found, path)
						break
					}
				}
			}
		}

		return nil
	})
	return found, nil
}

// ---------------------------------------------------------------------------
// Git Worktree Detection
// ---------------------------------------------------------------------------

// IsGitWorktree checks if the .git entry at the given path is a file
// (indicating a git worktree) rather than a directory.
func IsGitWorktree(dir string) bool {
	gitPath := filepath.Join(dir, ".git")
	info, err := os.Lstat(gitPath)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// ---------------------------------------------------------------------------
// Path Helpers
// ---------------------------------------------------------------------------

// FindFirstNonExistent returns the first component in a path that does not
// exist. Returns "" if the entire path exists.
func FindFirstNonExistent(path string) string {
	cleaned := filepath.Clean(path)

	// Collect ancestor chain from cleaned up to root/".".
	var chain []string
	cur := cleaned
	for {
		chain = append(chain, cur)
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}

	// Walk from the root (end of chain) towards the leaf (start of chain).
	// Return the first entry that doesn't exist, or "" if all exist.
	for i := len(chain) - 1; i >= 0; i-- {
		if _, err := os.Stat(chain[i]); err != nil {
			return chain[i]
		}
	}
	return ""
}

// ContainsNullByte returns true if the string contains a null byte.
func ContainsNullByte(s string) bool {
	return strings.ContainsRune(s, '\x00')
}

// StripNullBytes removes all null bytes from a string.
func StripNullBytes(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}
