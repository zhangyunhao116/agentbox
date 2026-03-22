// Package pathutil glob.go provides glob pattern matching utilities.
// It includes glob-to-regex conversion, pattern expansion against the
// filesystem, and glob metacharacter detection.
package pathutil

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

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

	// Fast path: try Go's built-in filepath.Glob for patterns that it
	// can handle natively (single-level wildcards like "/proc/*/mem").
	// filepath.Glob does NOT support "**" (recursive glob), so we only
	// use this fast path for patterns without "**". This avoids walking
	// huge virtual filesystems like /proc (which can have 100K+ entries
	// on busy systems).
	if !strings.Contains(pattern, "**") {
		if globMatches, err := filepath.Glob(pattern); err == nil {
			// filepath.Glob returns nil for no matches (not an error).
			return globMatches, nil
		}
	}

	// Slow path: fall back to filepath.Walk for complex patterns that
	// filepath.Glob cannot handle (e.g., recursive globs, regex-like).
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
