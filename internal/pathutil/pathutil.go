// Package pathutil provides path security utilities for sandbox isolation.
// It includes symlink boundary checking (symlink.go), glob pattern support
// (glob.go), dangerous file scanning (dangerous.go), git worktree detection
// (git.go), and general path helper functions (this file).
package pathutil

import (
	"os"
	"path/filepath"
	"strings"
)

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
