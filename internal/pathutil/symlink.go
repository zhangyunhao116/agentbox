// Package pathutil symlink.go provides symlink boundary checking utilities.
// These functions detect when symlink resolution would escape a directory
// boundary, which is critical for sandbox isolation.
package pathutil

import (
	"fmt"
	"path/filepath"
	"strings"
)

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
