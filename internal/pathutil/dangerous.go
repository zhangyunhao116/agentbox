// Package pathutil dangerous.go provides dangerous file and directory scanning.
// It maintains lists of security-sensitive files (e.g., .gitconfig, .bashrc)
// and directories (e.g., .git/hooks, .vscode) that should be write-protected
// in sandboxed environments.
package pathutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
