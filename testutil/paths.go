package testutil

import (
	"os"
	"path/filepath"
)

// TempDir returns the platform-appropriate temporary directory.
// It is a thin wrapper around [os.TempDir] and exists so callers do not
// hard-code paths like "/tmp" which are not portable to Windows.
func TempDir() string {
	return os.TempDir()
}

// TempPath returns a file path inside the platform temporary directory
// constructed by joining [TempDir] with name.
func TempPath(name string) string {
	return filepath.Join(TempDir(), name)
}

// HomeDir returns the current user's home directory.  If the home directory
// cannot be determined it falls back to [TempDir] so callers always receive
// a usable path.
func HomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return TempDir()
	}
	return home
}
