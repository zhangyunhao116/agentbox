//go:build windows

package agentbox

import (
	"os"
	"path/filepath"
)

// defaultDenyWritePaths returns the default list of paths to deny write access to
// on Windows systems. These are core system directories that should not be modified
// by sandboxed processes.
func defaultDenyWritePaths(home string) []string {
	// Protect Windows system directories from sandbox writes.
	windir := os.Getenv("SYSTEMROOT") // typically C:\Windows
	if windir == "" {
		windir = `C:\Windows`
	}

	progFiles := os.Getenv("PROGRAMFILES") // typically C:\Program Files
	if progFiles == "" {
		progFiles = `C:\Program Files`
	}

	progFilesX86 := os.Getenv("PROGRAMFILES(X86)") // typically C:\Program Files (x86)
	if progFilesX86 == "" {
		progFilesX86 = `C:\Program Files (x86)`
	}

	progData := os.Getenv("PROGRAMDATA") // typically C:\ProgramData
	if progData == "" {
		progData = `C:\ProgramData`
	}

	return []string{
		home,
		windir,
		progFiles,
		progFilesX86,
		progData,
	}
}

// defaultDenyReadPaths returns the default list of paths to deny read access to
// on Windows systems. These are credential and sensitive configuration directories
// within the user's home directory.
func defaultDenyReadPaths(home string) []string {
	return []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".git-credentials"),
		filepath.Join(home, ".npmrc"),
		filepath.Join(home, ".netrc"),
		filepath.Join(home, ".docker"),
		filepath.Join(home, ".pypirc"),
		filepath.Join(home, ".kube"),
		filepath.Join(home, ".config", "gcloud"),
		// Note: No /proc/*/mem or /sys on Windows - these are Linux-specific.
	}
}
