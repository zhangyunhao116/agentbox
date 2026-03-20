//go:build !windows

package agentbox

import "path/filepath"

// defaultDenyWritePaths returns the default list of paths to deny write access to
// on Unix-like systems (Linux, macOS, BSDs).
func defaultDenyWritePaths(home string) []string {
	return []string{
		home,
		"/etc",
		"/usr",
		"/bin",
		"/sbin",
		"/lib",
		"/lib64",
		"/boot",
		"/opt",
		"/sys",
	}
}

// defaultDenyReadPaths returns the default list of paths to deny read access to
// on Unix-like systems. These are typically credential or sensitive configuration
// directories within the user's home directory, plus kernel memory interfaces.
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
		"/proc/*/mem",
		"/sys",
	}
}
