//go:build windows

package agentbox

import (
	"os"
	"path/filepath"
)

// defaultShellPath returns the default shell used for command execution on Windows.
// It constructs the path from the SystemRoot environment variable for reliability,
// matching the approach used in testutil.Shell(). Falls back to a hardcoded path
// when SystemRoot is empty (e.g., minimal containers).
func defaultShellPath() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return filepath.Join(root, "System32", "cmd.exe")
	}
	return `C:\Windows\System32\cmd.exe`
}

// defaultShellFlag returns the flag used to pass a command string to cmd.exe on Windows.
func defaultShellFlag() string {
	return "/c"
}
