//go:build !windows

package agentbox

// defaultShellPath returns the default shell used for command execution on Unix systems.
func defaultShellPath() string {
	return "/bin/sh"
}

// defaultShellFlag returns the flag used to pass a command string to /bin/sh on Unix systems.
func defaultShellFlag() string {
	return "-c"
}
