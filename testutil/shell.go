// Package testutil provides platform-aware test helpers so that tests can run
// on both Unix and Windows without hard-coding shell paths or OS-specific
// command syntax.
package testutil

import (
	"os"
	"path/filepath"
	"runtime"
)

// isWindows reports whether the current OS is Windows.
func isWindows() bool {
	return runtime.GOOS == "windows" //nolint:goconst // idiomatic runtime.GOOS comparison
}

// Shell returns the absolute path of the platform-appropriate shell executable.
// On Windows it returns the full path to cmd.exe (e.g. C:\Windows\System32\cmd.exe);
// on Unix-like systems it returns "/bin/sh".
func Shell() string {
	if isWindows() {
		return filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	}
	return "/bin/sh"
}

// ShellFlag returns the flag used to pass a command string to the shell.
// On Windows it returns "/c"; on Unix-like systems it returns "-c".
func ShellFlag() string {
	if isWindows() {
		return "/c"
	}
	return "-c"
}

// ShellArgs returns a complete argument slice for running cmd inside the
// platform shell.  The returned slice is suitable as the args parameter
// to exec.Command(Shell(), ShellArgs(cmd)...).
func ShellArgs(cmd string) []string {
	return []string{ShellFlag(), cmd}
}
