package testutil

import "testing"

// SkipIfWindows marks the test as skipped when running on Windows.
// Use this for tests that genuinely require Unix-specific features (e.g. Unix
// sockets, chmod semantics) rather than simply avoiding portability work.
func SkipIfWindows(t *testing.T, reason string) {
	t.Helper()
	if isWindows() {
		t.Skip("Skipped on Windows: " + reason)
	}
}

// SkipIfNotWindows marks the test as skipped when running on any platform
// other than Windows.
func SkipIfNotWindows(t *testing.T, reason string) {
	t.Helper()
	if !isWindows() {
		t.Skip("Skipped on non-Windows: " + reason)
	}
}

// RequireUnix marks the test as skipped when not running on a Unix-like
// system (i.e. when GOOS is "windows").
func RequireUnix(t *testing.T) {
	t.Helper()
	if isWindows() {
		t.Skip("Requires Unix-like system")
	}
}
