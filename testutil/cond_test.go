package testutil

import (
	"runtime"
	"testing"
)

func TestSkipIfWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test validates the non-Windows path")
	}
	// On non-Windows, SkipIfWindows should NOT skip.
	SkipIfWindows(t, "test reason")
	// Reaching here means the test was not skipped — correct for Unix.
}

func TestSkipIfNotWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows, SkipIfNotWindows should NOT skip.
		SkipIfNotWindows(t, "test reason")
		return
	}
	// On Unix, we cannot directly test SkipIfNotWindows without it
	// skipping the real test, so we verify indirectly via a subtest.
	t.Run("skips_on_unix", func(t *testing.T) {
		SkipIfNotWindows(t, "windows-only feature")
		// If we reach here, the skip did not work.
		t.Error("SkipIfNotWindows should have skipped on non-Windows")
	})
}

func TestRequireUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only for Unix platforms")
	}
	// On Unix, RequireUnix must not skip.
	RequireUnix(t)
	// Reaching here means it did not skip — correct.
}

func TestRequireUnixSkipsOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		// Verify that RequireUnix does NOT skip on Unix.
		RequireUnix(t)
		return
	}
	// On Windows this subtest would be skipped by RequireUnix.
	t.Run("skips", func(t *testing.T) {
		RequireUnix(t)
		t.Error("RequireUnix should have skipped on Windows")
	})
}

func TestSkipIfWindowsDoesNotSkipOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only test")
	}
	SkipIfWindows(t, "unix sockets required")
	// Reaching here confirms no skip occurred on Unix.
}

func TestSkipIfNotWindowsSkipsOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only test")
	}
	// Use a subtest so the outer test does not get skipped.
	t.Run("inner", func(t *testing.T) {
		SkipIfNotWindows(t, "windows-only feature")
		t.Error("should have been skipped on Unix")
	})
}

func TestSkipIfWindowsSkipsOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only test")
	}
	t.Run("inner", func(t *testing.T) {
		SkipIfWindows(t, "test reason")
		t.Error("should have been skipped on Windows")
	})
}

func TestSkipIfNotWindowsDoesNotSkipOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only test")
	}
	SkipIfNotWindows(t, "test reason")
	// Reaching here confirms no skip occurred on Windows.
}
