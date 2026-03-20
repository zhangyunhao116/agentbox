//go:build windows

package agentbox

import (
	"strings"
	"testing"
)

// testDefaultConfigPlatformSpecific verifies Windows-specific default paths.
func testDefaultConfigPlatformSpecific(t *testing.T, cfg *Config) {
	// On Windows, DenyWrite should contain Windows paths (with backslash or colon).
	hasWindowsPath := false
	for _, path := range cfg.Filesystem.DenyWrite {
		// Windows paths contain : (drive letter) or start with \\ (UNC)
		if strings.Contains(path, ":") || strings.HasPrefix(path, `\\`) {
			hasWindowsPath = true
			break
		}
	}
	if !hasWindowsPath {
		t.Error("DenyWrite should contain Windows paths with drive letters (e.g., C:\\Windows)")
	}

	// On Windows, DenyWrite should NOT contain Unix paths like /etc or /usr.
	for _, path := range cfg.Filesystem.DenyWrite {
		if path == "/etc" || path == "/usr" || path == "/bin" {
			t.Errorf("DenyWrite should not contain Unix path: %s", path)
		}
	}

	// On Windows, DenyRead should NOT contain Unix-specific paths like /proc or /sys.
	for _, path := range cfg.Filesystem.DenyRead {
		if strings.HasPrefix(path, "/proc") || path == "/sys" {
			t.Errorf("DenyRead should not contain Unix-specific path: %s", path)
		}
	}
}
