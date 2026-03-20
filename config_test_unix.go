//go:build !windows

package agentbox

import (
	"strings"
	"testing"
)

// testDefaultConfigPlatformSpecific verifies Unix-specific default paths.
func testDefaultConfigPlatformSpecific(t *testing.T, cfg *Config) {
	// On Unix, DenyWrite should contain Unix system paths.
	hasUnixPath := false
	for _, path := range cfg.Filesystem.DenyWrite {
		if strings.HasPrefix(path, "/etc") || strings.HasPrefix(path, "/usr") ||
			strings.HasPrefix(path, "/bin") || strings.HasPrefix(path, "/lib") {
			hasUnixPath = true
			break
		}
	}
	if !hasUnixPath {
		t.Error("DenyWrite should contain Unix system paths like /etc, /usr, /bin")
	}

	// On Unix, DenyRead should contain Unix-specific paths like /proc or /sys.
	hasUnixSpecific := false
	for _, path := range cfg.Filesystem.DenyRead {
		if strings.Contains(path, "/proc") || strings.Contains(path, "/sys") {
			hasUnixSpecific = true
			break
		}
	}
	if !hasUnixSpecific {
		t.Error("DenyRead should contain Unix-specific paths like /proc or /sys")
	}
}
