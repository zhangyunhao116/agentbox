//go:build !darwin && !linux

package platform

// SandboxExecPath is the path to the macOS sandbox-exec binary.
// On unsupported platforms this variable is unused but defined so that
// cross-platform tests that reference it can compile.
var SandboxExecPath = ""

// detectPlatform returns an unsupported platform stub for unrecognized operating systems.
func detectPlatform() Platform {
	return &unsupportedPlatform{}
}
