//go:build !darwin && !linux && !windows

package agentbox

import "os/exec"

// setupProcessGroup is a no-op on unsupported platforms.
func setupProcessGroup(_ *exec.Cmd) {}
