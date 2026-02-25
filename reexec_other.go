//go:build !linux

package agentbox

func maybeSandboxInitLinux() bool {
	return false
}
