//go:build linux

package agentbox

import "github.com/zhangyunhao116/agentbox/platform/linux"

func maybeSandboxInitLinux() bool {
	return linux.MaybeSandboxInit()
}
