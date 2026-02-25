//go:build linux

package agentbox

import (
	"github.com/zhangyunhao116/agentbox/platform"
	"github.com/zhangyunhao116/agentbox/platform/linux"
)

func init() {
	detectPlatformFn = func() platform.Platform {
		return linux.New()
	}
}
