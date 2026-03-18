//go:build windows

package agentbox

import (
	"github.com/zhangyunhao116/agentbox/platform"
	"github.com/zhangyunhao116/agentbox/platform/windows"
)

func init() {
	detectPlatformFn = func() platform.Platform {
		return windows.New()
	}
}
