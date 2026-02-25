//go:build darwin

package agentbox

import (
	"github.com/zhangyunhao116/agentbox/platform"
	"github.com/zhangyunhao116/agentbox/platform/darwin"
)

func init() {
	detectPlatformFn = func() platform.Platform {
		return darwin.New()
	}
}
