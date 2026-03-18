//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/zhangyunhao116/agentbox/platform"
)

// wrapCommandFullMode wraps cmd for Tier 2 (Linux-level isolation inside WSL2):
//
//	wsl.exe -d <distro> -e /opt/agentbox/helper '<config-json>'
//
// The helper binary applies namespace, Landlock, and seccomp restrictions
// before exec-ing the user command.
func (p *Platform) wrapCommandFullMode(_ context.Context, cmd *exec.Cmd, cfg *platform.WrapConfig) error {
	hCfg, err := buildHelperConfig(cmd.Args, cfg)
	if err != nil {
		return fmt.Errorf("building helper config: %w", err)
	}

	cfgJSON, err := json.Marshal(hCfg)
	if err != nil {
		return fmt.Errorf("marshaling helper config: %w", err)
	}

	// Build wsl.exe arguments:
	//   wsl.exe -d <distro> -e /opt/agentbox/helper '<json>'
	wslArgs := []string{
		p.wslPath,
		"-d", p.distroName,
		"-e", helperPath,
		string(cfgJSON),
	}

	cmd.Path = p.wslPath
	cmd.Args = wslArgs

	// Sanitize environment — same filtering as Simple Mode.
	cmd.Env = p.sanitizeEnv(cmd.Env, cfg)

	return nil
}
