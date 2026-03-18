// Package windows provides the WSL2-based sandbox for Windows.
//
// This file contains Full Mode (Tier 2) helper configuration types and
// path translation utilities. These types have no build-tag requirement
// because they are pure Go with no Windows-specific dependencies.
package windows

import (
	"fmt"
	"strings"

	"github.com/zhangyunhao116/agentbox/platform"
)

// helperConfig is the JSON configuration passed to the sandbox helper binary
// inside WSL2. Field names and types match HelperConfig in
// cmd/sandbox-helper/main.go:22.
type helperConfig struct {
	WritableRoots           []string              `json:"writable_roots,omitempty"`
	DenyWrite               []string              `json:"deny_write,omitempty"`
	DenyRead                []string              `json:"deny_read,omitempty"`
	NeedsNetworkRestriction bool                  `json:"needs_network_restriction,omitempty"`
	ResourceLimits          *helperResourceLimits `json:"resource_limits,omitempty"`
	Command                 []string              `json:"command"`
}

// helperResourceLimits mirrors platform.ResourceLimits with JSON tags matching
// cmd/sandbox-helper/main.go:31.
type helperResourceLimits struct {
	MaxProcesses       int   `json:"MaxProcesses,omitempty"`
	MaxMemoryBytes     int64 `json:"MaxMemoryBytes,omitempty"`
	MaxFileDescriptors int   `json:"MaxFileDescriptors,omitempty"`
	MaxCPUSeconds      int   `json:"MaxCPUSeconds,omitempty"`
}

// buildHelperConfig converts a WrapConfig and the original command arguments
// into a helperConfig suitable for JSON serialization.
// Windows paths in WritableRoots, DenyWrite, and DenyRead are translated to
// WSL paths using translatePaths.
func buildHelperConfig(origArgs []string, cfg *platform.WrapConfig) (*helperConfig, error) {
	writableRoots, err := translatePaths(cfg.WritableRoots)
	if err != nil {
		return nil, fmt.Errorf("translating WritableRoots: %w", err)
	}
	denyWrite, err := translatePaths(cfg.DenyWrite)
	if err != nil {
		return nil, fmt.Errorf("translating DenyWrite: %w", err)
	}
	denyRead, err := translatePaths(cfg.DenyRead)
	if err != nil {
		return nil, fmt.Errorf("translating DenyRead: %w", err)
	}

	hCfg := &helperConfig{
		WritableRoots:           writableRoots,
		DenyWrite:               denyWrite,
		DenyRead:                denyRead,
		NeedsNetworkRestriction: cfg.NeedsNetworkRestriction,
		Command:                 origArgs,
	}

	// Pass through resource limits if configured.
	if cfg.ResourceLimits != nil {
		hCfg.ResourceLimits = &helperResourceLimits{
			MaxProcesses:       cfg.ResourceLimits.MaxProcesses,
			MaxMemoryBytes:     cfg.ResourceLimits.MaxMemoryBytes,
			MaxFileDescriptors: cfg.ResourceLimits.MaxFileDescriptors,
			MaxCPUSeconds:      cfg.ResourceLimits.MaxCPUSeconds,
		}
	}

	return hCfg, nil
}

// translatePaths converts a slice of paths from Windows to WSL format.
// Paths that are already Unix-style (start with /) are kept as-is.
// Empty slices are returned as nil.
func translatePaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		if strings.HasPrefix(p, "/") {
			result = append(result, p)
			continue
		}
		wslPath, err := ToWSL(p)
		if err != nil {
			return nil, fmt.Errorf("translating path %q: %w", p, err)
		}
		result = append(result, wslPath)
	}
	return result, nil
}
