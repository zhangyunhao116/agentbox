//go:build linux

// Package main implements the sandbox helper binary that runs inside WSL2.
//
// It receives sandbox configuration as a JSON command-line argument from the
// Windows host, bridges it to the Linux reexec pipe protocol, and calls
// MaybeSandboxInit() which applies all Linux sandbox restrictions (harden,
// landlock, seccomp) before execing the user command.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/zhangyunhao116/agentbox/platform/linux"
)

// HelperConfig is the sandbox configuration received from the Windows host
// via the --config JSON argument.
type HelperConfig struct {
	WritableRoots           []string `json:"writable_roots,omitempty"`
	DenyWrite               []string `json:"deny_write,omitempty"`
	DenyRead                []string `json:"deny_read,omitempty"`
	NeedsNetworkRestriction bool     `json:"needs_network_restriction,omitempty"`
	// ResourceLimits mirrors platform.ResourceLimits without importing
	// the platform package. JSON field names match Go's default encoding
	// (no json tags on the struct fields) nested under "resource_limits".
	// Matches reExecConfig.ResourceLimits in platform/linux/reexec.go:39.
	ResourceLimits *struct {
		MaxProcesses       int   `json:"MaxProcesses,omitempty"`
		MaxMemoryBytes     int64 `json:"MaxMemoryBytes,omitempty"`
		MaxFileDescriptors int   `json:"MaxFileDescriptors,omitempty"`
		MaxCPUSeconds      int   `json:"MaxCPUSeconds,omitempty"`
	} `json:"resource_limits,omitempty"`
	Command []string `json:"command"`
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: sandbox-helper <config-json>")
	}

	var cfg HelperConfig
	if err := json.Unmarshal([]byte(os.Args[1]), &cfg); err != nil {
		fatalf("parsing config: %v", err)
	}

	// Determine command to execute.
	args := cfg.Command
	if len(args) == 0 {
		fatalf("no command specified in config")
	}

	// Build the reexec config that MaybeSandboxInit expects.
	// Matches reExecConfig in platform/linux/reexec.go:34.
	reexecCfg := struct {
		WritableRoots           []string `json:"writable_roots,omitempty"`
		DenyWrite               []string `json:"deny_write,omitempty"`
		DenyRead                []string `json:"deny_read,omitempty"`
		NeedsNetworkRestriction bool     `json:"needs_network_restriction,omitempty"`
		ResourceLimits          *struct {
			MaxProcesses       int   `json:"MaxProcesses,omitempty"`
			MaxMemoryBytes     int64 `json:"MaxMemoryBytes,omitempty"`
			MaxFileDescriptors int   `json:"MaxFileDescriptors,omitempty"`
			MaxCPUSeconds      int   `json:"MaxCPUSeconds,omitempty"`
		} `json:"resource_limits,omitempty"`
	}{
		WritableRoots:           cfg.WritableRoots,
		DenyWrite:               cfg.DenyWrite,
		DenyRead:                cfg.DenyRead,
		NeedsNetworkRestriction: cfg.NeedsNetworkRestriction,
		ResourceLimits:          cfg.ResourceLimits,
	}

	// Create a pipe and write the reexec config JSON to it.
	// This bridges the helper's CLI config to the reexec pipe protocol
	// used by MaybeSandboxInit (platform/linux/reexec.go:46).
	r, w, err := os.Pipe()
	if err != nil {
		fatalf("creating pipe: %v", err)
	}

	data, err := json.Marshal(reexecCfg)
	if err != nil {
		fatalf("marshaling reexec config: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		fatalf("writing config to pipe: %v", err)
	}
	if err := w.Close(); err != nil {
		fatalf("closing pipe writer: %v", err)
	}

	// Set the env var that MaybeSandboxInit reads to discover the config fd.
	fd := r.Fd()
	if err := os.Setenv("_AGENTBOX_CONFIG", strconv.FormatUint(uint64(fd), 10)); err != nil {
		fatalf("setting env: %v", err)
	}

	// Set os.Args so that sandboxInit reads args[1:] as the command to exec.
	// sandboxInit uses os.Args[1:] for the target command
	// (platform/linux/reexec.go:129).
	os.Args = append([]string{os.Args[0]}, args...)

	// Apply all sandbox restrictions and exec the command.
	// MaybeSandboxInit does not return on success — it calls os.Exit or
	// syscall.Exec internally.
	if !linux.MaybeSandboxInit() {
		fatalf("MaybeSandboxInit returned false unexpectedly")
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sandbox-helper: "+format+"\n", args...)
	os.Exit(1)
}
