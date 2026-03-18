// Example healthcheck simulates a health monitoring agent. Uses CIConfig
// (strictest settings) with FallbackWarn and ExecArgs only (no shell) for
// cross-platform support. Generates a structured JSON health report.
//
//	go run ./examples/healthcheck
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/zhangyunhao116/agentbox"
	"github.com/zhangyunhao116/agentbox/platform"
)

const (
	statusOK   = "ok"
	statusWarn = "warn"
	statusFail = "fail"
)

type (
	healthReport struct {
		Timestamp     string            `json:"timestamp"`
		System        systemInfo        `json:"system"`
		GoEnv         map[string]string `json:"go_env"`
		Sandbox       sandboxInfo       `json:"sandbox"`
		Checks        []checkEntry      `json:"checks"`
		OverallStatus string            `json:"overall_status"`
	}
	systemInfo struct {
		OS        string `json:"os"`
		Arch      string `json:"arch"`
		GoVersion string `json:"go_version"`
	}
	sandboxInfo struct {
		Available    bool            `json:"available"`
		Platform     string          `json:"platform"`
		Capabilities map[string]bool `json:"capabilities"`
	}
	checkEntry struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
)

func main() {
	if agentbox.MaybeSandboxInit() {
		return
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()
	// Step 1: Create temp workspace.
	fmt.Println("=== Step 1: Create temp workspace ===")
	ws, err := os.MkdirTemp("", "agentbox-healthcheck-*")
	if err != nil {
		return fmt.Errorf("create workspace: %w", err)
	}
	defer os.RemoveAll(ws)
	goCache, goPath := filepath.Join(ws, "cache"), filepath.Join(ws, "gopath")
	for _, d := range []string{goCache, goPath} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	// Step 2: Configure sandbox (CI network rules + FallbackWarn for portability).
	fmt.Println("=== Step 2: Configure sandbox (CI network rules, warn fallback) ===")
	cfg := agentbox.CIConfig()
	cfg.FallbackPolicy = agentbox.FallbackWarn
	cfg.Filesystem.WritableRoots = []string{ws, os.TempDir()}
	if runtime.GOOS == "windows" {
		// On Windows, os.TempDir() is under $HOME which is in the deny list.
		// Clear deny lists so the example can use temp dirs as writable roots.
		cfg.Filesystem.DenyWrite = nil
		cfg.Filesystem.DenyRead = nil
	}
	cfg.Shell = defaultShellPath()
	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}
	defer mgr.Cleanup(ctx)
	opts := []agentbox.Option{
		agentbox.WithWorkingDir(ws),
		agentbox.WithEnv("GOCACHE="+goCache, "GOPATH="+goPath),
		agentbox.WithTimeout(15 * time.Second),
	}
	report := healthReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		System:    systemInfo{OS: runtime.GOOS, Arch: runtime.GOARCH},
		GoEnv:     make(map[string]string),
	}
	var checks []checkEntry
	// Step 3: Check Go environment and version.
	fmt.Println("=== Step 3: Check Go environment ===")
	envKeys := []string{"GOVERSION", "GOOS", "GOARCH", "GOROOT", "GOPATH", "GOMODCACHE", "GOTMPDIR", "GOCACHE"}
	result, err := mgr.ExecArgs(ctx, "go", append([]string{"env"}, envKeys...), opts...)
	if err != nil {
		return fmt.Errorf("go env: %w", err)
	}
	for i, v := range strings.Split(strings.TrimSpace(result.Stdout), "\n") {
		if i < len(envKeys) {
			report.GoEnv[envKeys[i]] = strings.TrimSpace(v)
			fmt.Printf("  %s=%s\n", envKeys[i], strings.TrimSpace(v))
		}
	}
	result, err = mgr.ExecArgs(ctx, "go", []string{"version"}, opts...)
	if err != nil {
		return fmt.Errorf("go version: %w", err)
	}
	report.System.GoVersion = strings.TrimSpace(result.Stdout)
	fmt.Printf("  version: %s\n", report.System.GoVersion)
	checks = append(checks, checkEntry{"go_toolchain", statusOK, report.System.GoVersion})
	// Step 4: Verify workspace is writable.
	fmt.Println("=== Step 4: Verify workspace writable ===")
	probe := filepath.Join(ws, ".healthcheck-probe")
	if wErr := os.WriteFile(probe, []byte("ok"), 0o600); wErr != nil {
		checks = append(checks, checkEntry{"workspace_writable", statusFail, wErr.Error()})
	} else {
		os.Remove(probe)
		fmt.Println("  write+remove probe succeeded")
		checks = append(checks, checkEntry{"workspace_writable", statusOK, "write+remove succeeded"})
	}
	// Step 5: Inspect sandbox capabilities.
	fmt.Println("=== Step 5: Inspect sandbox capabilities ===")
	plat := platform.Detect()
	caps := plat.Capabilities()
	dep := mgr.CheckDependencies()
	report.Sandbox = sandboxInfo{
		Available: mgr.Available(), Platform: plat.Name(),
		Capabilities: map[string]bool{
			"file_read_deny": caps.FileReadDeny, "file_write_allow": caps.FileWriteAllow,
			"network_deny": caps.NetworkDeny, "network_proxy": caps.NetworkProxy,
			"pid_isolation": caps.PIDIsolation, "syscall_filter": caps.SyscallFilter,
			"process_harden": caps.ProcessHarden},
	}
	fmt.Printf("  platform=%s available=%v deps_ok=%v\n", plat.Name(), mgr.Available(), dep.OK())
	sbStatus, sbDetail := statusOK, "platform="+plat.Name()
	if !mgr.Available() {
		sbStatus, sbDetail = statusWarn, "sandbox unavailable; running unsandboxed"
	}
	checks = append(checks, checkEntry{"sandbox_active", sbStatus, sbDetail})
	// Step 6: Generate health report JSON.
	fmt.Println("=== Step 6: Generate health report ===")
	report.Checks, report.OverallStatus = checks, overallStatus(checks)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	rpath := filepath.Join(ws, "health-report.json")
	if err := os.WriteFile(rpath, data, 0o600); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	fmt.Printf("  wrote %s (%d bytes)\n", rpath, len(data))
	// Step 7: Print summary.
	fmt.Println("=== Step 7: Health Report Summary ===")
	for _, c := range checks {
		icon := "✓"
		switch c.Status {
		case statusFail:
			icon = "✗"
		case statusWarn:
			icon = "!"
		}
		fmt.Printf("  %s %-20s %s\n", icon, c.Name, c.Detail)
	}
	fmt.Printf("  Overall: %s\n", report.OverallStatus)
	fmt.Println("\nAll steps completed successfully.")
	return nil
}

func overallStatus(checks []checkEntry) string {
	hasWarn := false
	for _, c := range checks {
		switch c.Status {
		case statusFail:
			return "unhealthy"
		case statusWarn:
			hasWarn = true
		}
	}
	if hasWarn {
		return "degraded"
	}
	return "healthy"
}

// defaultShellPath returns a valid shell path; ExecArgs never uses it but NewManager validates it.
func defaultShellPath() string {
	if runtime.GOOS == "windows" {
		if root := os.Getenv("SYSTEMROOT"); root != "" {
			return filepath.Join(root, "System32", "cmd.exe")
		}
		return `C:\Windows\System32\cmd.exe`
	}
	return "/bin/sh"
}
