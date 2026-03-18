// Example codereview simulates a code review agent that analyzes Go source
// code inside a sandbox. It creates a sample project with deliberate issues,
// runs go vet, gofmt, and go test, then produces a structured JSON report.
//
// Uses ExecArgs exclusively — no shell commands — for cross-platform support.
//
// Usage:
//
//	go run ./examples/codereview
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
)

func main() {
	if agentbox.MaybeSandboxInit() {
		return
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// Status constants for check results.
const (
	statusPass    = "pass"
	statusWarning = "warning"
)

type reviewReport struct {
	Project string        `json:"project"`
	Checks  []checkResult `json:"checks"`
	Summary reportSummary `json:"summary"`
}

type checkResult struct {
	Tool     string   `json:"tool"`
	Status   string   `json:"status"`
	Findings []string `json:"findings"`
}

type reportSummary struct {
	TotalFindings int `json:"total_findings"`
	Pass          int `json:"pass"`
	Warnings      int `json:"warnings"`
}

func run() error {
	ctx := context.Background()

	// ── Step 1: Create temp workspace with GOCACHE/GOPATH ───────────────
	fmt.Println("\n=== Step 1: Create temp workspace ===")
	workspace, err := os.MkdirTemp("", "agentbox-codereview-*")
	if err != nil {
		return fmt.Errorf("create workspace: %w", err)
	}
	defer os.RemoveAll(workspace)

	goCache := filepath.Join(workspace, "cache")
	goPath := filepath.Join(workspace, "gopath")
	for _, d := range []string{goCache, goPath} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	fmt.Printf("  workspace: %s\n", workspace)

	// ── Step 2: Configure sandbox manager ───────────────────────────────
	fmt.Println("\n=== Step 2: Configure sandbox manager ===")
	cfg := agentbox.DefaultConfig()
	cfg.FallbackPolicy = agentbox.FallbackWarn
	cfg.Shell = defaultShellPath()
	cfg.Filesystem.WritableRoots = []string{workspace, os.TempDir()}
	if runtime.GOOS == "windows" {
		// On Windows, os.TempDir() is under $HOME which is in the deny list.
		// Clear deny lists so the example can use temp dirs as writable roots.
		cfg.Filesystem.DenyWrite = nil
		cfg.Filesystem.DenyRead = nil
	}
	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}
	defer mgr.Cleanup(ctx)
	fmt.Println("  manager ready")

	execOpts := []agentbox.Option{
		agentbox.WithWorkingDir(workspace),
		agentbox.WithEnv("GOCACHE="+goCache, "GOPATH="+goPath),
		agentbox.WithTimeout(30 * time.Second),
	}

	// ── Step 3: Create sample project to review ─────────────────────────
	fmt.Println("\n=== Step 3: Create sample project ===")
	if err := writeProjectFiles(workspace); err != nil {
		return fmt.Errorf("write project files: %w", err)
	}
	fmt.Println("  wrote go.mod, server.go, server_test.go, badformat.go")

	// ── Step 4: Run go vet ──────────────────────────────────────────────
	fmt.Println("\n=== Step 4: Run go vet ===")
	vetResult, err := mgr.ExecArgs(ctx, "go", []string{"vet", "./..."}, execOpts...)
	if err != nil {
		return fmt.Errorf("go vet exec: %w", err)
	}
	vetCheck := parseCheck("go vet", vetResult)
	printCheck(vetCheck)

	// ── Step 5: Run gofmt check ─────────────────────────────────────────
	fmt.Println("\n=== Step 5: Run gofmt check ===")
	fmtResult, err := mgr.ExecArgs(ctx, "gofmt", []string{"-l", "."}, execOpts...)
	if err != nil {
		return fmt.Errorf("gofmt exec: %w", err)
	}
	fmtCheck := parseFmtCheck(fmtResult)
	printCheck(fmtCheck)

	// ── Step 6: Run go test ─────────────────────────────────────────────
	fmt.Println("\n=== Step 6: Run go test ===")
	testResult, err := mgr.ExecArgs(ctx, "go", []string{"test", "-vet=off", "-v", "./..."}, execOpts...)
	if err != nil {
		return fmt.Errorf("go test exec: %w", err)
	}
	testCheck := parseCheck("go test", testResult)
	printCheck(testCheck)

	// ── Step 7: Generate review report ──────────────────────────────────
	fmt.Println("\n=== Step 7: Generate review report ===")
	report := buildReport("example.com/review-target",
		[]checkResult{vetCheck, fmtCheck, testCheck})
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	reportPath := filepath.Join(workspace, "review-report.json")
	if err := os.WriteFile(reportPath, reportJSON, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	fmt.Printf("  report written to %s\n", reportPath)

	// ── Step 8: Report summary ──────────────────────────────────────────
	fmt.Println("\n=== Step 8: Report summary ===")
	fmt.Println(string(reportJSON))
	return nil
}

// writeProjectFiles creates a Go project with deliberate issues for review.
func writeProjectFiles(workspace string) error {
	goMod := "module example.com/review-target\n\ngo 1.21\n"
	if err := os.WriteFile(filepath.Join(workspace, "go.mod"), []byte(goMod), 0o644); err != nil {
		return err
	}
	// server.go — deliberate issues:
	//   1. Exported HandleRoot missing doc comment.
	//   2. fmt.Printf with mismatched format args (go vet catches this).
	serverSrc := `package reviewtarget

import (
	"fmt"
	"net/http"
)

func HandleRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello, %s", r.URL.Path)
	debugLog(r.Method)
}

func debugLog(method string) {
	fmt.Printf("%d %d\n", 1)
	_ = method
}
`
	if err := os.WriteFile(filepath.Join(workspace, "server.go"), []byte(serverSrc), 0o644); err != nil {
		return err
	}
	// server_test.go — a basic passing test.
	testSrc := `package reviewtarget

import "testing"

func TestDebugLog(t *testing.T) {
	// Intentionally empty: verifies the package compiles.
}
`
	if err := os.WriteFile(filepath.Join(workspace, "server_test.go"), []byte(testSrc), 0o644); err != nil {
		return err
	}
	// badformat.go — spaces instead of tabs so gofmt flags it.
	badFmtSrc := "package reviewtarget\n\nfunc unused() {\n  x := 1\n  _ = x\n}\n"
	return os.WriteFile(filepath.Join(workspace, "badformat.go"), []byte(badFmtSrc), 0o644)
}

// printCheck prints a checkResult to stdout.
func printCheck(c checkResult) {
	fmt.Printf("  status: %s\n", c.Status)
	for _, f := range c.Findings {
		fmt.Printf("  finding: %s\n", f)
	}
}

// parseCheck converts an ExecResult from go vet or go test into a checkResult.
func parseCheck(tool string, r *agentbox.ExecResult) checkResult {
	combined := strings.TrimSpace(r.Stdout + r.Stderr)
	if r.ExitCode == 0 {
		return checkResult{Tool: tool, Status: statusPass, Findings: []string{}}
	}
	var findings []string
	for _, line := range strings.Split(combined, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			findings = append(findings, line)
		}
	}
	return checkResult{Tool: tool, Status: statusWarning, Findings: findings}
}

// parseFmtCheck converts gofmt -l output into a checkResult.
func parseFmtCheck(r *agentbox.ExecResult) checkResult {
	output := strings.TrimSpace(r.Stdout)
	if output == "" {
		return checkResult{Tool: "gofmt", Status: statusPass, Findings: []string{}}
	}
	var findings []string
	for _, file := range strings.Split(output, "\n") {
		if file = strings.TrimSpace(file); file != "" {
			findings = append(findings, "needs formatting: "+file)
		}
	}
	return checkResult{Tool: "gofmt", Status: statusWarning, Findings: findings}
}

// buildReport assembles a reviewReport from individual check results.
func buildReport(project string, checks []checkResult) reviewReport {
	var total, pass, warnings int
	for _, c := range checks {
		total += len(c.Findings)
		switch c.Status {
		case statusPass:
			pass++
		case statusWarning:
			warnings++
		}
	}
	return reviewReport{
		Project: project,
		Checks:  checks,
		Summary: reportSummary{TotalFindings: total, Pass: pass, Warnings: warnings},
	}
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
