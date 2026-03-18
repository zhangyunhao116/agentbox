// Example researchflow simulates a research agent workflow that discovers Go
// standard library packages, retrieves documentation summaries, and generates
// a structured JSON research report.
//
// It uses [agentbox.Manager.ExecArgs] exclusively (no shell), making it fully
// cross-platform (macOS, Linux, Windows).
//
// Usage:
//
//	go run ./examples/researchflow
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

// researchReport holds the final output of the research workflow.
type researchReport struct {
	Timestamp   string        `json:"timestamp"`
	Topic       string        `json:"topic"`
	StdlibCount int           `json:"stdlib_package_count"`
	Packages    []packageInfo `json:"selected_packages"`
	Summary     string        `json:"summary"`
}

// packageInfo describes a single standard library package.
type packageInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func run() error {
	ctx := context.Background()

	// Step 1: Create a temporary workspace.
	workdir, err := os.MkdirTemp("", "agentbox-researchflow-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(workdir)

	// GOCACHE and GOPATH must reside inside writable roots so the Go
	// toolchain can write build-cache and module artifacts.
	gocache := filepath.Join(workdir, "cache")
	gopath := filepath.Join(workdir, "gopath")
	for _, d := range []string{gocache, gopath} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create dir %s: %w", d, err)
		}
	}

	// Step 2: Configure sandbox with FallbackWarn.
	cfg := agentbox.DefaultConfig()
	cfg.FallbackPolicy = agentbox.FallbackWarn
	cfg.Shell = defaultShellPath()
	cfg.Filesystem.WritableRoots = []string{workdir, os.TempDir()}
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

	execOpts := []agentbox.Option{
		agentbox.WithWorkingDir(workdir),
		agentbox.WithEnv("GOCACHE="+gocache, "GOPATH="+gopath),
		agentbox.WithTimeout(30 * time.Second),
	}

	step := 0

	// Step 3: Discover — run "go list std" to list all stdlib packages.
	step++
	printStep(step, "Discover standard library packages")
	result, err := mgr.ExecArgs(ctx, "go", []string{"list", "std"}, execOpts...)
	if err != nil {
		return fmt.Errorf("go list std: %w", err)
	}
	printResult(result)
	if result.ExitCode != 0 {
		return fmt.Errorf("go list std failed: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}

	stdlibPkgs := parseLines(result.Stdout)
	fmt.Printf("  Found %d standard library packages.\n", len(stdlibPkgs))

	// Step 4: Deep-dive — pick specific packages and get their docs.
	step++
	printStep(step, "Retrieve documentation for selected packages")
	targetPkgs := []string{"encoding/json", "net/http", "os"}
	packages := make([]packageInfo, 0, len(targetPkgs))
	for _, pkg := range targetPkgs {
		res, err := mgr.ExecArgs(ctx, "go", []string{"doc", pkg}, execOpts...)
		if err != nil {
			return fmt.Errorf("go doc %s: %w", pkg, err)
		}
		printResult(res)
		if res.ExitCode != 0 {
			fmt.Printf("  ⚠ go doc %s failed (exit %d), skipping.\n", pkg, res.ExitCode)
			continue
		}
		// Step 5 (inline): Parse the doc output to extract the first sentence.
		desc := extractDescription(res.Stdout)
		packages = append(packages, packageInfo{Name: pkg, Description: desc})
		fmt.Printf("  %s: %s\n", pkg, desc)
	}

	// Step 6: Generate JSON research report.
	step++
	printStep(step, "Generate research report")
	report := researchReport{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Topic:       "Go Standard Library Survey",
		StdlibCount: len(stdlibPkgs),
		Packages:    packages,
		Summary: fmt.Sprintf(
			"Surveyed %d stdlib packages; retrieved docs for %d selected packages.",
			len(stdlibPkgs), len(packages),
		),
	}

	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	reportPath := filepath.Join(workdir, "report.json")
	if err := os.WriteFile(reportPath, reportJSON, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	fmt.Printf("  Report written to %s\n", reportPath)

	// Step 7: Print summary.
	step++
	printStep(step, "Summary")
	fmt.Println(string(reportJSON))
	fmt.Printf("\nResearch completed in %d steps.\n", step)
	return nil
}

func printStep(n int, desc string) {
	fmt.Printf("\n=== Step %d: %s ===\n", n, desc)
}

func printResult(r *agentbox.ExecResult) {
	fmt.Printf("  exit=%d sandboxed=%v duration=%s\n", r.ExitCode, r.Sandboxed, r.Duration.Round(time.Millisecond))
}

// parseLines splits output into non-empty lines.
func parseLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// extractDescription returns the first sentence of a go doc output. It looks
// for the first non-empty line after the "package ..." declaration line or, if
// absent, returns the first non-empty line.
func extractDescription(docOutput string) string {
	lines := strings.Split(docOutput, "\n")
	pastHeader := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "package ") || strings.HasPrefix(trimmed, "import ") {
			pastHeader = true
			continue
		}
		// Skip "var", "func", "type" declaration lines.
		if strings.HasPrefix(trimmed, "var ") ||
			strings.HasPrefix(trimmed, "func ") ||
			strings.HasPrefix(trimmed, "type ") ||
			strings.HasPrefix(trimmed, "const ") {
			break
		}
		if pastHeader {
			return firstSentence(trimmed)
		}
	}
	return "(no description)"
}

// firstSentence returns text up to and including the first period followed by
// a space or end-of-string.
func firstSentence(s string) string {
	if idx := strings.Index(s, ". "); idx >= 0 {
		return s[:idx+1]
	}
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s
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
