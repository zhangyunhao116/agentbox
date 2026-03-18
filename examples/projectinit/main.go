// Example projectinit simulates a Project Initialization Agent that bootstraps
// a Go microservice project, runs a full CI pipeline (build, vet, format check,
// test) inside a sandbox, and produces a JSON summary.
//
// It uses [agentbox.Manager.ExecArgs] exclusively (no shell), making it fully
// cross-platform (macOS, Linux, Windows).
//
// Usage:
//
//	go run ./examples/projectinit
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

type ciReport struct {
	Project string   `json:"project"`
	Steps   []ciStep `json:"steps"`
	Overall string   `json:"overall"`
}
type ciStep struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Output string `json:"output,omitempty"`
}

const (
	statusPass = "pass"
	statusFail = "fail"
)

func run() error {
	ctx := context.Background()

	// Step 1: Create temp workspace.
	printStep(1, "Create temp workspace")
	workdir, err := os.MkdirTemp("", "agentbox-projectinit-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(workdir)

	// GOCACHE and GOPATH must reside inside writable roots.
	gocache := filepath.Join(workdir, "cache")
	gopath := filepath.Join(workdir, "gopath")
	for _, d := range []string{gocache, gopath} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create dir %s: %w", d, err)
		}
	}

	// Step 2: Configure sandbox with FallbackWarn.
	printStep(2, "Configure sandbox with FallbackWarn")
	cfg := agentbox.DefaultConfig()
	cfg.FallbackPolicy = agentbox.FallbackWarn
	cfg.Shell = defaultShellPath()
	cfg.Filesystem.WritableRoots = []string{workdir, os.TempDir()}
	if runtime.GOOS == "windows" {
		// On Windows, os.TempDir() is under $HOME which is in the deny list.
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

	// Step 3: Initialize Go module.
	printStep(3, "Initialize Go module")
	result, err := mgr.ExecArgs(ctx, "go", []string{"mod", "init", "example.com/myservice"}, execOpts...)
	if err != nil {
		return fmt.Errorf("go mod init: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("go mod init failed: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}
	fmt.Println("  initialized example.com/myservice")

	// Step 4: Create project files.
	printStep(4, "Create project files")
	for name, content := range map[string]string{"main.go": mainGoSrc, "handler.go": handlerGoSrc, "handler_test.go": handlerTestGoSrc} {
		if err := os.WriteFile(filepath.Join(workdir, name), []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	fmt.Println("  created main.go, handler.go, handler_test.go")

	// Steps 5-8: CI Pipeline (build, vet, format, test).
	report := ciReport{Project: "example.com/myservice"}
	for _, ci := range []struct {
		step int
		name string
		prog string
		args []string
	}{
		{5, "build", "go", []string{"build", "./..."}},
		{6, "vet", "go", []string{"vet", "./..."}},
		{7, "format", "gofmt", []string{"-l", "."}},
		{8, "test", "go", []string{"test", "-v", "./..."}},
	} {
		printStep(ci.step, "CI Pipeline — "+ci.name)
		result, err = mgr.ExecArgs(ctx, ci.prog, ci.args, execOpts...)
		if err != nil {
			return fmt.Errorf("%s %s: %w", ci.prog, ci.name, err)
		}
		printResult(result)
		s := ciStep{Name: ci.name, Status: statusPass}
		passed := result.ExitCode == 0
		// gofmt -l prints unformatted files to stdout; empty = pass.
		if ci.name == "format" && strings.TrimSpace(result.Stdout) != "" {
			passed = false
		}
		if passed {
			fmt.Printf("  ✓ %s passed\n", ci.name)
		} else {
			s.Status = statusFail
			s.Output = strings.TrimSpace(result.Stderr + result.Stdout)
			fmt.Printf("  ✗ %s failed\n", ci.name)
		}
		report.Steps = append(report.Steps, s)
	}

	// Step 9: Generate CI results summary (JSON).
	printStep(9, "Generate CI results summary")
	report.Overall = statusPass
	for _, s := range report.Steps {
		if s.Status == statusFail {
			report.Overall = statusFail
			break
		}
	}
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	fmt.Println(string(jsonData))

	// Step 10: Print summary with pass/fail status.
	printStep(10, "CI Summary")
	for _, s := range report.Steps {
		icon := "✓"
		if s.Status == statusFail {
			icon = "✗"
		}
		fmt.Printf("  %s %s: %s\n", icon, s.Name, s.Status)
	}
	fmt.Printf("\n  Overall: %s\n", report.Overall)
	fmt.Println("\nAll steps completed successfully.")
	return nil
}

func printStep(n int, desc string) { fmt.Printf("\n=== Step %d: %s ===\n", n, desc) }

func printResult(r *agentbox.ExecResult) {
	fmt.Printf("  exit=%d sandboxed=%v duration=%s\n", r.ExitCode, r.Sandboxed, r.Duration.Round(time.Millisecond))
	if out := strings.TrimSpace(r.Stdout); out != "" {
		for _, line := range strings.Split(out, "\n") {
			fmt.Printf("  stdout: %s\n", line)
		}
	}
	if out := strings.TrimSpace(r.Stderr); out != "" {
		for _, line := range strings.Split(out, "\n") {
			fmt.Printf("  stderr: %s\n", line)
		}
	}
}

// defaultShellPath returns a valid shell; ExecArgs never uses it but NewManager validates it.
func defaultShellPath() string {
	if runtime.GOOS == "windows" {
		if root := os.Getenv("SYSTEMROOT"); root != "" {
			return filepath.Join(root, "System32", "cmd.exe")
		}
		return `C:\Windows\System32\cmd.exe`
	}
	return "/bin/sh"
}

// Embedded source files for the agent's micro-project.

const mainGoSrc = `package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/echo", handleEcho)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("listening on :%s\n", port)
	_ = &http.Server{Addr: ":" + port, Handler: mux}
}
`

const handlerGoSrc = `package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"
)

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
		"go":     runtime.Version(),
		"os":     runtime.GOOS,
		"arch":   runtime.GOARCH,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleEcho(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	if msg == "" {
		http.Error(w, "missing msg parameter", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "echo: %s\n", msg)
}
`

const handlerTestGoSrc = `package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("health returned %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ok") {
		t.Errorf("health body missing 'ok': %s", w.Body.String())
	}
}
func TestHandleEcho(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/echo?msg=hello", nil)
	w := httptest.NewRecorder()
	handleEcho(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("echo returned %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "hello") {
		t.Error("echo body missing 'hello'")
	}
}
func TestHandleEchoMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/echo", nil)
	w := httptest.NewRecorder()
	handleEcho(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("echo without msg returned %d, want 400", w.Code)
	}
}
`
