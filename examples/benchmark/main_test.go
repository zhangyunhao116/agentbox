package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/zhangyunhao116/agentbox"
	"github.com/zhangyunhao116/agentbox/testutil"
)

// ---------------------------------------------------------------------------
// Shared state — one sandboxed manager, one nop (unsandboxed) manager.
// ---------------------------------------------------------------------------

var (
	setupOnce        sync.Once
	benchMgr         agentbox.Manager // sandboxed (or fallback-warn)
	nopMgr           agentbox.Manager // always unsandboxed
	sandboxAvailable bool             // true when benchMgr actually sandboxes
	benchDir         string
	benchOpts        []agentbox.Option
)

func setupBench(b *testing.B) {
	b.Helper()
	setupOnce.Do(func() {
		dir, err := os.MkdirTemp("", "agentbox-bench-*")
		if err != nil {
			panic(err)
		}
		benchDir = dir

		goCache := filepath.Join(dir, "cache")
		goPath := filepath.Join(dir, "gopath")
		for _, d := range []string{goCache, goPath} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				panic(err)
			}
		}

		// Write a minimal Go project for vet/fmt/build/test benchmarks.
		goMod := "module example.com/bench\n\ngo 1.21\n"
		mainSrc := "package bench\n\n// Add returns a + b.\nfunc Add(a, b int) int { return a + b }\n"
		testSrc := "package bench\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) {\n\tif Add(1, 2) != 3 {\n\t\tt.Fatal(\"Add(1,2) != 3\")\n\t}\n}\n"
		for name, content := range map[string]string{
			"go.mod":        goMod,
			"bench.go":      mainSrc,
			"bench_test.go": testSrc,
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				panic(err)
			}
		}

		// Sandboxed manager.
		cfg := agentbox.DefaultConfig()
		cfg.FallbackPolicy = agentbox.FallbackWarn
		cfg.Shell = testutil.Shell()
		cfg.Filesystem.WritableRoots = []string{dir, os.TempDir()}
		if runtime.GOOS == "windows" {
			cfg.Filesystem.DenyWrite = nil
			cfg.Filesystem.DenyRead = nil
		}
		mgr, err := agentbox.NewManager(cfg)
		if err != nil {
			panic(err)
		}
		benchMgr = mgr

		// Probe whether the sandbox actually wraps commands.
		// nopManager.Available() returns true even though it does not sandbox,
		// so we run one real command and check the Sandboxed flag.
		probe, probeErr := mgr.ExecArgs(context.Background(), "go", []string{"version"},
			agentbox.WithWorkingDir(dir),
			agentbox.WithTimeout(15*time.Second))
		if probeErr == nil {
			sandboxAvailable = probe.Sandboxed
		}

		// Nop (unsandboxed) manager — always runs commands directly.
		nopMgr = agentbox.NewNopManager()

		benchOpts = []agentbox.Option{
			agentbox.WithWorkingDir(dir),
			agentbox.WithEnv("GOCACHE="+goCache, "GOPATH="+goPath),
			agentbox.WithTimeout(30 * time.Second),
		}
	})
}

func TestMain(m *testing.M) {
	if agentbox.MaybeSandboxInit() {
		return
	}
	code := m.Run()
	if benchDir != "" {
		os.RemoveAll(benchDir)
	}
	if benchMgr != nil {
		benchMgr.Cleanup(context.Background())
	}
	if nopMgr != nil {
		nopMgr.Cleanup(context.Background())
	}
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// Manager creation benchmark.
// ---------------------------------------------------------------------------

// BenchmarkNewManager measures the cost of creating and tearing down a Manager.
func BenchmarkNewManager(b *testing.B) {
	b.ResetTimer()
	for b.Loop() {
		cfg := agentbox.DefaultConfig()
		cfg.FallbackPolicy = agentbox.FallbackWarn
		cfg.Shell = testutil.Shell()
		mgr, err := agentbox.NewManager(cfg)
		if err != nil {
			b.Fatal(err)
		}
		mgr.Cleanup(context.Background())
	}
}

// ---------------------------------------------------------------------------
// Helper: run a benchmark for both sandboxed and unsandboxed managers.
// ---------------------------------------------------------------------------

func benchExec(b *testing.B, name string, args []string) {
	b.Helper()
	setupBench(b)
	ctx := context.Background()

	if !sandboxAvailable {
		// Sandbox unavailable — both managers run unsandboxed.
		// Only benchmark the direct (nop) path; skip the misleading comparison.
		b.Run("unsandboxed", func(b *testing.B) {
			b.ResetTimer()
			for b.Loop() {
				result, err := nopMgr.ExecArgs(ctx, name, args, benchOpts...)
				if err != nil {
					b.Fatal(err)
				}
				if result.ExitCode != 0 {
					b.Fatalf("exit %d: %s", result.ExitCode, result.Stderr)
				}
			}
		})
		return
	}

	b.Run("sandbox", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			result, err := benchMgr.ExecArgs(ctx, name, args, benchOpts...)
			if err != nil {
				b.Fatal(err)
			}
			if result.ExitCode != 0 {
				b.Fatalf("exit %d: %s", result.ExitCode, result.Stderr)
			}
		}
	})

	b.Run("nosandbox", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			result, err := nopMgr.ExecArgs(ctx, name, args, benchOpts...)
			if err != nil {
				b.Fatal(err)
			}
			if result.ExitCode != 0 {
				b.Fatalf("exit %d: %s", result.ExitCode, result.Stderr)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Individual command benchmarks — each tests sandbox vs nosandbox.
// ---------------------------------------------------------------------------

// BenchmarkGoVersion runs "go version" (minimal baseline).
func BenchmarkGoVersion(b *testing.B) {
	benchExec(b, "go", []string{"version"})
}

// BenchmarkGoEnv queries Go environment variables.
func BenchmarkGoEnv(b *testing.B) {
	benchExec(b, "go", []string{"env", "GOVERSION", "GOOS", "GOARCH"})
}

// BenchmarkGoVet runs "go vet ./..." on a tiny Go project.
func BenchmarkGoVet(b *testing.B) {
	benchExec(b, "go", []string{"vet", "./..."})
}

// BenchmarkGofmtCheck runs "gofmt -l ." to check formatting.
func BenchmarkGofmtCheck(b *testing.B) {
	benchExec(b, "gofmt", []string{"-l", "."})
}

// BenchmarkGoBuild builds a tiny Go package.
func BenchmarkGoBuild(b *testing.B) {
	benchExec(b, "go", []string{"build", "./..."})
}

// BenchmarkGoTest runs "go test ./..." on a tiny package.
func BenchmarkGoTest(b *testing.B) {
	benchExec(b, "go", []string{"test", "./..."})
}

// BenchmarkGoListStd lists all standard library packages.
func BenchmarkGoListStd(b *testing.B) {
	benchExec(b, "go", []string{"list", "std"})
}

// BenchmarkGoDoc looks up documentation for fmt.Println.
func BenchmarkGoDoc(b *testing.B) {
	benchExec(b, "go", []string{"doc", "fmt.Println"})
}
