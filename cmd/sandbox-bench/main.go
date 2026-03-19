// Command sandbox-bench is a minimal CLI wrapper for benchmarking agentbox.
//
// Usage:
//
//	sandbox-bench <command> [args...]              # single execution
//	sandbox-bench --batch N <command> [args...]    # N sequential executions with timing
package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"time"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	if agentbox.MaybeSandboxInit() {
		return
	}

	os.Exit(run())
}

func run() int {
	// Parse --batch flag if present
	batchCount := 0
	cmdStart := 1

	if len(os.Args) >= 3 && os.Args[1] == "--batch" {
		n, err := strconv.Atoi(os.Args[2])
		if err != nil || n < 1 {
			fmt.Fprintf(os.Stderr, "error: --batch requires a positive integer\n")
			return 1
		}
		batchCount = n
		cmdStart = 3
	}

	if len(os.Args) < cmdStart+1 {
		fmt.Fprintf(os.Stderr, "usage: %s [--batch N] <command> [args...]\n", os.Args[0])
		return 1
	}

	ctx := context.Background()

	cfg := agentbox.DefaultConfig()
	cfg.FallbackPolicy = agentbox.FallbackWarn

	// On Windows, use cmd.exe as the shell since /bin/sh doesn't exist
	if runtime.GOOS == "windows" {
		cfg.Shell = `C:\Windows\System32\cmd.exe`
	}

	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer func() {
		if cleanupErr := mgr.Cleanup(ctx); cleanupErr != nil {
			fmt.Fprintf(os.Stderr, "cleanup error: %v\n", cleanupErr)
		}
	}()

	command := os.Args[cmdStart]
	args := os.Args[cmdStart+1:]

	// Single execution mode (existing behavior)
	if batchCount == 0 {
		result, err := mgr.ExecArgs(ctx, command, args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}

		if _, writeErr := os.Stdout.WriteString(result.Stdout); writeErr != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", writeErr)
			return 1
		}

		return result.ExitCode
	}

	// Batch mode: run N times and collect timing
	timings := make([]float64, 0, batchCount)
	var totalDuration time.Duration

	for i := 0; i < batchCount; i++ {
		start := time.Now()
		result, err := mgr.ExecArgs(ctx, command, args)
		elapsed := time.Since(start)

		if err != nil {
			fmt.Fprintf(os.Stderr, "error on run %d: %v\n", i+1, err)
			return 1
		}
		if result.ExitCode != 0 {
			fmt.Fprintf(os.Stderr, "command failed on run %d with exit code %d\n", i+1, result.ExitCode)
			return result.ExitCode
		}

		timings = append(timings, elapsed.Seconds()*1000) // convert to ms
		totalDuration += elapsed
	}

	// Sort for percentile calculation
	slices.Sort(timings)

	// Calculate statistics
	minTime := timings[0]
	maxTime := timings[len(timings)-1]
	mean := totalDuration.Seconds() * 1000 / float64(batchCount)
	p50 := percentile(timings, 0.50)
	p95 := percentile(timings, 0.95)

	// Print results
	fmt.Printf("Batch: %d runs\n", batchCount)
	fmt.Printf("  Min:    %.2f ms\n", minTime)
	fmt.Printf("  Max:    %.2f ms\n", maxTime)
	fmt.Printf("  Mean:   %.2f ms\n", mean)
	fmt.Printf("  P50:    %.2f ms\n", p50)
	fmt.Printf("  P95:    %.2f ms\n", p95)
	fmt.Printf("  Total:  %.1f ms\n", totalDuration.Seconds()*1000)

	return 0
}

// percentile computes a linearly interpolated percentile from sorted data.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 1 {
		return sorted[0]
	}
	rank := p * float64(len(sorted)-1)
	lower := int(rank)
	upper := lower + 1
	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	frac := rank - float64(lower)
	return sorted[lower] + frac*(sorted[upper]-sorted[lower])
}
