# sandbox-bench

A minimal CLI wrapper for benchmarking agentbox with tools like `hyperfine`.

## Usage

```bash
sandbox-bench <command> [args...]
```

## Build

```bash
go build -o sandbox-bench ./cmd/sandbox-bench/
```

## Example

```bash
# Run a simple command
./sandbox-bench echo hello

# Benchmark with hyperfine
hyperfine './sandbox-bench echo hello' 'other-sandbox echo hello'
```

## Features

- Uses `agentbox.DefaultConfig()` with `FallbackWarn` policy
- Prints stdout from sandboxed command
- Exits with the command's exit code
- Handles cleanup properly via defer
- Cross-platform (Linux, macOS, Windows)

## Benchmarking

The `testdata/` directory contains benchmark helper scripts for testing sandbox-bench performance and comparing it against other sandbox tools.

### Running Benchmarks

**Cold-start and hot-start benchmarks:**

```bash
# Run both cold and hot benchmarks with default settings
./cmd/sandbox-bench/testdata/bench.sh

# Run only cold-start benchmarks (10 runs by default)
./cmd/sandbox-bench/testdata/bench.sh --cold-only

# Run only hot-start benchmarks (50 runs by default)
./cmd/sandbox-bench/testdata/bench.sh --hot-only

# Custom number of runs
./cmd/sandbox-bench/testdata/bench.sh --runs 100
```

The benchmark script tests a standard set of commands:
- `echo hello` - minimal overhead baseline
- `true` - no-op, pure sandbox overhead
- `cat /dev/null` - file I/O test
- `go version` - real tool startup

Cold-start benchmarks use [hyperfine](https://github.com/sharkdp/hyperfine) if available, otherwise fall back to bash timing. Hot-start benchmarks use `sandbox-bench --batch N` for sequential executions within a single sandbox process.

**Competitor comparison:**

```bash
# Compare against other sandbox tools (codex, srt, bare)
./cmd/sandbox-bench/testdata/compare.sh
```

The comparison script auto-detects available tools and benchmarks all of them with the same test command. Tools checked:
- `sandbox-bench` (agentbox) - always required
- `codex` (OpenAI Codex CLI) - optional
- `srt` (Claude Code sandbox-runtime) - optional
- bare execution (no sandbox) - always included as baseline

### Workload Scripts

The `testdata/workloads/` directory contains small test scripts for specific use cases:

**File I/O test (`write_file.sh`):**
```bash
./cmd/sandbox-bench/testdata/workloads/write_file.sh
```
Creates a temp file, writes 1KB, reads it back, and cleans up. Tests file I/O sandbox overhead.

**CPU-bound test (`cpu_work.sh`):**
```bash
./cmd/sandbox-bench/testdata/workloads/cpu_work.sh
```
Generates 100KB of random data and calculates its MD5 hash. Tests CPU-bound workload performance.

### Example Output

Cold-start benchmark output (with hyperfine):
```
=== Sandbox Benchmark ===
Platform:    macOS
Go version:  go1.22.0 darwin/arm64
Date:        2026-03-19 12:35:00
Hyperfine:   available

Cold-start benchmarks (10 runs each)
Command              Sandboxed       Bare            Overhead
-------              ---------       ----            --------
echo hello           5.2 ms          1.1 ms          372.7%
true                 4.8 ms          0.9 ms          433.3%
cat /dev/null        5.3 ms          1.2 ms          341.7%
go version           45.2 ms         42.1 ms         7.4%

Hot-start benchmarks (50 runs each)
Command              Mean Time
-------              ---------
echo hello           0.85 ms
true                 0.78 ms
cat /dev/null        0.92 ms
go version           38.34 ms
```

Comparison output:
```
=== Sandbox Tool Comparison ===
Platform:    macOS
Go version:  go1.22.0 darwin/arm64
Date:        2026-03-19 12:35:00
Test cmd:    echo hello
Runs:        10 (cold-start)
Hyperfine:   available

Detected tools:
  ✓ sandbox-bench
  ✓ bare (no sandbox)

Not found:
  ✗ codex
  ✗ srt

Cold-start benchmark (10 runs)
Tool                 Mean Time       vs Bare
----                 ---------       -------
sandbox-bench        5.2 ms          0.21x
bare                 1.1 ms          (baseline)

Hot-start benchmark (50 runs, if supported)
Tool                 Mean Time
----                 ---------
sandbox-bench        0.85 ms
```
