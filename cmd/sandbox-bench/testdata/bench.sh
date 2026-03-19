#!/usr/bin/env bash
# bench.sh - Benchmark sandbox-bench in cold-start and hot-start modes
#
# Usage:
#   ./bench.sh [OPTIONS]
#
# Options:
#   --cold-only       Run only cold-start benchmarks
#   --hot-only        Run only hot-start benchmarks
#   --runs N          Number of runs (default: 50 for hot, 10 for cold)
#   --help            Show this help message
#
# Requires:
#   - Go toolchain (to build sandbox-bench)
#   - hyperfine (optional, for better cold-start benchmarking)

set -euo pipefail

# ANSI color codes
if [ "${NO_COLOR:-}" = "" ] && [ -t 1 ]; then
    BOLD="\033[1m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    BLUE="\033[34m"
    RESET="\033[0m"
else
    BOLD=""
    GREEN=""
    YELLOW=""
    BLUE=""
    RESET=""
fi

# Default configuration
COLD_RUNS=10
HOT_RUNS=50
RUN_COLD=1
RUN_HOT=1

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --cold-only)
            RUN_HOT=0
            shift
            ;;
        --hot-only)
            RUN_COLD=0
            shift
            ;;
        --runs)
            COLD_RUNS="$2"
            HOT_RUNS="$2"
            shift 2
            ;;
        --help)
            sed -n '2,/^$/p' "$0" | sed 's/^# //; s/^#//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Detect platform
detect_platform() {
    local os
    os=$(uname -s)
    case "$os" in
        Darwin)
            echo "macOS"
            ;;
        Linux)
            if grep -qi microsoft /proc/version 2>/dev/null; then
                echo "Linux (WSL)"
            else
                echo "Linux"
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            echo "Windows"
            ;;
        *)
            echo "Unknown ($os)"
            ;;
    esac
}

# Build sandbox-bench if needed
build_sandbox_bench() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local repo_root
    repo_root="$(cd "$script_dir/../../.." && pwd)"
    local bench_bin="$repo_root/sandbox-bench"

    if [ ! -f "$bench_bin" ] || [ "$repo_root/cmd/sandbox-bench/main.go" -nt "$bench_bin" ]; then
        echo -e "${YELLOW}Building sandbox-bench...${RESET}"
        (cd "$repo_root" && go build -o sandbox-bench ./cmd/sandbox-bench/)
    fi

    echo "$bench_bin"
}

# Check if hyperfine is available
has_hyperfine() {
    command -v hyperfine >/dev/null 2>&1
}

# Run cold-start benchmark with hyperfine
bench_cold_hyperfine() {
    local cmd="$1"
    local runs="$2"
    
    hyperfine --warmup 1 --min-runs "$runs" --shell=none "$cmd" 2>&1 | \
        awk '/Time \(mean ± σ\):/ { print $5, $6 }'
}

# Run cold-start benchmark with bash (fallback)
bench_cold_bash() {
    local cmd="$1"
    local runs="$2"
    local total=0
    local min=999999
    local max=0
    
    for ((i=1; i<=runs; i++)); do
        local start
        start=$(date +%s%N)
        eval "$cmd" >/dev/null 2>&1
        local end
        end=$(date +%s%N)
        local elapsed=$(( (end - start) / 1000000 ))  # Convert to ms
        
        total=$((total + elapsed))
        [ "$elapsed" -lt "$min" ] && min=$elapsed
        [ "$elapsed" -gt "$max" ] && max=$elapsed
    done
    
    local mean=$((total / runs))
    echo "${mean}.0 ms"
}

# Run hot-start benchmark using --batch
bench_hot() {
    local bench_bin="$1"
    local cmd="$2"
    local runs="$3"
    
    # Parse command into args
    local cmd_array
    IFS=' ' read -ra cmd_array <<< "$cmd"
    
    "$bench_bin" --batch "$runs" "${cmd_array[@]}" 2>&1 | \
        awk '/Mean:/ { print $2, $3 }'
}

# Run bare (no sandbox) benchmark
bench_bare() {
    local cmd="$1"
    local runs="$2"
    
    if has_hyperfine; then
        # Use --shell=bash since the command may be a shell builtin (echo, true).
        hyperfine --warmup 1 --min-runs "$runs" --shell=bash "$cmd" 2>&1 | \
            awk '/Time \(mean ± σ\):/ { print $5, $6 }'
    else
        bench_cold_bash "$cmd" "$runs"
    fi
}

# Calculate overhead ratio (handles µs/ms/s units)
calc_overhead() {
    local sandboxed="$1"
    local bare="$2"
    
    awk -v s_str="$sandboxed" -v b_str="$bare" 'BEGIN {
        split(s_str, s_parts, " ")
        s_val = s_parts[1] + 0
        s_unit = s_parts[2]
        if (s_unit == "s") s_val *= 1000
        else if (s_unit == "µs" || s_unit == "μs") s_val /= 1000

        split(b_str, b_parts, " ")
        b_val = b_parts[1] + 0
        b_unit = b_parts[2]
        if (b_unit == "s") b_val *= 1000
        else if (b_unit == "µs" || b_unit == "μs") b_val /= 1000

        if (b_val > 0) {
            ratio = s_val / b_val
            if (ratio >= 2) {
                printf "%.0fx", ratio
            } else {
                printf "%.1fx", ratio
            }
        } else {
            print "N/A"
        }
    }'
}

# Print header
print_header() {
    echo -e "${BOLD}=== Sandbox Benchmark ===${RESET}"
    echo "Platform:    $(detect_platform)"
    echo "Go version:  $(go version | awk '{print $3, $4}')"
    echo "Date:        $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Hyperfine:   $(has_hyperfine && echo 'available' || echo 'not found (using fallback)')"
    echo ""
}

# Main benchmark routine
main() {
    print_header
    
    local bench_bin
    bench_bin=$(build_sandbox_bench)
    
    # Test commands
    declare -a commands=(
        "echo hello"
        "true"
        "cat /dev/null"
        "go version"
    )
    
    # Cold-start benchmarks
    if [ "$RUN_COLD" -eq 1 ]; then
        echo -e "${BOLD}${BLUE}Cold-start benchmarks${RESET} (${COLD_RUNS} runs each)"
        printf "%-20s %-15s %-15s %-10s\n" "Command" "Sandboxed" "Bare" "Overhead"
        printf "%-20s %-15s %-15s %-10s\n" "-------" "---------" "----" "--------"
        
        for cmd in "${commands[@]}"; do
            local sandboxed bare overhead
            
            if has_hyperfine; then
                sandboxed=$(bench_cold_hyperfine "$bench_bin $cmd" "$COLD_RUNS")
                bare=$(bench_bare "$cmd" "$COLD_RUNS")
            else
                sandboxed=$(bench_cold_bash "$bench_bin $cmd" "$COLD_RUNS")
                bare=$(bench_cold_bash "$cmd" "$COLD_RUNS")
            fi
            
            overhead=$(calc_overhead "$sandboxed" "$bare")
            
            printf "%-20s ${GREEN}%-15s${RESET} %-15s %-10s\n" \
                "$cmd" "$sandboxed" "$bare" "$overhead"
        done
        echo ""
    fi
    
    # Hot-start benchmarks
    if [ "$RUN_HOT" -eq 1 ]; then
        echo -e "${BOLD}${BLUE}Hot-start benchmarks${RESET} (${HOT_RUNS} runs each)"
        printf "%-20s %-15s\n" "Command" "Mean Time"
        printf "%-20s %-15s\n" "-------" "---------"
        
        for cmd in "${commands[@]}"; do
            local result
            result=$(bench_hot "$bench_bin" "$cmd" "$HOT_RUNS")
            printf "%-20s ${GREEN}%-15s${RESET}\n" "$cmd" "$result"
        done
        echo ""
    fi
    
    echo -e "${BOLD}Benchmark complete!${RESET}"
}

main
