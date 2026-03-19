#!/usr/bin/env bash
# compare.sh - Compare sandbox-bench against competitor sandbox tools
#
# Usage:
#   ./compare.sh [OPTIONS]
#
# Options:
#   --runs N          Number of cold-start runs (default: 10)
#   --help            Show this help message
#
# Auto-detects available tools:
#   - sandbox-bench (agentbox) - required
#   - codex (OpenAI Codex CLI) - optional
#   - srt (Claude Code sandbox-runtime) - optional
#   - bare execution (always)
#
# Uses hyperfine if available, falls back to bash timing otherwise.

set -uo pipefail
# Note: not using set -e; we handle errors explicitly so that
# a broken competitor tool doesn't abort the whole comparison.

# ANSI color codes
if [ "${NO_COLOR:-}" = "" ] && [ -t 1 ]; then
    BOLD="\033[1m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    BLUE="\033[34m"
    RED="\033[31m"
    RESET="\033[0m"
else
    BOLD=""
    GREEN=""
    YELLOW=""
    BLUE=""
    RED=""
    RESET=""
fi

# Configuration
RUNS=10
TEST_CMD="echo hello"

# Parse arguments
while [ $# -gt 0 ]; do
    case $1 in
        --runs)
            RUNS="$2"
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

# Build sandbox-bench if needed
build_sandbox_bench() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local repo_root
    repo_root="$(cd "$script_dir/../../.." && pwd)"
    local bench_bin="$repo_root/sandbox-bench"

    if [ ! -f "$bench_bin" ] || [ "$repo_root/cmd/sandbox-bench/main.go" -nt "$bench_bin" ]; then
        echo -e "${YELLOW}Building sandbox-bench...${RESET}" >&2
        (cd "$repo_root" && go build -o sandbox-bench ./cmd/sandbox-bench/)
    fi
    echo "$bench_bin"
}

has_hyperfine() {
    command -v hyperfine >/dev/null 2>&1
}

# Check tool actually works (not just exists in PATH)
check_tool_works() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        return 1
    fi
    # Verify the tool can actually execute a trivial command
    case "$tool" in
        codex)  codex exec -- true >/dev/null 2>&1 || return 1 ;;
        srt)    srt run -- true >/dev/null 2>&1 || return 1 ;;
    esac
    return 0
}

# Benchmark a command (cold-start). Returns "N.N ms" or "error".
bench_cold() {
    local cmd="$1"
    local use_shell="${2:-none}"  # "bash" for bare commands, "none" for tool binaries

    if has_hyperfine; then
        local result
        result=$(hyperfine --warmup 3 --min-runs "$RUNS" --shell="$use_shell" "$cmd" 2>&1 | \
            awk '/Time \(mean ± σ\):/ { print $5, $6 }')
        if [ -n "$result" ]; then
            echo "$result"
        else
            echo "error"
        fi
    else
        local total=0
        local i
        for ((i=1; i<=RUNS; i++)); do
            local start end elapsed
            start=$(python3 -c 'import time; print(int(time.time()*1000))' 2>/dev/null || date +%s%N)
            eval "$cmd" >/dev/null 2>&1
            end=$(python3 -c 'import time; print(int(time.time()*1000))' 2>/dev/null || date +%s%N)
            if [ ${#start} -gt 13 ]; then
                elapsed=$(( (end - start) / 1000000 ))
            else
                elapsed=$((end - start))
            fi
            total=$((total + elapsed))
        done
        local mean=$((total / RUNS))
        echo "${mean}.0 ms"
    fi
}

# Calculate overhead ratio (handles µs/ms/s units)
calc_overhead() {
    local tool_time="$1"
    local bare_time="$2"

    awk -v t_str="$tool_time" -v b_str="$bare_time" 'BEGIN {
        split(t_str, t, " "); t_val = t[1]+0; t_unit = t[2]
        if (t_unit == "s") t_val *= 1000
        else if (t_unit == "µs" || t_unit == "μs") t_val /= 1000

        split(b_str, b, " "); b_val = b[1]+0; b_unit = b[2]
        if (b_unit == "s") b_val *= 1000
        else if (b_unit == "µs" || b_unit == "μs") b_val /= 1000

        if (b_val > 0 && t_val > 0) {
            ratio = t_val / b_val
            printf "%.1fx", ratio
        } else {
            print "N/A"
        }
    }'
}

# Main
main() {
    echo -e "${BOLD}=== Sandbox Tool Comparison ===${RESET}"
    echo "Platform:    $(uname -s)"
    echo "Go version:  $(go version | awk '{print $3, $4}')"
    echo "Date:        $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Test cmd:    $TEST_CMD"
    echo "Runs:        $RUNS (cold-start)"
    echo "Hyperfine:   $(has_hyperfine && echo 'available' || echo 'not found (using fallback)')"
    echo ""

    local bench_bin
    bench_bin=$(build_sandbox_bench)

    # Collect tools (parallel arrays — bash 3.2 compatible)
    local names=()
    local cmds=()
    local shell_modes=()   # "none" for tool binaries, "bash" for bare

    names+=("sandbox-bench")
    cmds+=("$bench_bin $TEST_CMD")
    shell_modes+=("none")

    if check_tool_works codex; then
        names+=("codex")
        cmds+=("codex exec -- $TEST_CMD")
        shell_modes+=("none")
    fi

    if check_tool_works srt; then
        names+=("srt")
        cmds+=("srt run -- $TEST_CMD")
        shell_modes+=("none")
    fi

    names+=("bare")
    cmds+=("$TEST_CMD")
    shell_modes+=("bash")

    # Print detected tools
    echo -e "${BOLD}${BLUE}Detected tools:${RESET}"
    local i
    for ((i=0; i<${#names[@]}; i++)); do
        local name="${names[$i]}"
        if [ "$name" = "bare" ]; then
            echo -e "  ${GREEN}✓${RESET} $name (no sandbox)"
        else
            echo -e "  ${GREEN}✓${RESET} $name"
        fi
    done

    # Show missing
    echo ""
    local any_missing=0
    local missing_list=""
    if ! check_tool_works codex; then
        missing_list="${missing_list}  ${RED}✗${RESET} codex (OpenAI Codex CLI)\n"
        any_missing=1
    fi
    if ! check_tool_works srt; then
        missing_list="${missing_list}  ${RED}✗${RESET} srt (Claude Code sandbox-runtime)\n"
        any_missing=1
    fi
    if [ "$any_missing" -eq 1 ]; then
        echo -e "${BOLD}${YELLOW}Not found / not working:${RESET}"
        echo -e "$missing_list"
    fi

    # Cold-start benchmarks
    echo -e "${BOLD}${BLUE}Cold-start benchmark${RESET} ($RUNS runs)"
    printf "%-20s %-15s %-12s\n" "Tool" "Mean Time" "vs Bare"
    printf "%-20s %-15s %-12s\n" "----" "---------" "-------"

    local results=()
    for ((i=0; i<${#names[@]}; i++)); do
        results+=("$(bench_cold "${cmds[$i]}" "${shell_modes[$i]}")")
    done

    # Bare result is the last entry
    local bare_result="${results[${#results[@]}-1]}"

    for ((i=0; i<${#names[@]}; i++)); do
        local name="${names[$i]}"
        local result="${results[$i]}"
        if [ "$name" = "bare" ]; then
            printf "%-20s ${GREEN}%-15s${RESET} %-12s\n" "$name" "$result" "(baseline)"
        elif [ "$result" = "error" ]; then
            printf "%-20s ${RED}%-15s${RESET} %-12s\n" "$name" "error" "N/A"
        else
            local overhead
            overhead=$(calc_overhead "$result" "$bare_result")
            printf "%-20s ${GREEN}%-15s${RESET} %-12s\n" "$name" "$result" "$overhead"
        fi
    done
    echo ""

    # Hot-start (only sandbox-bench supports --batch)
    echo -e "${BOLD}${BLUE}Hot-start benchmark${RESET} (50 runs)"
    printf "%-20s %-15s\n" "Tool" "Mean Time"
    printf "%-20s %-15s\n" "----" "---------"

    local hot_result
    hot_result=$("$bench_bin" --batch 50 $TEST_CMD 2>&1 | awk '/Mean:/ { print $2, $3 }') || hot_result="error"
    printf "%-20s ${GREEN}%-15s${RESET}\n" "sandbox-bench" "$hot_result"

    for ((i=0; i<${#names[@]}; i++)); do
        local name="${names[$i]}"
        if [ "$name" = "sandbox-bench" ] || [ "$name" = "bare" ]; then
            continue
        fi
        printf "%-20s ${YELLOW}%-15s${RESET}\n" "$name" "N/A (no batch)"
    done
    echo ""

    echo -e "${BOLD}Comparison complete!${RESET}"
}

main
