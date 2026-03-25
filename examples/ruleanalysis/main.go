// Example ruleanalysis runs ALL classification rules against a large command
// dataset and produces a per-rule breakdown report grouped by decision level.
//
// The dataset is a JSON array of {"command": "...", "count": N} entries
// (≈3.2M records, 373 MB). The file is streamed with encoding/json.Decoder
// so memory usage stays low regardless of file size.
//
// Usage:
//
//	go run ./examples/ruleanalysis -file all_commands_merged.json
//	go run ./examples/ruleanalysis -file all_commands_merged.json -top 5
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zhangyunhao116/agentbox"
)

// entry mirrors a single object in the JSON dataset.
type entry struct {
	Command string `json:"command"`
	Count   int    `json:"count"`
}

// commandSample records a matched command along with its occurrence count.
type commandSample struct {
	Command string
	Count   int
}

// ruleStats aggregates all commands matching a single classification rule.
type ruleStats struct {
	Rule       string
	Decision   agentbox.Decision
	Unique     int // number of unique commands matched
	TotalCount int // sum of occurrence counts
	Samples    []commandSample
}

// decisionStats aggregates totals for a decision level.
type decisionStats struct {
	Unique     int
	TotalCount int
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

//nolint:unparam // error return kept for consistency with other examples.
func run() error {
	filePath := flag.String("file", "all_commands_merged.json", "path to the JSON dataset")
	topN := flag.Int("top", 10, "number of sample commands to show per rule")
	flag.Parse()

	f, err := os.Open(*filePath)
	if err != nil {
		return fmt.Errorf("open dataset: %w", err)
	}
	defer f.Close()

	stats, totals, err := scanDataset(f, *topN)
	if err != nil {
		return err
	}

	printReport(stats, totals, *topN)
	return nil
}

// scanDataset streams the JSON array and collects per-rule statistics.
func scanDataset(r io.Reader, topN int) (map[string]*ruleStats, map[agentbox.Decision]*decisionStats, error) {
	classifier := agentbox.DefaultClassifier()

	dec := json.NewDecoder(r)

	// Consume the opening '['.
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, fmt.Errorf("read opening token: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return nil, nil, fmt.Errorf("expected JSON array, got %v", tok)
	}

	// ruleMap keys by rule name (or "sandboxed" for unmatched commands).
	ruleMap := make(map[string]*ruleStats)
	totals := make(map[agentbox.Decision]*decisionStats)

	var totalCommands int
	start := time.Now()

	for dec.More() {
		var e entry
		if err := dec.Decode(&e); err != nil {
			return nil, nil, fmt.Errorf("decode entry %d: %w", totalCommands+1, err)
		}
		totalCommands++

		result := classifier.Classify(e.Command)

		// Determine the map key: rule name for matched rules, "sandboxed" for no match.
		key := string(result.Rule)
		if key == "" {
			key = "sandboxed"
		}

		rs, ok := ruleMap[key]
		if !ok {
			rs = &ruleStats{
				Rule:     key,
				Decision: result.Decision,
			}
			ruleMap[key] = rs
		}
		rs.Unique++
		rs.TotalCount += e.Count
		insertSample(rs, e.Command, e.Count, topN)

		// Accumulate per-decision totals.
		ds := totals[result.Decision]
		if ds == nil {
			ds = &decisionStats{}
			totals[result.Decision] = ds
		}
		ds.Unique++
		ds.TotalCount += e.Count

		// Progress indicator every 500k commands.
		if totalCommands%500_000 == 0 {
			elapsed := time.Since(start)
			fmt.Fprintf(os.Stderr, "\r  scanned %dk commands (%s)...", totalCommands/1000, elapsed.Round(time.Millisecond))
		}
	}

	// Consume the closing ']'.
	if _, err := dec.Token(); err != nil && err != io.EOF {
		return nil, nil, fmt.Errorf("read closing token: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\r") // clear progress line
	fmt.Fprintf(os.Stderr, "  Done: scanned %d commands in %s\n", totalCommands, time.Since(start).Round(time.Millisecond))

	return ruleMap, totals, nil
}

// insertSample maintains a top-N list of samples sorted by count descending.
// It avoids accumulating all commands in memory by keeping only the top N.
func insertSample(rs *ruleStats, command string, count, topN int) {
	if topN <= 0 {
		return
	}
	sample := commandSample{Command: command, Count: count}

	if len(rs.Samples) < topN {
		rs.Samples = append(rs.Samples, sample)
		// Re-sort after insertion to maintain order.
		sort.Slice(rs.Samples, func(i, j int) bool {
			return rs.Samples[i].Count > rs.Samples[j].Count
		})
		return
	}
	// Only insert if this sample has a higher count than the smallest in the list.
	if count > rs.Samples[len(rs.Samples)-1].Count {
		rs.Samples[len(rs.Samples)-1] = sample
		sort.Slice(rs.Samples, func(i, j int) bool {
			return rs.Samples[i].Count > rs.Samples[j].Count
		})
	}
}

// printReport writes the human-readable per-rule breakdown to stdout.
func printReport(ruleMap map[string]*ruleStats, totals map[agentbox.Decision]*decisionStats, topN int) {
	sep := strings.Repeat("─", 80)

	fmt.Println(sep)
	fmt.Println("  Rule Analysis — Per-Rule Classification Breakdown")
	fmt.Println(sep)

	// Ordered decision levels for output grouping.
	levels := []agentbox.Decision{
		agentbox.Forbidden,
		agentbox.Escalated,
		agentbox.Allow,
		agentbox.Sandboxed,
	}

	for _, level := range levels {
		rules := rulesForDecision(ruleMap, level)
		if len(rules) == 0 {
			continue
		}

		fmt.Println()
		fmt.Printf("  ══ %s ══  (%d rules matched)\n", strings.ToUpper(level.String()), len(rules))
		fmt.Println()

		for _, rs := range rules {
			printRuleSection(rs, topN)
		}
	}

	// Summary table.
	fmt.Println()
	fmt.Println(sep)
	fmt.Println("  SUMMARY")
	fmt.Println(sep)
	fmt.Printf("  %-12s %15s %18s\n", "Decision", "Unique Commands", "Total Occurrences")
	fmt.Printf("  %-12s %15s %18s\n", "────────────", "───────────────", "──────────────────")

	var grandUnique, grandTotal int
	for _, level := range levels {
		ds := totals[level]
		if ds == nil {
			ds = &decisionStats{}
		}
		fmt.Printf("  %-12s %15d %18d\n", level.String(), ds.Unique, ds.TotalCount)
		grandUnique += ds.Unique
		grandTotal += ds.TotalCount
	}
	fmt.Printf("  %-12s %15s %18s\n", "────────────", "───────────────", "──────────────────")
	fmt.Printf("  %-12s %15d %18d\n", "TOTAL", grandUnique, grandTotal)
	fmt.Println(sep)
}

// rulesForDecision extracts and sorts rules belonging to the given decision level.
// Rules are sorted by total occurrence count descending.
func rulesForDecision(ruleMap map[string]*ruleStats, decision agentbox.Decision) []*ruleStats {
	var rules []*ruleStats
	for _, rs := range ruleMap {
		if rs.Decision == decision {
			rules = append(rules, rs)
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].TotalCount > rules[j].TotalCount
	})
	return rules
}

// printRuleSection prints the details for a single rule.
func printRuleSection(rs *ruleStats, topN int) {
	fmt.Printf("  ┌─ Rule: %-30s  Decision: %s\n", rs.Rule, rs.Decision.String())
	fmt.Printf("  │  Unique commands: %d    Total occurrences: %d\n", rs.Unique, rs.TotalCount)

	limit := topN
	if limit > len(rs.Samples) {
		limit = len(rs.Samples)
	}
	if limit > 0 {
		fmt.Printf("  │  Top %d samples:\n", limit)
		for i := 0; i < limit; i++ {
			cmd := rs.Samples[i].Command
			if len(cmd) > 90 {
				cmd = cmd[:87] + "..."
			}
			fmt.Printf("  │    [%d×]  %s\n", rs.Samples[i].Count, cmd)
		}
	}
	fmt.Println("  └─")
	fmt.Println()
}
