// Example trustlevel9 scans a large dataset of real-world commands and reports
// which ones would be blocked at Trust Level 9 ("System Admin").
//
// At Level 9 every Escalated rule (sudo, docker, ssh, …) is treated as Allow,
// so only truly destructive Forbidden commands are blocked.
//
// The dataset is a JSON array of {"command": "...", "count": N} entries
// (≈3.2M records, 373 MB). The file is streamed via the dataset helper
// so memory usage stays low regardless of file size.
//
// Usage:
//
//	go run ./examples/trustlevel9 -file all_commands_merged.json
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zhangyunhao116/agentbox"
	"github.com/zhangyunhao116/agentbox/examples/internal/dataset"
)

// forbiddenHit records one command that was classified as Forbidden.
type forbiddenHit struct {
	Command string
	Rule    string
	Count   int
}

// ruleGroup aggregates all forbidden hits sharing the same rule name.
type ruleGroup struct {
	Rule     string
	Commands []forbiddenHit
	Total    int // sum of counts across all commands in the group
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

//nolint:unparam // error return kept for consistency with other examples.
func run() error {
	filePath := flag.String("file", "all_commands_merged.json", "path to the JSON dataset")
	flag.Parse()

	f, err := os.Open(*filePath)
	if err != nil {
		return fmt.Errorf("open dataset: %w", err)
	}
	defer f.Close()

	classifier := agentbox.DefaultClassifier()

	var (
		totalCommands int
		forbidden     []forbiddenHit
	)
	start := time.Now()

	err = dataset.ScanEntries(f, func(command string, count int) error {
		totalCommands++
		result := classifier.Classify(command)

		// Level 9 logic: Escalated → Allow; only Forbidden remains blocked.
		if result.Decision == agentbox.Forbidden {
			forbidden = append(forbidden, forbiddenHit{
				Command: command,
				Rule:    string(result.Rule),
				Count:   count,
			})
		}
		return nil
	})
	if err != nil {
		return err
	}

	elapsed := time.Since(start)

	// Group forbidden hits by rule name.
	groups := groupByRule(forbidden)

	// Print report.
	printReport(totalCommands, forbidden, groups, elapsed)

	return nil
}

// groupByRule buckets forbidden hits by their rule name and sorts groups by
// total occurrence count (descending).
func groupByRule(hits []forbiddenHit) []ruleGroup {
	m := make(map[string]*ruleGroup, len(hits))
	for _, h := range hits {
		g, ok := m[h.Rule]
		if !ok {
			g = &ruleGroup{Rule: h.Rule}
			m[h.Rule] = g
		}
		g.Commands = append(g.Commands, h)
		g.Total += h.Count
	}

	groups := make([]ruleGroup, 0, len(m))
	for _, g := range m {
		// Sort commands within each group by count descending.
		sort.Slice(g.Commands, func(i, j int) bool {
			return g.Commands[i].Count > g.Commands[j].Count
		})
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Total > groups[j].Total
	})
	return groups
}

// printReport writes the human-readable summary to stdout.
func printReport(total int, forbidden []forbiddenHit, groups []ruleGroup, elapsed time.Duration) {
	sep := strings.Repeat("─", 72)

	fmt.Println(sep)
	fmt.Println("  Trust Level 9 — Command Classification Report")
	fmt.Println(sep)
	fmt.Printf("  Total commands scanned : %d\n", total)
	fmt.Printf("  Unique forbidden cmds  : %d\n", len(forbidden))
	fmt.Printf("  Forbidden rule groups  : %d\n", len(groups))
	fmt.Printf("  Scan duration          : %s\n", elapsed.Round(time.Millisecond))
	fmt.Println(sep)
	fmt.Println()

	if len(groups) == 0 {
		fmt.Println("  No forbidden commands found.")
		return
	}

	for _, g := range groups {
		fmt.Printf("  Rule: %s  (total occurrences: %d)\n", g.Rule, g.Total)
		for _, c := range g.Commands {
			cmd := c.Command
			if len(cmd) > 90 {
				cmd = cmd[:87] + "..."
			}
			fmt.Printf("    [%d×]  %s\n", c.Count, cmd)
		}
		fmt.Println()
	}

	fmt.Println(sep)
	fmt.Println("  Level 9 allows ALL Escalated commands (sudo, docker, ssh, …).")
	fmt.Println("  Only truly destructive operations remain Forbidden.")
	fmt.Println(sep)
}
