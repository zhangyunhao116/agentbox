package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/zhangyunhao116/agentbox"
)

// testEntry is used to build JSON test datasets matching the expected format.
type testEntry struct {
	Command string `json:"command"`
	Count   int    `json:"count"`
}

// TestScanDatasetSmall verifies that scanDataset correctly processes a small
// synthetic dataset and produces the expected per-rule and per-decision stats.
func TestScanDatasetSmall(t *testing.T) {
	// Build a small JSON dataset with known classification outcomes.
	entries := []testEntry{
		{Command: "ls -la", Count: 100},             // Allow: common-safe-commands
		{Command: "git status", Count: 50},           // Allow: git-read-commands
		{Command: "rm -rf --no-preserve-root /", Count: 3}, // Forbidden: recursive-delete-root
		{Command: "sudo apt install vim", Count: 7},  // Escalated: sudo
		{Command: "somecustomthing", Count: 20},       // Sandboxed (no rule)
	}

	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal test data: %v", err)
	}

	ruleMap, totals, err := scanDataset(bytes.NewReader(data), 5)
	if err != nil {
		t.Fatalf("scanDataset: %v", err)
	}

	// Verify we got some rules back.
	if len(ruleMap) == 0 {
		t.Fatal("expected non-empty ruleMap")
	}

	// Verify totals cover all entries.
	var totalUnique int
	for _, ds := range totals {
		totalUnique += ds.Unique
	}
	if totalUnique != len(entries) {
		t.Errorf("total unique commands = %d, want %d", totalUnique, len(entries))
	}

	// Verify sandboxed entry exists (the "somecustomthing" command).
	ds := totals[agentbox.Sandboxed]
	if ds == nil {
		t.Fatal("expected sandboxed decision stats to exist")
	}
	if ds.Unique < 1 {
		t.Errorf("expected at least 1 sandboxed command, got %d", ds.Unique)
	}
}

// TestInsertSample verifies the top-N sample tracking logic.
func TestInsertSample(t *testing.T) {
	rs := &ruleStats{Rule: "test"}
	topN := 3

	// Insert 5 samples; only top 3 by count should be retained.
	insertSample(rs, "cmd1", 10, topN)
	insertSample(rs, "cmd2", 50, topN)
	insertSample(rs, "cmd3", 30, topN)
	insertSample(rs, "cmd4", 5, topN)  // should be evicted
	insertSample(rs, "cmd5", 40, topN) // should evict cmd1 (10)

	if len(rs.Samples) != topN {
		t.Fatalf("expected %d samples, got %d", topN, len(rs.Samples))
	}

	// Verify ordering: highest count first.
	for i := 1; i < len(rs.Samples); i++ {
		if rs.Samples[i].Count > rs.Samples[i-1].Count {
			t.Errorf("samples not sorted: index %d (%d) > index %d (%d)",
				i, rs.Samples[i].Count, i-1, rs.Samples[i-1].Count)
		}
	}

	// The minimum should be at least 30 (cmd1=10 and cmd4=5 should have been evicted).
	minCount := rs.Samples[len(rs.Samples)-1].Count
	if minCount < 30 {
		t.Errorf("smallest sample count = %d, want >= 30", minCount)
	}
}

// TestInsertSampleZeroTop verifies that topN=0 keeps no samples.
func TestInsertSampleZeroTop(t *testing.T) {
	rs := &ruleStats{Rule: "test"}
	insertSample(rs, "cmd1", 100, 0)
	if len(rs.Samples) != 0 {
		t.Errorf("expected 0 samples with topN=0, got %d", len(rs.Samples))
	}
}

// TestRulesForDecision verifies grouping and sorting by decision level.
func TestRulesForDecision(t *testing.T) {
	ruleMap := map[string]*ruleStats{
		"rule-a": {Rule: "rule-a", Decision: agentbox.Forbidden, TotalCount: 100},
		"rule-b": {Rule: "rule-b", Decision: agentbox.Forbidden, TotalCount: 500},
		"rule-c": {Rule: "rule-c", Decision: agentbox.Allow, TotalCount: 200},
	}

	forbidden := rulesForDecision(ruleMap, agentbox.Forbidden)
	if len(forbidden) != 2 {
		t.Fatalf("expected 2 forbidden rules, got %d", len(forbidden))
	}
	// Should be sorted by TotalCount descending.
	if forbidden[0].TotalCount < forbidden[1].TotalCount {
		t.Error("forbidden rules not sorted by TotalCount descending")
	}

	allow := rulesForDecision(ruleMap, agentbox.Allow)
	if len(allow) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(allow))
	}

	escalated := rulesForDecision(ruleMap, agentbox.Escalated)
	if len(escalated) != 0 {
		t.Errorf("expected 0 escalated rules, got %d", len(escalated))
	}
}
