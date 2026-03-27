package main

import (
	"sort"
	"testing"
)

// TestGroupByRule verifies that groupByRule correctly buckets forbidden hits
// by rule name, sorts commands within each group by count descending, and
// sorts groups themselves by total count descending.
func TestGroupByRule(t *testing.T) {
	hits := []forbiddenHit{
		{Command: "rm -rf /", Rule: "recursive-delete-root", Count: 100},
		{Command: "rm -rf /*", Rule: "recursive-delete-root", Count: 50},
		{Command: ":(){ :|:& };:", Rule: "fork-bomb", Count: 200},
		{Command: "dd if=/dev/zero of=/dev/sda", Rule: "disk-wipe", Count: 10},
	}

	groups := groupByRule(hits)

	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}

	// Groups should be sorted by total count descending.
	for i := 1; i < len(groups); i++ {
		if groups[i].Total > groups[i-1].Total {
			t.Errorf("groups not sorted: group %d total (%d) > group %d total (%d)",
				i, groups[i].Total, i-1, groups[i-1].Total)
		}
	}

	// Find the recursive-delete-root group and verify internal sorting.
	var rdrGroup *ruleGroup
	for i := range groups {
		if groups[i].Rule == "recursive-delete-root" {
			rdrGroup = &groups[i]
			break
		}
	}
	if rdrGroup == nil {
		t.Fatal("expected recursive-delete-root group")
	}
	if rdrGroup.Total != 150 {
		t.Errorf("recursive-delete-root total = %d, want 150", rdrGroup.Total)
	}
	if len(rdrGroup.Commands) != 2 {
		t.Fatalf("expected 2 commands in group, got %d", len(rdrGroup.Commands))
	}
	// Commands within group should be sorted by count descending.
	if rdrGroup.Commands[0].Count < rdrGroup.Commands[1].Count {
		t.Error("commands within group not sorted by count descending")
	}
}

// TestGroupByRuleEmpty verifies that groupByRule handles an empty input.
func TestGroupByRuleEmpty(t *testing.T) {
	groups := groupByRule(nil)
	if len(groups) != 0 {
		t.Errorf("expected 0 groups for nil input, got %d", len(groups))
	}
}

// TestGroupByRuleSingleHit verifies a single hit produces one group.
func TestGroupByRuleSingleHit(t *testing.T) {
	hits := []forbiddenHit{
		{Command: "rm -rf /", Rule: "recursive-delete-root", Count: 42},
	}
	groups := groupByRule(hits)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].Rule != "recursive-delete-root" {
		t.Errorf("rule = %q, want %q", groups[0].Rule, "recursive-delete-root")
	}
	if groups[0].Total != 42 {
		t.Errorf("total = %d, want 42", groups[0].Total)
	}
}

// TestPrintReport is a smoke test that verifies printReport does not panic.
func TestPrintReport(t *testing.T) {
	hits := []forbiddenHit{
		{Command: "rm -rf /", Rule: "recursive-delete-root", Count: 5},
	}
	groups := groupByRule(hits)

	// Verify no panic with valid input.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("printReport panicked: %v", r)
		}
	}()

	printReport(100, hits, groups, 0)

	// Also verify no panic with empty input.
	printReport(0, nil, nil, 0)
}

// TestGroupByRuleEqualTotals verifies that groups with the same total
// still form a valid descending sort.
func TestGroupByRuleEqualTotals(t *testing.T) {
	hits := []forbiddenHit{
		{Command: "cmd-a", Rule: "rule-a", Count: 10},
		{Command: "cmd-b", Rule: "rule-b", Count: 10},
		{Command: "cmd-c", Rule: "rule-c", Count: 10},
	}

	groups := groupByRule(hits)
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}

	// All totals should be equal.
	for _, g := range groups {
		if g.Total != 10 {
			t.Errorf("group %q total = %d, want 10", g.Rule, g.Total)
		}
	}

	// Verify it's a valid sort (stable or not, it shouldn't violate the ordering).
	isSorted := sort.SliceIsSorted(groups, func(i, j int) bool {
		return groups[i].Total > groups[j].Total
	})
	if !isSorted {
		t.Error("groups not sorted by total descending")
	}
}
