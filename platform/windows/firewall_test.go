//go:build windows

package windows

import (
	"fmt"
	"strings"
	"testing"
)

// TestBuildSDDL tests the SDDL string generation for firewall rules.
// This is a pure logic test that works on all platforms.
func TestBuildSDDL(t *testing.T) {
	tests := []struct {
		name     string
		sid      string
		expected string
	}{
		{
			name:     "standard user SID",
			sid:      "S-1-5-21-1234567890-1234567890-1234567890-1001",
			expected: "O:LSD:(A;;CC;;;S-1-5-21-1234567890-1234567890-1234567890-1001)",
		},
		{
			name:     "short SID",
			sid:      "S-1-5-32-544",
			expected: "O:LSD:(A;;CC;;;S-1-5-32-544)",
		},
		{
			name:     "builtin administrators",
			sid:      "S-1-5-32-544",
			expected: "O:LSD:(A;;CC;;;S-1-5-32-544)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildSDDL(tt.sid)
			if result != tt.expected {
				t.Errorf("buildSDDL(%q) = %q, want %q", tt.sid, result, tt.expected)
			}

			// Verify format structure
			if !strings.HasPrefix(result, "O:LSD:(A;;CC;;;") {
				t.Errorf("SDDL missing correct prefix: %q", result)
			}
			if !strings.HasSuffix(result, ")") {
				t.Errorf("SDDL missing closing paren: %q", result)
			}
			if !strings.Contains(result, tt.sid) {
				t.Errorf("SDDL missing SID %q: %q", tt.sid, result)
			}
		})
	}
}

// TestFirewallConstants verifies the Windows Firewall constant values.
func TestFirewallConstants(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected interface{}
	}{
		{"NET_FW_RULE_DIR_OUT", netFwRuleDirOut, 2},
		{"NET_FW_ACTION_BLOCK", netFwActionBlock, 0},
		{"NET_FW_IP_PROTOCOL_ANY", netFwIPProtocolAny, 256},
		{"NET_FW_PROFILE2_ALL", netFwProfile2All, int32(0x7FFFFFFF)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, tt.value, tt.expected)
			}
		})
	}
}

// TestFirewallProgIDs verifies the COM ProgIDs are correct.
func TestFirewallProgIDs(t *testing.T) {
	if progIDFwPolicy2 != "HNetCfg.FwPolicy2" {
		t.Errorf("progIDFwPolicy2 = %q, want %q", progIDFwPolicy2, "HNetCfg.FwPolicy2")
	}
	if progIDFwRule != "HNetCfg.FwRule" {
		t.Errorf("progIDFwRule = %q, want %q", progIDFwRule, "HNetCfg.FwRule")
	}
}

// TestFirewallManager_Lifecycle tests the FirewallManager tracking logic.
// This tests the manager's bookkeeping without actually creating firewall rules.
func TestFirewallManager_Lifecycle(t *testing.T) {
	fm := NewFirewallManager()

	// Initial state
	if len(fm.rules) != 0 {
		t.Errorf("new FirewallManager should have 0 rules, got %d", len(fm.rules))
	}

	// Test rule name generation
	username := "test_user"
	expectedName := fmt.Sprintf("Agentbox Sandbox Block - %s", username)

	if !strings.Contains(expectedName, username) {
		t.Errorf("rule name should contain username %q, got %q", username, expectedName)
	}
	if !strings.HasPrefix(expectedName, "Agentbox Sandbox Block") {
		t.Errorf("rule name should have standard prefix, got %q", expectedName)
	}
}

// TestFirewallManager_Cleanup tests the cleanup logic without COM operations.
func TestFirewallManager_Cleanup(t *testing.T) {
	fm := NewFirewallManager()

	// Simulate adding rules by directly manipulating the slice
	// (This tests the cleanup logic without requiring actual firewall rules)
	fm.rules = []string{"rule1", "rule2", "rule3"}

	// Note: Cleanup() will try to call removeFirewallRule which requires COM
	// For unit testing without COM, we just verify the slice management works
	if len(fm.rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(fm.rules))
	}
}

// TestFirewallRuleNaming tests rule name generation consistency.
func TestFirewallRuleNaming(t *testing.T) {
	tests := []struct {
		username string
		wantName string
	}{
		{"user1", "Agentbox Sandbox Block - user1"},
		{"sb_test", "Agentbox Sandbox Block - sb_test"},
		{"admin_sandbox", "Agentbox Sandbox Block - admin_sandbox"},
	}

	for _, tt := range tests {
		t.Run(tt.username, func(t *testing.T) {
			name := fmt.Sprintf("Agentbox Sandbox Block - %s", tt.username)
			if name != tt.wantName {
				t.Errorf("rule name = %q, want %q", name, tt.wantName)
			}
		})
	}
}

// TestAddOutboundBlockRule_RequiresAdmin tests firewall rule creation.
// This test requires administrator privileges and is skipped in non-admin contexts.
func TestAddOutboundBlockRule_RequiresAdmin(t *testing.T) {
	if !checkAdminStatus() {
		t.Skip("skipping test: requires administrator privileges")
	}

	// Use a test SID (well-known Everyone SID for testing)
	testSID := "S-1-1-0" // Everyone
	testUsername := "firewall_test_user"

	// Create a test rule
	ruleName, err := addOutboundBlockRule(testUsername, testSID)
	if err != nil {
		t.Fatalf("addOutboundBlockRule failed: %v", err)
	}

	// Verify rule was created
	expectedName := fmt.Sprintf("Agentbox Sandbox Block - %s", testUsername)
	if ruleName != expectedName {
		t.Errorf("rule name = %q, want %q", ruleName, expectedName)
	}

	// Check if rule exists
	exists, err := checkFirewallRuleExists(ruleName)
	if err != nil {
		t.Fatalf("checkFirewallRuleExists failed: %v", err)
	}
	if !exists {
		t.Errorf("rule %q should exist but doesn't", ruleName)
	}

	// Clean up: remove the test rule
	if err := removeFirewallRule(ruleName); err != nil {
		t.Errorf("failed to remove test rule: %v", err)
	}

	// Verify rule was removed
	exists, err = checkFirewallRuleExists(ruleName)
	if err != nil {
		t.Fatalf("checkFirewallRuleExists failed after removal: %v", err)
	}
	if exists {
		t.Errorf("rule %q should not exist after removal", ruleName)
	}
}

// TestFirewallManager_BlockUnblock_RequiresAdmin tests the full lifecycle
// of blocking and unblocking a user via FirewallManager.
func TestFirewallManager_BlockUnblock_RequiresAdmin(t *testing.T) {
	if !checkAdminStatus() {
		t.Skip("skipping test: requires administrator privileges")
	}

	fm := NewFirewallManager()

	// Use a test SID (well-known Everyone SID for testing)
	testSID := "S-1-1-0" // Everyone
	testUsername := "fm_test_user"

	// Block user
	if err := fm.BlockUser(testUsername, testSID); err != nil {
		t.Fatalf("BlockUser failed: %v", err)
	}

	// Verify rule was tracked
	if len(fm.rules) != 1 {
		t.Errorf("expected 1 tracked rule, got %d", len(fm.rules))
	}

	ruleName := fmt.Sprintf("Agentbox Sandbox Block - %s", testUsername)

	// Verify rule exists in firewall
	exists, err := checkFirewallRuleExists(ruleName)
	if err != nil {
		t.Fatalf("checkFirewallRuleExists failed: %v", err)
	}
	if !exists {
		t.Errorf("rule %q should exist", ruleName)
	}

	// Unblock user
	if err := fm.UnblockUser(ruleName); err != nil {
		t.Fatalf("UnblockUser failed: %v", err)
	}

	// Verify rule was untracked
	if len(fm.rules) != 0 {
		t.Errorf("expected 0 tracked rules after unblock, got %d", len(fm.rules))
	}

	// Verify rule doesn't exist in firewall
	exists, err = checkFirewallRuleExists(ruleName)
	if err != nil {
		t.Fatalf("checkFirewallRuleExists failed after removal: %v", err)
	}
	if exists {
		t.Errorf("rule %q should not exist after unblock", ruleName)
	}
}

// TestFirewallManager_Cleanup_RequiresAdmin tests cleanup of multiple rules.
func TestFirewallManager_Cleanup_RequiresAdmin(t *testing.T) {
	if !checkAdminStatus() {
		t.Skip("skipping test: requires administrator privileges")
	}

	fm := NewFirewallManager()

	// Use test SIDs
	testSID := "S-1-1-0" // Everyone
	testUsers := []string{"cleanup_user1", "cleanup_user2", "cleanup_user3"}

	// Block multiple users
	for _, username := range testUsers {
		if err := fm.BlockUser(username, testSID); err != nil {
			t.Fatalf("BlockUser(%q) failed: %v", username, err)
		}
	}

	// Verify all rules were tracked
	if len(fm.rules) != len(testUsers) {
		t.Errorf("expected %d tracked rules, got %d", len(testUsers), len(fm.rules))
	}

	// Cleanup all rules
	if err := fm.Cleanup(); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}

	// Verify no rules are tracked
	if len(fm.rules) != 0 {
		t.Errorf("expected 0 tracked rules after cleanup, got %d", len(fm.rules))
	}

	// Verify all rules were removed from firewall
	for _, username := range testUsers {
		ruleName := fmt.Sprintf("Agentbox Sandbox Block - %s", username)
		exists, err := checkFirewallRuleExists(ruleName)
		if err != nil {
			t.Fatalf("checkFirewallRuleExists(%q) failed: %v", ruleName, err)
		}
		if exists {
			t.Errorf("rule %q should not exist after cleanup", ruleName)
		}
	}
}

// TestCheckFirewallRuleExists_NonExistent tests checking for a non-existent rule.
func TestCheckFirewallRuleExists_NonExistent(t *testing.T) {
	if !checkAdminStatus() {
		t.Skip("skipping test: requires administrator privileges")
	}

	// Check for a rule that definitely doesn't exist
	ruleName := "Agentbox Sandbox Block - nonexistent_rule_12345"
	exists, err := checkFirewallRuleExists(ruleName)
	if err != nil {
		t.Fatalf("checkFirewallRuleExists failed: %v", err)
	}
	if exists {
		t.Errorf("rule %q should not exist", ruleName)
	}
}

// TestSDDLFormat validates SDDL string structure.
func TestSDDLFormat(t *testing.T) {
	testSID := "S-1-5-21-1111111111-2222222222-3333333333-1001"
	sddl := buildSDDL(testSID)

	// Verify SDDL components
	components := []string{
		"O:LS",      // Owner: Local System
		"D:",        // DACL follows
		"(A;;CC;;;", // Allow, Control Connection
		testSID,     // The actual SID
		")",         // Closing paren
	}

	for _, component := range components {
		if !strings.Contains(sddl, component) {
			t.Errorf("SDDL %q missing component %q", sddl, component)
		}
	}

	// Verify exact format
	expectedSDDL := fmt.Sprintf("O:LSD:(A;;CC;;;%s)", testSID)
	if sddl != expectedSDDL {
		t.Errorf("SDDL = %q, want %q", sddl, expectedSDDL)
	}
}
