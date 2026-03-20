//go:build windows

package windows

import (
	"fmt"
	"sync"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// Windows Firewall COM interface constants.
// These are used to interact with INetFwPolicy2 and INetFwRule3 COM interfaces.
const (
	// COM CLSIDs and IIDs for Windows Firewall interfaces.
	// CLSID_NetFwPolicy2 = {E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}
	progIDFwPolicy2 = "HNetCfg.FwPolicy2"
	// CLSID_NetFwRule = {2C5BC43E-3369-4C33-AB0C-BE9469677AF4}
	progIDFwRule = "HNetCfg.FwRule"

	// NET_FW_RULE_DIR_OUT specifies outbound traffic direction.
	netFwRuleDirOut = 2

	// NET_FW_ACTION_BLOCK specifies that matching traffic should be blocked.
	netFwActionBlock = 0

	// NET_FW_IP_PROTOCOL_ANY matches any IP protocol.
	netFwIPProtocolAny = 256

	// NET_FW_PROFILE2_ALL applies the rule to all profiles (Domain, Private, Public).
	// 0x7FFFFFFF = binary 01111111111111111111111111111111 (all profiles enabled)
	netFwProfile2All = int32(0x7FFFFFFF)
)

// FirewallManager manages Windows Firewall rules for sandbox users.
// It tracks active rules for cleanup and provides thread-safe operations.
//
// The manager creates per-user-SID outbound block rules to prevent sandboxed
// processes from making network connections, providing network isolation without
// requiring AppContainer.
//
// Thread-safety: FirewallManager is safe for concurrent use via mutex protection.
type FirewallManager struct {
	mu    sync.Mutex
	rules []string // active rule names for cleanup
}

// NewFirewallManager creates a new firewall manager instance.
func NewFirewallManager() *FirewallManager {
	return &FirewallManager{
		rules: make([]string, 0),
	}
}

// BlockUser creates a Windows Firewall rule that blocks all outbound traffic
// for the specified user SID. The rule is scoped to the user via SDDL in the
// LocalUserAuthorizedList property.
//
// Parameters:
//   - username: The username for naming the rule (e.g., "sb_user1")
//   - userSID: The user's SID string (e.g., "S-1-5-21-...")
//
// Returns the rule name on success, which can be used later to remove the rule.
func (fm *FirewallManager) BlockUser(username, userSID string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	ruleName, err := addOutboundBlockRule(username, userSID)
	if err != nil {
		return fmt.Errorf("failed to add firewall rule: %w", err)
	}

	fm.rules = append(fm.rules, ruleName)
	return nil
}

// UnblockUser removes a Windows Firewall rule by name.
//
// Parameters:
//   - ruleName: The name of the rule to remove (returned by BlockUser)
func (fm *FirewallManager) UnblockUser(ruleName string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if err := removeFirewallRule(ruleName); err != nil {
		return fmt.Errorf("failed to remove firewall rule: %w", err)
	}

	// Remove from tracked rules
	for i, name := range fm.rules {
		if name == ruleName {
			fm.rules = append(fm.rules[:i], fm.rules[i+1:]...)
			break
		}
	}

	return nil
}

// Cleanup removes all tracked firewall rules.
// Errors are logged but do not stop cleanup - this is best-effort.
// Returns the first error encountered, if any.
func (fm *FirewallManager) Cleanup() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	var firstErr error
	for _, ruleName := range fm.rules {
		if err := removeFirewallRule(ruleName); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to remove firewall rule %s: %w", ruleName, err)
			}
			// Continue cleanup even on error
		}
	}

	fm.rules = fm.rules[:0] // clear the slice
	return firstErr
}

// addOutboundBlockRule creates a Windows Firewall rule that blocks all outbound
// traffic for a specific user SID using COM automation via INetFwPolicy2.
//
// The rule is configured with:
//   - Direction: Outbound (NET_FW_RULE_DIR_OUT)
//   - Action: Block (NET_FW_ACTION_BLOCK)
//   - Protocol: Any (NET_FW_IP_PROTOCOL_ANY)
//   - Profiles: All (Domain, Private, Public)
//   - Enabled: true
//   - LocalUserAuthorizedList: SDDL string scoping rule to specific user SID
//
// Parameters:
//   - username: The username for naming the rule
//   - userSID: The user's SID string (e.g., "S-1-5-21-...")
//
// Returns the rule name on success.
func addOutboundBlockRule(username, userSID string) (string, error) {
	// Initialize COM for this goroutine
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		return "", fmt.Errorf("CoInitializeEx failed: %w", err)
	}
	defer ole.CoUninitialize()

	// Create INetFwPolicy2 instance
	unknownPolicy, err := oleutil.CreateObject(progIDFwPolicy2)
	if err != nil {
		return "", fmt.Errorf("CreateObject(HNetCfg.FwPolicy2) failed: %w", err)
	}
	defer unknownPolicy.Release()

	policy, err := unknownPolicy.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return "", fmt.Errorf("QueryInterface(IDispatch) for policy failed: %w", err)
	}
	defer policy.Release()

	// Get Rules collection
	rulesVar, err := oleutil.GetProperty(policy, "Rules")
	if err != nil {
		return "", fmt.Errorf("GetProperty(Rules) failed: %w", err)
	}
	rules := rulesVar.ToIDispatch()
	defer rules.Release()

	// Create INetFwRule instance
	unknownRule, err := oleutil.CreateObject(progIDFwRule)
	if err != nil {
		return "", fmt.Errorf("CreateObject(HNetCfg.FwRule) failed: %w", err)
	}
	defer unknownRule.Release()

	rule, err := unknownRule.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return "", fmt.Errorf("QueryInterface(IDispatch) for rule failed: %w", err)
	}
	defer rule.Release()

	// Configure rule properties
	ruleName := fmt.Sprintf("Agentbox Sandbox Block - %s", username)
	ruleDesc := "Blocks outbound network for agentbox sandbox user"
	sddl := buildSDDL(userSID)

	// Set each property using PutProperty
	if _, err := oleutil.PutProperty(rule, "Name", ruleName); err != nil {
		return "", fmt.Errorf("PutProperty(Name) failed: %w", err)
	}

	if _, err := oleutil.PutProperty(rule, "Description", ruleDesc); err != nil {
		return "", fmt.Errorf("PutProperty(Description) failed: %w", err)
	}

	if _, err := oleutil.PutProperty(rule, "Direction", netFwRuleDirOut); err != nil {
		return "", fmt.Errorf("PutProperty(Direction) failed: %w", err)
	}

	if _, err := oleutil.PutProperty(rule, "Action", netFwActionBlock); err != nil {
		return "", fmt.Errorf("PutProperty(Action) failed: %w", err)
	}

	if _, err := oleutil.PutProperty(rule, "Protocol", netFwIPProtocolAny); err != nil {
		return "", fmt.Errorf("PutProperty(Protocol) failed: %w", err)
	}

	if _, err := oleutil.PutProperty(rule, "Profiles", netFwProfile2All); err != nil {
		return "", fmt.Errorf("PutProperty(Profiles) failed: %w", err)
	}

	if _, err := oleutil.PutProperty(rule, "Enabled", true); err != nil {
		return "", fmt.Errorf("PutProperty(Enabled) failed: %w", err)
	}

	if _, err := oleutil.PutProperty(rule, "LocalUserAuthorizedList", sddl); err != nil {
		return "", fmt.Errorf("PutProperty(LocalUserAuthorizedList) failed: %w", err)
	}

	if _, err := oleutil.PutProperty(rule, "Grouping", "Agentbox Sandbox"); err != nil {
		return "", fmt.Errorf("PutProperty(Grouping) failed: %w", err)
	}

	// Add the rule to the Rules collection
	if _, err := oleutil.CallMethod(rules, "Add", rule); err != nil {
		return "", fmt.Errorf("CallMethod(Rules.Add) failed: %w", err)
	}

	return ruleName, nil
}

// removeFirewallRule removes a Windows Firewall rule by name using COM automation.
//
// Parameters:
//   - ruleName: The name of the rule to remove
func removeFirewallRule(ruleName string) error {
	// Initialize COM for this goroutine
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		return fmt.Errorf("CoInitializeEx failed: %w", err)
	}
	defer ole.CoUninitialize()

	// Create INetFwPolicy2 instance
	unknownPolicy, err := oleutil.CreateObject(progIDFwPolicy2)
	if err != nil {
		return fmt.Errorf("CreateObject(HNetCfg.FwPolicy2) failed: %w", err)
	}
	defer unknownPolicy.Release()

	policy, err := unknownPolicy.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("QueryInterface(IDispatch) for policy failed: %w", err)
	}
	defer policy.Release()

	// Get Rules collection
	rulesVar, err := oleutil.GetProperty(policy, "Rules")
	if err != nil {
		return fmt.Errorf("GetProperty(Rules) failed: %w", err)
	}
	rules := rulesVar.ToIDispatch()
	defer rules.Release()

	// Remove the rule
	if _, err := oleutil.CallMethod(rules, "Remove", ruleName); err != nil {
		return fmt.Errorf("CallMethod(Rules.Remove) failed: %w", err)
	}

	return nil
}

// checkFirewallRuleExists checks if a Windows Firewall rule exists by name.
//
// Parameters:
//   - ruleName: The name of the rule to check
//
// Returns true if the rule exists, false otherwise.
func checkFirewallRuleExists(ruleName string) (bool, error) {
	// Initialize COM for this goroutine
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		return false, fmt.Errorf("CoInitializeEx failed: %w", err)
	}
	defer ole.CoUninitialize()

	// Create INetFwPolicy2 instance
	unknownPolicy, err := oleutil.CreateObject(progIDFwPolicy2)
	if err != nil {
		return false, fmt.Errorf("CreateObject(HNetCfg.FwPolicy2) failed: %w", err)
	}
	defer unknownPolicy.Release()

	policy, err := unknownPolicy.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return false, fmt.Errorf("QueryInterface(IDispatch) for policy failed: %w", err)
	}
	defer policy.Release()

	// Get Rules collection
	rulesVar, err := oleutil.GetProperty(policy, "Rules")
	if err != nil {
		return false, fmt.Errorf("GetProperty(Rules) failed: %w", err)
	}
	rules := rulesVar.ToIDispatch()
	defer rules.Release()

	// Try to get the rule by name
	itemVar, err := oleutil.CallMethod(rules, "Item", ruleName)
	if err != nil {
		// Rule doesn't exist — no COM object to release on error
		return false, nil
	}
	// If successful, release the returned COM object
	if item := itemVar.ToIDispatch(); item != nil {
		defer item.Release()
	}
	return true, nil
}

// buildSDDL constructs an SDDL string for the LocalUserAuthorizedList property.
// The SDDL scopes the firewall rule to a specific user SID.
//
// Format: O:LSD:(A;;CC;;;{SID})
//   - O:LS - Owner: Local System
//   - D: - DACL follows
//   - (A;;CC;;;{SID}) - Allow (A), Control Connection (CC), to the specified SID
//
// Parameters:
//   - sid: The user's SID string (e.g., "S-1-5-21-...")
//
// Returns the SDDL string.
func buildSDDL(sid string) string {
	return fmt.Sprintf("O:LSD:(A;;CC;;;%s)", sid)
}
