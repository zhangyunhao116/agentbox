# Windows Firewall Integration

This document describes the Windows Firewall integration for Tier 2 admin features.

## Overview

`platform/windows/firewall.go` provides COM-based Windows Firewall management for creating per-user-SID outbound block rules. This enables network isolation for sandboxed processes without requiring AppContainer.

## Architecture

When an admin creates a sandbox user (Tier 2 feature), the system also creates a Windows Firewall rule that blocks ALL outbound traffic for that specific user SID. This provides network-level isolation.

## Implementation Details

### COM Interfaces Used

- **INetFwPolicy2** (CLSID: E2B3C97F-6AE1-41AC-817A-F6F92166D7DD)
  - Main interface for Windows Firewall management
  - Accessed via ProgID: `HNetCfg.FwPolicy2`

- **INetFwRule** (CLSID: 2C5BC43E-3369-4C33-AB0C-BE9469677AF4)
  - Represents a firewall rule
  - Accessed via ProgID: `HNetCfg.FwRule`

### Rule Configuration

Each rule created has the following properties:

- **Name**: `"Agentbox Sandbox Block - {username}"`
- **Description**: `"Blocks outbound network for agentbox sandbox user"`
- **Direction**: Outbound (NET_FW_RULE_DIR_OUT = 2)
- **Action**: Block (NET_FW_ACTION_BLOCK = 0)
- **Protocol**: Any (NET_FW_IP_PROTOCOL_ANY = 256)
- **Profiles**: All profiles - Domain, Private, Public (0x7FFFFFFF)
- **Enabled**: true
- **LocalUserAuthorizedList**: SDDL string `O:LSD:(A;;CC;;;{SID})`
- **Grouping**: `"Agentbox Sandbox"`

### SDDL Format

The `LocalUserAuthorizedList` uses Security Descriptor Definition Language (SDDL) to scope the rule to a specific user:

```
O:LSD:(A;;CC;;;S-1-5-21-XXXX-YYYY-ZZZZ-1001)
```

- `O:LS` - Owner: Local System
- `D:` - DACL follows
- `(A;;CC;;;{SID})` - Allow (A), Control Connection (CC), to the specified SID

## API Usage

### Basic Usage

```go
import "github.com/zhangyunhao116/agentbox/platform/windows"

// Create a firewall manager
fm := windows.NewFirewallManager()

// Block a user
username := "sb_user1"
userSID := "S-1-5-21-1234567890-1234567890-1234567890-1001"
err := fm.BlockUser(username, userSID)
if err != nil {
    log.Fatalf("Failed to block user: %v", err)
}

// Unblock a user (using rule name)
ruleName := "Agentbox Sandbox Block - sb_user1"
err = fm.UnblockUser(ruleName)
if err != nil {
    log.Fatalf("Failed to unblock user: %v", err)
}

// Cleanup all tracked rules
err = fm.Cleanup()
if err != nil {
    log.Printf("Cleanup had errors: %v", err)
}
```

### FirewallManager

The `FirewallManager` struct provides thread-safe operations and tracks active rules for cleanup:

```go
type FirewallManager struct {
    mu    sync.Mutex
    rules []string // active rule names for cleanup
}
```

**Methods:**

- `BlockUser(username, userSID string) error` - Creates a firewall rule and tracks it
- `UnblockUser(ruleName string) error` - Removes a firewall rule and untracks it
- `Cleanup() error` - Removes all tracked rules (best-effort, returns first error)

## Requirements

- **Administrator Privileges**: Required to modify Windows Firewall rules
- **go-ole v1.3.0**: COM automation library (already in go.mod)
- **Windows 10+**: Modern Windows Firewall with INetFwPolicy2 support

## Testing

### Unit Tests (No Admin Required)

These tests verify logic without COM operations:

```bash
go test -v -run "TestBuildSDDL|TestFirewallConstants" ./platform/windows/
```

### Integration Tests (Admin Required)

These tests create actual firewall rules:

```bash
# On Windows with admin privileges:
go test -v -run "TestAddOutboundBlockRule_RequiresAdmin" ./platform/windows/
```

## Behavioral Verification

To verify the firewall rule actually blocks network traffic:

1. Create a test user with a known SID
2. Use `BlockUser()` to create a rule for that SID
3. Run a network test as that user (e.g., `ping google.com`)
4. Verify the connection is blocked
5. Remove the rule with `UnblockUser()`
6. Verify the connection works again

## References

- Codex firewall.rs implementation: https://github.com/openai/codex/blob/main/codex-rs/windows-sandbox-rs/src/firewall.rs
- Windows Firewall COM API: https://docs.microsoft.com/en-us/windows/win32/api/netfw/
- go-ole library: https://github.com/go-ole/go-ole
