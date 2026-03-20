//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SE_GROUP_LOGON_ID is the combined attribute for logon SID identification.
// It combines SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED | SE_GROUP_LOGON_ID_flag.
const seGroupLogonID = 0xC0000000

// CreateSandboxToken creates a restricted token suitable for sandboxed process execution.
// The token is created with the following restrictions:
// 1. Removes all privileges except SeChangeNotifyPrivilege
// 2. Creates a LUA (Limited User Account) token
// 3. Applies write restrictions
// 4. Sets Low Integrity Level
// 5. Adds restricting SIDs (logon SID and Everyone SID)
//
// The returned token handle must be closed by the caller.
//
// This function is exported to allow standalone testing outside the Go test framework,
// which is necessary because certain Windows API calls hang when invoked from test
// binaries under Cygwin SSH.
func CreateSandboxToken() (windows.Token, error) {
	return createSandboxToken()
}

// createSandboxToken is the internal implementation.
func createSandboxToken() (windows.Token, error) {
	// Step 1: Open current process token for duplication and modification.
	// TOKEN_ASSIGN_PRIMARY is required because Go's CreateProcessAsUser needs
	// the token handle to be opened with this access right when used as a
	// primary token for a new process via SysProcAttr.Token.
	var baseToken windows.Token
	err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_PRIVILEGES,
		&baseToken,
	)
	if err != nil {
		return 0, fmt.Errorf("OpenProcessToken failed: %w", err)
	}
	defer baseToken.Close()

	// Step 2: Try to extract the logon SID (may not exist in non-interactive sessions)
	// extractLogonSID returns a Go-managed copy — no FreeSid needed.
	logonSID, logonErr := extractLogonSID(baseToken)

	// Step 3: Create well-known Everyone SID
	// NOTE: CreateWellKnownSid returns a Go-managed SID (backed by make([]byte, n)),
	// so we must NOT call FreeSid on it — FreeSid is only for Windows-API-allocated SIDs.
	everyoneSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return 0, fmt.Errorf("CreateWellKnownSid(WinWorldSid) failed: %w", err)
	}

	// Step 4: Build restricting SIDs array
	// Restricting SIDs: Attributes MUST be zero per Microsoft docs.
	// "The Attributes member of the SID_AND_ATTRIBUTES structure must be zero.
	// Restricting SIDs are always enabled for access checks."
	var caps []windows.SIDAndAttributes
	if logonErr == nil {
		// Interactive session: use both logon SID and Everyone SID
		caps = []windows.SIDAndAttributes{
			{Sid: logonSID, Attributes: 0},
			{Sid: everyoneSID, Attributes: 0},
		}
	} else {
		// Non-interactive session (SSH, service) — use Everyone SID only
		caps = []windows.SIDAndAttributes{
			{Sid: everyoneSID, Attributes: 0},
		}
	}

	// Step 5: Create restricted token with restricting SIDs
	var restrictedToken windows.Token
	var capsPtr *windows.SIDAndAttributes
	if len(caps) > 0 {
		capsPtr = &caps[0]
	}
	err = createRestrictedToken(
		baseToken,
		disableMaxPrivilege|luaToken|writeRestricted,
		0, nil,                  // No SIDs to disable
		0, nil,                  // No privileges to delete
		uint32(len(caps)), capsPtr, // Restricting SIDs
		&restrictedToken,
	)
	if err != nil {
		// Fallback: create restricted token without restricting SIDs
		// This may happen in unusual environments (Cygwin SSH, containers, etc.)
		// The token still has DISABLE_MAX_PRIVILEGE + LUA_TOKEN + WRITE_RESTRICTED
		err = createRestrictedToken(
			baseToken,
			disableMaxPrivilege|luaToken|writeRestricted,
			0, nil,   // No SIDs to disable
			0, nil,   // No privileges to delete
			0, nil,   // No restricting SIDs
			&restrictedToken,
		)
		if err != nil {
			return 0, fmt.Errorf("createRestrictedToken failed (with and without restricting SIDs): %w", err)
		}
	}

	// Ensure cleanup on error paths below
	var success bool
	defer func() {
		if !success {
			restrictedToken.Close()
		}
	}()

	// Step 6: Set Low Integrity Level
	err = setLowIntegrityLevel(restrictedToken)
	if err != nil {
		return 0, fmt.Errorf("setLowIntegrityLevel failed: %w", err)
	}

	// Step 7: Enable SeChangeNotifyPrivilege (needed for directory traversal)
	err = enableChangeNotifyPrivilege(restrictedToken)
	if err != nil {
		return 0, fmt.Errorf("enableChangeNotifyPrivilege failed: %w", err)
	}

	success = true
	return restrictedToken, nil
}

// extractLogonSID retrieves the logon SID from a token's groups.
// The logon SID is identified by the SE_GROUP_LOGON_ID attribute (0xC0000000).
// Returns a Go-managed copy of the SID — no FreeSid needed.
func extractLogonSID(token windows.Token) (*windows.SID, error) {
	// First call to get required buffer size
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenGroups, nil, 0, &size)
	if err != nil && err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("GetTokenInformation size query failed: %w", err)
	}

	// Allocate buffer and retrieve token groups
	buf := make([]byte, size)
	err = windows.GetTokenInformation(token, windows.TokenGroups, &buf[0], size, &size)
	if err != nil {
		return nil, fmt.Errorf("GetTokenInformation failed: %w", err)
	}

	// Parse TOKEN_GROUPS structure
	groups := (*windows.Tokengroups)(unsafe.Pointer(&buf[0]))

	// Scan for the logon SID (identified by SE_GROUP_LOGON_ID attribute)
	// Use AllGroups() method to safely iterate over the variable-length array
	for _, group := range groups.AllGroups() {
		if group.Attributes&seGroupLogonID == seGroupLogonID {
			// CRITICAL: Copy the SID to Go-managed memory.
			// group.Sid points into buf which becomes invalid after this function returns.
			copiedSID, copyErr := group.Sid.Copy()
			if copyErr != nil {
				return nil, fmt.Errorf("SID.Copy failed: %w", copyErr)
			}
			return copiedSID, nil
		}
	}

	return nil, fmt.Errorf("logon SID not found in token groups")
}

// enableChangeNotifyPrivilege enables the SeChangeNotifyPrivilege on the token.
// This privilege is required for directory traversal and is typically the only
// privilege retained in a restricted token.
func enableChangeNotifyPrivilege(token windows.Token) error {
	// Lookup the LUID for SeChangeNotifyPrivilege
	var luid windows.LUID
	err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeChangeNotifyPrivilege"), &luid)
	if err != nil {
		return fmt.Errorf("LookupPrivilegeValue(SeChangeNotifyPrivilege) failed: %w", err)
	}

	// Build TOKEN_PRIVILEGES structure with the privilege enabled
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	// Adjust token privileges
	err = windows.AdjustTokenPrivileges(
		token,
		false, // Do not disable all privileges
		&tp,
		uint32(unsafe.Sizeof(tp)),
		nil, // Don't need previous state
		nil,
	)
	if err != nil {
		return fmt.Errorf("AdjustTokenPrivileges failed: %w", err)
	}

	return nil
}
