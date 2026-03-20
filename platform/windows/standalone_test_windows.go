//go:build ignore
// +build ignore

// standalone_test_windows.go is a standalone program to verify sandbox token creation
// outside of the Go test framework, bypassing Cygwin SSH TTY issues.
//
// Build and run on Windows:
//   go run platform/windows/standalone_test_windows.go
//
// This verifies that createSandboxToken works correctly when called from a regular
// program (not a test binary under Cygwin SSH).

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken = modadvapi32.NewProc("CreateRestrictedToken")
)

const (
	disableMaxPrivilege = 0x1
	luaToken            = 0x4
	writeRestricted     = 0x8
	seGroupLogonID      = 0xC0000000
)

func main() {
	fmt.Println("=== Windows Sandbox Token Test (Standalone) ===")
	fmt.Println()

	fmt.Println("[Step 1] Opening current process token...")
	var baseToken windows.Token
	err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_PRIVILEGES,
		&baseToken,
	)
	if err != nil {
		fmt.Printf("FAIL: OpenProcessToken failed: %v\n", err)
		os.Exit(1)
	}
	defer baseToken.Close()
	fmt.Println("PASS: Token opened")

	fmt.Println("[Step 2] Extracting logon SID...")
	logonSID, err := extractLogonSID(baseToken)
	if err != nil {
		fmt.Printf("FAIL: extractLogonSID failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: Logon SID extracted")

	fmt.Println("[Step 3] Creating Everyone SID...")
	everyoneSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		fmt.Printf("FAIL: CreateWellKnownSid failed: %v\n", err)
		os.Exit(1)
	}
	// NOTE: Do NOT call FreeSid on everyoneSID — CreateWellKnownSid returns Go-managed memory
	fmt.Println("PASS: Everyone SID created")

	fmt.Println("[Step 4] Creating restricted token...")
	const groupAttrs = windows.SE_GROUP_MANDATORY | windows.SE_GROUP_ENABLED_BY_DEFAULT | windows.SE_GROUP_ENABLED
	caps := []windows.SIDAndAttributes{
		{Sid: logonSID, Attributes: groupAttrs},
		{Sid: everyoneSID, Attributes: groupAttrs},
	}

	var restrictedToken windows.Token
	err = createRestrictedToken(
		baseToken,
		disableMaxPrivilege|luaToken|writeRestricted,
		0, nil,
		0, nil,
		uint32(len(caps)), &caps[0],
		&restrictedToken,
	)
	if err != nil {
		fmt.Printf("FAIL: createRestrictedToken failed: %v\n", err)
		os.Exit(1)
	}
	defer restrictedToken.Close()
	fmt.Println("PASS: Restricted token created")

	fmt.Println("[Step 5] Setting Low Integrity Level...")
	err = setLowIntegrityLevel(restrictedToken)
	if err != nil {
		fmt.Printf("FAIL: setLowIntegrityLevel failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: Low Integrity Level set")

	fmt.Println()
	fmt.Println("=== All Steps PASSED ===")
	fmt.Println("Token creation works correctly in standalone program!")
}

func extractLogonSID(token windows.Token) (*windows.SID, error) {
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenGroups, nil, 0, &size)
	if err != nil && err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("GetTokenInformation size query failed: %w", err)
	}

	buf := make([]byte, size)
	err = windows.GetTokenInformation(token, windows.TokenGroups, &buf[0], size, &size)
	if err != nil {
		return nil, fmt.Errorf("GetTokenInformation failed: %w", err)
	}

	groups := (*windows.Tokengroups)(unsafe.Pointer(&buf[0]))
	for _, group := range groups.AllGroups() {
		if group.Attributes&seGroupLogonID == seGroupLogonID {
			return group.Sid, nil
		}
	}

	return nil, fmt.Errorf("logon SID not found")
}

func createRestrictedToken(
	existingToken windows.Token,
	flags uint32,
	disableSidCount uint32,
	sidsToDisable *windows.SIDAndAttributes,
	deletePrivilegeCount uint32,
	privilegesToDelete *windows.LUIDAndAttributes,
	restrictedSidCount uint32,
	sidsToRestrict *windows.SIDAndAttributes,
	newToken *windows.Token,
) error {
	r1, _, e1 := procCreateRestrictedToken.Call(
		uintptr(existingToken),
		uintptr(flags),
		uintptr(disableSidCount),
		uintptr(unsafe.Pointer(sidsToDisable)),
		uintptr(deletePrivilegeCount),
		uintptr(unsafe.Pointer(privilegesToDelete)),
		uintptr(restrictedSidCount),
		uintptr(unsafe.Pointer(sidsToRestrict)),
		uintptr(unsafe.Pointer(newToken)),
	)
	if r1 == 0 {
		if e1 != nil {
			return fmt.Errorf("CreateRestrictedToken failed: %w", e1)
		}
		return fmt.Errorf("CreateRestrictedToken failed")
	}
	return nil
}

func setLowIntegrityLevel(token windows.Token) error {
	sid, err := windows.CreateWellKnownSid(windows.WinLowLabelSid)
	if err != nil {
		return fmt.Errorf("CreateWellKnownSid(WinLowLabelSid) failed: %w", err)
	}
	// NOTE: Do NOT call FreeSid on sid — CreateWellKnownSid returns Go-managed memory

	tml := windows.Tokenmandatorylabel{
		Label: windows.SIDAndAttributes{
			Sid:        sid,
			Attributes: windows.SE_GROUP_INTEGRITY,
		},
	}

	// CRITICAL: Use tml.Size() — not unsafe.Sizeof(tml) — because the latter returns
	// only the Go struct header size (16 bytes on amd64), while Windows requires
	// the full buffer including the variable-length SID data (28 bytes for Low IL).
	// Using Sizeof causes Windows to read past the allocation → heap corruption 0xc0000374.
	err = windows.SetTokenInformation(
		token,
		windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&tml)),
		tml.Size(),
	)
	if err != nil {
		return fmt.Errorf("SetTokenInformation(TokenIntegrityLevel) failed: %w", err)
	}

	return nil
}
