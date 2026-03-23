//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32                   = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken     = modadvapi32.NewProc("CreateRestrictedToken")
	procGetNamedSecurityInfoW     = modadvapi32.NewProc("GetNamedSecurityInfoW")
	procSetNamedSecurityInfoW     = modadvapi32.NewProc("SetNamedSecurityInfoW")
	procSetEntriesInAclW          = modadvapi32.NewProc("SetEntriesInAclW")
	procCreateProcessWithLogonW   = modadvapi32.NewProc("CreateProcessWithLogonW")

	modkernel32   = windows.NewLazySystemDLL("kernel32.dll")
	procLocalFree = modkernel32.NewProc("LocalFree")

	modnetapi32                      = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd                   = modnetapi32.NewProc("NetUserAdd")
	procNetUserDel                   = modnetapi32.NewProc("NetUserDel")
	procNetLocalGroupAdd             = modnetapi32.NewProc("NetLocalGroupAdd")
	procNetLocalGroupAddMembers      = modnetapi32.NewProc("NetLocalGroupAddMembers")
	procNetLocalGroupDel             = modnetapi32.NewProc("NetLocalGroupDel")

	modcrypt32               = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData     = modcrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData   = modcrypt32.NewProc("CryptUnprotectData")
)

// CreateRestrictedToken flags for restricting token privileges and access.
const (
	// disableMaxPrivilege removes all privileges except SeChangeNotifyPrivilege.
	disableMaxPrivilege = 0x1
	// sandboxInert makes the token inert for sandboxing purposes.
	sandboxInert = 0x2
	// luaToken creates a Limited User Account token.
	luaToken = 0x4
	// writeRestricted restricts the token for write access only.
	writeRestricted = 0x8
)

// NetAPI error codes
const (
	nerrSuccess       = 0
	nerrGroupNotFound = 2220
	nerrGroupExists   = 2223
	nerrUserNotFound  = 2221
	nerrUserExists    = 2224
)

// Win32 error codes for local group operations.
// NetLocalGroupAdd returns ERROR_ALIAS_EXISTS (1379) when the group already exists,
// not NERR_GroupExists (2223). Windows local groups are internally called "aliases".
const (
	errorAliasExists = 1379
)

// netAPIError represents an error from a Windows NetAPI32 function.
// It carries the numeric error code so callers can check specific conditions
// without fragile string matching.
type netAPIError struct {
	Code uint32
	API  string
}

func (e *netAPIError) Error() string {
	return fmt.Sprintf("%s failed with code %d", e.API, e.Code)
}

// User flags for NetUserAdd
const (
	ufScript            = 0x0001
	ufDontExpirePasswd  = 0x10000
)

// User privilege levels
const (
	userPrivUser = 1
)

// DPAPI flags for CryptProtectData/CryptUnprotectData
const (
	cryptprotectUIForbidden    = 0x1
	cryptprotectLocalMachine   = 0x4
)

// CreateProcessWithLogonW flags
const (
	logonWithProfile = 0x00000001
)

// dataBlob is the DATA_BLOB structure used by DPAPI functions.
type dataBlob struct {
	Size uint32
	Data *byte
}

// createRestrictedToken creates a restricted access token from an existing token.
// It wraps the CreateRestrictedToken Windows API from advapi32.dll.
//
// Parameters:
//   - existingToken: Handle to an existing access token
//   - flags: Combination of restriction flags (disableMaxPrivilege, sandboxInert, luaToken, writeRestricted)
//   - disableSidCount: Number of SIDs to disable (can be 0)
//   - sidsToDisable: Array of SIDs to disable (can be nil if count is 0)
//   - deletePrivilegeCount: Number of privileges to delete (can be 0)
//   - privilegesToDelete: Array of privileges to delete (can be nil if count is 0)
//   - restrictedSidCount: Number of restricting SIDs (can be 0)
//   - sidsToRestrict: Array of restricting SIDs (can be nil if count is 0)
//   - newToken: Receives the handle to the new restricted token
//
// Returns an error if the token creation fails.
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

// setLowIntegrityLevel sets a token to Low Integrity Level (S-1-16-4096).
// This prevents the process from writing to Medium or higher integrity level objects.
//
// Low Integrity Level is commonly used for sandboxed processes to restrict their
// ability to modify user data and system objects.
//
// Parameters:
//   - token: Handle to the token to modify
//
// Returns an error if the operation fails.
func setLowIntegrityLevel(token windows.Token) error {
	// Low Integrity SID: S-1-16-4096
	// NOTE: CreateWellKnownSid returns a Go-managed SID (backed by make([]byte, n)),
	// so we must NOT call FreeSid on it — FreeSid is only for Windows-API-allocated SIDs
	// (e.g., from AllocateAndInitializeSid). Calling FreeSid on Go-managed memory
	// corrupts the Windows heap → STATUS_HEAP_CORRUPTION (0xC0000374).
	sid, err := windows.CreateWellKnownSid(windows.WinLowLabelSid)
	if err != nil {
		return fmt.Errorf("CreateWellKnownSid(WinLowLabelSid) failed: %w", err)
	}

	// Build TOKEN_MANDATORY_LABEL structure
	tml := windows.Tokenmandatorylabel{
		Label: windows.SIDAndAttributes{
			Sid:        sid,
			Attributes: windows.SE_GROUP_INTEGRITY,
		},
	}

	// Set the token integrity level.
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

// netUserAdd creates a new local user account.
// It wraps the NetUserAdd Windows API from netapi32.dll.
//
// Parameters:
//   - serverName: Name of the remote server, or nil for local
//   - level: Information level (1 for USER_INFO_1)
//   - buf: Pointer to USER_INFO_1 structure
//   - parmErr: Receives the index of the first parameter that causes an error
//
// Returns an error if the operation fails. NERR_UserExists (2224) is returned
// if the user already exists.
func netUserAdd(serverName *uint16, level uint32, buf *byte, parmErr *uint32) error {
	r1, _, _ := procNetUserAdd.Call(
		uintptr(unsafe.Pointer(serverName)),
		uintptr(level),
		uintptr(unsafe.Pointer(buf)),
		uintptr(unsafe.Pointer(parmErr)),
	)
	if r1 != nerrSuccess {
		return fmt.Errorf("NetUserAdd failed with code %d", r1)
	}
	return nil
}

// netUserDel deletes a local user account.
// It wraps the NetUserDel Windows API from netapi32.dll.
//
// Parameters:
//   - serverName: Name of the remote server, or nil for local
//   - username: Name of the user account to delete
//
// Returns an error if the operation fails.
func netUserDel(serverName *uint16, username *uint16) error {
	r1, _, _ := procNetUserDel.Call(
		uintptr(unsafe.Pointer(serverName)),
		uintptr(unsafe.Pointer(username)),
	)
	if r1 != nerrSuccess {
		return &netAPIError{Code: uint32(r1), API: "NetUserDel"}
	}
	return nil
}

// netLocalGroupAdd creates a new local group.
// It wraps the NetLocalGroupAdd Windows API from netapi32.dll.
//
// Parameters:
//   - serverName: Name of the remote server, or nil for local
//   - level: Information level (1 for LOCALGROUP_INFO_1)
//   - buf: Pointer to LOCALGROUP_INFO_1 structure
//   - parmErr: Receives the index of the first parameter that causes an error
//
// Returns an error if the operation fails. ERROR_ALIAS_EXISTS (1379) is returned
// if the local group already exists (Windows local groups are internally "aliases").
func netLocalGroupAdd(serverName *uint16, level uint32, buf *byte, parmErr *uint32) error {
	r1, _, _ := procNetLocalGroupAdd.Call(
		uintptr(unsafe.Pointer(serverName)),
		uintptr(level),
		uintptr(unsafe.Pointer(buf)),
		uintptr(unsafe.Pointer(parmErr)),
	)
	if r1 != nerrSuccess {
		return &netAPIError{Code: uint32(r1), API: "NetLocalGroupAdd"}
	}
	return nil
}

// netLocalGroupAddMembers adds members to a local group.
// It wraps the NetLocalGroupAddMembers Windows API from netapi32.dll.
//
// Parameters:
//   - serverName: Name of the remote server, or nil for local
//   - groupName: Name of the local group
//   - level: Information level (3 for LOCALGROUP_MEMBERS_INFO_3)
//   - buf: Pointer to array of LOCALGROUP_MEMBERS_INFO_3 structures
//   - totalEntries: Number of entries in the buffer
//
// Returns an error if the operation fails.
func netLocalGroupAddMembers(serverName *uint16, groupName *uint16, level uint32, buf *byte, totalEntries uint32) error {
	r1, _, _ := procNetLocalGroupAddMembers.Call(
		uintptr(unsafe.Pointer(serverName)),
		uintptr(unsafe.Pointer(groupName)),
		uintptr(level),
		uintptr(unsafe.Pointer(buf)),
		uintptr(totalEntries),
	)
	if r1 != nerrSuccess {
		return fmt.Errorf("NetLocalGroupAddMembers failed with code %d", r1)
	}
	return nil
}

// netLocalGroupDel deletes a local group.
// It wraps the NetLocalGroupDel Windows API from netapi32.dll.
//
// Parameters:
//   - serverName: Name of the remote server, or nil for local
//   - groupName: Name of the local group to delete
//
// Returns an error if the operation fails.
func netLocalGroupDel(serverName *uint16, groupName *uint16) error {
	r1, _, _ := procNetLocalGroupDel.Call(
		uintptr(unsafe.Pointer(serverName)),
		uintptr(unsafe.Pointer(groupName)),
	)
	if r1 != nerrSuccess {
		return &netAPIError{Code: uint32(r1), API: "NetLocalGroupDel"}
	}
	return nil
}

// cryptProtectData encrypts data using DPAPI (Data Protection API).
// It wraps the CryptProtectData Windows API from crypt32.dll.
//
// Parameters:
//   - dataIn: Input data to encrypt
//   - description: Optional description string
//   - optionalEntropy: Optional entropy for additional security
//   - reserved: Must be 0
//   - promptStruct: Must be 0 (no UI prompt)
//   - flags: Protection flags (e.g., CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE)
//   - dataOut: Receives the encrypted data
//
// Returns an error if the operation fails.
func cryptProtectData(dataIn *dataBlob, description *uint16, optionalEntropy *dataBlob, reserved uintptr, promptStruct uintptr, flags uint32, dataOut *dataBlob) error {
	r1, _, e1 := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(dataIn)),
		uintptr(unsafe.Pointer(description)),
		uintptr(unsafe.Pointer(optionalEntropy)),
		reserved,
		promptStruct,
		uintptr(flags),
		uintptr(unsafe.Pointer(dataOut)),
	)
	if r1 == 0 {
		if e1 != nil {
			return fmt.Errorf("CryptProtectData failed: %w", e1)
		}
		return fmt.Errorf("CryptProtectData failed")
	}
	return nil
}

// cryptUnprotectData decrypts data using DPAPI (Data Protection API).
// It wraps the CryptUnprotectData Windows API from crypt32.dll.
//
// Parameters:
//   - dataIn: Encrypted data to decrypt
//   - description: Receives the description string (can be nil)
//   - optionalEntropy: Optional entropy (must match the one used for encryption)
//   - reserved: Must be 0
//   - promptStruct: Must be 0 (no UI prompt)
//   - flags: Protection flags (e.g., CRYPTPROTECT_UI_FORBIDDEN)
//   - dataOut: Receives the decrypted data
//
// Returns an error if the operation fails.
func cryptUnprotectData(dataIn *dataBlob, description **uint16, optionalEntropy *dataBlob, reserved uintptr, promptStruct uintptr, flags uint32, dataOut *dataBlob) error {
	r1, _, e1 := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(dataIn)),
		uintptr(unsafe.Pointer(description)),
		uintptr(unsafe.Pointer(optionalEntropy)),
		reserved,
		promptStruct,
		uintptr(flags),
		uintptr(unsafe.Pointer(dataOut)),
	)
	if r1 == 0 {
		if e1 != nil {
			return fmt.Errorf("CryptUnprotectData failed: %w", e1)
		}
		return fmt.Errorf("CryptUnprotectData failed")
	}
	return nil
}

// localFree frees memory allocated by Windows API functions.
// It wraps the LocalFree Windows API from kernel32.dll.
//
// Parameters:
//   - hMem: Handle to the memory to free
//
// Returns the handle if the function fails, or 0 if successful.
func localFree(hMem uintptr) uintptr {
	r1, _, _ := procLocalFree.Call(hMem)
	return r1
}

// createProcessWithLogonW creates a new process and logs on a specified user.
// It wraps the CreateProcessWithLogonW Windows API from advapi32.dll.
//
// This function allows creating a process under a different user account without
// requiring SeAssignPrimaryTokenPrivilege. It's commonly used for running processes
// with different credentials.
//
// Parameters:
//   - username: Username to log on
//   - domain: Domain name, or "." for local account
//   - password: User's password
//   - logonFlags: Logon options (e.g., LOGON_WITH_PROFILE)
//   - appName: Application name (can be nil if cmdLine specifies the executable)
//   - cmdLine: Command line string
//   - creationFlags: Process creation flags
//   - env: Environment block (nil to inherit)
//   - cwd: Current working directory (nil to inherit)
//   - si: Startup information
//   - pi: Receives process information
//
// Returns an error if the operation fails.
func createProcessWithLogonW(username *uint16, domain *uint16, password *uint16, logonFlags uint32, appName *uint16, cmdLine *uint16, creationFlags uint32, env *uint16, cwd *uint16, si *windows.StartupInfo, pi *windows.ProcessInformation) error {
	r1, _, e1 := procCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(username)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		uintptr(logonFlags),
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(cmdLine)),
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(env)),
		uintptr(unsafe.Pointer(cwd)),
		uintptr(unsafe.Pointer(si)),
		uintptr(unsafe.Pointer(pi)),
	)
	if r1 == 0 {
		if e1 != nil {
			return fmt.Errorf("CreateProcessWithLogonW failed: %w", e1)
		}
		return fmt.Errorf("CreateProcessWithLogonW failed")
	}
	return nil
}
