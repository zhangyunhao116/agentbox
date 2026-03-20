//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"github.com/zhangyunhao116/agentbox/platform"
	"golang.org/x/sys/windows"
)

// Constants for ACL manipulation.
const (
	// Security object types for GetNamedSecurityInfoW/SetNamedSecurityInfoW.
	seFileObject = 1

	// Security information flags.
	daclSecurityInformation = 0x00000004

	// EXPLICIT_ACCESS AccessMode values.
	grantAccess  = 1
	setAccess    = 2
	denyAccess   = 3
	revokeAccess = 4

	// ACE inheritance flags.
	objectInheritACE    = 0x1
	containerInheritACE = 0x2

	// File access rights.
	fileWriteData       = 0x0002
	fileAppendData      = 0x0004
	fileWriteEA         = 0x0010
	fileWriteAttributes = 0x0100
	delete              = 0x00010000
	writeDac            = 0x00040000
	writeOwner          = 0x00080000
	genericWrite        = 0x40000000

	// Combined file access masks.
	fileGenericRead    = 0x00120089
	fileGenericWrite   = 0x00120116
	fileGenericExecute = 0x001200A0

	// TRUSTEE form and type values.
	trusteeIsSid            = 0
	trusteeIsWellKnownGroup = 5
)

// explicitAccessW represents the EXPLICIT_ACCESS_W structure from Windows API.
// This structure defines access control information for a trustee (user/group).
type explicitAccessW struct {
	AccessPermissions uint32
	AccessMode        uint32 // grantAccess, denyAccess, etc.
	Inheritance       uint32
	Trustee           trusteeW
}

// trusteeW represents the TRUSTEE_W structure from Windows API.
// This structure identifies the user, group, or other security principal.
type trusteeW struct {
	MultipleTrustee          *trusteeW
	MultipleTrusteeOperation uint32
	TrusteeForm              uint32 // trusteeIsSid
	TrusteeType              uint32 // trusteeIsWellKnownGroup, etc.
	TrusteeValue             uintptr // Pointer to SID
}

// aclEntry tracks an ACL modification for cleanup purposes.
type aclEntry struct {
	path    string
	aclType int // 0=allow, 1=deny
}

// addAllowACE adds an allow ACE to the file/directory DACL for the specified SID.
// This grants full read/write/execute access to the specified principal.
func addAllowACE(path string, sid *windows.SID) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString(%s): %w", path, err)
	}

	var oldDACL windows.Handle
	var sd windows.Handle

	// Get current DACL from the file/directory.
	r1, _, e1 := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(seFileObject),
		uintptr(daclSecurityInformation),
		0, // ppsidOwner
		0, // ppsidGroup
		uintptr(unsafe.Pointer(&oldDACL)),
		0, // ppSacl
		uintptr(unsafe.Pointer(&sd)),
	)
	if r1 != 0 {
		if e1 != nil {
			return fmt.Errorf("GetNamedSecurityInfoW(%s): %w", path, e1)
		}
		return fmt.Errorf("GetNamedSecurityInfoW(%s): error code %d", path, r1)
	}
	defer windows.LocalFree(sd)

	// Build EXPLICIT_ACCESS structure for full access.
	ea := explicitAccessW{
		AccessPermissions: fileGenericRead | fileGenericWrite | fileGenericExecute,
		AccessMode:        grantAccess,
		Inheritance:       containerInheritACE | objectInheritACE,
		Trustee: trusteeW{
			TrusteeForm:  trusteeIsSid,
			TrusteeType:  trusteeIsWellKnownGroup,
			TrusteeValue: uintptr(unsafe.Pointer(sid)),
		},
	}

	var newDACL windows.Handle

	// Merge the new ACE into the DACL.
	r1, _, e1 = procSetEntriesInAclW.Call(
		1, // cCountOfExplicitEntries
		uintptr(unsafe.Pointer(&ea)),
		uintptr(oldDACL),
		uintptr(unsafe.Pointer(&newDACL)),
	)
	if r1 != 0 {
		if e1 != nil {
			return fmt.Errorf("SetEntriesInAclW(%s): %w", path, e1)
		}
		return fmt.Errorf("SetEntriesInAclW(%s): error code %d", path, r1)
	}
	defer windows.LocalFree(newDACL)

	// Apply the new DACL to the file/directory.
	r1, _, e1 = procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(seFileObject),
		uintptr(daclSecurityInformation),
		0, // psidOwner
		0, // psidGroup
		uintptr(newDACL),
		0, // pSacl
	)
	if r1 != 0 {
		if e1 != nil {
			return fmt.Errorf("SetNamedSecurityInfoW(%s): %w", path, e1)
		}
		return fmt.Errorf("SetNamedSecurityInfoW(%s): error code %d", path, r1)
	}

	return nil
}

// addDenyWriteACE adds a deny ACE to the file/directory DACL for the specified SID.
// This explicitly denies write access to prevent modifications.
func addDenyWriteACE(path string, sid *windows.SID) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString(%s): %w", path, err)
	}

	var oldDACL windows.Handle
	var sd windows.Handle

	// Get current DACL from the file/directory.
	r1, _, e1 := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(seFileObject),
		uintptr(daclSecurityInformation),
		0, // ppsidOwner
		0, // ppsidGroup
		uintptr(unsafe.Pointer(&oldDACL)),
		0, // ppSacl
		uintptr(unsafe.Pointer(&sd)),
	)
	if r1 != 0 {
		if e1 != nil {
			return fmt.Errorf("GetNamedSecurityInfoW(%s): %w", path, e1)
		}
		return fmt.Errorf("GetNamedSecurityInfoW(%s): error code %d", path, r1)
	}
	defer windows.LocalFree(sd)

	// Build EXPLICIT_ACCESS structure for deny-write.
	// Deny all write-related permissions including delete.
	denyMask := uint32(fileWriteData | fileAppendData | fileWriteEA | fileWriteAttributes | delete | genericWrite)
	ea := explicitAccessW{
		AccessPermissions: denyMask,
		AccessMode:        denyAccess,
		Inheritance:       containerInheritACE | objectInheritACE,
		Trustee: trusteeW{
			TrusteeForm:  trusteeIsSid,
			TrusteeType:  trusteeIsWellKnownGroup,
			TrusteeValue: uintptr(unsafe.Pointer(sid)),
		},
	}

	var newDACL windows.Handle

	// Merge the new ACE into the DACL.
	r1, _, e1 = procSetEntriesInAclW.Call(
		1, // cCountOfExplicitEntries
		uintptr(unsafe.Pointer(&ea)),
		uintptr(oldDACL),
		uintptr(unsafe.Pointer(&newDACL)),
	)
	if r1 != 0 {
		if e1 != nil {
			return fmt.Errorf("SetEntriesInAclW(%s): %w", path, e1)
		}
		return fmt.Errorf("SetEntriesInAclW(%s): error code %d", path, r1)
	}
	defer windows.LocalFree(newDACL)

	// Apply the new DACL to the file/directory.
	r1, _, e1 = procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(seFileObject),
		uintptr(daclSecurityInformation),
		0, // psidOwner
		0, // psidGroup
		uintptr(newDACL),
		0, // pSacl
	)
	if r1 != 0 {
		if e1 != nil {
			return fmt.Errorf("SetNamedSecurityInfoW(%s): %w", path, e1)
		}
		return fmt.Errorf("SetNamedSecurityInfoW(%s): error code %d", path, r1)
	}

	return nil
}

// revokeACE removes all ACEs for the specified SID from the file/directory DACL.
// This is used during cleanup to restore original permissions.
func revokeACE(path string, sid *windows.SID) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString(%s): %w", path, err)
	}

	var oldDACL windows.Handle
	var sd windows.Handle

	// Get current DACL from the file/directory.
	r1, _, e1 := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(seFileObject),
		uintptr(daclSecurityInformation),
		0, // ppsidOwner
		0, // ppsidGroup
		uintptr(unsafe.Pointer(&oldDACL)),
		0, // ppSacl
		uintptr(unsafe.Pointer(&sd)),
	)
	if r1 != 0 {
		if e1 != nil {
			return fmt.Errorf("GetNamedSecurityInfoW(%s): %w", path, e1)
		}
		return fmt.Errorf("GetNamedSecurityInfoW(%s): error code %d", path, r1)
	}
	defer windows.LocalFree(sd)

	// Build EXPLICIT_ACCESS structure for revoke.
	ea := explicitAccessW{
		AccessPermissions: 0, // ignored for REVOKE_ACCESS
		AccessMode:        revokeAccess,
		Inheritance:       0, // ignored for REVOKE_ACCESS
		Trustee: trusteeW{
			TrusteeForm:  trusteeIsSid,
			TrusteeType:  trusteeIsWellKnownGroup,
			TrusteeValue: uintptr(unsafe.Pointer(sid)),
		},
	}

	var newDACL windows.Handle

	// Remove the ACE from the DACL.
	r1, _, e1 = procSetEntriesInAclW.Call(
		1, // cCountOfExplicitEntries
		uintptr(unsafe.Pointer(&ea)),
		uintptr(oldDACL),
		uintptr(unsafe.Pointer(&newDACL)),
	)
	if r1 != 0 {
		if e1 != nil {
			return fmt.Errorf("SetEntriesInAclW(%s): %w", path, e1)
		}
		return fmt.Errorf("SetEntriesInAclW(%s): error code %d", path, r1)
	}
	defer windows.LocalFree(newDACL)

	// Apply the new DACL to the file/directory.
	r1, _, e1 = procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(seFileObject),
		uintptr(daclSecurityInformation),
		0, // psidOwner
		0, // psidGroup
		uintptr(newDACL),
		0, // pSacl
	)
	if r1 != 0 {
		if e1 != nil {
			return fmt.Errorf("SetNamedSecurityInfoW(%s): %w", path, e1)
		}
		return fmt.Errorf("SetNamedSecurityInfoW(%s): error code %d", path, r1)
	}

	return nil
}

// isValidWindowsPath returns true if the path looks like a valid Windows path.
// This filters out Unix paths (starting with /) that may leak from DefaultConfig
// on misconfigured systems or build-tag issues.
//
// Valid Windows paths include:
// - Absolute paths with drive letters (e.g., C:\Windows)
// - UNC paths (e.g., \\server\share)
// - Relative paths (not starting with /)
//
// Unix paths like /etc, /usr, /proc are rejected.
func isValidWindowsPath(path string) bool {
	if path == "" {
		return false
	}
	// Accept absolute Windows paths with drive letter (e.g., C:\)
	if len(path) >= 2 && path[1] == ':' {
		return true
	}
	// Accept UNC paths (e.g., \\server\share)
	if len(path) >= 2 && path[0] == '\\' && path[1] == '\\' {
		return true
	}
	// Reject Unix absolute paths (starting with /)
	if path[0] == '/' {
		return false
	}
	// Accept relative paths (anything else)
	return true
}

// applyACLs applies filesystem access controls based on the WrapConfig.
// It grants access to WritableRoots and denies write access to DenyWrite paths.
// Returns a slice of applied entries for later cleanup.
//
// Invalid paths (Unix-style paths like /etc on Windows) are silently skipped
// to prevent ACL setup failures when using cross-platform default configurations.
func applyACLs(cfg *platform.WrapConfig, sid *windows.SID) ([]aclEntry, error) {
	var applied []aclEntry

	// Grant full access to writable roots.
	for _, path := range cfg.WritableRoots {
		// Skip invalid Windows paths (e.g., Unix paths from misconfiguration).
		if !isValidWindowsPath(path) {
			continue
		}
		if err := addAllowACE(path, sid); err != nil {
			// Best effort cleanup on failure.
			_ = cleanupACLs(applied, sid)
			return nil, fmt.Errorf("failed to grant access to %s: %w", path, err)
		}
		applied = append(applied, aclEntry{path: path, aclType: 0})
	}

	// Deny write access to specified paths.
	for _, path := range cfg.DenyWrite {
		// Skip invalid Windows paths (e.g., Unix paths from misconfiguration).
		if !isValidWindowsPath(path) {
			continue
		}
		if err := addDenyWriteACE(path, sid); err != nil {
			// Best effort cleanup on failure.
			_ = cleanupACLs(applied, sid)
			return nil, fmt.Errorf("failed to deny write to %s: %w", path, err)
		}
		applied = append(applied, aclEntry{path: path, aclType: 1})
	}

	return applied, nil
}

// cleanupACLs removes all ACL entries that were applied by applyACLs.
// This restores the original permissions for the modified paths.
func cleanupACLs(applied []aclEntry, sid *windows.SID) error {
	var errs []error

	for _, entry := range applied {
		if err := revokeACE(entry.path, sid); err != nil {
			errs = append(errs, fmt.Errorf("revoke %s: %w", entry.path, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("ACL cleanup failed for %d/%d paths: %v", len(errs), len(applied), errs)
	}

	return nil
}
