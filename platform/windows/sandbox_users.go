//go:build windows

// Package windows provides Windows-specific sandbox implementations.
//
// This file implements Tier 2 admin features for Windows sandboxing using
// dedicated local user accounts. Instead of running sandboxed processes under
// the caller's restricted token, we create separate local users and launch
// processes via CreateProcessWithLogonW. This provides stronger isolation:
//   - Separate user profile (no access to caller's files by default)
//   - Dedicated SID for firewall rules and ACL checks
//   - No SeAssignPrimaryTokenPrivilege required (unlike CreateProcessAsUser)
//
// Architecture:
//   - Local group: "AgentboxSandboxUsers" contains all sandbox accounts
//   - Random usernames: "agentbox_sb_<8 hex chars>"
//   - Random passwords: 24+ characters, cryptographically secure
//   - Password storage: DPAPI with CRYPTPROTECT_LOCAL_MACHINE (any admin can decrypt)
//   - Process creation: CreateProcessWithLogonW with LOGON_WITH_PROFILE
//
// This approach mirrors OpenAI Codex's sandbox_users.rs pattern.
//
// Requirements:
//   - Administrator privileges for Setup/Teardown operations
//   - Windows 7+ (netapi32.dll, crypt32.dll, advapi32.dll)
//
// Security properties:
//   - Dedicated user profile isolation (stronger than Restricted Token alone)
//   - Compatible with firewall rules scoped to user SID
//   - Supports ACL-based filesystem access control per user
//
// Trade-offs:
//   - Requires admin setup (one-time group/user creation)
//   - Runtime CreateProcessWithLogonW requires knowing the password (stored via DPAPI)
//   - More complex lifecycle management vs. inline token restriction
//
package windows

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// sandboxGroupName is the name of the local group for sandbox users.
	sandboxGroupName = "AgentboxSandboxUsers"

	// sandboxUserPrefix is the prefix for generated sandbox usernames.
	sandboxUserPrefix = "agentbox_sb_"

	// passwordLength is the length of generated passwords (minimum 24 characters).
	passwordLength = 24

	// usernameRandomLength is the number of random hex characters in the username.
	usernameRandomLength = 8
)

// SandboxUser represents a Windows local user account for sandboxing.
type SandboxUser struct {
	// Username is the Windows username (e.g., "agentbox_sb_a1b2c3d4").
	Username string

	// Password is the plaintext password (stored in-memory only).
	Password string

	// SID is the Security Identifier string (e.g., "S-1-5-21-...").
	SID string
}

// SandboxUserManager manages the lifecycle of sandbox users.
// It creates a dedicated local group and user accounts for isolated process execution.
//
// This manager is used for Tier 2 admin features where processes run under
// separate user accounts via CreateProcessWithLogonW instead of using the
// caller's restricted token.
type SandboxUserManager struct {
	mu           sync.Mutex
	users        []*SandboxUser
	groupCreated bool
}

// userInfo1 represents the USER_INFO_1 structure for NetUserAdd.
// Layout must match the Windows API structure exactly.
type userInfo1 struct {
	Name         *uint16
	Password     *uint16
	PasswordAge  uint32
	Priv         uint32
	HomeDir      *uint16
	Comment      *uint16
	Flags        uint32
	ScriptPath   *uint16
}

// localGroupInfo1 represents the LOCALGROUP_INFO_1 structure.
// Layout must match the Windows API structure exactly.
type localGroupInfo1 struct {
	Name    *uint16
	Comment *uint16
}

// localGroupMembersInfo3 represents the LOCALGROUP_MEMBERS_INFO_3 structure.
// Layout must match the Windows API structure exactly.
type localGroupMembersInfo3 struct {
	DomainAndName *uint16
}

// Setup initializes the sandbox user environment.
// It creates the sandbox group and one sandbox user.
//
// This method requires administrator privileges.
//
// Returns an error if group or user creation fails.
func (m *SandboxUserManager) Setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create the sandbox group
	if err := m.createSandboxGroupLocked(); err != nil {
		return fmt.Errorf("failed to create sandbox group: %w", err)
	}

	// Create one sandbox user
	user, err := m.createSandboxUserLocked()
	if err != nil {
		return fmt.Errorf("failed to create sandbox user: %w", err)
	}

	m.users = append(m.users, user)
	return nil
}

// GetUser returns an available sandbox user.
// Currently returns the first (and only) user.
//
// Returns an error if no users are available.
func (m *SandboxUserManager) GetUser() (*SandboxUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.users) == 0 {
		return nil, fmt.Errorf("no sandbox users available")
	}

	return m.users[0], nil
}

// Teardown cleans up all sandbox users and the sandbox group.
// This is a best-effort operation that continues even if individual
// deletions fail.
//
// This method requires administrator privileges.
//
// Returns an error if critical cleanup operations fail, but attempts
// all cleanup operations regardless.
func (m *SandboxUserManager) Teardown() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error

	// Delete all users
	for _, user := range m.users {
		if err := deleteSandboxUserLocked(user.Username); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete user %s: %w", user.Username, err))
		}
	}
	m.users = nil

	// Delete the group
	if m.groupCreated {
		if err := deleteSandboxGroupLocked(); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete sandbox group: %w", err))
		}
		m.groupCreated = false
	}

	if len(errs) > 0 {
		return fmt.Errorf("teardown encountered %d error(s): %v", len(errs), errs)
	}

	return nil
}

// createSandboxGroupLocked creates the local sandbox group.
// Caller must hold m.mu.
func (m *SandboxUserManager) createSandboxGroupLocked() error {
	if err := createSandboxGroup(); err != nil {
		return err
	}
	m.groupCreated = true
	return nil
}

// createSandboxUserLocked creates a new sandbox user and adds it to the group.
// Caller must hold m.mu.
func (m *SandboxUserManager) createSandboxUserLocked() (*SandboxUser, error) {
	return createSandboxUser()
}

// createSandboxGroup creates the local group for sandbox users.
// It ignores NERR_GroupExists (2223) if the group already exists.
//
// Returns an error if group creation fails for reasons other than
// the group already existing.
func createSandboxGroup() error {
	groupNamePtr, err := windows.UTF16PtrFromString(sandboxGroupName)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString failed: %w", err)
	}

	commentPtr, err := windows.UTF16PtrFromString("Agentbox sandbox user accounts")
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString failed: %w", err)
	}

	info := localGroupInfo1{
		Name:    groupNamePtr,
		Comment: commentPtr,
	}

	var parmErr uint32
	err = netLocalGroupAdd(nil, 1, (*byte)(unsafe.Pointer(&info)), &parmErr)
	if err != nil {
		// Ignore "group already exists" errors.
		// NetLocalGroupAdd returns ERROR_ALIAS_EXISTS (1379) for local groups,
		// not NERR_GroupExists (2223), because local groups are "aliases" internally.
		var netErr *netAPIError
		if errors.As(err, &netErr) && (netErr.Code == errorAliasExists || netErr.Code == nerrGroupExists) {
			return nil
		}
		return fmt.Errorf("NetLocalGroupAdd failed: %w", err)
	}

	return nil
}

// deleteSandboxGroupLocked deletes the sandbox group.
func deleteSandboxGroupLocked() error {
	groupNamePtr, err := windows.UTF16PtrFromString(sandboxGroupName)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString failed: %w", err)
	}

	err = netLocalGroupDel(nil, groupNamePtr)
	if err != nil {
		// Ignore "group not found" errors — the group not existing is the
		// desired end state for deletion.
		var netErr *netAPIError
		if errors.As(err, &netErr) && netErr.Code == nerrGroupNotFound {
			return nil
		}
		return fmt.Errorf("NetLocalGroupDel failed: %w", err)
	}

	return nil
}

// createSandboxUser creates a new local sandbox user with a random username and password.
// It adds the user to the sandbox group and resolves the user's SID.
//
// The username format is: agentbox_sb_<8 random hex chars>
// The password is 24 random characters (letters, digits, special chars).
//
// Returns the created SandboxUser or an error if creation fails.
func createSandboxUser() (*SandboxUser, error) {
	// Generate random username
	username, err := generateUsername()
	if err != nil {
		return nil, fmt.Errorf("failed to generate username: %w", err)
	}

	// Generate random password
	password, err := generatePassword(passwordLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate password: %w", err)
	}

	// Create the user account
	usernamePtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return nil, fmt.Errorf("UTF16PtrFromString failed: %w", err)
	}

	passwordPtr, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return nil, fmt.Errorf("UTF16PtrFromString failed: %w", err)
	}

	commentPtr, err := windows.UTF16PtrFromString("Agentbox sandbox user")
	if err != nil {
		return nil, fmt.Errorf("UTF16PtrFromString failed: %w", err)
	}

	info := userInfo1{
		Name:     usernamePtr,
		Password: passwordPtr,
		Priv:     userPrivUser,
		Flags:    ufScript | ufDontExpirePasswd,
		Comment:  commentPtr,
	}

	var parmErr uint32
	err = netUserAdd(nil, 1, (*byte)(unsafe.Pointer(&info)), &parmErr)
	if err != nil {
		return nil, fmt.Errorf("NetUserAdd failed: %w", err)
	}

	// Add user to sandbox group
	groupNamePtr, err := windows.UTF16PtrFromString(sandboxGroupName)
	if err != nil {
		return nil, fmt.Errorf("UTF16PtrFromString failed: %w", err)
	}

	memberInfo := localGroupMembersInfo3{
		DomainAndName: usernamePtr,
	}

	err = netLocalGroupAddMembers(nil, groupNamePtr, 3, (*byte)(unsafe.Pointer(&memberInfo)), 1)
	if err != nil {
		// Try to clean up the user if group membership fails
		_ = deleteSandboxUserLocked(username)
		return nil, fmt.Errorf("NetLocalGroupAddMembers failed: %w", err)
	}

	// Resolve SID
	sid, err := resolveSID(username)
	if err != nil {
		// Try to clean up the user if SID resolution fails
		_ = deleteSandboxUserLocked(username)
		return nil, fmt.Errorf("failed to resolve SID: %w", err)
	}

	return &SandboxUser{
		Username: username,
		Password: password,
		SID:      sid,
	}, nil
}

// deleteSandboxUserLocked deletes a sandbox user account.
func deleteSandboxUserLocked(username string) error {
	usernamePtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString failed: %w", err)
	}

	err = netUserDel(nil, usernamePtr)
	if err != nil {
		// Ignore "user not found" errors — the user not existing is the
		// desired end state for deletion.
		var netErr *netAPIError
		if errors.As(err, &netErr) && netErr.Code == nerrUserNotFound {
			return nil
		}
		return fmt.Errorf("NetUserDel failed: %w", err)
	}

	return nil
}

// generateUsername generates a random username with the format:
// agentbox_sb_<8 random hex chars>
func generateUsername() (string, error) {
	randomBytes := make([]byte, usernameRandomLength/2)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("rand.Read failed: %w", err)
	}

	return sandboxUserPrefix + hex.EncodeToString(randomBytes), nil
}

// generatePassword generates a cryptographically random password.
// The password contains a mix of uppercase letters, lowercase letters,
// digits, and special characters to meet Windows complexity requirements.
//
// Length must be at least 24 characters.
func generatePassword(length int) (string, error) {
	if length < 24 {
		return "", fmt.Errorf("password length must be at least 24 characters")
	}

	// Character sets for password diversity
	const (
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		special   = "!@#$%^&*()-_=+[]{}|;:,.<>?"
		allChars  = lowercase + uppercase + digits + special
	)

	password := make([]byte, length)
	randomBytes := make([]byte, length)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("rand.Read failed: %w", err)
	}

	// Use rejection sampling to eliminate modulo bias.
	// maxValid is the largest multiple of len(allChars) that fits in a byte.
	maxValid := byte(256 - (256 % len(allChars)))
	for i := 0; i < length; i++ {
		for randomBytes[i] >= maxValid {
			// Re-sample this byte
			if _, err := rand.Read(randomBytes[i : i+1]); err != nil {
				return "", fmt.Errorf("crypto/rand.Read failed: %w", err)
			}
		}
		password[i] = allChars[int(randomBytes[i])%len(allChars)]
	}

	return string(password), nil
}

// resolveSID resolves a username to its SID string.
func resolveSID(username string) (string, error) {
	sid, _, _, err := windows.LookupSID("", username)
	if err != nil {
		return "", fmt.Errorf("LookupSID failed: %w", err)
	}

	sidStr := sid.String()
	return sidStr, nil
}

// encryptPassword encrypts a password using DPAPI (Data Protection API).
// The encrypted data can be decrypted by any administrator on the same machine.
//
// This uses CRYPTPROTECT_LOCAL_MACHINE flag to allow any admin to decrypt,
// and CRYPTPROTECT_UI_FORBIDDEN to prevent UI prompts.
//
// Returns the encrypted password bytes or an error.
func encryptPassword(password string) ([]byte, error) {
	passwordBytes := []byte(password)

	dataIn := dataBlob{
		Size: uint32(len(passwordBytes)),
		Data: &passwordBytes[0],
	}

	var dataOut dataBlob
	flags := uint32(cryptprotectUIForbidden | cryptprotectLocalMachine)

	err := cryptProtectData(&dataIn, nil, nil, 0, 0, flags, &dataOut)
	if err != nil {
		// Defensive cleanup: Windows may allocate memory before failing
		if dataOut.Data != nil {
			localFree(uintptr(unsafe.Pointer(dataOut.Data)))
		}
		return nil, fmt.Errorf("CryptProtectData failed: %w", err)
	}

	// Copy the encrypted data before freeing
	encryptedData := make([]byte, dataOut.Size)
	src := unsafe.Slice(dataOut.Data, dataOut.Size)
	copy(encryptedData, src)

	// Free the memory allocated by CryptProtectData
	localFree(uintptr(unsafe.Pointer(dataOut.Data)))

	return encryptedData, nil
}

// decryptPassword decrypts a password using DPAPI (Data Protection API).
// The encrypted data must have been created with CRYPTPROTECT_LOCAL_MACHINE flag.
//
// decryptPassword uses only CRYPTPROTECT_UI_FORBIDDEN (not CRYPTPROTECT_LOCAL_MACHINE)
// because the LOCAL_MACHINE flag is a storage directive for encryption, not needed for decryption.
// Windows determines the decryption scope from the encrypted data blob itself.
//
// Returns the decrypted password string or an error.
func decryptPassword(encrypted []byte) (string, error) {
	if len(encrypted) == 0 {
		return "", fmt.Errorf("encrypted data is empty")
	}

	dataIn := dataBlob{
		Size: uint32(len(encrypted)),
		Data: &encrypted[0],
	}

	var dataOut dataBlob
	flags := uint32(cryptprotectUIForbidden)

	err := cryptUnprotectData(&dataIn, nil, nil, 0, 0, flags, &dataOut)
	if err != nil {
		// Defensive cleanup: Windows may allocate memory before failing
		if dataOut.Data != nil {
			localFree(uintptr(unsafe.Pointer(dataOut.Data)))
		}
		return "", fmt.Errorf("CryptUnprotectData failed: %w", err)
	}

	// Copy the decrypted data before freeing
	decryptedData := make([]byte, dataOut.Size)
	src := unsafe.Slice(dataOut.Data, dataOut.Size)
	copy(decryptedData, src)

	// Free the memory allocated by CryptUnprotectData
	localFree(uintptr(unsafe.Pointer(dataOut.Data)))

	return string(decryptedData), nil
}
