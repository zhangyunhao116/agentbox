//go:build windows

package windows

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// isAdmin checks if the current process is running with administrator privileges.
func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}

	return member
}

func TestGenerateUsername(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	username, err := generateUsername()
	if err != nil {
		t.Fatalf("generateUsername failed: %v", err)
	}

	// Check prefix
	if !strings.HasPrefix(username, sandboxUserPrefix) {
		t.Errorf("username %q does not have prefix %q", username, sandboxUserPrefix)
	}

	// Check length (prefix + 8 hex chars)
	expectedLen := len(sandboxUserPrefix) + usernameRandomLength
	if len(username) != expectedLen {
		t.Errorf("username length = %d, want %d", len(username), expectedLen)
	}

	// Check uniqueness - generate multiple usernames
	usernames := make(map[string]struct{})
	for i := 0; i < 10; i++ {
		u, err := generateUsername()
		if err != nil {
			t.Fatalf("generateUsername failed on iteration %d: %v", i, err)
		}
		if _, ok := usernames[u]; ok {
			t.Errorf("duplicate username generated: %q", u)
		}
		usernames[u] = struct{}{}
	}
}

func TestGeneratePassword(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tests := []struct {
		name      string
		length    int
		wantError bool
	}{
		{"valid minimum", 24, false},
		{"valid longer", 32, false},
		{"too short", 20, true},
		{"too short minimum", 23, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := generatePassword(tt.length)

			if tt.wantError {
				if err == nil {
					t.Errorf("generatePassword(%d) succeeded, want error", tt.length)
				}
				return
			}

			if err != nil {
				t.Fatalf("generatePassword(%d) failed: %v", tt.length, err)
			}

			if len(password) != tt.length {
				t.Errorf("password length = %d, want %d", len(password), tt.length)
			}

			// Check character diversity
			hasLower := false
			hasUpper := false
			hasDigit := false

			for _, ch := range password {
				switch {
				case ch >= 'a' && ch <= 'z':
					hasLower = true
				case ch >= 'A' && ch <= 'Z':
					hasUpper = true
				case ch >= '0' && ch <= '9':
					hasDigit = true
				}
			}

			// With 24+ random characters, we should have diversity
			// (statistical test - may rarely fail but extremely unlikely)
			if !hasLower && !hasUpper && !hasDigit {
				t.Errorf("password lacks character diversity: %q", password)
			}
		})
	}
}

func TestGeneratePasswordUniqueness(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	passwords := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		password, err := generatePassword(24)
		if err != nil {
			t.Fatalf("generatePassword failed on iteration %d: %v", i, err)
		}
		if _, ok := passwords[password]; ok {
			t.Errorf("duplicate password generated: %q", password)
		}
		passwords[password] = struct{}{}
	}
}

func TestEncryptDecryptPassword(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tests := []struct {
		name     string
		password string
	}{
		{"simple", "TestPassword123!"},
		{"complex", "Ab3$%^&*()_+[]{}|;:,.<>?"},
		{"long", strings.Repeat("x", 100)},
		{"with unicode", "Пароль123!@#"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := encryptPassword(tt.password)
			if err != nil {
				t.Fatalf("encryptPassword failed: %v", err)
			}

			if len(encrypted) == 0 {
				t.Error("encrypted data is empty")
			}

			// Decrypt
			decrypted, err := decryptPassword(encrypted)
			if err != nil {
				t.Fatalf("decryptPassword failed: %v", err)
			}

			if decrypted != tt.password {
				t.Errorf("decrypted password = %q, want %q", decrypted, tt.password)
			}
		})
	}
}

func TestDecryptPasswordEmptyData(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	_, err := decryptPassword([]byte{})
	if err == nil {
		t.Error("decryptPassword with empty data succeeded, want error")
	}
}

func TestDecryptPasswordInvalidData(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	// Try to decrypt random garbage
	_, err := decryptPassword([]byte{0x01, 0x02, 0x03, 0x04})
	if err == nil {
		t.Error("decryptPassword with invalid data succeeded, want error")
	}
}

func TestDataBlobLayout(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	// Verify dataBlob struct layout matches Windows DATA_BLOB
	var blob dataBlob
	size := unsafe.Sizeof(blob)

	// DATA_BLOB is 8 bytes on 32-bit, 16 bytes on 64-bit
	var expectedSize uintptr
	if unsafe.Sizeof(uintptr(0)) == 4 {
		expectedSize = 8
	} else {
		expectedSize = 16
	}

	if size != expectedSize {
		t.Errorf("dataBlob size = %d, want %d", size, expectedSize)
	}

	// Check field offsets
	sizeOffset := unsafe.Offsetof(blob.Size)
	dataOffset := unsafe.Offsetof(blob.Data)

	if sizeOffset != 0 {
		t.Errorf("Size offset = %d, want 0", sizeOffset)
	}

	if dataOffset != 4 && dataOffset != 8 {
		t.Errorf("Data offset = %d, want 4 or 8", dataOffset)
	}
}

func TestUserInfo1Layout(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	// Verify userInfo1 struct layout matches Windows USER_INFO_1
	var info userInfo1

	// Check field order and alignment
	if unsafe.Offsetof(info.Name) != 0 {
		t.Errorf("Name offset = %d, want 0", unsafe.Offsetof(info.Name))
	}

	// Password should follow Name (pointer size)
	ptrSize := unsafe.Sizeof(uintptr(0))
	if unsafe.Offsetof(info.Password) != ptrSize {
		t.Errorf("Password offset = %d, want %d", unsafe.Offsetof(info.Password), ptrSize)
	}
}

func TestLocalGroupInfo1Layout(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	// Verify localGroupInfo1 struct layout
	var info localGroupInfo1

	if unsafe.Offsetof(info.Name) != 0 {
		t.Errorf("Name offset = %d, want 0", unsafe.Offsetof(info.Name))
	}

	ptrSize := unsafe.Sizeof(uintptr(0))
	if unsafe.Offsetof(info.Comment) != ptrSize {
		t.Errorf("Comment offset = %d, want %d", unsafe.Offsetof(info.Comment), ptrSize)
	}
}

func TestConstantValues(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	// Verify constant values match Windows API documentation
	tests := []struct {
		name  string
		value uint32
		want  uint32
	}{
		{"NERR_Success", nerrSuccess, 0},
		{"NERR_GroupNotFound", nerrGroupNotFound, 2220},
		{"NERR_UserNotFound", nerrUserNotFound, 2221},
		{"NERR_GroupExists", nerrGroupExists, 2223},
		{"NERR_UserExists", nerrUserExists, 2224},
		{"UF_SCRIPT", ufScript, 0x0001},
		{"UF_DONT_EXPIRE_PASSWD", ufDontExpirePasswd, 0x10000},
		{"USER_PRIV_USER", userPrivUser, 1},
		{"CRYPTPROTECT_UI_FORBIDDEN", cryptprotectUIForbidden, 0x1},
		{"CRYPTPROTECT_LOCAL_MACHINE", cryptprotectLocalMachine, 0x4},
		{"LOGON_WITH_PROFILE", logonWithProfile, 0x1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = 0x%X, want 0x%X", tt.name, tt.value, tt.want)
			}
		})
	}
}

func TestResolveSID(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	// Try to resolve a well-known account (should exist on all Windows systems)
	sid, err := resolveSID("SYSTEM")
	if err != nil {
		t.Skipf("resolveSID(SYSTEM) failed (may not work in all contexts): %v", err)
	}

	// SYSTEM SID should start with S-1-5-18
	if !strings.HasPrefix(sid, "S-1-5-18") {
		t.Errorf("SYSTEM SID = %q, want prefix S-1-5-18", sid)
	}
}

func TestCreateSandboxGroup(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	if !isAdmin() {
		t.Skip("requires administrator privileges")
	}

	// Clean up any existing group first
	groupNamePtr, _ := windows.UTF16PtrFromString(sandboxGroupName)
	_ = netLocalGroupDel(nil, groupNamePtr)

	// Create the group
	err := createSandboxGroup()
	if err != nil {
		t.Fatalf("createSandboxGroup failed: %v", err)
	}

	// Try creating again - should succeed (ignore exists error)
	err = createSandboxGroup()
	if err != nil {
		t.Errorf("createSandboxGroup second call failed: %v", err)
	}

	// Clean up
	err = netLocalGroupDel(nil, groupNamePtr)
	if err != nil {
		t.Errorf("cleanup failed: %v", err)
	}
}

func TestSandboxUserManagerLifecycle(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	if !isAdmin() {
		t.Skip("requires administrator privileges")
	}

	manager := &SandboxUserManager{}

	// Setup
	err := manager.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Verify we can get a user
	user, err := manager.GetUser()
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}

	if user.Username == "" {
		t.Error("user has empty username")
	}

	if user.Password == "" {
		t.Error("user has empty password")
	}

	if user.SID == "" {
		t.Error("user has empty SID")
	}

	if !strings.HasPrefix(user.SID, "S-1-5-21-") {
		t.Errorf("user SID = %q, want prefix S-1-5-21-", user.SID)
	}

	// Teardown
	err = manager.Teardown()
	if err != nil {
		t.Errorf("Teardown failed: %v", err)
	}

	// Verify teardown cleared users
	if len(manager.users) != 0 {
		t.Errorf("manager still has %d users after Teardown", len(manager.users))
	}
}

func TestSandboxUserManagerGetUserBeforeSetup(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	manager := &SandboxUserManager{}

	_, err := manager.GetUser()
	if err == nil {
		t.Error("GetUser before Setup succeeded, want error")
	}
}

func TestSandboxUserManagerConcurrency(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	if !isAdmin() {
		t.Skip("requires administrator privileges")
	}

	manager := &SandboxUserManager{}

	err := manager.Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer func() {
		_ = manager.Teardown()
	}()

	// Access GetUser concurrently
	const goroutines = 10
	done := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			user, err := manager.GetUser()
			if err != nil {
				done <- err
				return
			}
			if user == nil {
				done <- err
				return
			}
			done <- nil
		}()
	}

	for i := 0; i < goroutines; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent GetUser failed: %v", err)
		}
	}
}

// TestNetAPIErrorType verifies the netAPIError type can be inspected with
// errors.As, which is the pattern used by deleteSandboxGroupLocked and
// deleteSandboxUserLocked to ignore "not found" errors.
func TestNetAPIErrorType(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tests := []struct {
		name    string
		err     error
		code    uint32
		wantMsg string
	}{
		{
			name:    "group not found",
			err:     fmt.Errorf("wrapped: %w", &netAPIError{Code: nerrGroupNotFound, API: "NetLocalGroupDel"}),
			code:    nerrGroupNotFound,
			wantMsg: "NetLocalGroupDel failed with code 2220",
		},
		{
			name:    "user not found",
			err:     fmt.Errorf("wrapped: %w", &netAPIError{Code: nerrUserNotFound, API: "NetUserDel"}),
			code:    nerrUserNotFound,
			wantMsg: "NetUserDel failed with code 2221",
		},
		{
			name:    "group exists",
			err:     &netAPIError{Code: nerrGroupExists, API: "NetLocalGroupAdd"},
			code:    nerrGroupExists,
			wantMsg: "NetLocalGroupAdd failed with code 2223",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var netErr *netAPIError
			if !errors.As(tt.err, &netErr) {
				t.Fatal("errors.As failed to unwrap netAPIError")
			}
			if netErr.Code != tt.code {
				t.Errorf("Code = %d, want %d", netErr.Code, tt.code)
			}
			if netErr.Error() != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", netErr.Error(), tt.wantMsg)
			}
		})
	}
}

// TestDeleteGroupNotFoundIsIgnored verifies that deleteSandboxGroupLocked
// treats NERR_GroupNotFound (2220) as success — the group not existing is the
// desired end state for deletion.
func TestDeleteGroupNotFoundIsIgnored(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}
	if !isAdmin() {
		t.Skip("requires administrator privileges")
	}

	// Ensure the group does not exist by trying to delete it.
	// Then call deleteSandboxGroupLocked again — it should succeed (not error)
	// because nerrGroupNotFound is treated as success.
	_ = deleteSandboxGroupLocked()
	err := deleteSandboxGroupLocked()
	if err != nil {
		t.Fatalf("deleteSandboxGroupLocked() on non-existent group: %v", err)
	}
}
