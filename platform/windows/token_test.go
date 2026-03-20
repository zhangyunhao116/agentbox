//go:build windows

package windows

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestCreateSandboxToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that creates real Windows tokens in short mode")
	}

	token, err := createSandboxToken()
	if err != nil {
		t.Fatalf("createSandboxToken failed: %v", err)
	}
	defer token.Close()
	t.Log("Token created successfully")
}

func TestExtractLogonSID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that calls Windows token APIs in short mode")
	}

	var baseToken windows.Token
	err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY,
		&baseToken,
	)
	if err != nil {
		t.Fatalf("OpenProcessToken failed: %v", err)
	}
	defer baseToken.Close()

	sid, err := extractLogonSID(baseToken)
	if err != nil {
		// Not having a logon SID is OK in non-interactive sessions
		t.Logf("extractLogonSID returned error (expected in non-interactive sessions): %v", err)
		return
	}
	t.Logf("Logon SID: %s", sid.String())
}
