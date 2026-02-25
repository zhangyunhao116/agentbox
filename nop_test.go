package agentbox

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNopManagerWrap(t *testing.T) {
	mgr := NewNopManager()
	cmd := exec.Command("echo", "hello")
	err := mgr.Wrap(context.Background(), cmd)
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}
}

func TestNopManagerExec(t *testing.T) {
	mgr := NewNopManager()
	result, err := mgr.Exec(context.Background(), "echo hello")
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if result == nil {
		t.Fatal("Exec() returned nil result")
	}
	if got := strings.TrimSpace(result.Stdout); got != "hello" {
		t.Errorf("Stdout = %q, want %q", got, "hello")
	}
	if result.Sandboxed {
		t.Error("Sandboxed should be false for NopManager")
	}
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if result.Duration <= 0 {
		t.Error("Duration should be positive")
	}
}

func TestNopManagerExecNonZeroExit(t *testing.T) {
	mgr := NewNopManager()
	result, err := mgr.Exec(context.Background(), "exit 42")
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if result.ExitCode != 42 {
		t.Errorf("ExitCode = %d, want 42", result.ExitCode)
	}
}

func TestNopManagerExecStderr(t *testing.T) {
	mgr := NewNopManager()
	result, err := mgr.Exec(context.Background(), "echo error >&2")
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if got := strings.TrimSpace(result.Stderr); got != "error" {
		t.Errorf("Stderr = %q, want %q", got, "error")
	}
}

func TestNopManagerExecArgs(t *testing.T) {
	mgr := NewNopManager()
	result, err := mgr.ExecArgs(context.Background(), "echo", []string{"world"})
	if err != nil {
		t.Fatalf("ExecArgs() error: %v", err)
	}
	if result == nil {
		t.Fatal("ExecArgs() returned nil result")
	}
	if got := strings.TrimSpace(result.Stdout); got != "world" {
		t.Errorf("Stdout = %q, want %q", got, "world")
	}
	if result.Sandboxed {
		t.Error("Sandboxed should be false for NopManager")
	}
}

func TestNopManagerExecArgsNonZeroExit(t *testing.T) {
	mgr := NewNopManager()
	result, err := mgr.ExecArgs(context.Background(), "/bin/sh", []string{"-c", "exit 7"})
	if err != nil {
		t.Fatalf("ExecArgs() error: %v", err)
	}
	if result.ExitCode != 7 {
		t.Errorf("ExitCode = %d, want 7", result.ExitCode)
	}
}

func TestNopManagerAvailable(t *testing.T) {
	mgr := NewNopManager()
	if !mgr.Available() {
		t.Error("Available() should return true")
	}
}

func TestNopManagerCheckDependencies(t *testing.T) {
	mgr := NewNopManager()
	dc := mgr.CheckDependencies()
	if dc == nil {
		t.Fatal("CheckDependencies() returned nil")
	}
	if !dc.OK() {
		t.Error("CheckDependencies() should be OK")
	}
}

func TestNopManagerCleanup(t *testing.T) {
	mgr := NewNopManager()
	err := mgr.Cleanup(context.Background())
	if err != nil {
		t.Fatalf("Cleanup() error: %v", err)
	}
}

func TestNopManagerAfterCleanup(t *testing.T) {
	mgr := NewNopManager()
	_ = mgr.Cleanup(context.Background())

	t.Run("Wrap", func(t *testing.T) {
		cmd := exec.Command("echo", "hello")
		err := mgr.Wrap(context.Background(), cmd)
		if !errors.Is(err, ErrManagerClosed) {
			t.Errorf("Wrap() after Cleanup: got %v, want ErrManagerClosed", err)
		}
	})

	t.Run("Exec", func(t *testing.T) {
		_, err := mgr.Exec(context.Background(), "echo hello")
		if !errors.Is(err, ErrManagerClosed) {
			t.Errorf("Exec() after Cleanup: got %v, want ErrManagerClosed", err)
		}
	})

	t.Run("ExecArgs", func(t *testing.T) {
		_, err := mgr.ExecArgs(context.Background(), "echo", []string{"hello"})
		if !errors.Is(err, ErrManagerClosed) {
			t.Errorf("ExecArgs() after Cleanup: got %v, want ErrManagerClosed", err)
		}
	})
}

func TestNopManagerImplementsInterface(t *testing.T) {
	var _ = NewNopManager()
}

func TestNopManagerExecInvalidCommand(t *testing.T) {
	mgr := NewNopManager()
	_, err := mgr.Exec(context.Background(), "nonexistent_command_xyz_12345")
	// The command should fail but not return a Go error for exit code issues.
	// However, for a truly nonexistent command, the shell returns exit code 127.
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
}

func TestNopManagerExecArgsInvalidCommand(t *testing.T) {
	mgr := NewNopManager()
	_, err := mgr.ExecArgs(context.Background(), "/nonexistent_binary_xyz", nil)
	// exec.CommandContext with a nonexistent binary returns an error from Run().
	if err == nil {
		t.Fatal("ExecArgs() with nonexistent binary should return error")
	}
}

// TestNopManagerConcurrentAccess verifies that nopManager is safe for
// concurrent use from multiple goroutines.
func TestNopManagerConcurrentAccess(t *testing.T) {
	mgr := NewNopManager()
	var wg sync.WaitGroup

	// Concurrent Exec calls.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = mgr.Exec(context.Background(), "echo concurrent")
		}()
	}

	// Concurrent Wrap calls.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command("echo", "hello")
			_ = mgr.Wrap(context.Background(), cmd)
		}()
	}

	// Concurrent ExecArgs calls.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = mgr.ExecArgs(context.Background(), "echo", []string{"hello"})
		}()
	}

	wg.Wait()
	_ = mgr.Cleanup(context.Background())
}

// TestNopManagerConcurrentCleanup verifies that concurrent Cleanup calls
// do not race or panic.
func TestNopManagerConcurrentCleanup(t *testing.T) {
	mgr := NewNopManager()
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = mgr.Cleanup(context.Background())
		}()
	}
	wg.Wait()

	// After cleanup, all operations should return ErrManagerClosed.
	cmd := exec.Command("echo", "hello")
	if err := mgr.Wrap(context.Background(), cmd); !errors.Is(err, ErrManagerClosed) {
		t.Errorf("Wrap after concurrent Cleanup: got %v, want ErrManagerClosed", err)
	}
}

// TestNopManagerExecWithShell verifies that WithShell option is applied
// in nopManager.Exec.
func TestNopManagerExecWithShell(t *testing.T) {
	mgr := NewNopManager()
	// Use /bin/sh explicitly via WithShell (should work the same as default).
	result, err := mgr.Exec(context.Background(), "echo shell_test", WithShell("/bin/sh"))
	if err != nil {
		t.Fatalf("Exec() with WithShell error: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "shell_test" {
		t.Errorf("Stdout = %q, want %q", got, "shell_test")
	}
}

// TestNopManagerExecWithEnv verifies that WithEnv option is applied
// in nopManager.Exec.
func TestNopManagerExecWithEnv(t *testing.T) {
	mgr := NewNopManager()
	result, err := mgr.Exec(context.Background(), "echo $NOP_TEST_VAR",
		WithEnv("NOP_TEST_VAR=nop_value"),
	)
	if err != nil {
		t.Fatalf("Exec() with WithEnv error: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "nop_value" {
		t.Errorf("Stdout = %q, want %q", got, "nop_value")
	}
}

// TestNopManagerExecArgsWithEnv verifies that WithEnv option is applied
// in nopManager.ExecArgs.
func TestNopManagerExecArgsWithEnv(t *testing.T) {
	mgr := NewNopManager()
	result, err := mgr.ExecArgs(context.Background(), "/bin/sh", []string{"-c", "echo $NOP_ARGS_VAR"},
		WithEnv("NOP_ARGS_VAR=args_value"),
	)
	if err != nil {
		t.Fatalf("ExecArgs() with WithEnv error: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "args_value" {
		t.Errorf("Stdout = %q, want %q", got, "args_value")
	}
}

// TestNopManagerUpdateConfig verifies that UpdateConfig validates and accepts
// a valid config.
func TestNopManagerUpdateConfig(t *testing.T) {
	mgr := NewNopManager()
	cfg := &Config{
		Network: NetworkConfig{
			Mode: NetworkAllowed,
		},
	}
	err := mgr.UpdateConfig(cfg)
	if err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}
}

// TestNopManagerUpdateConfigInvalid verifies that UpdateConfig rejects
// an invalid config.
func TestNopManagerUpdateConfigInvalid(t *testing.T) {
	mgr := NewNopManager()
	badCfg := &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: []string{""},
		},
	}
	err := mgr.UpdateConfig(badCfg)
	if err == nil {
		t.Fatal("UpdateConfig() with invalid config should return error")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

// TestNopManagerUpdateConfigClosed verifies that UpdateConfig returns
// ErrManagerClosed after Cleanup.
func TestNopManagerUpdateConfigClosed(t *testing.T) {
	mgr := NewNopManager()
	_ = mgr.Cleanup(context.Background())

	cfg := &Config{
		Network: NetworkConfig{
			Mode: NetworkAllowed,
		},
	}
	err := mgr.UpdateConfig(cfg)
	if !errors.Is(err, ErrManagerClosed) {
		t.Errorf("UpdateConfig() after Cleanup: got %v, want ErrManagerClosed", err)
	}
}

// TestNopManagerUpdateConfigNil verifies that nopManager.UpdateConfig rejects
// a nil config with ErrConfigInvalid.
func TestNopManagerUpdateConfigNil(t *testing.T) {
	mgr := NewNopManager()
	err := mgr.UpdateConfig(nil)
	if err == nil {
		t.Fatal("UpdateConfig(nil) should return error")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

// TestNopManagerCheck verifies that nopManager.Check uses the default classifier.
func TestNopManagerCheck(t *testing.T) {
	mgr := NewNopManager()
	result, err := mgr.Check(context.Background(), "echo hello")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if result.Decision != Allow {
		t.Errorf("Decision: got %v, want Allow", result.Decision)
	}
}

// TestNopManagerCheckForbiddenCommand verifies that nopManager.Check returns
// Forbidden for commands that the default classifier forbids.
func TestNopManagerCheckForbiddenCommand(t *testing.T) {
	mgr := NewNopManager()
	result, err := mgr.Check(context.Background(), "rm -rf /")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if result.Decision != Forbidden {
		t.Errorf("Decision: got %v, want Forbidden", result.Decision)
	}
}

// TestNopManagerExecWithWorkingDir verifies that WithWorkingDir option is applied
// in nopManager.Exec.
func TestNopManagerExecWithWorkingDir(t *testing.T) {
	mgr := NewNopManager()
	result, err := mgr.Exec(context.Background(), "pwd", WithWorkingDir("/tmp"))
	if err != nil {
		t.Fatalf("Exec() with WithWorkingDir error: %v", err)
	}
	// On macOS, /tmp is a symlink to /private/tmp.
	got := strings.TrimSpace(result.Stdout)
	if got != "/tmp" && got != "/private/tmp" {
		t.Errorf("Stdout = %q, want /tmp or /private/tmp", got)
	}
}

// TestNopManagerExecArgsWithWorkingDir verifies that WithWorkingDir option is applied
// in nopManager.ExecArgs.
func TestNopManagerExecArgsWithWorkingDir(t *testing.T) {
	mgr := NewNopManager()
	result, err := mgr.ExecArgs(context.Background(), "/bin/sh", []string{"-c", "pwd"},
		WithWorkingDir("/tmp"),
	)
	if err != nil {
		t.Fatalf("ExecArgs() with WithWorkingDir error: %v", err)
	}
	got := strings.TrimSpace(result.Stdout)
	if got != "/tmp" && got != "/private/tmp" {
		t.Errorf("Stdout = %q, want /tmp or /private/tmp", got)
	}
}

// TestNopManagerExecWithTimeout verifies that WithTimeout option cancels
// a long-running command in nopManager.Exec.
func TestNopManagerExecWithTimeout(t *testing.T) {
	mgr := NewNopManager()
	start := time.Now()
	result, err := mgr.Exec(context.Background(), "sleep 30", WithTimeout(100*time.Millisecond))
	elapsed := time.Since(start)

	// The command should have been killed by the timeout.
	// cmd.Run returns *exec.ExitError when killed, which is converted to a non-zero exit code.
	if elapsed > 5*time.Second {
		t.Errorf("command took %v, expected it to be killed quickly by timeout", elapsed)
	}
	if err != nil {
		// Context cancellation may surface as a Go error on some platforms.
		return
	}
	if result.ExitCode == 0 {
		t.Error("expected non-zero exit code for killed command")
	}
}

// TestNopManagerExecArgsWithTimeout verifies that WithTimeout option cancels
// a long-running command in nopManager.ExecArgs.
func TestNopManagerExecArgsWithTimeout(t *testing.T) {
	mgr := NewNopManager()
	start := time.Now()
	result, err := mgr.ExecArgs(context.Background(), "sleep", []string{"30"},
		WithTimeout(100*time.Millisecond),
	)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Errorf("command took %v, expected it to be killed quickly by timeout", elapsed)
	}
	if err != nil {
		return
	}
	if result.ExitCode == 0 {
		t.Error("expected non-zero exit code for killed command")
	}
}

// TestNopManagerWrapNilCmd verifies that Wrap returns ErrNilCommand when
// a nil *exec.Cmd is passed.
func TestNopManagerWrapNilCmd(t *testing.T) {
	mgr := NewNopManager()
	err := mgr.Wrap(context.Background(), nil)
	if !errors.Is(err, ErrNilCommand) {
		t.Errorf("Wrap(nil cmd): got %v, want ErrNilCommand", err)
	}
}

// TestNopManagerCheckAfterCleanup verifies that Check returns
// ErrManagerClosed after Cleanup has been called.
func TestNopManagerCheckAfterCleanup(t *testing.T) {
	mgr := NewNopManager()
	_ = mgr.Cleanup(context.Background())

	_, err := mgr.Check(context.Background(), "echo hello")
	if !errors.Is(err, ErrManagerClosed) {
		t.Errorf("Check() after Cleanup: got %v, want ErrManagerClosed", err)
	}
}

// TestNopManagerExecForbiddenCommand verifies that nopManager rejects
// commands that the default classifier marks as Forbidden.
func TestNopManagerExecForbiddenCommand(t *testing.T) {
	mgr := NewNopManager()
	// Use Check (classify-only) instead of Exec to avoid executing dangerous commands.
	result, err := mgr.Check(context.Background(), "rm -rf /")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if result.Decision != Forbidden {
		t.Errorf("Check() decision: got %v, want Forbidden", result.Decision)
	}

	// Also verify that Exec rejects forbidden commands using a safe command
	// with a mock classifier that returns Forbidden.
	forbidAll := &mockClassifier{result: ClassifyResult{Decision: Forbidden, Reason: "test forbidden"}}
	_, err = mgr.Exec(context.Background(), "echo hello", WithClassifier(forbidAll))
	if err == nil {
		t.Fatal("Exec() should return error for forbidden command")
	}
	if !errors.Is(err, ErrForbiddenCommand) {
		t.Errorf("Exec() error: got %v, want ErrForbiddenCommand", err)
	}
}

// TestNopManagerExecArgsForbiddenCommand verifies that nopManager.ExecArgs
// rejects commands that the default classifier marks as Forbidden.
func TestNopManagerExecArgsForbiddenCommand(t *testing.T) {
	mgr := NewNopManager()
	// Use a safe command with a mock classifier that returns Forbidden,
	// instead of passing a dangerous command to ExecArgs.
	forbidAll := &mockClassifier{result: ClassifyResult{Decision: Forbidden, Reason: "test forbidden"}}
	_, err := mgr.ExecArgs(context.Background(), "echo", []string{"hello"}, WithClassifier(forbidAll))
	if err == nil {
		t.Fatal("ExecArgs() should return error for forbidden command")
	}
	if !errors.Is(err, ErrForbiddenCommand) {
		t.Errorf("ExecArgs() error: got %v, want ErrForbiddenCommand", err)
	}
}

// TestNopManagerExecWithCustomClassifier verifies that a per-call classifier
// overrides the default in nopManager.Exec.
func TestNopManagerExecWithCustomClassifier(t *testing.T) {
	mgr := NewNopManager()
	// Custom classifier that forbids everything.
	forbidAll := &mockClassifier{result: ClassifyResult{Decision: Forbidden, Reason: "custom forbid"}}
	_, err := mgr.Exec(context.Background(), "echo hello", WithClassifier(forbidAll))
	if err == nil {
		t.Fatal("Exec() should return error with custom forbid-all classifier")
	}
	if !errors.Is(err, ErrForbiddenCommand) {
		t.Errorf("Exec() error: got %v, want ErrForbiddenCommand", err)
	}
}

// TestNopManagerExecMaxOutputBytes verifies that nopManager.Exec respects
// the MaxOutputBytes option and truncates output.
func TestNopManagerExecMaxOutputBytes(t *testing.T) {
	mgr := NewNopManager()
	// Generate output larger than 10 bytes.
	result, err := mgr.Exec(context.Background(), "echo 'this is a long output string that exceeds the limit'",
		WithMaxOutputBytes(10),
	)
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if len(result.Stdout) > 10 {
		t.Errorf("Stdout length = %d, want <= 10 (MaxOutputBytes)", len(result.Stdout))
	}
}

// ---------------------------------------------------------------------------
// Escalated command handling tests
// ---------------------------------------------------------------------------

// TestNopManagerExecEscalatedNoCallback verifies that nopManager.Exec returns
// ErrEscalatedCommand when a command is classified as Escalated and no
// approval callback is set.
func TestNopManagerExecEscalatedNoCallback(t *testing.T) {
	mgr := NewNopManager()
	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	_, err := mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if err == nil {
		t.Fatal("Exec() should return error for escalated command without callback")
	}
	if !errors.Is(err, ErrEscalatedCommand) {
		t.Errorf("Exec() error: got %v, want ErrEscalatedCommand", err)
	}
}

// TestNopManagerExecArgsEscalatedNoCallback verifies that nopManager.ExecArgs
// returns ErrEscalatedCommand when a command is classified as Escalated and
// no approval callback is set.
func TestNopManagerExecArgsEscalatedNoCallback(t *testing.T) {
	mgr := NewNopManager()
	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	_, err := mgr.ExecArgs(context.Background(), "docker", []string{"build", "."}, WithClassifier(escalateAll))
	if err == nil {
		t.Fatal("ExecArgs() should return error for escalated command without callback")
	}
	if !errors.Is(err, ErrEscalatedCommand) {
		t.Errorf("ExecArgs() error: got %v, want ErrEscalatedCommand", err)
	}
}

// TestNopManagerExecEscalatedApproved verifies that nopManager.Exec allows
// execution when the approval callback approves the escalated command.
func TestNopManagerExecEscalatedApproved(t *testing.T) {
	mgr := newNopManagerWithApproval(func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		return Approve, nil
	})
	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	result, err := mgr.Exec(context.Background(), "echo approved", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if result == nil {
		t.Fatal("Exec() returned nil result")
	}
	if got := strings.TrimSpace(result.Stdout); got != "approved" {
		t.Errorf("Stdout = %q, want %q", got, "approved")
	}
}

// TestNopManagerExecArgsEscalatedApproved verifies that nopManager.ExecArgs
// allows execution when the approval callback approves the escalated command.
func TestNopManagerExecArgsEscalatedApproved(t *testing.T) {
	mgr := newNopManagerWithApproval(func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		return Approve, nil
	})
	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	result, err := mgr.ExecArgs(context.Background(), "echo", []string{"approved"}, WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("ExecArgs() error: %v", err)
	}
	if result == nil {
		t.Fatal("ExecArgs() returned nil result")
	}
	if got := strings.TrimSpace(result.Stdout); got != "approved" {
		t.Errorf("Stdout = %q, want %q", got, "approved")
	}
}

// TestNopManagerExecEscalatedDenied verifies that nopManager.Exec returns
// ErrEscalatedCommand when the approval callback denies the command.
func TestNopManagerExecEscalatedDenied(t *testing.T) {
	mgr := newNopManagerWithApproval(func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		return Deny, nil
	})
	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	_, err := mgr.Exec(context.Background(), "echo denied", WithClassifier(escalateAll))
	if err == nil {
		t.Fatal("Exec() should return error for denied escalated command")
	}
	if !errors.Is(err, ErrEscalatedCommand) {
		t.Errorf("Exec() error: got %v, want ErrEscalatedCommand", err)
	}
	if !strings.Contains(err.Error(), "denied by user") {
		t.Errorf("error should contain 'denied by user', got: %v", err)
	}
}

// TestNopManagerExecEscalatedCallbackError verifies that nopManager.Exec
// propagates errors from the approval callback.
func TestNopManagerExecEscalatedCallbackError(t *testing.T) {
	cbErr := errors.New("callback failed")
	mgr := newNopManagerWithApproval(func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		return Deny, cbErr
	})
	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	_, err := mgr.Exec(context.Background(), "echo test", WithClassifier(escalateAll))
	if err == nil {
		t.Fatal("Exec() should return error when callback fails")
	}
	if !errors.Is(err, ErrEscalatedCommand) {
		t.Errorf("error should wrap ErrEscalatedCommand, got: %v", err)
	}
	if !errors.Is(err, cbErr) {
		t.Errorf("error should wrap callback error, got: %v", err)
	}
}

// TestNopManagerExecEscalatedSessionCache verifies that ApproveSession caches
// the command so the callback is not invoked on subsequent calls.
func TestNopManagerExecEscalatedSessionCache(t *testing.T) {
	callCount := 0
	mgr := newNopManagerWithApproval(func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		callCount++
		return ApproveSession, nil
	})
	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}

	// First call: callback should be invoked.
	_, err := mgr.Exec(context.Background(), "echo cached", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("first Exec() error: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("callback count after first Exec = %d, want 1", callCount)
	}

	// Second call with same command: callback should be skipped (cached).
	_, err = mgr.Exec(context.Background(), "echo cached", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("second Exec() error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callback count after second Exec = %d, want 1 (cached)", callCount)
	}
}

// TestNopManagerExecEscalatedSessionCacheNormalized verifies that session
// approval cache normalizes whitespace so "echo  hello" and "echo hello"
// share the same cache entry.
func TestNopManagerExecEscalatedSessionCacheNormalized(t *testing.T) {
	callCount := 0
	mgr := newNopManagerWithApproval(func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		callCount++
		return ApproveSession, nil
	})
	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}

	// First call with extra whitespace.
	_, err := mgr.Exec(context.Background(), "echo  hello", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("first Exec() error: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("callback count after first Exec = %d, want 1", callCount)
	}

	// Second call with normalized whitespace: should hit cache.
	_, err = mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("second Exec() error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callback count after second Exec = %d, want 1 (normalized cache hit)", callCount)
	}
}

// TestNopManagerExecEscalatedUnsetDecision verifies that a callback returning
// the zero value of ApprovalDecision (approvalUnset) is treated as deny.
func TestNopManagerExecEscalatedUnsetDecision(t *testing.T) {
	mgr := newNopManagerWithApproval(func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		// Return the zero value (approvalUnset) — simulates a callback that
		// forgets to set the return value.
		var d ApprovalDecision
		return d, nil
	})
	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	_, err := mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if err == nil {
		t.Fatal("Exec() should return error when callback returns zero-value decision")
	}
	if !errors.Is(err, ErrEscalatedCommand) {
		t.Errorf("Exec() error: got %v, want ErrEscalatedCommand", err)
	}
}

// --- Tests for Task 1: nopManager uses stored classifier ---

// alwaysForbidClassifier is a test classifier that forbids all commands.
type alwaysForbidClassifier struct{}

func (c *alwaysForbidClassifier) Classify(_ string) ClassifyResult {
	return ClassifyResult{Decision: Forbidden, Reason: "always forbidden"}
}

func (c *alwaysForbidClassifier) ClassifyArgs(_ string, _ []string) ClassifyResult {
	return ClassifyResult{Decision: Forbidden, Reason: "always forbidden"}
}

func TestNopManagerUsesStoredClassifier(t *testing.T) {
	// Create a nopManager with a classifier that forbids everything.
	mgr := newNopManagerWithConfig(&Config{Classifier: &alwaysForbidClassifier{}, FallbackPolicy: FallbackWarn})

	// Exec should be forbidden.
	_, err := mgr.Exec(context.Background(), "echo hello")
	if err == nil {
		t.Fatal("Exec() should have returned an error for forbidden command")
	}
	if !errors.Is(err, ErrForbiddenCommand) {
		t.Errorf("Exec() error = %v, want ErrForbiddenCommand", err)
	}
}

func TestNopManagerExecArgsUsesStoredClassifier(t *testing.T) {
	mgr := newNopManagerWithConfig(&Config{Classifier: &alwaysForbidClassifier{}, FallbackPolicy: FallbackWarn})

	_, err := mgr.ExecArgs(context.Background(), "echo", []string{"hello"})
	if err == nil {
		t.Fatal("ExecArgs() should have returned an error for forbidden command")
	}
	if !errors.Is(err, ErrForbiddenCommand) {
		t.Errorf("ExecArgs() error = %v, want ErrForbiddenCommand", err)
	}
}

func TestNopManagerCheckUsesStoredClassifier(t *testing.T) {
	mgr := newNopManagerWithConfig(&Config{Classifier: &alwaysForbidClassifier{}, FallbackPolicy: FallbackWarn})

	result, err := mgr.Check(context.Background(), "echo hello")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if result.Decision != Forbidden {
		t.Errorf("Check() decision = %v, want Forbidden", result.Decision)
	}
}

// --- Tests for Task 2: nopManager.Wrap processes options and classifies ---

func TestNopManagerWrapClassifiesForbidden(t *testing.T) {
	mgr := newNopManagerWithConfig(&Config{Classifier: &alwaysForbidClassifier{}, FallbackPolicy: FallbackWarn})
	cmd := exec.Command("echo", "hello")
	err := mgr.Wrap(context.Background(), cmd)
	if err == nil {
		t.Fatal("Wrap() should have returned an error for forbidden command")
	}
	if !errors.Is(err, ErrForbiddenCommand) {
		t.Errorf("Wrap() error = %v, want ErrForbiddenCommand", err)
	}
}

func TestNopManagerWrapEmptyArgs(t *testing.T) {
	mgr := NewNopManager()
	cmd := &exec.Cmd{} // empty Args
	err := mgr.Wrap(context.Background(), cmd)
	if err == nil {
		t.Fatal("Wrap() should have returned an error for empty Args")
	}
	if !errors.Is(err, ErrNilCommand) {
		t.Errorf("Wrap() error = %v, want ErrNilCommand", err)
	}
}

func TestNopManagerWrapPerCallClassifier(t *testing.T) {
	// Default classifier allows "echo hello", but per-call classifier forbids it.
	mgr := NewNopManager()
	cmd := exec.Command("echo", "hello")
	err := mgr.Wrap(context.Background(), cmd, WithClassifier(&alwaysForbidClassifier{}))
	if err == nil {
		t.Fatal("Wrap() should have returned an error with per-call forbid classifier")
	}
	if !errors.Is(err, ErrForbiddenCommand) {
		t.Errorf("Wrap() error = %v, want ErrForbiddenCommand", err)
	}
}

func TestNopManagerWrapAppliesEnv(t *testing.T) {
	mgr := NewNopManager()
	cmd := exec.Command("echo", "hello")
	err := mgr.Wrap(context.Background(), cmd, WithEnv("FOO=bar"))
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}
	// Check that the env was applied.
	found := false
	for _, e := range cmd.Env {
		if e == "FOO=bar" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Wrap() did not apply per-call env var FOO=bar")
	}
}

// --- Tests for Task 1 continued: UpdateConfig updates classifier ---

func TestNopManagerUpdateConfigUpdatesClassifier(t *testing.T) {
	mgr := NewNopManager()

	// Initially, "echo hello" should be allowed.
	result, err := mgr.Check(context.Background(), "echo hello")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if result.Decision == Forbidden {
		t.Error("Check() should not forbid 'echo hello' initially")
	}

	// Update config with a forbid-all classifier.
	cfg := DefaultConfig()
	cfg.Classifier = &alwaysForbidClassifier{}
	if err := mgr.UpdateConfig(cfg); err != nil {
		t.Fatalf("UpdateConfig() error: %v", err)
	}

	// Now "echo hello" should be forbidden.
	result, err = mgr.Check(context.Background(), "echo hello")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if result.Decision != Forbidden {
		t.Errorf("Check() decision = %v, want Forbidden after UpdateConfig", result.Decision)
	}
}

// --- Tests for Task 1: newNopManagerWithConfig ---

func TestNewNopManagerWithConfigUsesClassifier(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Classifier = &alwaysForbidClassifier{}

	mgr := newNopManagerWithConfig(cfg)

	result, err := mgr.Check(context.Background(), "echo hello")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if result.Decision != Forbidden {
		t.Errorf("Check() decision = %v, want Forbidden", result.Decision)
	}
}

func TestNewNopManagerWithConfigNilConfig(t *testing.T) {
	// nil config should use DefaultClassifier.
	mgr := newNopManagerWithConfig(nil)

	result, err := mgr.Check(context.Background(), "echo hello")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	// "echo hello" should be allowed by default classifier.
	if result.Decision == Forbidden {
		t.Error("Check() should not forbid 'echo hello' with nil config")
	}
}

// --- Tests for Task 3: DefaultClassifier caching ---

func TestDefaultClassifierReturnsSameInstance(t *testing.T) {
	c1 := DefaultClassifier()
	c2 := DefaultClassifier()
	if c1 != c2 {
		t.Error("DefaultClassifier() should return the same cached instance")
	}
}

// --- Tests for Task 4: MaxOutputBytes zero-value semantics ---

func TestDefaultConfigMaxOutputBytesIsDefault(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxOutputBytes != defaultMaxOutputBytes {
		t.Errorf("DefaultConfig().MaxOutputBytes = %d, want %d", cfg.MaxOutputBytes, defaultMaxOutputBytes)
	}
}

func TestMaxOutputBytesZeroMeansNoLimit(t *testing.T) {
	// When MaxOutputBytes is explicitly set to 0, it should be preserved
	// (meaning no limit), not overridden with the default.
	cfg := DefaultConfig()
	cfg.MaxOutputBytes = 0

	// Validate should pass with 0.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
}

// TestNopManagerConcurrentUpdateConfigAndOps verifies that concurrent
// UpdateConfig calls do not race with Exec, ExecArgs, Wrap, or Check.
// This is a regression test for a data race where n.classifier was read
// after the mutex was unlocked while UpdateConfig wrote it under the lock.
func TestNopManagerConcurrentUpdateConfigAndOps(t *testing.T) {
	mgr := NewNopManager()
	var wg sync.WaitGroup

	ctx := context.Background()

	// Concurrent UpdateConfig calls that swap the classifier.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = mgr.UpdateConfig(&Config{
				Classifier: DefaultClassifier(),
			})
		}()
	}

	// Concurrent Exec calls.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = mgr.Exec(ctx, "echo race-test")
		}()
	}

	// Concurrent ExecArgs calls.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = mgr.ExecArgs(ctx, "echo", []string{"race-test"})
		}()
	}

	// Concurrent Wrap calls.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command("echo", "race-test")
			_ = mgr.Wrap(ctx, cmd)
		}()
	}

	// Concurrent Check calls.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = mgr.Check(ctx, "echo race-test")
		}()
	}

	wg.Wait()
	_ = mgr.Cleanup(ctx)
}
