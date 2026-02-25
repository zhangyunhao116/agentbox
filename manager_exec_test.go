package agentbox

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/zhangyunhao116/agentbox/platform"
)

// isStubWrapError returns true if the error is from the built-in platform stub
// that does not implement WrapCommand. Tests that need actual command execution
// (not sandbox testing) should skip when this is the case.
func isStubWrapError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "built-in stub does not implement WrapCommand") ||
		strings.Contains(s, "test-stub: WrapCommand not implemented")
}

func TestManagerWrapForbiddenCommand(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// "rm -rf /" is classified as Forbidden by the default classifier.
	cmd := exec.Command("rm", "-rf", "/")
	err = mgr.Wrap(context.Background(), cmd)
	if !errors.Is(err, ErrForbiddenCommand) {
		t.Errorf("Wrap() with forbidden command: got %v, want ErrForbiddenCommand", err)
	}

	// Verify errors.As extracts the structured ForbiddenCommandError.
	var fce *ForbiddenCommandError
	if !errors.As(err, &fce) {
		t.Fatalf("expected ForbiddenCommandError via errors.As, got %T", err)
	}
	if fce.Command == "" {
		t.Error("expected Command to be populated")
	}
}

func TestManagerWrapEscalatedNoCallback(t *testing.T) {
	cfg := newTestConfig(t)
	// No approval callback set.
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Use a mock classifier that escalates a safe command.
	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	cmd := exec.Command("echo", "hello")
	err = mgr.Wrap(context.Background(), cmd, WithClassifier(escalateAll))
	if !errors.Is(err, ErrEscalatedCommand) {
		t.Errorf("Wrap() with escalated command (no callback): got %v, want ErrEscalatedCommand", err)
	}

	// Verify errors.As extracts the structured EscalatedCommandError.
	var ece *EscalatedCommandError
	if !errors.As(err, &ece) {
		t.Fatalf("expected EscalatedCommandError via errors.As, got %T", err)
	}
	if ece.Command == "" {
		t.Error("expected Command to be populated")
	}
}

func TestManagerWrapEscalatedWithApproval(t *testing.T) {
	cfg := newTestConfig(t)
	var receivedCommand string
	cfg.ApprovalCallback = func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		receivedCommand = req.Command
		return Approve, nil
	}
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Use a mock classifier that escalates a safe command; callback approves it.
	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	cmd := exec.Command("echo", "approved")
	err = mgr.Wrap(context.Background(), cmd, WithClassifier(escalateAll))
	// WrapCommand on the stub darwin platform returns an error ("not yet implemented"),
	// but the classification + approval flow should succeed.
	// The error from WrapCommand is expected here.
	if errors.Is(err, ErrEscalatedCommand) {
		t.Error("Wrap() should not return ErrEscalatedCommand when callback approves")
	}
	// Verify the actual command was passed, not the rule name.
	if receivedCommand != "echo approved" {
		t.Errorf("ApprovalRequest.Command = %q, want %q", receivedCommand, "echo approved")
	}
}

func TestManagerWrapEscalatedWithDenial(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.ApprovalCallback = func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		return Deny, nil
	}
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	cmd := exec.Command("echo", "denied")
	err = mgr.Wrap(context.Background(), cmd, WithClassifier(escalateAll))
	if !errors.Is(err, ErrEscalatedCommand) {
		t.Errorf("Wrap() with denied escalation: got %v, want ErrEscalatedCommand", err)
	}
}

func TestManagerExec(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	result, err := mgr.Exec(context.Background(), "echo hello")
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if result == nil {
		t.Fatal("Exec() returned nil result")
	}
	if got := strings.TrimSpace(result.Stdout); got != "hello" {
		t.Errorf("Stdout = %q, want %q", got, "hello")
	}
	if result.Duration <= 0 {
		t.Error("Duration should be positive")
	}
}

func TestManagerExecForbidden(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Use a safe command with a mock classifier that returns Forbidden,
	// instead of passing a dangerous command to Exec.
	forbidAll := &mockClassifier{result: ClassifyResult{Decision: Forbidden, Reason: "test forbidden"}}
	_, err = mgr.Exec(context.Background(), "echo hello", WithClassifier(forbidAll))
	if !errors.Is(err, ErrForbiddenCommand) {
		t.Errorf("Exec() with forbidden command: got %v, want ErrForbiddenCommand", err)
	}
}

func TestManagerExecArgs(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	result, err := mgr.ExecArgs(context.Background(), "echo", []string{"world"})
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("ExecArgs() error: %v", err)
	}
	if result == nil {
		t.Fatal("ExecArgs() returned nil result")
	}
	if got := strings.TrimSpace(result.Stdout); got != "world" {
		t.Errorf("Stdout = %q, want %q", got, "world")
	}
}

func TestManagerExecArgsForbidden(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Use a safe command with a mock classifier that returns Forbidden,
	// instead of passing a dangerous command to ExecArgs.
	forbidAll := &mockClassifier{result: ClassifyResult{Decision: Forbidden, Reason: "test forbidden"}}
	_, err = mgr.ExecArgs(context.Background(), "echo", []string{"hello"}, WithClassifier(forbidAll))
	if !errors.Is(err, ErrForbiddenCommand) {
		t.Errorf("ExecArgs() with forbidden command: got %v, want ErrForbiddenCommand", err)
	}
}

func TestManagerMaxOutputBytesTruncation(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.MaxOutputBytes = 10 // Very small limit.

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Generate output larger than 10 bytes.
	result, err := mgr.Exec(context.Background(), "echo 'this is a long output string that exceeds the limit'")
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if result == nil {
		t.Fatal("Exec() returned nil result")
	}
	if len(result.Stdout) > 10 {
		t.Errorf("Stdout length = %d, should be <= 10", len(result.Stdout))
	}
	if !result.Truncated {
		t.Error("Truncated should be true when output exceeds MaxOutputBytes")
	}
}

func TestOptionMerging(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Use WithShell to override the shell for a single call.
	result, err := mgr.Exec(context.Background(), "echo merged",
		WithShell("/bin/sh"),
	)
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("Exec() with options error: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "merged" {
		t.Errorf("Stdout = %q, want %q", got, "merged")
	}
}

func TestManagerWithClassifierOption(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Use a custom classifier that forbids everything.
	forbidAll := &ruleClassifier{
		rules: []rule{
			{
				Name: "forbid-all",
				Match: func(command string) (ClassifyResult, bool) {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "all commands forbidden",
						Rule:     "forbid-all",
					}, true
				},
			},
		},
	}

	_, err = mgr.Exec(context.Background(), "echo hello", WithClassifier(forbidAll))
	if !errors.Is(err, ErrForbiddenCommand) {
		t.Errorf("Exec() with forbid-all classifier: got %v, want ErrForbiddenCommand", err)
	}
}

func TestManagerExecNonZeroExit(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	result, err := mgr.Exec(context.Background(), "exit 42")
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if result.ExitCode != 42 {
		t.Errorf("ExitCode = %d, want 42", result.ExitCode)
	}
}

func TestManagerExecStderr(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	result, err := mgr.Exec(context.Background(), "echo error >&2")
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if got := strings.TrimSpace(result.Stderr); got != "error" {
		t.Errorf("Stderr = %q, want %q", got, "error")
	}
}

func TestManagerExecWithEnv(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	result, err := mgr.Exec(context.Background(), "echo $TEST_VAR",
		WithEnv("TEST_VAR=hello_env"),
	)
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "hello_env" {
		t.Errorf("Stdout = %q, want %q", got, "hello_env")
	}
}

// TestManagerExecApprovalReceivesCommand verifies that the approval callback
// receives the actual command string, not the rule name.
func TestManagerExecApprovalReceivesCommand(t *testing.T) {
	cfg := newTestConfig(t)
	var receivedCommand string
	cfg.ApprovalCallback = func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		receivedCommand = req.Command
		return Approve, nil
	}
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	_, err = mgr.Exec(context.Background(), "echo approved", WithClassifier(escalateAll))
	if isStubWrapError(err) {
		// On stub platforms, WrapCommand is not implemented; the approval
		// flow still ran, so we can still verify the callback received the command.
	} else if err != nil {
		t.Fatalf("Exec() after approval should succeed, got: %v", err)
	}
	if receivedCommand != "echo approved" {
		t.Errorf("ApprovalRequest.Command = %q, want %q", receivedCommand, "echo approved")
	}
}

// TestManagerExecArgsApprovalReceivesCommand verifies that ExecArgs passes
// the full command string to the approval callback.
func TestManagerExecArgsApprovalReceivesCommand(t *testing.T) {
	cfg := newTestConfig(t)
	var receivedCommand string
	cfg.ApprovalCallback = func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		receivedCommand = req.Command
		return Approve, nil
	}
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	_, err = mgr.ExecArgs(context.Background(), "echo", []string{"approved"}, WithClassifier(escalateAll))
	if isStubWrapError(err) {
		// On stub platforms, WrapCommand is not implemented; the approval
		// flow still ran, so we can still verify the callback received the command.
	} else if err != nil {
		t.Fatalf("ExecArgs() after approval should succeed, got: %v", err)
	}
	if receivedCommand != "echo approved" {
		t.Errorf("ApprovalRequest.Command = %q, want %q", receivedCommand, "echo approved")
	}
}

func TestLimitedWriter(t *testing.T) {
	t.Run("within limit", func(t *testing.T) {
		var buf bytes.Buffer
		lw := &limitedWriter{buf: &buf, limit: 20}
		n, err := lw.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("Write() error: %v", err)
		}
		if n != 5 {
			t.Errorf("Write() = %d, want 5", n)
		}
		if buf.String() != "hello" {
			t.Errorf("buf = %q, want %q", buf.String(), "hello")
		}
	})

	t.Run("exceeds limit", func(t *testing.T) {
		var buf bytes.Buffer
		lw := &limitedWriter{buf: &buf, limit: 5}
		n, err := lw.Write([]byte("hello world"))
		if err != nil {
			t.Fatalf("Write() error: %v", err)
		}
		// Should report full length written (to avoid io.ErrShortWrite).
		if n != 11 {
			t.Errorf("Write() = %d, want 11", n)
		}
		if buf.String() != "hello" {
			t.Errorf("buf = %q, want %q", buf.String(), "hello")
		}
	})

	t.Run("at limit", func(t *testing.T) {
		var buf bytes.Buffer
		lw := &limitedWriter{buf: &buf, limit: 5}
		lw.Write([]byte("hello"))
		// Now at limit, further writes should be discarded.
		n, err := lw.Write([]byte("world"))
		if err != nil {
			t.Fatalf("Write() error: %v", err)
		}
		if n != 5 {
			t.Errorf("Write() = %d, want 5 (discarded)", n)
		}
		if buf.String() != "hello" {
			t.Errorf("buf = %q, want %q", buf.String(), "hello")
		}
	})
}

// ---------------------------------------------------------------------------
// classifyArgs branch coverage
// ---------------------------------------------------------------------------

// TestManagerClassifyArgsWithNilClassifierOption verifies that classifyArgs
// uses the config classifier when the per-call classifier option is nil.
func TestManagerClassifyArgsWithNilClassifierOption(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// ExecArgs with no classifier option should use the default classifier.
	// "echo" is a safe command.
	result, err := mgr.ExecArgs(context.Background(), "echo", []string{"test"})
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("ExecArgs() error: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "test" {
		t.Errorf("Stdout = %q, want %q", got, "test")
	}
}

// TestManagerClassifyArgsWithCustomClassifier verifies that a per-call
// classifier overrides the config classifier for ExecArgs.
func TestManagerClassifyArgsWithCustomClassifier(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Custom classifier that forbids everything via ClassifyArgs.
	forbidAll := &ruleClassifier{
		rules: []rule{
			{
				Name: "forbid-all-args",
				MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
					return ClassifyResult{
						Decision: Forbidden,
						Reason:   "all commands forbidden",
						Rule:     "forbid-all-args",
					}, true
				},
			},
		},
	}

	_, err = mgr.ExecArgs(context.Background(), "echo", []string{"test"}, WithClassifier(forbidAll))
	if !errors.Is(err, ErrForbiddenCommand) {
		t.Errorf("ExecArgs() with forbid-all classifier: got %v, want ErrForbiddenCommand", err)
	}
}

// ---------------------------------------------------------------------------
// Wrap branch coverage
// ---------------------------------------------------------------------------

// TestManagerWrapSingleArg verifies Wrap with a command that has only
// one arg (no additional arguments).
func TestManagerWrapSingleArg(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Single arg command (just the program name, no extra args).
	cmd := exec.Command("echo")
	err = mgr.Wrap(context.Background(), cmd)
	// Should not return a classification error for "echo".
	if errors.Is(err, ErrForbiddenCommand) {
		t.Error("Wrap() should not forbid 'echo'")
	}
}

// TestManagerWrapEmptyArgs verifies Wrap with a command that has empty Args
// returns an error (empty args are rejected).
func TestManagerWrapEmptyArgs(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Empty Args slice.
	cmd := &exec.Cmd{Path: "/bin/echo"}
	cmd.Args = nil
	err = mgr.Wrap(context.Background(), cmd)
	if !errors.Is(err, ErrNilCommand) {
		t.Errorf("Wrap() with empty args: got %v, want ErrNilCommand", err)
	}
}

// TestManagerWrapWithEnv verifies that per-call env is applied in Wrap.
func TestManagerWrapWithEnv(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Network.Mode = NetworkAllowed
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	cmd := exec.Command("/bin/echo", "test")
	err = mgr.Wrap(context.Background(), cmd, WithEnv("MY_VAR=hello"))
	// The env should be set on the cmd.
	if err != nil {
		// WrapCommand may fail on some platforms, but env should still be set.
		_ = err
	}
	found := false
	for _, e := range cmd.Env {
		if e == "MY_VAR=hello" {
			found = true
			break
		}
	}
	if !found {
		t.Error("MY_VAR=hello should be in cmd.Env after Wrap with WithEnv")
	}
}

func TestManagerWrapNilCmd(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	err = mgr.Wrap(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil cmd, got nil")
	}
	if !errors.Is(err, ErrNilCommand) {
		t.Errorf("expected ErrNilCommand, got: %v", err)
	}
}

// TestManagerExecWithWorkingDir verifies that WithWorkingDir sets cmd.Dir
// in the real manager.
func TestManagerExecWithWorkingDir(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	result, err := mgr.Exec(context.Background(), "pwd", WithWorkingDir("/tmp"))
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	got := strings.TrimSpace(result.Stdout)
	// On macOS, /tmp is a symlink to /private/tmp.
	if got != "/tmp" && got != "/private/tmp" {
		t.Errorf("Stdout = %q, want /tmp or /private/tmp", got)
	}
}

// TestManagerExecArgsWithWorkingDir verifies that WithWorkingDir sets cmd.Dir
// in ExecArgs.
func TestManagerExecArgsWithWorkingDir(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	result, err := mgr.ExecArgs(context.Background(), "/bin/sh", []string{"-c", "pwd"},
		WithWorkingDir("/tmp"),
	)
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("ExecArgs() error: %v", err)
	}
	got := strings.TrimSpace(result.Stdout)
	if got != "/tmp" && got != "/private/tmp" {
		t.Errorf("Stdout = %q, want /tmp or /private/tmp", got)
	}
}

// TestManagerExecWithTimeout verifies that WithTimeout cancels a long-running
// command in the real manager.
func TestManagerExecWithTimeout(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	start := time.Now()
	result, err := mgr.Exec(context.Background(), "sleep 30", WithTimeout(100*time.Millisecond))
	elapsed := time.Since(start)

	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
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

// ---------------------------------------------------------------------------
// Coverage gap: ExecArgs timeout branch (L385-389)
// ---------------------------------------------------------------------------

func TestManagerExecArgsWithTimeout(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	start := time.Now()
	result, err := mgr.ExecArgs(context.Background(), "sleep", []string{"30"},
		WithTimeout(100*time.Millisecond),
	)
	elapsed := time.Since(start)

	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
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

func TestRunCommandNonExitError(t *testing.T) {
	useStubPlatform(t)
	cfg := DefaultConfig()
	cfg.FallbackPolicy = FallbackWarn
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// ExecArgs with a nonexistent binary triggers a non-ExitError
	// because exec.Command cannot find the binary.
	_, err = mgr.ExecArgs(context.Background(), "/nonexistent/binary/xyz", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}
	// The error should NOT be ErrForbiddenCommand.
	if errors.Is(err, ErrForbiddenCommand) {
		t.Error("error should not be ErrForbiddenCommand")
	}
}

// TestManagerExecFailClosedDefault verifies that newManager returns an error
// when FallbackPolicy is FallbackStrict and the platform is unavailable.
func TestManagerExecFailClosedDefault(t *testing.T) {
	// Use real platform detection (not the test stub) to verify fail-closed behavior.
	origDetect := detectPlatformFn
	detectPlatformFn = platform.Detect
	defer func() { detectPlatformFn = origDetect }()

	cfg := DefaultConfig()
	cfg.FallbackPolicy = FallbackStrict
	_, err := newManager(cfg)
	if err == nil {
		// On platforms where the platform is available, this test is not applicable.
		t.Skip("platform available; fail-closed test not applicable on this platform")
	}
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("expected ErrUnsupportedPlatform, got: %v", err)
	}
}

// TestManagerExecFallbackWarnContinues verifies that WrapCommand failure
// allows execution to continue when FallbackPolicy is FallbackWarn.
func TestManagerExecFallbackWarnContinues(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.FallbackPolicy = FallbackWarn
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	result, err := mgr.Exec(context.Background(), "echo fallback_test")
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "fallback_test" {
		t.Errorf("Stdout = %q, want %q", got, "fallback_test")
	}
	// On platforms where WrapCommand fails, Sandboxed should be false.
	// On platforms where it succeeds, Sandboxed should be true.
	// We just verify the command ran successfully.
}
