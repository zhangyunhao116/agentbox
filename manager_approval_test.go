package agentbox

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestManagerApproveSession verifies that ApproveSession caches the command
// so the callback is not invoked on subsequent calls with the same command.
func TestManagerApproveSession(t *testing.T) {
	cfg := newTestConfig(t)
	callCount := 0
	cfg.ApprovalCallback = func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		callCount++
		return ApproveSession, nil
	}
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}

	// First call: callback should be invoked.
	_, err = mgr.Exec(context.Background(), "echo approved", WithClassifier(escalateAll))
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("Exec() after approval should succeed, got: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("callback call count after first Exec = %d, want 1", callCount)
	}

	// Second call with same command: callback should be skipped (cached).
	_, err = mgr.Exec(context.Background(), "echo approved", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("Exec() after cached approval should succeed, got: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callback call count after second Exec = %d, want 1 (cached)", callCount)
	}
}

// TestManagerApproveDoesNotCache verifies that Approve does NOT cache the command,
// so the callback is invoked again on subsequent calls.
func TestManagerApproveDoesNotCache(t *testing.T) {
	cfg := newTestConfig(t)
	callCount := 0
	cfg.ApprovalCallback = func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		callCount++
		return Approve, nil
	}
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}

	// First call: callback invoked.
	_, err = mgr.Exec(context.Background(), "echo approved", WithClassifier(escalateAll))
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("Exec() after approval should succeed, got: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("callback call count after first Exec = %d, want 1", callCount)
	}

	// Second call: callback invoked again (not cached).
	_, err = mgr.Exec(context.Background(), "echo approved", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("Exec() after approval should succeed, got: %v", err)
	}
	if callCount != 2 {
		t.Errorf("callback call count after second Exec = %d, want 2 (not cached)", callCount)
	}
}

// TestManagerApproveSessionDifferentCommands verifies that session approval
// is per-command: different commands each trigger the callback.
func TestManagerApproveSessionDifferentCommands(t *testing.T) {
	cfg := newTestConfig(t)
	callCount := 0
	cfg.ApprovalCallback = func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		callCount++
		return ApproveSession, nil
	}
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}

	// First command.
	_, err = mgr.Exec(context.Background(), "echo approved", WithClassifier(escalateAll))
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("Exec() after approval should succeed, got: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("callback count after first command = %d, want 1", callCount)
	}

	// Different command: callback should be invoked again.
	_, err = mgr.Exec(context.Background(), "echo different", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("Exec() after approval should succeed, got: %v", err)
	}
	if callCount != 2 {
		t.Errorf("callback count after second (different) command = %d, want 2", callCount)
	}

	// Repeat first command: should be cached.
	_, err = mgr.Exec(context.Background(), "echo approved", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("Exec() after cached approval should succeed, got: %v", err)
	}
	if callCount != 2 {
		t.Errorf("callback count after repeat of first command = %d, want 2 (cached)", callCount)
	}
}

// ---------------------------------------------------------------------------
// Approval callback error path
// ---------------------------------------------------------------------------

// TestManagerApprovalCallbackError verifies that an error from the approval
// callback is propagated.
func TestManagerApprovalCallbackError(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.ApprovalCallback = func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		return Deny, errors.New("callback error")
	}
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	_, err = mgr.Exec(context.Background(), "echo test", WithClassifier(escalateAll))
	if !errors.Is(err, ErrEscalatedCommand) {
		t.Errorf("Exec() with callback error: got %v, want ErrEscalatedCommand", err)
	}
	if !strings.Contains(err.Error(), "callback error") {
		t.Errorf("error should contain 'callback error', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Zero-value safety
// ---------------------------------------------------------------------------

// TestManagerApprovalUnsetDecision verifies that a callback returning the
// zero value of ApprovalDecision (approvalUnset) is treated as deny.
func TestManagerApprovalUnsetDecision(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.ApprovalCallback = func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		// Return the zero value — simulates a callback that forgets to set
		// the return value via named returns.
		var d ApprovalDecision
		return d, nil
	}
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	_, err = mgr.Exec(context.Background(), "echo test", WithClassifier(escalateAll))
	if !errors.Is(err, ErrEscalatedCommand) {
		t.Fatalf("expected ErrEscalatedCommand for zero-value decision, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error wrapping verification (Go 1.20+ multi-%w)
// ---------------------------------------------------------------------------

// TestErrorWrappingApprovalCallback verifies that the approval callback error
// is properly wrapped with %w so both errors are in the chain.
func TestErrorWrappingApprovalCallback(t *testing.T) {
	cfg := newTestConfig(t)
	innerErr := errors.New("inner callback error")
	cfg.ApprovalCallback = func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		return Deny, innerErr
	}
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}
	_, err = mgr.Exec(context.Background(), "echo test", WithClassifier(escalateAll))
	if !errors.Is(err, ErrEscalatedCommand) {
		t.Errorf("error should wrap ErrEscalatedCommand, got: %v", err)
	}
	// With %w, the inner error should also be in the chain.
	if !errors.Is(err, innerErr) {
		t.Errorf("error should wrap inner callback error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Cache normalization
// ---------------------------------------------------------------------------

// TestManagerApproveSessionCacheNormalized verifies that session approval
// cache normalizes whitespace.
func TestManagerApproveSessionCacheNormalized(t *testing.T) {
	cfg := newTestConfig(t)
	callCount := 0
	cfg.ApprovalCallback = func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		callCount++
		return ApproveSession, nil
	}
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "needs approval"}}

	// First call with extra whitespace.
	_, err = mgr.Exec(context.Background(), "echo  hello", WithClassifier(escalateAll))
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
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

// ---------------------------------------------------------------------------
// ExecArgs with approval
// ---------------------------------------------------------------------------

// TestManagerExecArgsApproved verifies that ExecArgs works with approval.
func TestManagerExecArgsApproved(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.ApprovalCallback = func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
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
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("ExecArgs() after approval should succeed, got: %v", err)
	}
}
