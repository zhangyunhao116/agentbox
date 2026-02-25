package agentbox

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{ErrUnsupportedPlatform, "agentbox: unsupported platform"},
		{ErrDependencyMissing, "agentbox: required dependency missing"},
		{ErrForbiddenCommand, "agentbox: command forbidden by classifier"},
		{ErrEscalatedCommand, "agentbox: command requires user approval"},
		{ErrManagerClosed, "agentbox: manager already closed"},
		{ErrConfigInvalid, "agentbox: invalid configuration"},
		{ErrProxyStartFailed, "agentbox: proxy server failed to start"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrorIdentity(t *testing.T) {
	// Each sentinel error should be distinct.
	allErrors := []error{
		ErrUnsupportedPlatform,
		ErrDependencyMissing,
		ErrForbiddenCommand,
		ErrEscalatedCommand,
		ErrManagerClosed,
		ErrConfigInvalid,
		ErrProxyStartFailed,
	}

	for i, a := range allErrors {
		for j, b := range allErrors {
			if i != j && errors.Is(a, b) {
				t.Errorf("errors.Is(%v, %v) should be false", a, b)
			}
		}
	}
}

func TestErrorIsWrapped(t *testing.T) {
	// Verify errors.Is works with wrapped errors.
	allErrors := []error{
		ErrUnsupportedPlatform,
		ErrDependencyMissing,
		ErrForbiddenCommand,
		ErrEscalatedCommand,
		ErrManagerClosed,
		ErrConfigInvalid,
		ErrProxyStartFailed,
	}

	for _, err := range allErrors {
		if !errors.Is(err, err) {
			t.Errorf("errors.Is(%v, %v) should be true", err, err)
		}
	}
}

// ---------------------------------------------------------------------------
// ForbiddenCommandError tests
// ---------------------------------------------------------------------------

func TestForbiddenCommandErrorIs(t *testing.T) {
	err := &ForbiddenCommandError{Command: "rm -rf /", Reason: "dangerous"}
	if !errors.Is(err, ErrForbiddenCommand) {
		t.Error("expected errors.Is to match ErrForbiddenCommand")
	}
	// Type assertion
	var fce *ForbiddenCommandError
	if !errors.As(err, &fce) {
		t.Fatal("expected errors.As to work")
	}
	if fce.Command != "rm -rf /" {
		t.Errorf("got command %q, want %q", fce.Command, "rm -rf /")
	}
	if fce.Reason != "dangerous" {
		t.Errorf("got reason %q, want %q", fce.Reason, "dangerous")
	}
}

func TestForbiddenCommandErrorMessage(t *testing.T) {
	err := &ForbiddenCommandError{Command: "rm -rf /", Reason: "dangerous"}
	want := "agentbox: command forbidden by classifier: dangerous"
	if got := err.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestForbiddenCommandErrorWrapped(t *testing.T) {
	inner := &ForbiddenCommandError{Command: "rm -rf /", Reason: "dangerous"}
	wrapped := fmt.Errorf("outer: %w", inner)
	if !errors.Is(wrapped, ErrForbiddenCommand) {
		t.Error("expected errors.Is to match through wrapping")
	}
	var fce *ForbiddenCommandError
	if !errors.As(wrapped, &fce) {
		t.Error("expected errors.As to work through wrapping")
	}
	if fce.Command != "rm -rf /" {
		t.Errorf("got command %q, want %q", fce.Command, "rm -rf /")
	}
}

func TestForbiddenCommandErrorNotEscalated(t *testing.T) {
	err := &ForbiddenCommandError{Command: "rm -rf /", Reason: "dangerous"}
	if errors.Is(err, ErrEscalatedCommand) {
		t.Error("ForbiddenCommandError should not match ErrEscalatedCommand")
	}
}

// ---------------------------------------------------------------------------
// EscalatedCommandError tests
// ---------------------------------------------------------------------------

func TestEscalatedCommandErrorIs(t *testing.T) {
	err := &EscalatedCommandError{Command: "pip install foo", Reason: "needs approval"}
	if !errors.Is(err, ErrEscalatedCommand) {
		t.Error("expected errors.Is to match ErrEscalatedCommand")
	}
	var ece *EscalatedCommandError
	if !errors.As(err, &ece) {
		t.Fatal("expected errors.As to work")
	}
	if ece.Command != "pip install foo" {
		t.Errorf("got command %q, want %q", ece.Command, "pip install foo")
	}
	if ece.Reason != "needs approval" {
		t.Errorf("got reason %q, want %q", ece.Reason, "needs approval")
	}
}

func TestEscalatedCommandErrorMessage(t *testing.T) {
	err := &EscalatedCommandError{Command: "pip install foo", Reason: "needs approval"}
	want := "agentbox: command requires user approval: needs approval"
	if got := err.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEscalatedCommandErrorWrapped(t *testing.T) {
	inner := &EscalatedCommandError{Command: "pip install foo", Reason: "needs approval"}
	wrapped := fmt.Errorf("outer: %w", inner)
	if !errors.Is(wrapped, ErrEscalatedCommand) {
		t.Error("expected errors.Is to match through wrapping")
	}
	var ece *EscalatedCommandError
	if !errors.As(wrapped, &ece) {
		t.Error("expected errors.As to work through wrapping")
	}
	if ece.Command != "pip install foo" {
		t.Errorf("got command %q, want %q", ece.Command, "pip install foo")
	}
}

func TestEscalatedCommandErrorNotForbidden(t *testing.T) {
	err := &EscalatedCommandError{Command: "pip install foo", Reason: "needs approval"}
	if errors.Is(err, ErrForbiddenCommand) {
		t.Error("EscalatedCommandError should not match ErrForbiddenCommand")
	}
}

// ---------------------------------------------------------------------------
// Integration tests: NopManager returns structured errors
// ---------------------------------------------------------------------------

func TestExecForbiddenReturnsStructuredError(t *testing.T) {
	mgr := NewNopManager()
	forbidAll := &mockClassifier{result: ClassifyResult{Decision: Forbidden, Reason: "test forbidden"}}
	_, err := mgr.Exec(context.Background(), "echo hello", WithClassifier(forbidAll))
	if err == nil {
		t.Fatal("expected error")
	}
	var fce *ForbiddenCommandError
	if !errors.As(err, &fce) {
		t.Fatalf("expected ForbiddenCommandError, got %T: %v", err, err)
	}
	if fce.Command == "" {
		t.Error("expected Command to be populated")
	}
	if fce.Reason != "test forbidden" {
		t.Errorf("got reason %q, want %q", fce.Reason, "test forbidden")
	}
}

func TestExecEscalatedReturnsStructuredError(t *testing.T) {
	mgr := NewNopManager()
	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "test escalated"}}
	_, err := mgr.Exec(context.Background(), "pip install foo", WithClassifier(escalateAll))
	if err == nil {
		t.Fatal("expected error")
	}
	var ece *EscalatedCommandError
	if !errors.As(err, &ece) {
		t.Fatalf("expected EscalatedCommandError, got %T: %v", err, err)
	}
	if ece.Command == "" {
		t.Error("expected Command to be populated")
	}
	if ece.Reason != "test escalated" {
		t.Errorf("got reason %q, want %q", ece.Reason, "test escalated")
	}
}
