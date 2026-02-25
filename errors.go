package agentbox

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by the agentbox package.
var (
	// ErrUnsupportedPlatform indicates the current OS/architecture is not supported.
	ErrUnsupportedPlatform = errors.New("agentbox: unsupported platform")

	// ErrDependencyMissing indicates a required system dependency is not available.
	ErrDependencyMissing = errors.New("agentbox: required dependency missing")

	// ErrForbiddenCommand indicates the command was rejected by the classifier.
	ErrForbiddenCommand = errors.New("agentbox: command forbidden by classifier")

	// ErrEscalatedCommand indicates the command requires user approval before execution.
	ErrEscalatedCommand = errors.New("agentbox: command requires user approval")

	// ErrManagerClosed indicates the manager has already been closed via Cleanup.
	ErrManagerClosed = errors.New("agentbox: manager already closed")

	// ErrConfigInvalid indicates the provided configuration failed validation.
	ErrConfigInvalid = errors.New("agentbox: invalid configuration")

	// ErrProxyStartFailed indicates the network proxy server could not be started.
	ErrProxyStartFailed = errors.New("agentbox: proxy server failed to start")

	// ErrNilCommand indicates a nil *exec.Cmd was passed to Wrap.
	ErrNilCommand = errors.New("agentbox: cmd must not be nil")
)

// ForbiddenCommandError is returned when a command is rejected by the classifier.
// It wraps ErrForbiddenCommand so that errors.Is(err, ErrForbiddenCommand) still works.
type ForbiddenCommandError struct {
	// Command is the command string that was forbidden.
	Command string
	// Reason explains why the command was forbidden.
	Reason string
}

func (e *ForbiddenCommandError) Error() string {
	return fmt.Sprintf("%s: %s", ErrForbiddenCommand.Error(), e.Reason)
}

func (e *ForbiddenCommandError) Unwrap() error {
	return ErrForbiddenCommand
}

// EscalatedCommandError is returned when a command requires user approval.
// It wraps ErrEscalatedCommand so that errors.Is(err, ErrEscalatedCommand) still works.
type EscalatedCommandError struct {
	// Command is the command string that was escalated.
	Command string
	// Reason explains why the command was escalated.
	Reason string
}

func (e *EscalatedCommandError) Error() string {
	return fmt.Sprintf("%s: %s", ErrEscalatedCommand.Error(), e.Reason)
}

func (e *EscalatedCommandError) Unwrap() error {
	return ErrEscalatedCommand
}
