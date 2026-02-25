package agentbox

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
)

// nopManager is a pass-through Manager that executes commands without
// any sandboxing. It is returned when FallbackWarn is set and the
// platform sandbox is unavailable.
type nopManager struct {
	mu               sync.Mutex
	closed           bool
	classifier       Classifier
	approvalCb       ApprovalCallback
	sessionApprovals map[string]struct{}
}

// NewNopManager creates a Manager that passes through all commands
// without sandboxing. Useful for testing or when sandbox isolation
// is not required.
func NewNopManager() Manager {
	n := &nopManager{
		classifier:       DefaultClassifier(),
		sessionApprovals: make(map[string]struct{}),
	}
	return n
}

// newNopManagerWithConfig creates a nopManager using the classifier from cfg
// and the provided approval callback. If cfg is nil or cfg.Classifier is nil,
// DefaultClassifier() is used. Used internally when FallbackWarn is active.
func newNopManagerWithConfig(cfg *Config) Manager {
	cl := DefaultClassifier()
	var cb ApprovalCallback
	if cfg != nil {
		if cfg.Classifier != nil {
			cl = cfg.Classifier
		}
		cb = cfg.ApprovalCallback
	}
	return &nopManager{
		classifier:       cl,
		approvalCb:       cb,
		sessionApprovals: make(map[string]struct{}),
	}
}

// newNopManagerWithApproval creates a nopManager with an approval callback
// for handling escalated commands. Uses DefaultClassifier().
func newNopManagerWithApproval(cb ApprovalCallback) Manager {
	return newNopManagerWithConfig(&Config{ApprovalCallback: cb})
}

func (n *nopManager) Wrap(ctx context.Context, cmd *exec.Cmd, opts ...Option) error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return ErrManagerClosed
	}
	cl := n.classifier
	n.mu.Unlock()
	if cmd == nil {
		return ErrNilCommand
	}

	co := mergeCallOptions(opts...)

	// Reject commands with empty Args to prevent unclassified execution.
	if len(cmd.Args) == 0 {
		return fmt.Errorf("%w: cmd.Args must not be empty", ErrNilCommand)
	}

	// Classify the command from cmd.Args.
	if co.classifier != nil {
		cl = co.classifier
	}
	var result ClassifyResult
	if len(cmd.Args) > 1 {
		result = cl.ClassifyArgs(cmd.Args[0], cmd.Args[1:])
	} else {
		result = cl.ClassifyArgs(cmd.Args[0], nil)
	}

	command := buildCommandKey(cmd.Args[0], cmd.Args[1:])
	if err := n.handleDecision(ctx, result, command); err != nil {
		return err
	}

	// Apply per-call env vars.
	if len(co.env) > 0 {
		cmd.Env = append(cmd.Environ(), co.env...)
	}

	return nil // no-op: command is left unmodified (no sandbox wrapping)
}

func (n *nopManager) Exec(ctx context.Context, command string, opts ...Option) (*ExecResult, error) {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil, ErrManagerClosed
	}
	cl := n.classifier
	n.mu.Unlock()

	co := mergeCallOptions(opts...)

	// Apply per-call timeout BEFORE classification and approval.
	if co.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, co.timeout)
		defer cancel()
	}

	// Classify the command.
	if co.classifier != nil {
		cl = co.classifier
	}
	clResult := cl.Classify(command)
	if err := n.handleDecision(ctx, clResult, command); err != nil {
		return nil, err
	}

	shell := defaultShell
	if co.shell != "" {
		shell = co.shell
	}
	cmd := exec.CommandContext(ctx, shell, "-c", command)

	// Apply per-call working directory.
	if co.workingDir != "" {
		cmd.Dir = co.workingDir
	}

	// Apply per-call env vars.
	if len(co.env) > 0 {
		cmd.Env = append(cmd.Environ(), co.env...)
	}

	return n.execCommand(cmd, co.maxOutputBytes)
}

func (n *nopManager) ExecArgs(ctx context.Context, name string, args []string, opts ...Option) (*ExecResult, error) {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil, ErrManagerClosed
	}
	cl := n.classifier
	n.mu.Unlock()

	co := mergeCallOptions(opts...)

	// Apply per-call timeout BEFORE classification and approval.
	if co.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, co.timeout)
		defer cancel()
	}

	// Classify the command.
	if co.classifier != nil {
		cl = co.classifier
	}
	clResult := cl.ClassifyArgs(name, args)
	command := buildCommandKey(name, args)
	if err := n.handleDecision(ctx, clResult, command); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, name, args...)

	// Apply per-call working directory.
	if co.workingDir != "" {
		cmd.Dir = co.workingDir
	}

	// Apply per-call env vars.
	if len(co.env) > 0 {
		cmd.Env = append(cmd.Environ(), co.env...)
	}

	return n.execCommand(cmd, co.maxOutputBytes)
}

// execCommand runs a prepared *exec.Cmd and returns an ExecResult.
// This is the shared implementation used by both Exec and ExecArgs.
// maxOutput limits captured stdout/stderr; 0 means no limit.
func (n *nopManager) execCommand(cmd *exec.Cmd, maxOutput int) (*ExecResult, error) {
	return execHelper(cmd, maxOutput, false)
}

// handleDecision checks the classification result and returns an error for
// Forbidden or Escalated (without approval) commands.
func (n *nopManager) handleDecision(ctx context.Context, result ClassifyResult, command string) error {
	switch result.Decision {
	case Forbidden:
		return &ForbiddenCommandError{Command: command, Reason: result.Reason}
	case Escalated:
		// Check session-level approval cache and snapshot the callback under
		// the lock so that concurrent UpdateConfig calls do not race.
		normalizedCmd := normalizeCommand(command)
		n.mu.Lock()
		_, cached := n.sessionApprovals[normalizedCmd]
		cb := n.approvalCb
		n.mu.Unlock()
		if cached {
			return nil
		}

		if cb == nil {
			return &EscalatedCommandError{Command: command, Reason: result.Reason}
		}
		decision, err := cb(ctx, ApprovalRequest{
			Command:  command,
			Reason:   result.Reason,
			Decision: result.Decision,
		})
		if err != nil {
			return fmt.Errorf("%w: %w", &EscalatedCommandError{Command: command, Reason: result.Reason}, err)
		}
		switch decision {
		case Approve:
			// fall through to return nil
		case ApproveSession:
			n.mu.Lock()
			n.sessionApprovals[normalizedCmd] = struct{}{}
			n.mu.Unlock()
		default:
			// Treat unknown/unset decisions as deny for safety.
			return &EscalatedCommandError{Command: command, Reason: "denied by user"}
		}
		return nil
	default:
		return nil
	}
}

func (n *nopManager) Check(_ context.Context, command string) (ClassifyResult, error) {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return ClassifyResult{}, ErrManagerClosed
	}
	cl := n.classifier
	n.mu.Unlock()
	return cl.Classify(command), nil
}

func (n *nopManager) Cleanup(_ context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closed = true
	return nil
}

func (n *nopManager) Available() bool { return true }

func (n *nopManager) CheckDependencies() *DependencyCheck {
	return &DependencyCheck{}
}

// UpdateConfig validates the new configuration and stores it.
// Since nopManager does not enforce sandboxing, only validation is performed.
func (n *nopManager) UpdateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("%w: config must not be nil", ErrConfigInvalid)
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return ErrManagerClosed
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	// Update the classifier if the new config provides one.
	if cfg.Classifier != nil {
		n.classifier = cfg.Classifier
	}

	// Update the approval callback.
	n.approvalCb = cfg.ApprovalCallback

	return nil
}
