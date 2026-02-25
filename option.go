package agentbox

import (
	"context"
	"time"
)

// Option configures a single Exec or Wrap call.
type Option func(*callOptions)

// callOptions holds per-call configuration applied via Option functions.
type callOptions struct {
	writableRoots  []string
	network        *NetworkConfig
	env            []string
	shell          string
	classifier     Classifier
	workingDir     string
	timeout        time.Duration
	denyRead       []string
	denyWrite      []string
	maxOutputBytes int
}

// ApprovalCallback is invoked when a command is classified as Escalated.
// The callback should prompt the user and return a decision.
type ApprovalCallback func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error)

// ApprovalRequest contains information about a command that requires approval.
type ApprovalRequest struct {
	// Command is the full command string that requires approval.
	Command string

	// Reason explains why the command was escalated.
	Reason string

	// Decision is the classifier's original decision.
	Decision Decision
}

// ApprovalDecision represents the user's response to an approval request.
type ApprovalDecision int

const (
	// approvalUnset is the zero value, treated as Deny for safety.
	// It is unexported to prevent direct use.
	approvalUnset ApprovalDecision = iota

	// Approve allows the command to execute this one time.
	Approve

	// Deny rejects the command.
	Deny

	// ApproveSession allows the command for the remainder of the session.
	ApproveSession
)

// String returns the string representation of an ApprovalDecision.
func (d ApprovalDecision) String() string {
	switch d {
	case approvalUnset:
		return "unset"
	case Approve:
		return "approve"
	case Deny:
		return "deny"
	case ApproveSession:
		return "approve_session"
	default:
		return unknownStr
	}
}

// WithWritableRoots adds additional writable root directories for a single call.
func WithWritableRoots(roots ...string) Option {
	cpy := append([]string(nil), roots...)
	return func(o *callOptions) {
		o.writableRoots = append(o.writableRoots, cpy...)
	}
}

// WithNetwork overrides the network configuration for a single call.
// The provided config is deep-copied to prevent aliasing.
func WithNetwork(cfg *NetworkConfig) Option {
	if cfg == nil {
		return func(o *callOptions) {
			o.network = nil
		}
	}
	cpy := *cfg
	cpy.AllowedDomains = append([]string(nil), cfg.AllowedDomains...)
	cpy.DeniedDomains = append([]string(nil), cfg.DeniedDomains...)
	cpy.AllowUnixSockets = append([]string(nil), cfg.AllowUnixSockets...)
	if cfg.MITMProxy != nil {
		mp := *cfg.MITMProxy
		mp.Domains = append([]string(nil), cfg.MITMProxy.Domains...)
		cpy.MITMProxy = &mp
	}
	return func(o *callOptions) {
		o.network = &cpy
	}
}

// WithEnv adds environment variables for a single call.
// Each entry should be in "KEY=VALUE" format.
func WithEnv(env ...string) Option {
	cpy := append([]string(nil), env...)
	return func(o *callOptions) {
		o.env = append(o.env, cpy...)
	}
}

// WithShell overrides the shell used for a single call.
func WithShell(shell string) Option {
	return func(o *callOptions) {
		o.shell = shell
	}
}

// WithClassifier overrides the classifier for a single call.
func WithClassifier(c Classifier) Option {
	return func(o *callOptions) {
		o.classifier = c
	}
}

// WithWorkingDir sets the working directory for a single call.
func WithWorkingDir(dir string) Option {
	return func(o *callOptions) {
		o.workingDir = dir
	}
}

// WithTimeout sets a timeout for a single call. If the command does not
// complete within the timeout, it is killed and an error is returned.
// This is a convenience wrapper around context.WithTimeout.
func WithTimeout(d time.Duration) Option {
	return func(o *callOptions) {
		o.timeout = d
	}
}

// WithDenyRead adds paths that should be denied read access for a single call.
func WithDenyRead(paths ...string) Option {
	cpy := append([]string(nil), paths...)
	return func(o *callOptions) {
		o.denyRead = append(o.denyRead, cpy...)
	}
}

// WithDenyWrite adds paths that should be denied write access for a single call.
func WithDenyWrite(paths ...string) Option {
	cpy := append([]string(nil), paths...)
	return func(o *callOptions) {
		o.denyWrite = append(o.denyWrite, cpy...)
	}
}

// WithMaxOutputBytes sets the maximum output size (in bytes) for a single call.
// When set to a positive value, stdout and stderr are each truncated to this limit.
func WithMaxOutputBytes(n int) Option {
	return func(o *callOptions) {
		o.maxOutputBytes = n
	}
}

