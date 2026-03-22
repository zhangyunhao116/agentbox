package agentbox

import (
	"context"
	"fmt"
	"time"
)

// Option configures a single Exec or Wrap call.
type Option func(*callOptions)

// ConfigOption configures a [Manager] via its [Config].
// Unlike [Option], which is per-call, a ConfigOption applies once at
// Manager-creation time.
//
// Usage:
//
//	cfg := agentbox.DefaultConfig()
//	agentbox.WithApprovalCache(agentbox.NewMemoryApprovalCache())(cfg)
//	mgr, err := agentbox.NewManager(cfg)
type ConfigOption func(*Config)

// callOptions holds per-call configuration applied via Option functions.
type callOptions struct {
	writableRoots  []string
	network        *NetworkConfig
	env            []string
	shell          string
	classifier     Classifier
	customRules    []UserRule
	protectedPaths []ProtectedPath
	ruleOverrides  []RuleOverride
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
	Command string `json:"command"`

	// Reason explains why the command was escalated.
	Reason string `json:"reason,omitempty"`

	// Decision is the classifier's original decision.
	Decision Decision `json:"decision"`

	// Rule is the name of the classification rule that triggered escalation.
	Rule RuleName `json:"rule,omitempty"`
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

// MarshalText implements encoding.TextMarshaler.
// It encodes the ApprovalDecision as its string representation (e.g., "approve", "deny").
func (d ApprovalDecision) MarshalText() ([]byte, error) {
	s := d.String()
	if s == unknownStr {
		return nil, fmt.Errorf("agentbox: cannot marshal unknown ApprovalDecision value %d", int(d))
	}
	return []byte(s), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
// It accepts the lowercase string representations: "approve", "deny", "approve_session".
func (d *ApprovalDecision) UnmarshalText(text []byte) error {
	switch string(text) {
	case "approve":
		*d = Approve
	case "deny":
		*d = Deny
	case "approve_session":
		*d = ApproveSession
	default:
		return fmt.Errorf("unknown approval decision: %q", text)
	}
	return nil
}

// WithWritableRoots adds additional writable root directories for a single call.
// An empty slice grants no additional writable paths beyond the defaults.
func WithWritableRoots(roots ...string) Option {
	cpy := append([]string(nil), roots...)
	return func(o *callOptions) {
		o.writableRoots = append(o.writableRoots, cpy...)
	}
}

// WithNetwork overrides the network configuration for a single call.
// The provided config is deep-copied to prevent aliasing.
// A nil config disables per-call network overrides, using the manager's default.
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
// An empty slice adds no environment variables.
func WithEnv(env ...string) Option {
	cpy := append([]string(nil), env...)
	return func(o *callOptions) {
		o.env = append(o.env, cpy...)
	}
}

// WithShell overrides the shell used for a single call.
// An empty string uses the platform default shell.
func WithShell(shell string) Option {
	return func(o *callOptions) {
		o.shell = shell
	}
}

// WithClassifier overrides the classifier for a single call.
// A nil classifier uses the manager's configured classifier.
func WithClassifier(c Classifier) Option {
	return func(o *callOptions) {
		o.classifier = c
	}
}

// WithCustomRules adds user-defined classification rules that are evaluated
// before built-in rules. This allows users to override the default behavior
// for specific commands. Rules are evaluated in order; the first match wins.
//
// Custom rules are chained before the effective classifier (whether the
// config-level or a per-call override from WithClassifier) using
// ChainClassifier, so unmatched commands fall through to built-in rules.
func WithCustomRules(rules ...UserRule) Option {
	cpy := make([]UserRule, len(rules))
	copy(cpy, rules)
	return func(o *callOptions) {
		o.customRules = append(o.customRules, cpy...)
	}
}

// WithWorkingDir sets the working directory for a single call.
// An empty string uses the command's existing working directory.
func WithWorkingDir(dir string) Option {
	return func(o *callOptions) {
		o.workingDir = dir
	}
}

// WithTimeout sets a timeout for a single call. If the command does not
// complete within the timeout, it is killed and an error is returned.
// A zero or negative duration means no timeout.
// This is a convenience wrapper around context.WithTimeout.
func WithTimeout(d time.Duration) Option {
	return func(o *callOptions) {
		o.timeout = d
	}
}

// WithDenyRead adds paths that should be denied read access for a single call.
// An empty slice does not deny any additional paths.
func WithDenyRead(paths ...string) Option {
	cpy := append([]string(nil), paths...)
	return func(o *callOptions) {
		o.denyRead = append(o.denyRead, cpy...)
	}
}

// WithDenyWrite adds paths that should be denied write access for a single call.
// An empty slice does not deny any additional paths.
func WithDenyWrite(paths ...string) Option {
	cpy := append([]string(nil), paths...)
	return func(o *callOptions) {
		o.denyWrite = append(o.denyWrite, cpy...)
	}
}

// WithMaxOutputBytes sets the maximum output size (in bytes) for a single call.
// When set to a positive value, stdout and stderr are each truncated to this limit.
// A value of zero means no output limit.
func WithMaxOutputBytes(n int) Option {
	return func(o *callOptions) {
		o.maxOutputBytes = n
	}
}

// WithProtectedPaths adds path protection rules that detect write operations
// targeting sensitive directories and files. Protected path rules are evaluated
// after custom user rules but before built-in rules in the classification chain.
func WithProtectedPaths(paths ...ProtectedPath) Option {
	cpy := make([]ProtectedPath, len(paths))
	copy(cpy, paths)
	return func(o *callOptions) {
		o.protectedPaths = append(o.protectedPaths, cpy...)
	}
}

// WithRuleOverrides changes the decision of specific built-in rules.
// Overrides are applied to the base classifier (or a per-call WithClassifier
// replacement) before custom rules and protected paths are chained on top.
//
// Classification evaluation order: custom rules (WithCustomRules) → protected
// paths (WithProtectedPaths) → rule overrides (WithRuleOverrides) → built-in
// rules. The first non-Sandboxed result wins.
//
// Example — allow docker runtime commands without approval:
//
//	mgr.Exec(ctx, "docker run ubuntu",
//	    agentbox.WithRuleOverrides(agentbox.RuleOverride{
//	        Rule:     agentbox.RuleDockerRuntime,
//	        Decision: agentbox.Allow,
//	    }),
//	)
func WithRuleOverrides(overrides ...RuleOverride) Option {
	cpy := make([]RuleOverride, len(overrides))
	copy(cpy, overrides)
	return func(o *callOptions) {
		o.ruleOverrides = append(o.ruleOverrides, cpy...)
	}
}

// WithDefaultProtectedPaths enables the default set of protected path rules.
// This protects .git/hooks, .agent, .claude, .vscode, .idea, and .env files.
func WithDefaultProtectedPaths() Option {
	return WithProtectedPaths(defaultProtectedPaths...)
}

// WithApprovalCache sets the approval cache on a Config for remembering
// user approval decisions. When set, escalated commands that have been
// previously approved or denied will not trigger the ApprovalCallback
// again. The cache is shared across all calls to the same Manager
// instance.
//
// This is a Config-level helper, not a per-call Option. Usage:
//
//	cfg := agentbox.DefaultConfig()
//	agentbox.WithApprovalCache(agentbox.NewMemoryApprovalCache())(cfg)
func WithApprovalCache(cache ApprovalCache) ConfigOption {
	return func(cfg *Config) {
		cfg.ApprovalCache = cache
	}
}
