package agentbox

import "fmt"

// unknownStr is the string representation for unknown enum values.
const unknownStr = "unknown"

// Classifier determines how a command should be handled by the sandbox.
// Implementations inspect the command string or argument list and return
// a classification decision.
type Classifier interface {
	// Classify inspects a shell command string and returns a classification result.
	Classify(command string) ClassifyResult

	// ClassifyArgs classifies a command given its base name and argument list.
	// Implementations should handle a nil or empty args slice gracefully,
	// typically treating it as a command with no arguments.
	ClassifyArgs(name string, args []string) ClassifyResult
}

// Decision represents the classification outcome for a command.
type Decision int

const (
	// Sandboxed indicates the command should be executed within the sandbox.
	// It is the zero value, so an uninitialized ClassifyResult defaults to
	// the safest decision.
	Sandboxed Decision = iota

	// Allow indicates the command is safe and can be executed (still sandboxed).
	Allow

	// Escalated indicates the command requires user approval before execution.
	Escalated

	// Forbidden indicates the command must not be executed.
	Forbidden
)

// String returns the string representation of a Decision.
func (d Decision) String() string {
	switch d {
	case Sandboxed:
		return "sandboxed"
	case Allow:
		return "allow"
	case Escalated:
		return "escalated"
	case Forbidden:
		return "forbidden"
	default:
		return unknownStr
	}
}

// MarshalText implements encoding.TextMarshaler.
// It encodes the Decision as its string representation (e.g., "sandboxed", "allow").
func (d Decision) MarshalText() ([]byte, error) {
	s := d.String()
	if s == unknownStr {
		return nil, fmt.Errorf("agentbox: cannot marshal unknown Decision value %d", int(d))
	}
	return []byte(s), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
// It accepts the lowercase string representations: "sandboxed", "allow", "escalated", "forbidden".
func (d *Decision) UnmarshalText(text []byte) error {
	switch string(text) {
	case "sandboxed":
		*d = Sandboxed
	case "allow":
		*d = Allow
	case "escalated":
		*d = Escalated
	case "forbidden":
		*d = Forbidden
	default:
		return fmt.Errorf("unknown decision: %q", text)
	}
	return nil
}

// ClassifyResult holds the outcome of command classification.
type ClassifyResult struct {
	// Decision is the classification decision.
	Decision Decision `json:"decision"`

	// Reason is a human-readable explanation of why this decision was made.
	Reason string `json:"reason,omitempty"`

	// Rule is the identifier of the rule that matched, if any.
	Rule RuleName `json:"rule,omitempty"`
}

// String returns a human-readable representation of the classification result,
// for example "forbidden (reverse-shell: detected reverse shell pattern)".
func (r ClassifyResult) String() string {
	s := r.Decision.String()
	if r.Rule != "" {
		s += " (" + string(r.Rule)
		if r.Reason != "" {
			s += ": " + r.Reason
		}
		s += ")"
	} else if r.Reason != "" {
		s += " (" + r.Reason + ")"
	}
	return s
}
