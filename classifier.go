package agentbox

// unknownStr is the string representation for unknown enum values.
const unknownStr = "unknown"

// Classifier determines how a command should be handled by the sandbox.
// Implementations inspect the command string or argument list and return
// a classification decision.
type Classifier interface {
	// Classify inspects a shell command string and returns a classification result.
	Classify(command string) ClassifyResult

	// ClassifyArgs inspects a command specified as a program name and argument list.
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

// ClassifyResult holds the outcome of command classification.
type ClassifyResult struct {
	// Decision is the classification decision.
	Decision Decision

	// Reason is a human-readable explanation of why this decision was made.
	Reason string

	// Rule is the identifier of the rule that matched, if any.
	Rule string
}
