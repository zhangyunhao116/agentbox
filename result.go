package agentbox

import "time"

// ExecResult holds the outcome of a sandboxed command execution.
type ExecResult struct {
	// ExitCode is the process exit code. 0 typically indicates success.
	ExitCode int

	// Stdout contains the captured standard output of the process.
	Stdout string

	// Stderr contains the captured standard error of the process.
	Stderr string

	// Duration is the wall-clock time the process took to execute.
	Duration time.Duration

	// Sandboxed indicates whether the command was executed inside a sandbox.
	Sandboxed bool

	// Truncated indicates whether the output was truncated due to size limits.
	Truncated bool

	// Violations contains any sandbox policy violations detected during execution.
	// This field is reserved for future use and is currently always nil.
	Violations []Violation
}

// ViolationType represents the kind of sandbox policy violation.
type ViolationType string

const (
	ViolationFileRead  ViolationType = "file-read"
	ViolationFileWrite ViolationType = "file-write"
	ViolationNetwork   ViolationType = "network"
	ViolationProcess   ViolationType = "process"
	ViolationOther     ViolationType = "other"
)

// Violation represents a single sandbox policy violation detected during execution.
type Violation struct {
	// Operation is the type of operation that was denied (e.g., "file-write", "network").
	Operation ViolationType

	// Path is the filesystem path involved in the violation, if applicable.
	Path string

	// Detail is a human-readable description of the violation.
	Detail string

	// Process is the name of the process that triggered the violation.
	Process string

	// Raw is the raw violation message from the platform sandbox.
	Raw string
}
