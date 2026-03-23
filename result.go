package agentbox

import (
	"fmt"
	"time"
)

// ExecResult holds the outcome of a sandboxed command execution.
type ExecResult struct {
	// ExitCode is the process exit code. 0 typically indicates success.
	ExitCode int `json:"exitCode"`

	// Stdout contains the captured standard output of the process.
	Stdout string `json:"stdout"`

	// Stderr contains the captured standard error of the process.
	Stderr string `json:"stderr"`

	// Duration is the wall-clock time the process took to execute.
	Duration time.Duration `json:"duration"`

	// Sandboxed indicates whether the command was executed inside a sandbox.
	Sandboxed bool `json:"sandboxed"`

	// Truncated indicates whether the output was truncated due to size limits.
	Truncated bool `json:"truncated"`

	// Violations contains any sandbox policy violations detected during execution.
	// This field is reserved for future use and is currently always nil.
	Violations []Violation `json:"violations,omitempty"`
}

// String returns a human-readable summary of the execution result,
// for example "exit=0 sandboxed=true duration=42ms stdout=12B stderr=0B".
func (r *ExecResult) String() string {
	return fmt.Sprintf("exit=%d sandboxed=%t duration=%s stdout=%dB stderr=%dB",
		r.ExitCode, r.Sandboxed, r.Duration.Round(time.Millisecond), len(r.Stdout), len(r.Stderr))
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

// String returns the string representation of the violation type.
func (v ViolationType) String() string {
	return string(v)
}

// Violation represents a single sandbox policy violation detected during execution.
type Violation struct {
	// Operation is the type of operation that was denied (e.g., "file-write", "network").
	Operation ViolationType `json:"operation"`

	// Path is the filesystem path involved in the violation, if applicable.
	Path string `json:"path,omitempty"`

	// Detail is a human-readable description of the violation.
	Detail string `json:"detail,omitempty"`

	// Process is the name of the process that triggered the violation.
	Process string `json:"process,omitempty"`

	// Raw is the raw violation message from the platform sandbox.
	Raw string `json:"raw,omitempty"`
}
