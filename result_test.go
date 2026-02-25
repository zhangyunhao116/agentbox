package agentbox

import (
	"testing"
	"time"
)

func TestExecResultZeroValue(t *testing.T) {
	var r ExecResult
	if r.ExitCode != 0 {
		t.Errorf("ExitCode zero value: got %d, want 0", r.ExitCode)
	}
	if r.Stdout != "" {
		t.Errorf("Stdout zero value: got %q, want empty", r.Stdout)
	}
	if r.Stderr != "" {
		t.Errorf("Stderr zero value: got %q, want empty", r.Stderr)
	}
	if r.Duration != 0 {
		t.Errorf("Duration zero value: got %v, want 0", r.Duration)
	}
	if r.Sandboxed {
		t.Error("Sandboxed zero value: got true, want false")
	}
	if r.Truncated {
		t.Error("Truncated zero value: got true, want false")
	}
	if r.Violations != nil {
		t.Errorf("Violations zero value: got %v, want nil", r.Violations)
	}
}

func TestExecResultPopulated(t *testing.T) {
	r := ExecResult{
		ExitCode:  1,
		Stdout:    "hello",
		Stderr:    "error",
		Duration:  5 * time.Second,
		Sandboxed: true,
		Truncated: true,
		Violations: []Violation{
			{Operation: ViolationFileWrite, Path: "/etc/passwd", Process: "bash", Raw: "denied write"},
		},
	}

	if r.ExitCode != 1 {
		t.Errorf("ExitCode: got %d, want 1", r.ExitCode)
	}
	if r.Stdout != "hello" {
		t.Errorf("Stdout: got %q, want %q", r.Stdout, "hello")
	}
	if r.Stderr != "error" {
		t.Errorf("Stderr: got %q, want %q", r.Stderr, "error")
	}
	if r.Duration != 5*time.Second {
		t.Errorf("Duration: got %v, want %v", r.Duration, 5*time.Second)
	}
	if !r.Sandboxed {
		t.Error("Sandboxed: got false, want true")
	}
	if !r.Truncated {
		t.Error("Truncated: got false, want true")
	}
	if len(r.Violations) != 1 {
		t.Fatalf("Violations: got %d, want 1", len(r.Violations))
	}
	v := r.Violations[0]
	if v.Operation != ViolationFileWrite {
		t.Errorf("Violation.Operation: got %q, want %q", v.Operation, ViolationFileWrite)
	}
	if v.Path != "/etc/passwd" {
		t.Errorf("Violation.Path: got %q, want %q", v.Path, "/etc/passwd")
	}
	if v.Process != "bash" {
		t.Errorf("Violation.Process: got %q, want %q", v.Process, "bash")
	}
	if v.Raw != "denied write" {
		t.Errorf("Violation.Raw: got %q, want %q", v.Raw, "denied write")
	}
}

func TestViolationZeroValue(t *testing.T) {
	var v Violation
	if v.Operation != "" {
		t.Errorf("Operation zero value: got %q, want empty", v.Operation)
	}
	if v.Path != "" {
		t.Errorf("Path zero value: got %q, want empty", v.Path)
	}
	if v.Process != "" {
		t.Errorf("Process zero value: got %q, want empty", v.Process)
	}
	if v.Raw != "" {
		t.Errorf("Raw zero value: got %q, want empty", v.Raw)
	}
	if v.Detail != "" {
		t.Errorf("Detail zero value: got %q, want empty", v.Detail)
	}
}

func TestViolationType(t *testing.T) {
	tests := []struct {
		vt   ViolationType
		want string
	}{
		{ViolationFileRead, "file-read"},
		{ViolationFileWrite, "file-write"},
		{ViolationNetwork, "network"},
		{ViolationProcess, "process"},
		{ViolationOther, "other"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if string(tt.vt) != tt.want {
				t.Errorf("ViolationType: got %q, want %q", tt.vt, tt.want)
			}
		})
	}
}

func TestViolationTypeAssignment(t *testing.T) {
	v := Violation{
		Operation: ViolationFileWrite,
		Path:      "/etc/passwd",
		Detail:    "write denied",
	}
	if v.Operation != ViolationFileWrite {
		t.Errorf("Operation: got %q, want %q", v.Operation, ViolationFileWrite)
	}
	if v.Path != "/etc/passwd" {
		t.Errorf("Path: got %q, want %q", v.Path, "/etc/passwd")
	}
	if v.Detail != "write denied" {
		t.Errorf("Detail: got %q, want %q", v.Detail, "write denied")
	}
}
