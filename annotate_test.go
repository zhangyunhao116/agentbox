package agentbox

import (
	"strings"
	"testing"
)

// TestAnnotateStderrEmpty verifies that no violations leaves stderr unchanged.
func TestAnnotateStderrEmpty(t *testing.T) {
	stderr := "some error output"
	result := annotateStderrWithViolations(stderr, nil)
	if result != stderr {
		t.Errorf("expected unchanged stderr %q, got %q", stderr, result)
	}

	result = annotateStderrWithViolations(stderr, []string{})
	if result != stderr {
		t.Errorf("expected unchanged stderr %q, got %q", stderr, result)
	}
}

// TestAnnotateStderrWithViolationsFormat verifies violations are appended in correct format.
func TestAnnotateStderrWithViolationsFormat(t *testing.T) {
	stderr := "command failed"
	violations := []string{"network access denied: example.com"}
	result := annotateStderrWithViolations(stderr, violations)

	if !strings.HasPrefix(result, stderr) {
		t.Errorf("result should start with original stderr")
	}
	if !strings.Contains(result, "<sandbox_violations>") {
		t.Error("result should contain <sandbox_violations> tag")
	}
	if !strings.Contains(result, "</sandbox_violations>") {
		t.Error("result should contain </sandbox_violations> tag")
	}
	if !strings.Contains(result, "network access denied: example.com") {
		t.Error("result should contain the violation message")
	}
}

// TestAnnotateStderrEmptyStderr verifies that empty stderr + violations produces just the violations block.
func TestAnnotateStderrEmptyStderr(t *testing.T) {
	violations := []string{"file write denied: /etc/passwd"}
	result := annotateStderrWithViolations("", violations)

	if !strings.Contains(result, "<sandbox_violations>") {
		t.Error("result should contain <sandbox_violations> tag")
	}
	if !strings.Contains(result, "file write denied: /etc/passwd") {
		t.Error("result should contain the violation message")
	}
	if !strings.Contains(result, "</sandbox_violations>") {
		t.Error("result should contain closing tag")
	}
}

// TestAnnotateStderrMultipleViolations verifies that multiple violations are all present.
func TestAnnotateStderrMultipleViolations(t *testing.T) {
	stderr := "error"
	violations := []string{
		"network access denied: evil.com",
		"file write denied: /etc/shadow",
		"process fork blocked",
	}
	result := annotateStderrWithViolations(stderr, violations)

	for _, v := range violations {
		if !strings.Contains(result, v) {
			t.Errorf("result should contain violation %q", v)
		}
	}

	// Verify the format: each violation on its own line within the tags.
	expected := "\n<sandbox_violations>\n" +
		"network access denied: evil.com\n" +
		"file write denied: /etc/shadow\n" +
		"process fork blocked\n" +
		"</sandbox_violations>"
	if !strings.HasSuffix(result, expected) {
		t.Errorf("result should end with violations block.\ngot:  %q\nwant suffix: %q", result, expected)
	}
}
