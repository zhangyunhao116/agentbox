package agentbox

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"time"
)

// execHelper captures command output with size limits and returns an ExecResult.
// It encapsulates the shared output-capture, process-group setup, exit-code
// extraction, and truncation-detection logic used by both the sandboxed
// manager (runCommand) and the nopManager (execCommand).
//
// maxOutput limits captured stdout/stderr; 0 means no limit.
// sandboxed is recorded in the returned ExecResult.
func execHelper(cmd *exec.Cmd, maxOutput int, sandboxed bool) (*ExecResult, error) {
	var stdout, stderr bytes.Buffer
	var stdoutWriter, stderrWriter io.Writer
	stdoutWriter = &stdout
	stderrWriter = &stderr
	if maxOutput > 0 {
		stdoutWriter = &limitedWriter{buf: &stdout, limit: maxOutput}
		stderrWriter = &limitedWriter{buf: &stderr, limit: maxOutput}
	}
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter

	setupProcessGroup(cmd)

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
			err = nil // non-zero exit is not a Go error
		} else {
			return nil, err
		}
	}

	truncated := false
	if maxOutput > 0 {
		if stdout.Len() >= maxOutput || stderr.Len() >= maxOutput {
			truncated = true
		}
	}

	return &ExecResult{
		ExitCode:  exitCode,
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Duration:  duration,
		Sandboxed: sandboxed,
		Truncated: truncated,
	}, err
}
