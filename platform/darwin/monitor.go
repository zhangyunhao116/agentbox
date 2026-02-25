//go:build darwin

package darwin

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// defaultLogStreamCommand returns the default log stream command
// filtered by the given session suffix.
func defaultLogStreamCommand(sessionID string) []string {
	return []string{
		"log", "stream",
		"--predicate", fmt.Sprintf("eventMessage ENDSWITH %q", sessionID),
		"--style", "compact",
	}
}

// noiseProcesses lists system processes whose sandbox violations are
// considered noise and should be filtered out.
var noiseProcesses = []string{
	"mDNSResponder",
	"diagnosticd",
	"symptomsd",
	"syslogd",
	"logd",
	"opendirectoryd",
	"trustd",
	"securityd",
}

// ViolationEvent represents a single sandbox violation detected from
// the macOS system log.
type ViolationEvent struct {
	Timestamp time.Time
	Operation string // e.g., "file-write-data", "network-outbound"
	Path      string // affected path, if any
	Command   string // the command that caused the violation
	RawLine   string // raw log line
}

// IgnoreViolationsConfig maps command patterns to violation path patterns to ignore.
// The special key "*" matches all commands.
type IgnoreViolationsConfig map[string][]string

// ViolationMonitor watches the macOS system log for sandbox violations.
type ViolationMonitor struct {
	mu             sync.Mutex
	violations     []ViolationEvent
	maxSize        int // circular buffer size
	listeners      []func(ViolationEvent)
	cmd            *exec.Cmd
	cancel         context.CancelFunc
	done           chan struct{}
	sessionID      string                 // unique session identifier for filtering
	ignorePatterns IgnoreViolationsConfig // configurable ignore patterns
	logStreamCmd   []string               // custom log stream command (for testing)
}

// MonitorOption configures a ViolationMonitor.
type MonitorOption func(*ViolationMonitor)

// WithIgnorePatterns returns a MonitorOption that sets ignore patterns.
func WithIgnorePatterns(patterns IgnoreViolationsConfig) MonitorOption {
	return func(m *ViolationMonitor) {
		m.ignorePatterns = patterns
	}
}

// WithLogStreamCommand returns a MonitorOption that sets a custom log stream
// command. This is primarily used for testing to avoid depending on the real
// macOS log stream.
func WithLogStreamCommand(cmd []string) MonitorOption {
	return func(m *ViolationMonitor) {
		m.logStreamCmd = cmd
	}
}

// generateSessionID creates a unique session identifier suffix.
func generateSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("_%d_SBX", time.Now().UnixNano())
	}
	return fmt.Sprintf("_%x_SBX", b)
}

// NewViolationMonitor creates a new monitor with the given buffer size.
// If maxSize <= 0, defaults to 100.
func NewViolationMonitor(maxSize int, opts ...MonitorOption) *ViolationMonitor {
	if maxSize <= 0 {
		maxSize = 100
	}
	m := &ViolationMonitor{
		violations: make([]ViolationEvent, 0, maxSize),
		maxSize:    maxSize,
		sessionID:  generateSessionID(),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// SessionID returns the unique session identifier for this monitor.
func (m *ViolationMonitor) SessionID() string {
	return m.sessionID
}

// GenerateLogTag generates a log tag for the given command that can be
// used to correlate log entries with this monitor session.
func (m *ViolationMonitor) GenerateLogTag(command string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(command))
	return fmt.Sprintf("CMD64_%s_END%s", encoded, m.sessionID)
}

// Start begins monitoring the system log for sandbox violations.
// It spawns a `log stream` subprocess filtered for sandbox deny messages.
func (m *ViolationMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return errors.New("monitor already started")
	}

	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.done = make(chan struct{})

	cmdArgs := m.logStreamCmd
	if len(cmdArgs) == 0 {
		cmdArgs = defaultLogStreamCommand(m.sessionID)
	}
	if len(cmdArgs) < 2 {
		m.cancel = nil
		cancel()
		m.mu.Unlock()
		return errors.New("invalid log stream command")
	}

	//nolint:gosec // command is controlled by monitor option or default
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	m.cmd = cmd

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		m.cancel = nil
		cancel()
		m.mu.Unlock()
		return fmt.Errorf("creating stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		m.cancel = nil
		cancel()
		m.mu.Unlock()
		return fmt.Errorf("starting log stream: %w", err)
	}
	m.mu.Unlock()

	go func() {
		defer close(m.done)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if ev := parseLine(line); ev != nil {
				if m.shouldIgnore(ev.Command, ev.Path+" "+ev.RawLine) {
					continue
				}
				m.addViolation(*ev)
			}
		}
		// Wait for the process to finish; ignore errors from context
		// cancellation since that is the normal shutdown path.
		_ = cmd.Wait()
	}()

	return nil
}

// Stop gracefully stops the monitor.
func (m *ViolationMonitor) Stop() error {
	m.mu.Lock()
	cancel := m.cancel
	done := m.done
	m.cancel = nil
	m.mu.Unlock()

	if cancel == nil {
		return errors.New("monitor not started")
	}

	cancel()

	if done != nil {
		<-done
	}
	return nil
}

// Violations returns a copy of all recorded violations.
func (m *ViolationMonitor) Violations() []ViolationEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]ViolationEvent, len(m.violations))
	copy(result, m.violations)
	return result
}

// ViolationsForCommand returns violations matching the given command string.
func (m *ViolationMonitor) ViolationsForCommand(command string) []ViolationEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []ViolationEvent
	for _, v := range m.violations {
		if strings.Contains(v.Command, command) {
			result = append(result, v)
		}
	}
	return result
}

// OnViolation registers a callback for new violations.
func (m *ViolationMonitor) OnViolation(fn func(ViolationEvent)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, fn)
}

// addViolation adds a violation to the circular buffer and notifies listeners.
func (m *ViolationMonitor) addViolation(v ViolationEvent) {
	m.mu.Lock()
	if len(m.violations) >= m.maxSize {
		// Drop the oldest entry to maintain circular buffer semantics.
		copy(m.violations, m.violations[1:])
		m.violations = m.violations[:len(m.violations)-1]
	}
	m.violations = append(m.violations, v)
	// Copy listeners slice so we can release the lock before calling them.
	listeners := make([]func(ViolationEvent), len(m.listeners))
	copy(listeners, m.listeners)
	m.mu.Unlock()

	for _, fn := range listeners {
		fn(v)
	}
}

// matchCommand checks whether a command matches a pattern using exact match
// or prefix match with a space separator. This prevents false positives from
// substring matching (e.g., "curl" should not match "securlib").
func matchCommand(command, pattern string) bool {
	return command == pattern || strings.HasPrefix(command, pattern+" ")
}

// shouldIgnore checks whether a violation should be ignored based on
// the configured ignore patterns.
func (m *ViolationMonitor) shouldIgnore(command, violationDetails string) bool {
	if m.ignorePatterns == nil {
		return false
	}
	// Check wildcard patterns first.
	if wildcardPaths, ok := m.ignorePatterns["*"]; ok {
		for _, p := range wildcardPaths {
			if strings.Contains(violationDetails, p) {
				return true
			}
		}
	}
	// Check command-specific patterns.
	for pattern, paths := range m.ignorePatterns {
		if pattern == "*" {
			continue
		}
		if matchCommand(command, pattern) {
			for _, p := range paths {
				if strings.Contains(violationDetails, p) {
					return true
				}
			}
		}
	}
	return false
}

// parseLine parses a log stream line into a ViolationEvent.
// Returns nil if the line is not a sandbox violation.
func parseLine(line string) *ViolationEvent {
	// Must contain "deny" to be a sandbox violation.
	if !strings.Contains(line, "deny") {
		return nil
	}

	// Filter out noise from known system processes.
	for _, proc := range noiseProcesses {
		if strings.Contains(line, proc) {
			return nil
		}
	}

	ev := &ViolationEvent{
		Timestamp: time.Now(),
		RawLine:   line,
	}

	// Extract operation: look for common sandbox operation patterns.
	// Operations typically appear as "deny(OP)" or "deny OP" in log lines.
	ev.Operation = extractOperation(line)

	// Extract path if present.
	ev.Path = extractPath(line)

	// Try to decode base64-encoded command from LOGTAG:base64command format.
	ev.Command = extractCommand(line)

	return ev
}

// extractOperation extracts the sandbox operation from a log line.
// It looks for patterns like "deny(file-write-data)" or "deny file-write-data".
func extractOperation(line string) string {
	// Try "deny(operation)" pattern first.
	idx := strings.Index(line, "deny(")
	if idx >= 0 {
		start := idx + len("deny(")
		end := strings.Index(line[start:], ")")
		if end > 0 {
			return line[start : start+end]
		}
	}

	// Try "deny operation" pattern (space-separated).
	idx = strings.Index(line, "deny ")
	if idx >= 0 {
		rest := line[idx+len("deny "):]
		// The operation is the next whitespace-delimited token.
		end := strings.IndexAny(rest, " \t,;)")
		if end > 0 {
			return rest[:end]
		}
		if len(rest) > 0 {
			return rest
		}
	}

	return ""
}

// extractPath extracts a file path from a log line.
// It looks for absolute paths (starting with /) in the line.
func extractPath(line string) string {
	// Look for path patterns in the log line. Paths in sandbox logs
	// typically appear after the operation, often in parentheses or
	// after a colon.
	idx := 0
	for idx < len(line) {
		slashIdx := strings.Index(line[idx:], "/")
		if slashIdx < 0 {
			break
		}
		pos := idx + slashIdx

		// Must be an absolute path (preceded by space, paren, or start of line).
		if pos > 0 {
			prev := line[pos-1]
			if prev != ' ' && prev != '(' && prev != '\t' && prev != '"' {
				idx = pos + 1
				continue
			}
		}

		// Extract the path until a delimiter.
		end := strings.IndexAny(line[pos:], " \t)\"',;")
		if end > 0 {
			return line[pos : pos+end]
		}
		return line[pos:]
	}
	return ""
}

// extractCommand tries to extract a command from the log line.
// It first looks for a CMD64_{base64}_END pattern (matching GenerateLogTag output),
// then falls back to the legacy LOGTAG:base64command pattern, and finally
// extracts the process name from the log line.
func extractCommand(line string) string {
	// Look for CMD64_{base64}_END pattern (matches GenerateLogTag output).
	const cmd64Prefix = "CMD64_"
	const cmd64Sep = "_END"
	if idx := strings.Index(line, cmd64Prefix); idx >= 0 {
		rest := line[idx+len(cmd64Prefix):]
		endIdx := strings.Index(rest, cmd64Sep)
		if endIdx > 0 {
			encoded := rest[:endIdx]
			if decoded, err := base64.RawURLEncoding.DecodeString(encoded); err == nil && len(decoded) > 0 {
				return string(decoded)
			}
		}
	}

	// Fallback: look for legacy LOGTAG:base64command pattern.
	const tagPrefix = "LOGTAG:"
	if idx := strings.Index(line, tagPrefix); idx >= 0 {
		encoded := line[idx+len(tagPrefix):]
		// The base64 string ends at the next whitespace or end of line.
		end := strings.IndexAny(encoded, " \t\n,;)")
		if end > 0 {
			encoded = encoded[:end]
		}
		if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil && len(decoded) > 0 {
			return string(decoded)
		}
		// Try URL-safe or raw encoding as fallback.
		if decoded, err := base64.RawStdEncoding.DecodeString(encoded); err == nil && len(decoded) > 0 {
			return string(decoded)
		}
	}

	// Fallback: try to extract process name from compact log format.
	// Compact format typically looks like:
	//   TIMESTAMP Tt PROCESS[PID] ...
	return extractProcessName(line)
}

// extractProcessName extracts the process name from a compact log line.
// The compact format is: "TIMESTAMP Tt PROCESS[PID] ..."
func extractProcessName(line string) string {
	// Split on whitespace and look for a token containing "[" (PID bracket).
	fields := strings.Fields(line)
	for _, f := range fields {
		if bracketIdx := strings.Index(f, "["); bracketIdx > 0 {
			name := f[:bracketIdx]
			// Skip if it looks like a timestamp or hex value.
			if len(name) > 0 && name[0] != '0' {
				return name
			}
		}
	}
	return ""
}
