//go:build darwin

package darwin

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- parseLine tests ---

func TestParseLine_DenyWithParenOperation(t *testing.T) {
	line := `2026-02-16 10:00:00.000 Tt sandbox[1234] deny(file-write-data) /tmp/secret.txt`
	ev := parseLine(line)
	if ev == nil {
		t.Fatal("expected non-nil event for deny line")
	}
	if ev.Operation != "file-write-data" {
		t.Errorf("operation = %q, want %q", ev.Operation, "file-write-data")
	}
	if ev.Path != "/tmp/secret.txt" {
		t.Errorf("path = %q, want %q", ev.Path, "/tmp/secret.txt")
	}
	if ev.RawLine != line {
		t.Errorf("raw line mismatch")
	}
}

func TestParseLine_DenyWithSpaceOperation(t *testing.T) {
	line := `2026-02-16 10:00:00.000 Tt myapp[5678] deny network-outbound`
	ev := parseLine(line)
	if ev == nil {
		t.Fatal("expected non-nil event for deny line")
	}
	if ev.Operation != "network-outbound" {
		t.Errorf("operation = %q, want %q", ev.Operation, "network-outbound")
	}
}

func TestParseLine_NonDenyLine(t *testing.T) {
	line := `2026-02-16 10:00:00.000 Tt myapp[5678] allow file-read-data /usr/lib/libSystem.B.dylib`
	ev := parseLine(line)
	if ev != nil {
		t.Errorf("expected nil for non-deny line, got %+v", ev)
	}
}

func TestParseLine_NoiseFiltering(t *testing.T) {
	noisy := []string{
		`2026-02-16 10:00:00.000 Tt mDNSResponder[100] deny(network-outbound) /some/path`,
		`2026-02-16 10:00:00.000 Tt diagnosticd[200] deny(file-read-data) /var/log`,
		`2026-02-16 10:00:00.000 Tt symptomsd[300] deny(file-write-data) /tmp/x`,
		`2026-02-16 10:00:00.000 Tt syslogd[400] deny(file-read-data) /var/log/syslog`,
		`2026-02-16 10:00:00.000 Tt logd[500] deny(file-read-data) /var/log/system.log`,
		`2026-02-16 10:00:00.000 Tt opendirectoryd[600] deny(file-read-data) /etc/passwd`,
		`2026-02-16 10:00:00.000 Tt trustd[700] deny(file-read-data) /etc/ssl`,
		`2026-02-16 10:00:00.000 Tt securityd[800] deny(file-read-data) /etc/ssl`,
	}
	for _, line := range noisy {
		ev := parseLine(line)
		if ev != nil {
			t.Errorf("expected nil for noise line %q, got %+v", line, ev)
		}
	}
}

func TestParseLine_Base64Command(t *testing.T) {
	cmd := "/usr/bin/curl"
	encoded := base64.StdEncoding.EncodeToString([]byte(cmd))
	line := `2026-02-16 10:00:00.000 Tt sandbox[1234] deny(network-outbound) LOGTAG:` + encoded
	ev := parseLine(line)
	if ev == nil {
		t.Fatal("expected non-nil event")
	}
	if ev.Command != cmd {
		t.Errorf("command = %q, want %q", ev.Command, cmd)
	}
}

func TestParseLine_FallbackProcessName(t *testing.T) {
	line := `2026-02-16 10:00:00.000 Tt myprocess[9999] deny(file-write-data) /tmp/test`
	ev := parseLine(line)
	if ev == nil {
		t.Fatal("expected non-nil event")
	}
	if ev.Command != "myprocess" {
		t.Errorf("command = %q, want %q", ev.Command, "myprocess")
	}
}

func TestParseLine_EmptyLine(t *testing.T) {
	if ev := parseLine(""); ev != nil {
		t.Errorf("expected nil for empty line, got %+v", ev)
	}
}

func TestParseLine_PathExtraction(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "path after deny paren",
			line: `2026-02-16 Tt app[1] deny(file-read-data) /etc/passwd`,
			want: "/etc/passwd",
		},
		{
			name: "path in quotes",
			line: `2026-02-16 Tt app[1] deny(file-write-data) "/var/tmp/file.txt" extra`,
			want: "/var/tmp/file.txt",
		},
		{
			name: "no path",
			line: `2026-02-16 Tt app[1] deny(network-outbound) somehost:443`,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := parseLine(tt.line)
			if ev == nil {
				t.Fatal("expected non-nil event")
			}
			if ev.Path != tt.want {
				t.Errorf("path = %q, want %q", ev.Path, tt.want)
			}
		})
	}
}

// --- extractOperation tests ---

func TestExtractOperation(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"deny(file-write-data) /tmp/x", "file-write-data"},
		{"deny(network-outbound)", "network-outbound"},
		{"deny file-read-data /etc/passwd", "file-read-data"},
		{"no operation here", ""},
	}
	for _, tt := range tests {
		got := extractOperation(tt.line)
		if got != tt.want {
			t.Errorf("extractOperation(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

// --- extractPath tests ---

func TestExtractPath(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"deny(file-write-data) /tmp/secret.txt", "/tmp/secret.txt"},
		{`deny(file-write-data) "/var/log/test.log" more`, "/var/log/test.log"},
		{"deny(network-outbound) host:443", ""},
		{"no path here", ""},
	}
	for _, tt := range tests {
		got := extractPath(tt.line)
		if got != tt.want {
			t.Errorf("extractPath(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

// --- extractCommand tests ---

func TestExtractCommand(t *testing.T) {
	cmd := "/usr/bin/python3"
	encoded := base64.StdEncoding.EncodeToString([]byte(cmd))

	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "LOGTAG base64",
			line: fmt.Sprintf("deny(file-write-data) LOGTAG:%s /tmp/x", encoded),
			want: cmd,
		},
		{
			name: "process name fallback",
			line: "2026-02-16 Tt myapp[1234] deny(file-write-data)",
			want: "myapp",
		},
		{
			name: "no command info",
			line: "deny something",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCommand(tt.line)
			if got != tt.want {
				t.Errorf("extractCommand(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// --- ViolationMonitor tests ---

func TestNewViolationMonitor_DefaultSize(t *testing.T) {
	m := NewViolationMonitor(0)
	if m.maxSize != 100 {
		t.Errorf("maxSize = %d, want 100", m.maxSize)
	}
}

func TestNewViolationMonitor_NegativeSize(t *testing.T) {
	m := NewViolationMonitor(-5)
	if m.maxSize != 100 {
		t.Errorf("maxSize = %d, want 100", m.maxSize)
	}
}

func TestNewViolationMonitor_CustomSize(t *testing.T) {
	m := NewViolationMonitor(50)
	if m.maxSize != 50 {
		t.Errorf("maxSize = %d, want 50", m.maxSize)
	}
}

func TestViolationMonitor_CircularBuffer(t *testing.T) {
	m := NewViolationMonitor(3)

	// Add 5 violations to a buffer of size 3.
	for i := 0; i < 5; i++ {
		m.addViolation(ViolationEvent{
			Operation: fmt.Sprintf("op-%d", i),
			RawLine:   fmt.Sprintf("line-%d", i),
		})
	}

	violations := m.Violations()
	if len(violations) != 3 {
		t.Fatalf("len(violations) = %d, want 3", len(violations))
	}

	// Should have the last 3 violations (op-2, op-3, op-4).
	for i, v := range violations {
		want := fmt.Sprintf("op-%d", i+2)
		if v.Operation != want {
			t.Errorf("violations[%d].Operation = %q, want %q", i, v.Operation, want)
		}
	}
}

func TestViolationMonitor_CircularBuffer_ExactSize(t *testing.T) {
	m := NewViolationMonitor(3)

	// Add exactly maxSize violations.
	for i := 0; i < 3; i++ {
		m.addViolation(ViolationEvent{
			Operation: fmt.Sprintf("op-%d", i),
		})
	}

	violations := m.Violations()
	if len(violations) != 3 {
		t.Fatalf("len(violations) = %d, want 3", len(violations))
	}
	for i, v := range violations {
		want := fmt.Sprintf("op-%d", i)
		if v.Operation != want {
			t.Errorf("violations[%d].Operation = %q, want %q", i, v.Operation, want)
		}
	}
}

func TestViolationMonitor_ViolationsForCommand(t *testing.T) {
	m := NewViolationMonitor(10)

	m.addViolation(ViolationEvent{Command: "curl", Operation: "network-outbound"})
	m.addViolation(ViolationEvent{Command: "python3", Operation: "file-write-data"})
	m.addViolation(ViolationEvent{Command: "curl", Operation: "file-read-data"})
	m.addViolation(ViolationEvent{Command: "node", Operation: "network-outbound"})

	curlViolations := m.ViolationsForCommand("curl")
	if len(curlViolations) != 2 {
		t.Fatalf("len(curlViolations) = %d, want 2", len(curlViolations))
	}
	for _, v := range curlViolations {
		if v.Command != "curl" {
			t.Errorf("unexpected command %q in curl violations", v.Command)
		}
	}

	pythonViolations := m.ViolationsForCommand("python3")
	if len(pythonViolations) != 1 {
		t.Fatalf("len(pythonViolations) = %d, want 1", len(pythonViolations))
	}

	noMatch := m.ViolationsForCommand("ruby")
	if len(noMatch) != 0 {
		t.Errorf("expected no violations for ruby, got %d", len(noMatch))
	}
}

func TestViolationMonitor_ViolationsForCommand_Substring(t *testing.T) {
	m := NewViolationMonitor(10)
	m.addViolation(ViolationEvent{Command: "/usr/bin/curl", Operation: "network-outbound"})

	// Substring match should work.
	results := m.ViolationsForCommand("curl")
	if len(results) != 1 {
		t.Errorf("expected 1 result for substring match, got %d", len(results))
	}
}

func TestViolationMonitor_OnViolation(t *testing.T) {
	m := NewViolationMonitor(10)

	var received []ViolationEvent
	var mu sync.Mutex

	m.OnViolation(func(v ViolationEvent) {
		mu.Lock()
		received = append(received, v)
		mu.Unlock()
	})

	m.addViolation(ViolationEvent{Operation: "file-write-data", Path: "/tmp/test"})
	m.addViolation(ViolationEvent{Operation: "network-outbound"})

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("callback received %d events, want 2", len(received))
	}
	if received[0].Operation != "file-write-data" {
		t.Errorf("first event operation = %q, want %q", received[0].Operation, "file-write-data")
	}
	if received[1].Operation != "network-outbound" {
		t.Errorf("second event operation = %q, want %q", received[1].Operation, "network-outbound")
	}
}

func TestViolationMonitor_MultipleListeners(t *testing.T) {
	m := NewViolationMonitor(10)

	var count1, count2 atomic.Int32

	m.OnViolation(func(_ ViolationEvent) { count1.Add(1) })
	m.OnViolation(func(_ ViolationEvent) { count2.Add(1) })

	m.addViolation(ViolationEvent{Operation: "test"})

	if got := count1.Load(); got != 1 {
		t.Errorf("listener1 count = %d, want 1", got)
	}
	if got := count2.Load(); got != 1 {
		t.Errorf("listener2 count = %d, want 1", got)
	}
}

func TestViolationMonitor_ViolationsReturnsCopy(t *testing.T) {
	m := NewViolationMonitor(10)
	m.addViolation(ViolationEvent{Operation: "op1"})

	v1 := m.Violations()
	v1[0].Operation = "modified"

	v2 := m.Violations()
	if v2[0].Operation != "op1" {
		t.Errorf("Violations() did not return a copy; mutation leaked")
	}
}

func TestViolationMonitor_ConcurrentAccess(t *testing.T) {
	m := NewViolationMonitor(50)

	var wg sync.WaitGroup
	const goroutines = 10
	const opsPerGoroutine = 100

	// Writers.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				m.addViolation(ViolationEvent{
					Operation: fmt.Sprintf("op-%d-%d", id, j),
					Command:   fmt.Sprintf("cmd-%d", id),
				})
			}
		}(i)
	}

	// Readers.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				_ = m.Violations()
				_ = m.ViolationsForCommand("cmd-0")
			}
		}()
	}

	// Listener registrations.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.OnViolation(func(_ ViolationEvent) {})
		}()
	}

	wg.Wait()

	// Buffer should not exceed maxSize.
	violations := m.Violations()
	if len(violations) > 50 {
		t.Errorf("buffer exceeded maxSize: len = %d, maxSize = 50", len(violations))
	}
}

// --- Start/Stop lifecycle tests ---

func TestViolationMonitor_StartStop(t *testing.T) {
	// Use WithLogStreamCommand to set a custom command for testing.
	cmd := []string{"sh", "-c", `while true; do echo 'deny(file-write-data) /tmp/test'; sleep 0.1; done`}

	m := NewViolationMonitor(10, WithLogStreamCommand(cmd))
	ctx := context.Background()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Give it a moment to process some lines.
	time.Sleep(300 * time.Millisecond)

	if err := m.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}

	violations := m.Violations()
	if len(violations) == 0 {
		t.Error("expected at least one violation after monitoring")
	}
}

func TestViolationMonitor_DoubleStart(t *testing.T) {
	cmd := []string{"sh", "-c", "sleep 10"}

	m := NewViolationMonitor(10, WithLogStreamCommand(cmd))
	ctx := context.Background()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("first Start() error: %v", err)
	}
	defer m.Stop()

	err := m.Start(ctx)
	if err == nil {
		t.Error("expected error on double Start()")
	}
}

func TestViolationMonitor_StopWithoutStart(t *testing.T) {
	m := NewViolationMonitor(10)
	err := m.Stop()
	if err == nil {
		t.Error("expected error on Stop() without Start()")
	}
}

func TestViolationMonitor_ContextCancellation(t *testing.T) {
	cmd := []string{"sh", "-c", "sleep 60"}

	m := NewViolationMonitor(10, WithLogStreamCommand(cmd))
	ctx, cancel := context.WithCancel(context.Background())

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Cancel the parent context; the monitor should stop.
	cancel()

	// Stop should still work (it calls its own cancel which is already done).
	err := m.Stop()
	if err != nil {
		t.Errorf("Stop() after context cancel: %v", err)
	}
}

// --- Session ID and Log Tag tests ---

func TestSessionIDGeneration(t *testing.T) {
	m1 := NewViolationMonitor(10)
	m2 := NewViolationMonitor(10)

	// Session IDs should be unique.
	if m1.SessionID() == m2.SessionID() {
		t.Errorf("session IDs should be unique, both are %q", m1.SessionID())
	}

	// Session ID should have correct format: _<hex>_SBX
	sid := m1.SessionID()
	if !strings.HasPrefix(sid, "_") {
		t.Errorf("session ID should start with '_', got %q", sid)
	}
	if !strings.HasSuffix(sid, "_SBX") {
		t.Errorf("session ID should end with '_SBX', got %q", sid)
	}
	// The hex part should be 16 chars (8 bytes = 16 hex digits).
	// Format: _{16 hex chars}_SBX
	parts := strings.Split(sid, "_")
	// parts: ["", hex, "SBX"]
	if len(parts) != 3 {
		t.Errorf("session ID format unexpected: %q, parts: %v", sid, parts)
	} else if len(parts[1]) != 16 {
		t.Errorf("hex part should be 16 chars, got %d: %q", len(parts[1]), parts[1])
	}
}

func TestGenerateLogTag(t *testing.T) {
	m := NewViolationMonitor(10)
	command := "ls -la /tmp"
	tag := m.GenerateLogTag(command)

	// Tag should have format: CMD64_{base64}_END{sessionID}
	if !strings.HasPrefix(tag, "CMD64_") {
		t.Errorf("log tag should start with 'CMD64_', got %q", tag)
	}
	if !strings.HasSuffix(tag, m.SessionID()) {
		t.Errorf("log tag should end with session ID %q, got %q", m.SessionID(), tag)
	}
	if !strings.Contains(tag, "_END") {
		t.Errorf("log tag should contain '_END', got %q", tag)
	}

	// Verify the base64 part decodes to the original command.
	prefix := "CMD64_"
	endIdx := strings.Index(tag, "_END")
	encoded := tag[len(prefix):endIdx]
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("failed to decode base64 in log tag: %v", err)
	}
	if string(decoded) != command {
		t.Errorf("decoded command = %q, want %q", string(decoded), command)
	}
}

func TestShouldIgnoreWildcard(t *testing.T) {
	m := NewViolationMonitor(10, WithIgnorePatterns(IgnoreViolationsConfig{
		"*": {"/usr/lib", "/System"},
	}))

	// Wildcard should match any command.
	if !m.shouldIgnore("curl", "deny(file-read-data) /usr/lib/libSystem.B.dylib") {
		t.Error("expected wildcard pattern to match /usr/lib path")
	}
	if !m.shouldIgnore("python3", "deny(file-read-data) /System/Library/Frameworks") {
		t.Error("expected wildcard pattern to match /System path")
	}
	if m.shouldIgnore("curl", "deny(file-read-data) /tmp/secret.txt") {
		t.Error("wildcard pattern should not match /tmp/secret.txt")
	}
}

func TestShouldIgnoreCommandSpecific(t *testing.T) {
	m := NewViolationMonitor(10, WithIgnorePatterns(IgnoreViolationsConfig{
		"curl": {"/etc/ssl"},
		"git":  {"/usr/share/git-core"},
	}))

	// Command-specific exact match.
	if !m.shouldIgnore("curl", "deny(file-read-data) /etc/ssl/certs/ca-certificates.crt") {
		t.Error("expected curl pattern to match /etc/ssl path")
	}
	// Prefix match with space (e.g., "curl --insecure").
	if !m.shouldIgnore("curl --insecure", "deny(file-read-data) /etc/ssl/certs") {
		t.Error("expected curl pattern to match via prefix with space")
	}
	// Substring should NOT match (e.g., "/usr/bin/curl" should not match "curl").
	if m.shouldIgnore("/usr/bin/curl", "deny(file-read-data) /etc/ssl/certs") {
		t.Error("/usr/bin/curl should not match curl pattern (not exact or prefix+space)")
	}
	// Different command should not match.
	if m.shouldIgnore("python3", "deny(file-read-data) /etc/ssl/certs") {
		t.Error("python3 should not match curl pattern")
	}
	// Git pattern.
	if !m.shouldIgnore("git", "deny(file-read-data) /usr/share/git-core/templates") {
		t.Error("expected git pattern to match")
	}
}

func TestShouldIgnoreNoMatch(t *testing.T) {
	m := NewViolationMonitor(10, WithIgnorePatterns(IgnoreViolationsConfig{
		"curl": {"/etc/ssl"},
	}))

	// Non-matching command.
	if m.shouldIgnore("python3", "deny(file-write-data) /tmp/test") {
		t.Error("should not ignore non-matching command")
	}
	// Matching command but non-matching path.
	if m.shouldIgnore("curl", "deny(network-outbound) evil.com:443") {
		t.Error("should not ignore non-matching path")
	}
}

func TestShouldIgnoreNilConfig(t *testing.T) {
	m := NewViolationMonitor(10)

	// Nil config should never ignore.
	if m.shouldIgnore("curl", "deny(file-read-data) /etc/ssl/certs") {
		t.Error("nil config should not ignore anything")
	}
}

func TestMonitorWithIgnorePatterns(t *testing.T) {
	patterns := IgnoreViolationsConfig{
		"*":    {"/usr/lib"},
		"curl": {"/etc/ssl"},
	}
	m := NewViolationMonitor(10, WithIgnorePatterns(patterns))

	if m.ignorePatterns == nil {
		t.Fatal("ignore patterns should be set")
	}
	if len(m.ignorePatterns) != 2 {
		t.Errorf("expected 2 pattern groups, got %d", len(m.ignorePatterns))
	}
	wildcardPaths, ok := m.ignorePatterns["*"]
	if !ok {
		t.Fatal("missing wildcard pattern")
	}
	if len(wildcardPaths) != 1 || wildcardPaths[0] != "/usr/lib" {
		t.Errorf("wildcard paths = %v, want [/usr/lib]", wildcardPaths)
	}
}

func TestMonitorSessionFiltering(t *testing.T) {
	m := NewViolationMonitor(10)
	sid := m.SessionID()

	// Verify the default log stream command uses the session ID.
	cmd := defaultLogStreamCommand(sid)
	found := false
	for _, arg := range cmd {
		if strings.Contains(arg, sid) {
			found = true
			// Should use ENDSWITH predicate.
			if !strings.Contains(arg, "ENDSWITH") {
				t.Errorf("predicate should use ENDSWITH, got %q", arg)
			}
			break
		}
	}
	if !found {
		t.Errorf("session ID %q not found in log stream command %v", sid, cmd)
	}
}

// ---------------------------------------------------------------------------
// MEDIUM 2: extractCommand works with GenerateLogTag output
// ---------------------------------------------------------------------------

func TestExtractCommandWithGenerateLogTag(t *testing.T) {
	m := NewViolationMonitor(10)
	command := "ls -la /tmp"
	tag := m.GenerateLogTag(command)

	// Build a log line containing the tag.
	line := fmt.Sprintf("2026-02-16 10:00:00.000 Tt sandbox[1234] deny(file-read-data) %s /tmp/test", tag)

	extracted := extractCommand(line)
	if extracted != command {
		t.Errorf("extractCommand with GenerateLogTag: got %q, want %q", extracted, command)
	}
}

func TestExtractCommandWithCMD64Format(t *testing.T) {
	// Test CMD64_ format directly.
	command := "/usr/bin/python3"
	encoded := base64.RawURLEncoding.EncodeToString([]byte(command))
	line := fmt.Sprintf("deny(file-write-data) CMD64_%s_END_abc123_SBX /tmp/x", encoded)

	extracted := extractCommand(line)
	if extracted != command {
		t.Errorf("extractCommand with CMD64_ format: got %q, want %q", extracted, command)
	}
}

func TestExtractCommandFallsBackToLOGTAG(t *testing.T) {
	// Legacy LOGTAG format should still work.
	command := "/usr/bin/curl"
	encoded := base64.StdEncoding.EncodeToString([]byte(command))
	line := "deny(network-outbound) LOGTAG:" + encoded

	extracted := extractCommand(line)
	if extracted != command {
		t.Errorf("extractCommand with LOGTAG format: got %q, want %q", extracted, command)
	}
}

// ---------------------------------------------------------------------------
// MEDIUM 1: matchCommand tests
// ---------------------------------------------------------------------------

func TestMatchCommand(t *testing.T) {
	tests := []struct {
		command string
		pattern string
		want    bool
	}{
		{"curl", "curl", true},
		{"curl --insecure", "curl", true},
		{"curl", "cur", false},
		{"/usr/bin/curl", "curl", false},
		{"securlib", "curl", false},
		{"git", "git", true},
		{"git push", "git", true},
		{"", "curl", false},
		{"curl", "", false},
	}

	for _, tt := range tests {
		got := matchCommand(tt.command, tt.pattern)
		if got != tt.want {
			t.Errorf("matchCommand(%q, %q) = %v, want %v", tt.command, tt.pattern, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// HIGH 3: WithLogStreamCommand option test
// ---------------------------------------------------------------------------

func TestWithLogStreamCommand(t *testing.T) {
	cmd := []string{"echo", "test"}
	m := NewViolationMonitor(10, WithLogStreamCommand(cmd))

	if len(m.logStreamCmd) != 2 || m.logStreamCmd[0] != "echo" {
		t.Errorf("WithLogStreamCommand did not set logStreamCmd correctly: %v", m.logStreamCmd)
	}
}

// ---------------------------------------------------------------------------
// LOW 1: generateSessionID fallback test
// ---------------------------------------------------------------------------

func TestGenerateSessionIDFormat(t *testing.T) {
	sid := generateSessionID()
	if !strings.HasPrefix(sid, "_") {
		t.Errorf("session ID should start with '_', got %q", sid)
	}
	if !strings.HasSuffix(sid, "_SBX") {
		t.Errorf("session ID should end with '_SBX', got %q", sid)
	}
}
