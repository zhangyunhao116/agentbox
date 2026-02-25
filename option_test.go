package agentbox

import (
	"testing"
	"time"
)

// mockClassifier implements Classifier for testing.
type mockClassifier struct {
	result ClassifyResult
}

func (m *mockClassifier) Classify(command string) ClassifyResult {
	return m.result
}

func (m *mockClassifier) ClassifyArgs(name string, args []string) ClassifyResult {
	return m.result
}

func TestWithWritableRoots(t *testing.T) {
	opts := &callOptions{}
	WithWritableRoots("/tmp", "/var/tmp")(opts)

	if len(opts.writableRoots) != 2 {
		t.Fatalf("writableRoots: got %d entries, want 2", len(opts.writableRoots))
	}
	if opts.writableRoots[0] != "/tmp" {
		t.Errorf("writableRoots[0]: got %q, want %q", opts.writableRoots[0], "/tmp")
	}
	if opts.writableRoots[1] != "/var/tmp" {
		t.Errorf("writableRoots[1]: got %q, want %q", opts.writableRoots[1], "/var/tmp")
	}
}

func TestWithWritableRootsAppends(t *testing.T) {
	opts := &callOptions{}
	WithWritableRoots("/tmp")(opts)
	WithWritableRoots("/var/tmp")(opts)

	if len(opts.writableRoots) != 2 {
		t.Fatalf("writableRoots: got %d entries, want 2", len(opts.writableRoots))
	}
}

func TestWithNetwork(t *testing.T) {
	opts := &callOptions{}
	netCfg := &NetworkConfig{
		Mode:           NetworkBlocked,
		AllowedDomains: []string{"example.com"},
	}
	WithNetwork(netCfg)(opts)

	if opts.network == nil {
		t.Fatal("network: got nil")
	}
	if opts.network.Mode != NetworkBlocked {
		t.Errorf("network.Mode: got %v, want NetworkBlocked", opts.network.Mode)
	}
	if len(opts.network.AllowedDomains) != 1 {
		t.Errorf("network.AllowedDomains: got %d, want 1", len(opts.network.AllowedDomains))
	}
}

func TestWithEnv(t *testing.T) {
	opts := &callOptions{}
	WithEnv("FOO=bar", "BAZ=qux")(opts)

	if len(opts.env) != 2 {
		t.Fatalf("env: got %d entries, want 2", len(opts.env))
	}
	if opts.env[0] != "FOO=bar" {
		t.Errorf("env[0]: got %q, want %q", opts.env[0], "FOO=bar")
	}
	if opts.env[1] != "BAZ=qux" {
		t.Errorf("env[1]: got %q, want %q", opts.env[1], "BAZ=qux")
	}
}

func TestWithEnvAppends(t *testing.T) {
	opts := &callOptions{}
	WithEnv("FOO=bar")(opts)
	WithEnv("BAZ=qux")(opts)

	if len(opts.env) != 2 {
		t.Fatalf("env: got %d entries, want 2", len(opts.env))
	}
}

func TestWithShell(t *testing.T) {
	opts := &callOptions{}
	WithShell("/bin/zsh")(opts)

	if opts.shell != "/bin/zsh" {
		t.Errorf("shell: got %q, want %q", opts.shell, "/bin/zsh")
	}
}

func TestWithShellOverrides(t *testing.T) {
	opts := &callOptions{}
	WithShell("/bin/bash")(opts)
	WithShell("/bin/zsh")(opts)

	if opts.shell != "/bin/zsh" {
		t.Errorf("shell: got %q, want %q (should be overridden)", opts.shell, "/bin/zsh")
	}
}

func TestWithClassifier(t *testing.T) {
	opts := &callOptions{}
	mc := &mockClassifier{result: ClassifyResult{Decision: Forbidden, Reason: "test"}}
	WithClassifier(mc)(opts)

	if opts.classifier == nil {
		t.Fatal("classifier: got nil")
	}
	result := opts.classifier.Classify("test")
	if result.Decision != Forbidden {
		t.Errorf("classifier.Classify: got %v, want Forbidden", result.Decision)
	}
}

func TestApprovalDecisionString(t *testing.T) {
	tests := []struct {
		decision ApprovalDecision
		want     string
	}{
		{ApprovalDecision(0), "unset"},
		{Approve, "approve"},
		{Deny, "deny"},
		{ApproveSession, "approve_session"},
		{ApprovalDecision(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.decision.String(); got != tt.want {
				t.Errorf("ApprovalDecision(%d).String() = %q, want %q", tt.decision, got, tt.want)
			}
		})
	}
}

func TestApprovalDecisionValues(t *testing.T) {
	if Approve != 1 {
		t.Errorf("Approve: got %d, want 1", Approve)
	}
	if Deny != 2 {
		t.Errorf("Deny: got %d, want 2", Deny)
	}
	if ApproveSession != 3 {
		t.Errorf("ApproveSession: got %d, want 3", ApproveSession)
	}
	// Zero value must NOT be Approve.
	var zero ApprovalDecision
	if zero == Approve {
		t.Error("zero value of ApprovalDecision must not equal Approve")
	}
}

func TestApprovalRequest(t *testing.T) {
	req := ApprovalRequest{
		Command:  "sudo rm -rf /",
		Reason:   "destructive command",
		Decision: Escalated,
	}

	if req.Command != "sudo rm -rf /" {
		t.Errorf("Command: got %q", req.Command)
	}
	if req.Reason != "destructive command" {
		t.Errorf("Reason: got %q", req.Reason)
	}
	if req.Decision != Escalated {
		t.Errorf("Decision: got %v, want Escalated", req.Decision)
	}
}

func TestCallOptionsZeroValue(t *testing.T) {
	opts := &callOptions{}
	if opts.writableRoots != nil {
		t.Error("writableRoots should be nil")
	}
	if opts.network != nil {
		t.Error("network should be nil")
	}
	if opts.env != nil {
		t.Error("env should be nil")
	}
	if opts.shell != "" {
		t.Error("shell should be empty")
	}
	if opts.classifier != nil {
		t.Error("classifier should be nil")
	}
	if opts.workingDir != "" {
		t.Error("workingDir should be empty")
	}
	if opts.timeout != 0 {
		t.Error("timeout should be zero")
	}
	if opts.denyRead != nil {
		t.Error("denyRead should be nil")
	}
	if opts.denyWrite != nil {
		t.Error("denyWrite should be nil")
	}
}

func TestWithWorkingDir(t *testing.T) {
	opts := &callOptions{}
	WithWorkingDir("/tmp/workdir")(opts)

	if opts.workingDir != "/tmp/workdir" {
		t.Errorf("workingDir: got %q, want %q", opts.workingDir, "/tmp/workdir")
	}
}

func TestWithWorkingDirOverrides(t *testing.T) {
	opts := &callOptions{}
	WithWorkingDir("/first")(opts)
	WithWorkingDir("/second")(opts)

	if opts.workingDir != "/second" {
		t.Errorf("workingDir: got %q, want %q (should be overridden)", opts.workingDir, "/second")
	}
}

func TestWithTimeout(t *testing.T) {
	opts := &callOptions{}
	WithTimeout(5 * time.Second)(opts)

	if opts.timeout != 5*time.Second {
		t.Errorf("timeout: got %v, want %v", opts.timeout, 5*time.Second)
	}
}

func TestWithTimeoutOverrides(t *testing.T) {
	opts := &callOptions{}
	WithTimeout(5 * time.Second)(opts)
	WithTimeout(10 * time.Second)(opts)

	if opts.timeout != 10*time.Second {
		t.Errorf("timeout: got %v, want %v (should be overridden)", opts.timeout, 10*time.Second)
	}
}

func TestWithDenyRead(t *testing.T) {
	opts := &callOptions{}
	WithDenyRead("/etc/shadow", "/etc/passwd")(opts)

	if len(opts.denyRead) != 2 {
		t.Fatalf("denyRead: got %d entries, want 2", len(opts.denyRead))
	}
	if opts.denyRead[0] != "/etc/shadow" {
		t.Errorf("denyRead[0]: got %q, want %q", opts.denyRead[0], "/etc/shadow")
	}
	if opts.denyRead[1] != "/etc/passwd" {
		t.Errorf("denyRead[1]: got %q, want %q", opts.denyRead[1], "/etc/passwd")
	}
}

func TestWithDenyReadAppends(t *testing.T) {
	opts := &callOptions{}
	WithDenyRead("/etc/shadow")(opts)
	WithDenyRead("/etc/passwd")(opts)

	if len(opts.denyRead) != 2 {
		t.Fatalf("denyRead: got %d entries, want 2", len(opts.denyRead))
	}
}

func TestWithDenyWrite(t *testing.T) {
	opts := &callOptions{}
	WithDenyWrite("/etc/hosts", "/etc/resolv.conf")(opts)

	if len(opts.denyWrite) != 2 {
		t.Fatalf("denyWrite: got %d entries, want 2", len(opts.denyWrite))
	}
	if opts.denyWrite[0] != "/etc/hosts" {
		t.Errorf("denyWrite[0]: got %q, want %q", opts.denyWrite[0], "/etc/hosts")
	}
	if opts.denyWrite[1] != "/etc/resolv.conf" {
		t.Errorf("denyWrite[1]: got %q, want %q", opts.denyWrite[1], "/etc/resolv.conf")
	}
}

func TestWithDenyWriteAppends(t *testing.T) {
	opts := &callOptions{}
	WithDenyWrite("/etc/hosts")(opts)
	WithDenyWrite("/etc/resolv.conf")(opts)

	if len(opts.denyWrite) != 2 {
		t.Fatalf("denyWrite: got %d entries, want 2", len(opts.denyWrite))
	}
}

// Regression tests: verify that variadic option functions copy the input slice
// at closure creation time, so later mutations to the caller's slice do not
// affect the captured values.

func TestWithWritableRoots_SliceCopy(t *testing.T) {
	roots := []string{"/tmp/a", "/tmp/b"}
	opt := WithWritableRoots(roots...)
	// Mutate the original slice after creating the option.
	roots[0] = "/tmp/MUTATED"

	opts := &callOptions{}
	opt(opts)

	if len(opts.writableRoots) != 2 {
		t.Fatalf("writableRoots: got %d entries, want 2", len(opts.writableRoots))
	}
	if opts.writableRoots[0] != "/tmp/a" {
		t.Errorf("writableRoots[0]: got %q, want %q (slice was not copied)", opts.writableRoots[0], "/tmp/a")
	}
}

func TestWithEnv_SliceCopy(t *testing.T) {
	env := []string{"A=1", "B=2"}
	opt := WithEnv(env...)
	env[0] = "A=MUTATED"

	opts := &callOptions{}
	opt(opts)

	if len(opts.env) != 2 {
		t.Fatalf("env: got %d entries, want 2", len(opts.env))
	}
	if opts.env[0] != "A=1" {
		t.Errorf("env[0]: got %q, want %q (slice was not copied)", opts.env[0], "A=1")
	}
}

func TestWithDenyRead_SliceCopy(t *testing.T) {
	paths := []string{"/secret", "/private"}
	opt := WithDenyRead(paths...)
	paths[0] = "/MUTATED"

	opts := &callOptions{}
	opt(opts)

	if len(opts.denyRead) != 2 {
		t.Fatalf("denyRead: got %d entries, want 2", len(opts.denyRead))
	}
	if opts.denyRead[0] != "/secret" {
		t.Errorf("denyRead[0]: got %q, want %q (slice was not copied)", opts.denyRead[0], "/secret")
	}
}

func TestWithDenyWrite_SliceCopy(t *testing.T) {
	paths := []string{"/etc/hosts", "/etc/passwd"}
	opt := WithDenyWrite(paths...)
	paths[0] = "/MUTATED"

	opts := &callOptions{}
	opt(opts)

	if len(opts.denyWrite) != 2 {
		t.Fatalf("denyWrite: got %d entries, want 2", len(opts.denyWrite))
	}
	if opts.denyWrite[0] != "/etc/hosts" {
		t.Errorf("denyWrite[0]: got %q, want %q (slice was not copied)", opts.denyWrite[0], "/etc/hosts")
	}
}

// TestWithNetworkDeepCopy verifies that WithNetwork deep-copies the
// NetworkConfig so that later mutations to the caller's struct do not
// affect the stored option.
func TestWithNetworkDeepCopy(t *testing.T) {
	netCfg := &NetworkConfig{
		Mode:           NetworkBlocked,
		AllowedDomains: []string{"example.com"},
		DeniedDomains:  []string{"evil.com"},
	}
	opt := WithNetwork(netCfg)

	// Mutate the original after creating the option.
	netCfg.Mode = NetworkAllowed
	netCfg.AllowedDomains[0] = "mutated.com"
	netCfg.DeniedDomains[0] = "mutated.com"
	netCfg.AllowedDomains = append(netCfg.AllowedDomains, "extra.com")

	opts := &callOptions{}
	opt(opts)

	if opts.network == nil {
		t.Fatal("network: got nil")
	}
	if opts.network.Mode != NetworkBlocked {
		t.Errorf("network.Mode: got %v, want NetworkBlocked (should not be mutated)", opts.network.Mode)
	}
	if len(opts.network.AllowedDomains) != 1 {
		t.Fatalf("AllowedDomains: got %d entries, want 1", len(opts.network.AllowedDomains))
	}
	if opts.network.AllowedDomains[0] != "example.com" {
		t.Errorf("AllowedDomains[0]: got %q, want %q (should not be mutated)", opts.network.AllowedDomains[0], "example.com")
	}
	if len(opts.network.DeniedDomains) != 1 {
		t.Fatalf("DeniedDomains: got %d entries, want 1", len(opts.network.DeniedDomains))
	}
	if opts.network.DeniedDomains[0] != "evil.com" {
		t.Errorf("DeniedDomains[0]: got %q, want %q (should not be mutated)", opts.network.DeniedDomains[0], "evil.com")
	}
	// Verify the pointer is different (deep copy, not alias).
	if opts.network == netCfg {
		t.Error("network should be a deep copy, not the same pointer")
	}
}

func TestWithNetworkDeepCopyAllFields(t *testing.T) {
	netCfg := &NetworkConfig{
		Mode:             NetworkFiltered,
		AllowedDomains:   []string{"example.com"},
		DeniedDomains:    []string{"evil.com"},
		AllowUnixSockets: []string{"/var/run/docker.sock"},
		MITMProxy: &MITMProxyConfig{
			SocketPath: "/var/run/mitm.sock",
			Domains:    []string{"*.example.com"},
		},
	}
	opt := WithNetwork(netCfg)

	// Mutate the original after creating the option.
	netCfg.AllowUnixSockets[0] = "mutated"
	netCfg.AllowUnixSockets = append(netCfg.AllowUnixSockets, "/extra.sock")
	netCfg.MITMProxy.SocketPath = "/mutated.sock"
	netCfg.MITMProxy.Domains[0] = "mutated.com"

	opts := &callOptions{}
	opt(opts)

	if opts.network == nil {
		t.Fatal("network: got nil")
	}
	if len(opts.network.AllowUnixSockets) != 1 {
		t.Fatalf("AllowUnixSockets: got %d entries, want 1", len(opts.network.AllowUnixSockets))
	}
	if opts.network.AllowUnixSockets[0] != "/var/run/docker.sock" {
		t.Errorf("AllowUnixSockets[0]: got %q, want %q", opts.network.AllowUnixSockets[0], "/var/run/docker.sock")
	}
	if opts.network.MITMProxy == nil {
		t.Fatal("MITMProxy: got nil")
	}
	if opts.network.MITMProxy.SocketPath != "/var/run/mitm.sock" {
		t.Errorf("MITMProxy.SocketPath: got %q, want %q", opts.network.MITMProxy.SocketPath, "/var/run/mitm.sock")
	}
	if len(opts.network.MITMProxy.Domains) != 1 {
		t.Fatalf("MITMProxy.Domains: got %d entries, want 1", len(opts.network.MITMProxy.Domains))
	}
	if opts.network.MITMProxy.Domains[0] != "*.example.com" {
		t.Errorf("MITMProxy.Domains[0]: got %q, want %q", opts.network.MITMProxy.Domains[0], "*.example.com")
	}
	// Verify MITMProxy pointer is different.
	if opts.network.MITMProxy == netCfg.MITMProxy {
		t.Error("MITMProxy should be a deep copy, not the same pointer")
	}
}

func TestWithNetworkDeepCopyNilMITMProxy(t *testing.T) {
	netCfg := &NetworkConfig{
		Mode:             NetworkFiltered,
		AllowUnixSockets: []string{"/var/run/docker.sock"},
		MITMProxy:        nil,
	}
	opt := WithNetwork(netCfg)
	opts := &callOptions{}
	opt(opts)

	if opts.network == nil {
		t.Fatal("network: got nil")
	}
	if opts.network.MITMProxy != nil {
		t.Error("MITMProxy should remain nil")
	}
}

func TestWithNetworkNil(t *testing.T) {
	opt := WithNetwork(nil)
	co := &callOptions{}
	opt(co)
	if co.network != nil {
		t.Error("expected nil network")
	}
}
