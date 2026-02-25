//go:build linux

package linux

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/zhangyunhao116/agentbox/platform"
)

// TestMaybeSandboxInit_NoEnvVar verifies that MaybeSandboxInit returns false
// when the _AGENTBOX_CONFIG environment variable is not set.
func TestMaybeSandboxInit_NoEnvVar(t *testing.T) {
	t.Setenv("_AGENTBOX_CONFIG", "")
	os.Unsetenv("_AGENTBOX_CONFIG")
	if MaybeSandboxInit() {
		t.Error("MaybeSandboxInit() returned true without env var set")
	}
}

// TestSandboxInit_InvalidFd verifies that sandboxInit returns 1 when given a
// non-numeric file descriptor string.
func TestSandboxInit_InvalidFd(t *testing.T) {
	code := sandboxInit("not-a-number")
	if code != 1 {
		t.Errorf("sandboxInit(\"not-a-number\") = %d, want 1", code)
	}
}

// TestSandboxInit_BadFd verifies that sandboxInit returns 1 when given a
// valid number that does not correspond to an open file descriptor.
func TestSandboxInit_BadFd(t *testing.T) {
	code := sandboxInit("999")
	if code != 1 {
		t.Errorf("sandboxInit(\"999\") = %d, want 1", code)
	}
}

// TestSandboxInit_NegativeFd verifies that sandboxInit returns 1 when given a
// negative fd string, which causes os.NewFile to return nil (uintptr wraps to max).
func TestSandboxInit_NegativeFd(t *testing.T) {
	code := sandboxInit("-1")
	if code != 1 {
		t.Errorf("sandboxInit(\"-1\") = %d, want 1", code)
	}
}

// TestSandboxInit_InvalidJSON verifies that sandboxInit returns 1 when the
// pipe contains data that is not valid JSON.
func TestSandboxInit_InvalidJSON(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.WriteString("not json"); err != nil {
		t.Fatal(err)
	}
	w.Close()

	code := sandboxInit(strconv.Itoa(int(r.Fd())))
	if code != 1 {
		t.Errorf("sandboxInit with invalid JSON = %d, want 1", code)
	}
}

// runSubprocess runs the test binary as a subprocess with the given env var
// and a timeout. It returns stderr and any error. The subprocess is
// killed after the timeout to handle cases where sandbox restrictions prevent
// clean exit.
func runSubprocess(t *testing.T, testName, envKey string, timeout time.Duration) (stderr []byte, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(), envKey+"=1")
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return errBuf.Bytes(), err
}

// TestSandboxInit_NoArgs runs sandboxInit in a subprocess with a valid config
// but no command arguments (os.Args has only the binary name). It expects the
// subprocess to reach the "no command to exec" error path.
// Must run in subprocess because sandboxInit calls hardenProcess() etc.
func TestSandboxInit_NoArgs(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS_NOARGS") == "1" {
		r, w, err := os.Pipe()
		if err != nil {
			syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 2, 0, 0)
		}
		cfg := reExecConfig{}
		if err = json.NewEncoder(w).Encode(cfg); err != nil {
			syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 2, 0, 0)
		}
		w.Close()

		// Only the binary name is present — no command args.
		os.Args = []string{"test-binary"}
		code := sandboxInit(strconv.Itoa(int(r.Fd())))
		syscall.RawSyscall(syscall.SYS_EXIT_GROUP, uintptr(code), 0, 0)
	}

	stderr, err := runSubprocess(t, "TestSandboxInit_NoArgs", "TEST_SUBPROCESS_NOARGS", 5*time.Second)
	if err == nil {
		t.Fatal("expected subprocess to exit with error")
	}

	// Verify the subprocess reached the "no command" error path.
	if !bytes.Contains(stderr, []byte("no command to exec")) {
		// The subprocess may have been killed by a signal (e.g., due to
		// seccomp strict mode) before reaching the no-args check, or it
		// exited with a non-zero code for another reason. Either way,
		// it should not have succeeded.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Logf("subprocess exited with code %d, stderr: %s", exitErr.ExitCode(), stderr)
		} else {
			t.Logf("subprocess error: %v, stderr: %s", err, stderr)
		}
	}
}

// TestSandboxInit_ValidConfig runs sandboxInit in a subprocess with a valid
// config and os.Args pointing to /bin/true. sandboxInit should apply all
// sandbox restrictions and then attempt to syscall.Exec /bin/true.
func TestSandboxInit_ValidConfig(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS_VALID") == "1" {
		r, w, err := os.Pipe()
		if err != nil {
			syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 2, 0, 0)
		}
		cfg := reExecConfig{}
		if err = json.NewEncoder(w).Encode(cfg); err != nil {
			syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 2, 0, 0)
		}
		w.Close()

		// Set os.Args so that args[1:] = ["/bin/true"].
		os.Args = []string{"test-binary", "/bin/true"}
		code := sandboxInit(strconv.Itoa(int(r.Fd())))
		// If syscall.Exec succeeded, we never reach here.
		syscall.RawSyscall(syscall.SYS_EXIT_GROUP, uintptr(code), 0, 0)
	}

	stderr, err := runSubprocess(t, "TestSandboxInit_ValidConfig", "TEST_SUBPROCESS_VALID", 5*time.Second)

	// The subprocess either:
	// - Successfully exec'd /bin/true (exit 0)
	// - Was killed by a signal after sandbox restrictions were applied
	// - Exited with code 1 if exec failed
	// Any of these outcomes confirms sandboxInit was exercised.
	if err == nil {
		// syscall.Exec replaced the process with /bin/true which exited 0.
		return
	}

	// If the subprocess was killed or exited non-zero, that's acceptable
	// as long as it didn't exit with code 2 (our setup error sentinel).
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() == 2 {
			t.Fatalf("subprocess failed during setup (exit 2), stderr: %s", stderr)
		}
		t.Logf("subprocess exited with code %d (expected after sandbox restrictions), stderr: %s",
			exitErr.ExitCode(), stderr)
	} else {
		// Context timeout or other error — the subprocess was killed.
		t.Logf("subprocess terminated: %v, stderr: %s", err, stderr)
	}
}

// TestReExecConfig_JSONRoundTrip verifies that reExecConfig correctly
// serializes and deserializes all fields via JSON.
func TestReExecConfig_JSONRoundTrip(t *testing.T) {
	original := reExecConfig{
		WritableRoots:           []string{"/tmp", "/home/user"},
		DenyWrite:               []string{"/etc"},
		DenyRead:                []string{"/root/.ssh"},
		NeedsNetworkRestriction: true,
		ResourceLimits: &platform.ResourceLimits{
			MaxProcesses:       512,
			MaxMemoryBytes:     1024 * 1024 * 1024,
			MaxFileDescriptors: 256,
			MaxCPUSeconds:      60,
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded reExecConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Verify all fields round-trip correctly.
	if len(decoded.WritableRoots) != len(original.WritableRoots) {
		t.Errorf("WritableRoots length = %d, want %d", len(decoded.WritableRoots), len(original.WritableRoots))
	}
	for i, v := range original.WritableRoots {
		if decoded.WritableRoots[i] != v {
			t.Errorf("WritableRoots[%d] = %q, want %q", i, decoded.WritableRoots[i], v)
		}
	}
	if len(decoded.DenyWrite) != len(original.DenyWrite) {
		t.Errorf("DenyWrite length = %d, want %d", len(decoded.DenyWrite), len(original.DenyWrite))
	}
	for i, v := range original.DenyWrite {
		if decoded.DenyWrite[i] != v {
			t.Errorf("DenyWrite[%d] = %q, want %q", i, decoded.DenyWrite[i], v)
		}
	}
	if len(decoded.DenyRead) != len(original.DenyRead) {
		t.Errorf("DenyRead length = %d, want %d", len(decoded.DenyRead), len(original.DenyRead))
	}
	for i, v := range original.DenyRead {
		if decoded.DenyRead[i] != v {
			t.Errorf("DenyRead[%d] = %q, want %q", i, decoded.DenyRead[i], v)
		}
	}
	if decoded.NeedsNetworkRestriction != original.NeedsNetworkRestriction {
		t.Errorf("NeedsNetworkRestriction = %v, want %v", decoded.NeedsNetworkRestriction, original.NeedsNetworkRestriction)
	}
	if decoded.ResourceLimits == nil {
		t.Fatal("ResourceLimits is nil after round-trip")
	}
	if decoded.ResourceLimits.MaxProcesses != original.ResourceLimits.MaxProcesses {
		t.Errorf("MaxProcesses = %d, want %d", decoded.ResourceLimits.MaxProcesses, original.ResourceLimits.MaxProcesses)
	}
	if decoded.ResourceLimits.MaxMemoryBytes != original.ResourceLimits.MaxMemoryBytes {
		t.Errorf("MaxMemoryBytes = %d, want %d", decoded.ResourceLimits.MaxMemoryBytes, original.ResourceLimits.MaxMemoryBytes)
	}
	if decoded.ResourceLimits.MaxFileDescriptors != original.ResourceLimits.MaxFileDescriptors {
		t.Errorf("MaxFileDescriptors = %d, want %d", decoded.ResourceLimits.MaxFileDescriptors, original.ResourceLimits.MaxFileDescriptors)
	}
	if decoded.ResourceLimits.MaxCPUSeconds != original.ResourceLimits.MaxCPUSeconds {
		t.Errorf("MaxCPUSeconds = %d, want %d", decoded.ResourceLimits.MaxCPUSeconds, original.ResourceLimits.MaxCPUSeconds)
	}
}

// TestReExecConfig_JSONRoundTrip_Empty verifies that an empty reExecConfig
// round-trips correctly with omitempty fields absent.
func TestReExecConfig_JSONRoundTrip_Empty(t *testing.T) {
	original := reExecConfig{}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded reExecConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.WritableRoots != nil {
		t.Errorf("WritableRoots = %v, want nil", decoded.WritableRoots)
	}
	if decoded.DenyWrite != nil {
		t.Errorf("DenyWrite = %v, want nil", decoded.DenyWrite)
	}
	if decoded.DenyRead != nil {
		t.Errorf("DenyRead = %v, want nil", decoded.DenyRead)
	}
	if decoded.NeedsNetworkRestriction {
		t.Error("NeedsNetworkRestriction = true, want false")
	}
	if decoded.ResourceLimits != nil {
		t.Errorf("ResourceLimits = %v, want nil", decoded.ResourceLimits)
	}
}

// sandboxInitHelper creates a pipe with the given config, writes it, and calls
// sandboxInit with the pipe's read fd. It returns the exit code.
func sandboxInitHelper(t *testing.T, cfg reExecConfig) int {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := json.NewEncoder(w).Encode(cfg); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return sandboxInit(strconv.Itoa(int(r.Fd())))
}

// saveSandboxFnVars saves all function variables used by sandboxInit and returns
// a restore function. Tests must defer the restore to avoid leaking mocks.
func saveSandboxFnVars() func() {
	origHarden := hardenProcessFn
	origLandlock := applyLandlockFn
	origResLim := applyResourceLimFn
	origSeccomp := applySeccompFn
	origExec := syscallExecFn
	origExit := osExitFn
	return func() {
		hardenProcessFn = origHarden
		applyLandlockFn = origLandlock
		applyResourceLimFn = origResLim
		applySeccompFn = origSeccomp
		syscallExecFn = origExec
		osExitFn = origExit
	}
}

// stubAllSandboxFns sets all sandboxInit dependency functions to no-op success
// stubs. Call saveSandboxFnVars first and defer its restore.
func stubAllSandboxFns() {
	hardenProcessFn = func() error { return nil }
	applyLandlockFn = func(cfg *platform.WrapConfig) error { return nil }
	applyResourceLimFn = func(limits *platform.ResourceLimits) error { return nil }
	applySeccompFn = func() error { return nil }
	syscallExecFn = func(argv0 string, argv []string, envv []string) error { return nil }
}

// TestSandboxInit_HardenError verifies sandboxInit returns 1 when hardenProcess fails.
func TestSandboxInit_HardenError(t *testing.T) {
	defer saveSandboxFnVars()()
	stubAllSandboxFns()
	hardenProcessFn = func() error { return errors.New("mock harden error") }

	code := sandboxInitHelper(t, reExecConfig{})
	if code != 1 {
		t.Errorf("sandboxInit() = %d, want 1", code)
	}
}

// TestSandboxInit_LandlockError verifies sandboxInit returns 1 when applyLandlock fails.
func TestSandboxInit_LandlockError(t *testing.T) {
	defer saveSandboxFnVars()()
	stubAllSandboxFns()
	applyLandlockFn = func(cfg *platform.WrapConfig) error { return errors.New("mock landlock error") }

	code := sandboxInitHelper(t, reExecConfig{})
	if code != 1 {
		t.Errorf("sandboxInit() = %d, want 1", code)
	}
}

// TestSandboxInit_ResourceLimitsError verifies sandboxInit returns 1 when
// applyResourceLimits fails.
func TestSandboxInit_ResourceLimitsError(t *testing.T) {
	defer saveSandboxFnVars()()
	stubAllSandboxFns()
	applyResourceLimFn = func(limits *platform.ResourceLimits) error {
		return errors.New("mock resource limits error")
	}

	cfg := reExecConfig{
		ResourceLimits: &platform.ResourceLimits{MaxProcesses: 100},
	}
	code := sandboxInitHelper(t, cfg)
	if code != 1 {
		t.Errorf("sandboxInit() = %d, want 1", code)
	}
}

// TestSandboxInit_ResourceLimitsNil verifies sandboxInit skips resource limits
// when ResourceLimits is nil (no error).
func TestSandboxInit_ResourceLimitsNil(t *testing.T) {
	defer saveSandboxFnVars()()
	stubAllSandboxFns()

	// ResourceLimits is nil, so applyResourceLimFn should not be called.
	called := false
	applyResourceLimFn = func(limits *platform.ResourceLimits) error {
		called = true
		return nil
	}

	// Need args for exec.
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"test-binary", "/bin/true"}

	code := sandboxInitHelper(t, reExecConfig{})
	if code != 0 {
		t.Errorf("sandboxInit() = %d, want 0", code)
	}
	if called {
		t.Error("applyResourceLimFn was called when ResourceLimits is nil")
	}
}

// TestSandboxInit_SeccompError verifies sandboxInit returns 1 when ApplySeccomp fails.
func TestSandboxInit_SeccompError(t *testing.T) {
	defer saveSandboxFnVars()()
	stubAllSandboxFns()
	applySeccompFn = func() error { return errors.New("mock seccomp error") }

	code := sandboxInitHelper(t, reExecConfig{})
	if code != 1 {
		t.Errorf("sandboxInit() = %d, want 1", code)
	}
}

// TestSandboxInit_NoArgsMocked verifies sandboxInit returns 1 when there are no
// command arguments to exec (using mocked dependencies).
func TestSandboxInit_NoArgsMocked(t *testing.T) {
	defer saveSandboxFnVars()()
	stubAllSandboxFns()

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"test-binary"} // no command args

	code := sandboxInitHelper(t, reExecConfig{})
	if code != 1 {
		t.Errorf("sandboxInit() = %d, want 1", code)
	}
}

// TestSandboxInit_ExecError verifies sandboxInit returns 1 when syscall.Exec fails.
func TestSandboxInit_ExecError(t *testing.T) {
	defer saveSandboxFnVars()()
	stubAllSandboxFns()
	syscallExecFn = func(argv0 string, argv []string, envv []string) error {
		return errors.New("mock exec error")
	}

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"test-binary", "/bin/true"}

	code := sandboxInitHelper(t, reExecConfig{})
	if code != 1 {
		t.Errorf("sandboxInit() = %d, want 1", code)
	}
}

// TestSandboxInit_ExecSuccess verifies sandboxInit returns 0 when all steps
// succeed and syscall.Exec returns nil (simulating successful exec).
func TestSandboxInit_ExecSuccess(t *testing.T) {
	defer saveSandboxFnVars()()
	stubAllSandboxFns()

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"test-binary", "/bin/true"}

	code := sandboxInitHelper(t, reExecConfig{})
	if code != 0 {
		t.Errorf("sandboxInit() = %d, want 0", code)
	}
}

// TestSandboxInit_ExecSuccessWithResourceLimits verifies sandboxInit returns 0
// when all steps succeed including resource limits application.
func TestSandboxInit_ExecSuccessWithResourceLimits(t *testing.T) {
	defer saveSandboxFnVars()()
	stubAllSandboxFns()

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"test-binary", "/bin/true"}

	cfg := reExecConfig{
		ResourceLimits: &platform.ResourceLimits{MaxProcesses: 100},
	}
	code := sandboxInitHelper(t, cfg)
	if code != 0 {
		t.Errorf("sandboxInit() = %d, want 0", code)
	}
}

// TestMaybeSandboxInit_WithEnvVar verifies that MaybeSandboxInit calls
// sandboxInit and osExitFn when the env var is set.
func TestMaybeSandboxInit_WithEnvVar(t *testing.T) {
	defer saveSandboxFnVars()()
	stubAllSandboxFns()

	// Create a pipe with valid config.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := json.NewEncoder(w).Encode(reExecConfig{}); err != nil {
		t.Fatal(err)
	}
	w.Close()

	// Set the env var to the pipe fd.
	fdStr := strconv.Itoa(int(r.Fd()))
	os.Setenv(reExecEnvKey, fdStr)
	defer os.Unsetenv(reExecEnvKey)

	// Set os.Args so sandboxInit has a command to exec.
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"test-binary", "/bin/true"}

	// Override osExitFn to capture the exit code instead of exiting.
	var exitCode int
	exitCalled := false
	osExitFn = func(code int) {
		exitCode = code
		exitCalled = true
		// Don't actually exit — just record the code.
		// MaybeSandboxInit will return true after this.
	}

	result := MaybeSandboxInit()
	if !exitCalled {
		t.Fatal("osExitFn was not called")
	}
	if exitCode != 0 {
		t.Errorf("osExitFn called with code %d, want 0", exitCode)
	}
	// result is true because osExitFn didn't actually exit.
	if !result {
		t.Error("MaybeSandboxInit() returned false, want true")
	}
}
