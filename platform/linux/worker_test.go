//go:build linux

package linux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zhangyunhao116/agentbox/platform"
)

// TestWorkerProtocolRoundtrip verifies that workerRequest can be encoded
// and decoded correctly with all fields preserved.
func TestWorkerProtocolRoundtrip(t *testing.T) {
	// Create a workerRequest with all fields populated.
	req := &workerRequest{
		ID:   "test-req-123",
		Cmd:  "/usr/bin/echo",
		Args: []string{"hello", "world"},
		Dir:  "/tmp",
		Env:  []string{"FOO=bar", "BAZ=qux"},
		WritableRoots: []string{"/tmp", "/var/tmp"},
		DenyWrite:     []string{"/etc", "/usr"},
		DenyRead:      []string{"/root", "/home"},
		NeedsNetworkRestriction: true,
		ResourceLimits: &platform.ResourceLimits{
			MaxProcesses:       100,
			MaxMemoryBytes:     1024 * 1024 * 1024,
			MaxFileDescriptors: 512,
			MaxCPUSeconds:      60,
		},
	}

	// Create a pipe to simulate a Unix socket connection.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Encode on one end, decode on the other.
	errCh := make(chan error, 1)
	var decoded *workerRequest
	go func() {
		var err error
		decoded, err = decodeRequest(server)
		errCh <- err
	}()

	if err := encodeRequest(client, req); err != nil {
		t.Fatalf("encodeRequest failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("decodeRequest failed: %v", err)
	}

	// Verify all fields match.
	if decoded.ID != req.ID {
		t.Errorf("ID mismatch: got %q, want %q", decoded.ID, req.ID)
	}
	if decoded.Cmd != req.Cmd {
		t.Errorf("Cmd mismatch: got %q, want %q", decoded.Cmd, req.Cmd)
	}
	if !stringSliceEqual(decoded.Args, req.Args) {
		t.Errorf("Args mismatch: got %v, want %v", decoded.Args, req.Args)
	}
	if decoded.Dir != req.Dir {
		t.Errorf("Dir mismatch: got %q, want %q", decoded.Dir, req.Dir)
	}
	if !stringSliceEqual(decoded.Env, req.Env) {
		t.Errorf("Env mismatch: got %v, want %v", decoded.Env, req.Env)
	}
	if !stringSliceEqual(decoded.WritableRoots, req.WritableRoots) {
		t.Errorf("WritableRoots mismatch: got %v, want %v", decoded.WritableRoots, req.WritableRoots)
	}
	if !stringSliceEqual(decoded.DenyWrite, req.DenyWrite) {
		t.Errorf("DenyWrite mismatch: got %v, want %v", decoded.DenyWrite, req.DenyWrite)
	}
	if !stringSliceEqual(decoded.DenyRead, req.DenyRead) {
		t.Errorf("DenyRead mismatch: got %v, want %v", decoded.DenyRead, req.DenyRead)
	}
	if decoded.NeedsNetworkRestriction != req.NeedsNetworkRestriction {
		t.Errorf("NeedsNetworkRestriction mismatch: got %v, want %v", decoded.NeedsNetworkRestriction, req.NeedsNetworkRestriction)
	}
	if decoded.ResourceLimits.MaxProcesses != req.ResourceLimits.MaxProcesses {
		t.Errorf("MaxProcesses mismatch: got %d, want %d", decoded.ResourceLimits.MaxProcesses, req.ResourceLimits.MaxProcesses)
	}
	if decoded.ResourceLimits.MaxMemoryBytes != req.ResourceLimits.MaxMemoryBytes {
		t.Errorf("MaxMemoryBytes mismatch: got %d, want %d", decoded.ResourceLimits.MaxMemoryBytes, req.ResourceLimits.MaxMemoryBytes)
	}
}

// TestWorkerProtocolResponseRoundtrip verifies that workerResponse can be
// encoded and decoded correctly.
func TestWorkerProtocolResponseRoundtrip(t *testing.T) {
	resp := &workerResponse{
		ID:       "test-resp-456",
		Stdout:   []byte("stdout output"),
		Stderr:   []byte("stderr output"),
		ExitCode: 0,
		Error:    "",
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	errCh := make(chan error, 1)
	var decoded *workerResponse
	go func() {
		var err error
		decoded, err = decodeResponse(server)
		errCh <- err
	}()

	if err := encodeResponse(client, resp); err != nil {
		t.Fatalf("encodeResponse failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("decodeResponse failed: %v", err)
	}

	// Verify all fields match.
	if decoded.ID != resp.ID {
		t.Errorf("ID mismatch: got %q, want %q", decoded.ID, resp.ID)
	}
	if !bytes.Equal(decoded.Stdout, resp.Stdout) {
		t.Errorf("Stdout mismatch: got %q, want %q", decoded.Stdout, resp.Stdout)
	}
	if !bytes.Equal(decoded.Stderr, resp.Stderr) {
		t.Errorf("Stderr mismatch: got %q, want %q", decoded.Stderr, resp.Stderr)
	}
	if decoded.ExitCode != resp.ExitCode {
		t.Errorf("ExitCode mismatch: got %d, want %d", decoded.ExitCode, resp.ExitCode)
	}
	if decoded.Error != resp.Error {
		t.Errorf("Error mismatch: got %q, want %q", decoded.Error, resp.Error)
	}
}

// TestWorkerProtocolMaxPayload tests that payloads under 10MB work correctly.
func TestWorkerProtocolMaxPayload(t *testing.T) {
	// Create a request with a large Env field (under 10MB).
	// Each env entry is ~100 bytes, so 50k entries = ~5MB.
	largeEnv := make([]string, 50000)
	for i := range largeEnv {
		largeEnv[i] = strings.Repeat("X", 100)
	}

	req := &workerRequest{
		ID:   "large-payload",
		Cmd:  "/bin/true",
		Args: []string{},
		Env:  largeEnv,
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	errCh := make(chan error, 1)
	var decoded *workerRequest
	go func() {
		var err error
		decoded, err = decodeRequest(server)
		errCh <- err
	}()

	if err := encodeRequest(client, req); err != nil {
		t.Fatalf("encodeRequest failed with large payload: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("decodeRequest failed with large payload: %v", err)
	}

	if len(decoded.Env) != len(req.Env) {
		t.Errorf("Env length mismatch: got %d, want %d", len(decoded.Env), len(req.Env))
	}
}

// TestWorkerProtocolEOF verifies that EOF is properly detected and returned.
func TestWorkerProtocolEOF(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	// Close client side immediately to trigger EOF.
	client.Close()

	_, err := decodeRequest(server)
	if err == nil {
		t.Fatal("decodeRequest should return error on EOF")
	}

	// Check that the error contains "EOF" or is io.EOF.
	if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "EOF") {
		t.Errorf("expected EOF error, got: %v", err)
	}
}

// TestWorkerRequestSerialization tests JSON marshaling of workerRequest.
func TestWorkerRequestSerialization(t *testing.T) {
	tests := []struct {
		name string
		req  *workerRequest
	}{
		{
			name: "minimal request",
			req: &workerRequest{
				ID:   "minimal",
				Cmd:  "/bin/echo",
				Args: []string{"hello"},
			},
		},
		{
			name: "request with empty optional fields",
			req: &workerRequest{
				ID:   "empty-fields",
				Cmd:  "/bin/true",
				Args: []string{},
				Dir:  "",
				Env:  nil,
			},
		},
		{
			name: "request with all fields",
			req: &workerRequest{
				ID:   "full",
				Cmd:  "/usr/bin/ls",
				Args: []string{"-la"},
				Dir:  "/tmp",
				Env:  []string{"PATH=/usr/bin"},
				WritableRoots: []string{"/tmp"},
				DenyWrite:     []string{"/etc"},
				DenyRead:      []string{"/root"},
				NeedsNetworkRestriction: true,
				ResourceLimits: &platform.ResourceLimits{
					MaxProcesses: 10,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()

			errCh := make(chan error, 1)
			var decoded *workerRequest
			go func() {
				var err error
				decoded, err = decodeRequest(server)
				errCh <- err
			}()

			if err := encodeRequest(client, tt.req); err != nil {
				t.Fatalf("encodeRequest failed: %v", err)
			}

			if err := <-errCh; err != nil {
				t.Fatalf("decodeRequest failed: %v", err)
			}

			if decoded.ID != tt.req.ID {
				t.Errorf("ID mismatch: got %q, want %q", decoded.ID, tt.req.ID)
			}
			if decoded.Cmd != tt.req.Cmd {
				t.Errorf("Cmd mismatch: got %q, want %q", decoded.Cmd, tt.req.Cmd)
			}
		})
	}
}

// TestWorkerResponseSerialization tests JSON marshaling of workerResponse.
func TestWorkerResponseSerialization(t *testing.T) {
	tests := []struct {
		name string
		resp *workerResponse
	}{
		{
			name: "success response",
			resp: &workerResponse{
				ID:       "success",
				Stdout:   []byte("output"),
				Stderr:   []byte(""),
				ExitCode: 0,
			},
		},
		{
			name: "error response",
			resp: &workerResponse{
				ID:       "error",
				Stdout:   []byte(""),
				Stderr:   []byte("error message"),
				ExitCode: 1,
				Error:    "command failed",
			},
		},
		{
			name: "empty stdout stderr",
			resp: &workerResponse{
				ID:       "empty",
				Stdout:   []byte{},
				Stderr:   []byte{},
				ExitCode: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()

			errCh := make(chan error, 1)
			var decoded *workerResponse
			go func() {
				var err error
				decoded, err = decodeResponse(server)
				errCh <- err
			}()

			if err := encodeResponse(client, tt.resp); err != nil {
				t.Fatalf("encodeResponse failed: %v", err)
			}

			if err := <-errCh; err != nil {
				t.Fatalf("decodeResponse failed: %v", err)
			}

			if decoded.ID != tt.resp.ID {
				t.Errorf("ID mismatch: got %q, want %q", decoded.ID, tt.resp.ID)
			}
			if decoded.ExitCode != tt.resp.ExitCode {
				t.Errorf("ExitCode mismatch: got %d, want %d", decoded.ExitCode, tt.resp.ExitCode)
			}
		})
	}
}

// TestPlatformExecViaWorkerInterface verifies that Platform implements
// the platform.WorkerExecutor interface.
func TestPlatformExecViaWorkerInterface(t *testing.T) {
	p := &Platform{}
	_, ok := interface{}(p).(platform.WorkerExecutor)
	if !ok {
		t.Fatal("Platform does not implement platform.WorkerExecutor")
	}
}

// TestPlatformCleanupWithWorker verifies that Cleanup handles nil worker.
func TestPlatformCleanupWithWorker(t *testing.T) {
	p := &Platform{}
	ctx := context.Background()
	err := p.Cleanup(ctx)
	if err != nil {
		t.Errorf("Cleanup with nil worker failed: %v", err)
	}
}

// TestEnsureWorkerError verifies that workerErr prevents retry.
func TestEnsureWorkerError(t *testing.T) {
	p := &Platform{}
	p.workerErr = errors.New("previous worker failure")

	cfg := &platform.WrapConfig{}
	w := p.ensureWorkerUnlocked(cfg)
	if w != nil {
		t.Error("ensureWorkerUnlocked should return nil when workerErr is set")
	}
}

// TestBuildWrapConfig verifies that buildWrapConfig correctly converts
// reExecConfig to platform.WrapConfig.
func TestBuildWrapConfig(t *testing.T) {
	cfg := &reExecConfig{
		WritableRoots: []string{"/tmp", "/var/tmp"},
		DenyWrite:     []string{"/etc", "/usr"},
		DenyRead:      []string{"/root", "/home"},
		NeedsNetworkRestriction: true,
		ResourceLimits: &platform.ResourceLimits{
			MaxProcesses:       50,
			MaxMemoryBytes:     1024 * 1024 * 512,
			MaxFileDescriptors: 256,
			MaxCPUSeconds:      30,
		},
	}

	wcfg := buildWrapConfig(cfg)

	// Verify all fields are mapped correctly.
	if !stringSliceEqual(wcfg.WritableRoots, cfg.WritableRoots) {
		t.Errorf("WritableRoots mismatch: got %v, want %v", wcfg.WritableRoots, cfg.WritableRoots)
	}
	if !stringSliceEqual(wcfg.DenyWrite, cfg.DenyWrite) {
		t.Errorf("DenyWrite mismatch: got %v, want %v", wcfg.DenyWrite, cfg.DenyWrite)
	}
	if !stringSliceEqual(wcfg.DenyRead, cfg.DenyRead) {
		t.Errorf("DenyRead mismatch: got %v, want %v", wcfg.DenyRead, cfg.DenyRead)
	}
	if wcfg.NeedsNetworkRestriction != cfg.NeedsNetworkRestriction {
		t.Errorf("NeedsNetworkRestriction mismatch: got %v, want %v", wcfg.NeedsNetworkRestriction, cfg.NeedsNetworkRestriction)
	}
	if wcfg.ResourceLimits.MaxProcesses != cfg.ResourceLimits.MaxProcesses {
		t.Errorf("MaxProcesses mismatch: got %d, want %d", wcfg.ResourceLimits.MaxProcesses, cfg.ResourceLimits.MaxProcesses)
	}
	if wcfg.ResourceLimits.MaxMemoryBytes != cfg.ResourceLimits.MaxMemoryBytes {
		t.Errorf("MaxMemoryBytes mismatch: got %d, want %d", wcfg.ResourceLimits.MaxMemoryBytes, cfg.ResourceLimits.MaxMemoryBytes)
	}
}

// TestExecuteCommand tests the executeCommand function with a simple command.
// This test runs /bin/echo which should be available on all Linux systems.
func TestExecuteCommand(t *testing.T) {
	req := &workerRequest{
		ID:   "test-echo",
		Cmd:  "/bin/echo",
		Args: []string{"hello", "world"},
	}

	baseCfg := &reExecConfig{}
	resp := executeCommand(req, baseCfg)

	if resp.ID != req.ID {
		t.Errorf("response ID mismatch: got %q, want %q", resp.ID, req.ID)
	}

	if resp.ExitCode != 0 {
		t.Errorf("unexpected exit code: got %d, want 0", resp.ExitCode)
	}

	stdout := string(resp.Stdout)
	expected := "hello world\n"
	if stdout != expected {
		t.Errorf("stdout mismatch: got %q, want %q", stdout, expected)
	}

	if resp.Error != "" {
		t.Errorf("unexpected error: %v", resp.Error)
	}
}

// TestExecuteCommandFailure tests executeCommand with a command that fails.
func TestExecuteCommandFailure(t *testing.T) {
	req := &workerRequest{
		ID:   "test-false",
		Cmd:  "/bin/false",
		Args: []string{},
	}

	baseCfg := &reExecConfig{}
	resp := executeCommand(req, baseCfg)

	if resp.ExitCode == 0 {
		t.Error("expected non-zero exit code for /bin/false")
	}
}

// TestExecuteCommandWithDir tests executeCommand with a working directory.
func TestExecuteCommandWithDir(t *testing.T) {
	req := &workerRequest{
		ID:   "test-pwd",
		Cmd:  "/bin/pwd",
		Args: []string{},
		Dir:  "/tmp",
	}

	baseCfg := &reExecConfig{}
	resp := executeCommand(req, baseCfg)

	if resp.ExitCode != 0 {
		t.Errorf("unexpected exit code: got %d, want 0", resp.ExitCode)
	}

	stdout := strings.TrimSpace(string(resp.Stdout))
	if stdout != "/tmp" {
		t.Errorf("pwd output mismatch: got %q, want %q", stdout, "/tmp")
	}
}

// TestExecuteCommandWithEnv tests executeCommand with environment variables.
func TestExecuteCommandWithEnv(t *testing.T) {
	req := &workerRequest{
		ID:   "test-env",
		Cmd:  "/bin/sh",
		Args: []string{"-c", "echo $TEST_VAR"},
		Env:  []string{"TEST_VAR=hello"},
	}

	baseCfg := &reExecConfig{}
	resp := executeCommand(req, baseCfg)

	if resp.ExitCode != 0 {
		t.Errorf("unexpected exit code: got %d, want 0", resp.ExitCode)
	}

	stdout := strings.TrimSpace(string(resp.Stdout))
	if stdout != "hello" {
		t.Errorf("env var output mismatch: got %q, want %q", stdout, "hello")
	}
}

// TestWorkerClientAlive tests the alive and aliveUnlocked methods.
func TestWorkerClientAlive(t *testing.T) {
	done := make(chan struct{})
	w := &workerClient{
		done: done,
	}

	// Worker should be alive initially.
	if !w.alive() {
		t.Error("worker should be alive initially")
	}

	// Close the done channel to simulate worker exit.
	close(done)

	// Worker should now be dead.
	if w.alive() {
		t.Error("worker should be dead after done channel closed")
	}
}

// TestWorkerRequestDeadline tests that execCommand respects context deadlines.
func TestWorkerRequestDeadline(t *testing.T) {
	// Create a worker client with a pipe connection.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan struct{})
	w := &workerClient{
		conn: client,
		done: done,
	}

	// Create a context with a very short deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	req := &workerRequest{
		ID:  "timeout-test",
		Cmd: "/bin/sleep",
		Args: []string{"10"},
	}

	// This should fail with a deadline error because we don't have a
	// real worker on the other end to respond.
	_, err := w.execCommand(ctx, req)
	if err == nil {
		t.Error("execCommand should fail with deadline exceeded")
	}
}

// TestStartWorkerProcessFailureFastFail verifies that startWorker returns
// immediately when the worker process exits with a failure before connecting,
// rather than waiting the full 5s timeout.
func TestStartWorkerProcessFailureFastFail(t *testing.T) {
	// Save original function and restore after test.
	origHarden := workerHardenFn
	defer func() { workerHardenFn = origHarden }()

	// Mock hardenProcess to fail immediately, simulating Landlock failure.
	workerHardenFn = func() error {
		return errors.New("simulated Landlock not supported")
	}

	baseCfg := reExecConfig{
		WritableRoots: []string{"/tmp"},
	}

	start := time.Now()
	_, err := startWorker(baseCfg)
	elapsed := time.Since(start)

	// Verify that an error was returned.
	if err == nil {
		t.Fatal("startWorker should return error when worker process fails")
	}

	// Verify the error message indicates process failure.
	if !strings.Contains(err.Error(), "worker process failed") {
		t.Errorf("error should mention 'worker process failed', got: %v", err)
	}

	// Verify that it failed fast (< 1s), not after the full 5s timeout.
	// Allow generous margin for slow CI/test environments.
	if elapsed > 2*time.Second {
		t.Errorf("startWorker took %v, expected fast failure (< 2s) not timeout", elapsed)
	}
}

// stringSliceEqual compares two string slices for equality.
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
