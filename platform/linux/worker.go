//go:build linux

package linux

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// workerEnvKey is the environment variable set when re-exec'ing as a worker.
// Its value is the Unix socket path the worker should connect to.
const workerEnvKey = "_AGENTBOX_WORKER"

// workerClient manages a persistent sandbox worker process.
// The worker process applies base sandbox restrictions once at startup,
// then handles commands via IPC, eliminating per-command re-exec overhead.
type workerClient struct {
	mu       sync.Mutex
	conn     net.Conn    // Unix socket connection to worker
	proc     *os.Process // worker process
	sockPath string      // Unix socket path
	tmpDir   string      // temporary directory for socket
	done     chan struct{}

	// baseCfg is the broadest sandbox config passed to worker at startup.
	// It contains the union of all WritableRoots the Manager may use.
	baseCfg reExecConfig
}

// startWorker launches a new worker process and returns a client handle.
// The worker process applies base sandbox restrictions (hardening, seccomp,
// Landlock with baseCfg) once at startup, then listens on a Unix socket
// for command execution requests.
//
// The worker is started by re-exec'ing os.Args[0] with _AGENTBOX_WORKER
// and _AGENTBOX_CONFIG environment variables set.
func startWorker(baseCfg reExecConfig) (*workerClient, error) {
	// Create temporary directory for the Unix socket.
	// Socket path must be < 108 bytes on Linux.
	tmpDir, err := os.MkdirTemp("", "agentbox-worker-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	sockPath := filepath.Join(tmpDir, "worker.sock")

	// Verify socket path length (Linux limit is 108 bytes).
	if len(sockPath) >= 108 {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("socket path too long: %d bytes (max 108): %s", len(sockPath), sockPath)
	}

	// Create Unix listener before starting worker so we can accept connection.
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("create socket listener: %w", err)
	}
	// Restrict socket to owner-only to prevent other processes from connecting.
	if chmodErr := os.Chmod(sockPath, 0o600); chmodErr != nil {
		_ = listener.Close()
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("chmod socket: %w", chmodErr)
	}
	defer func() { _ = listener.Close() }()

	// Start the worker process.
	// The worker will connect back to the socket we're listening on.
	proc, err := startWorkerProcess(baseCfg, sockPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("start worker process: %w", err)
	}

	// Wait for the worker to connect (with 5 second timeout).
	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		connCh <- conn
	}()

	var conn net.Conn
	select {
	case conn = <-connCh:
		// Worker connected successfully.
	case err := <-errCh:
		_ = proc.Kill()
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("accept worker connection: %w", err)
	case <-time.After(5 * time.Second):
		_ = proc.Kill()
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("worker connection timeout (5s)")
	}

	done := make(chan struct{})

	// Monitor worker process in background.
	go func() {
		_, _ = proc.Wait()
		close(done)
	}()

	return &workerClient{
		conn:     conn,
		proc:     proc,
		sockPath: sockPath,
		tmpDir:   tmpDir,
		done:     done,
		baseCfg:  baseCfg,
	}, nil
}

// startWorkerProcess spawns the worker process with _AGENTBOX_WORKER
// and _AGENTBOX_CONFIG environment variables set.
func startWorkerProcess(baseCfg reExecConfig, sockPath string) (*os.Process, error) {
	// Create pipe for passing baseCfg to the worker.
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create config pipe: %w", err)
	}
	defer func() { _ = w.Close() }()

	// Prepare command: re-exec self with worker environment.
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("%s=%s", workerEnvKey, sockPath),
		fmt.Sprintf("%s=%d", reExecEnvKey, r.Fd()),
	)
	cmd.ExtraFiles = []*os.File{r}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	// Start the worker process.
	if err := cmd.Start(); err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("exec worker: %w", err)
	}

	// Close read end in parent (worker will read it).
	_ = r.Close()

	// Write baseCfg to the pipe.
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(baseCfg); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("write worker config: %w", err)
	}

	return cmd.Process, nil
}

// execCommand sends a command to the worker and waits for the result.
// This is the fast path: no re-exec, no Go runtime restart, just IPC.
// The worker applies per-command sandbox restrictions before executing.
func (w *workerClient) execCommand(ctx context.Context, req *workerRequest) (*workerResponse, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check if worker is still alive.
	if !w.aliveUnlocked() {
		return nil, fmt.Errorf("worker process has exited")
	}

	// Set deadline from context.
	if deadline, ok := ctx.Deadline(); ok {
		if err := w.conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set deadline: %w", err)
		}
		defer func() {
			// Clear deadline after this operation.
			_ = w.conn.SetDeadline(time.Time{})
		}()
	}

	// Send request to worker.
	if err := encodeRequest(w.conn, req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	// Receive response from worker.
	resp, err := decodeResponse(w.conn)
	if err != nil {
		return nil, fmt.Errorf("receive response: %w", err)
	}

	return resp, nil
}

// alive reports whether the worker process is still running.
func (w *workerClient) alive() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.aliveUnlocked()
}

// aliveUnlocked checks if worker is alive (caller must hold w.mu).
func (w *workerClient) aliveUnlocked() bool {
	select {
	case <-w.done:
		return false
	default:
		return true
	}
}

// stop gracefully shuts down the worker process.
// It closes the socket (worker detects EOF and exits), waits for the
// process with a timeout, and cleans up the socket file and temp directory.
func (w *workerClient) stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Close the socket connection (worker will detect EOF and exit).
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}

	// Wait for worker to exit (with 2 second timeout).
	select {
	case <-w.done:
		// Worker exited gracefully.
	case <-time.After(2 * time.Second):
		// Timeout: force kill the worker.
		if w.proc != nil {
			_ = w.proc.Kill()
			// Wait again after kill.
			select {
			case <-w.done:
			case <-time.After(1 * time.Second):
			}
		}
	}

	// Clean up socket file and temp directory.
	if w.tmpDir != "" {
		_ = os.RemoveAll(w.tmpDir)
	}

	return nil
}
