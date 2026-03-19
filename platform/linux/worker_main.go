//go:build linux

package linux

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"

	"github.com/zhangyunhao116/agentbox/internal/envutil"
	"github.com/zhangyunhao116/agentbox/platform"
)

// Function variables for dependency injection in tests.
var (
	workerHardenFn    = hardenProcess
	workerBindMountFn = applyReadOnlyBindMounts
	workerLandlockFn  = applyLandlock
	// Note: NO seccomp for the worker itself — it needs socket + fork/exec syscalls.
)

// workerMain is the entry point for the persistent sandbox worker process.
// It applies one-time base sandbox restrictions and then listens for commands
// via Unix domain socket. It never returns — it calls os.Exit when done.
func workerMain(sockPath string) int {
	// Lock OS thread (required for seccomp, Landlock, prctl operations).
	// This is the worker process, so we lock and never unlock — the process
	// will run the main loop until shutdown.
	runtime.LockOSThread()

	// Read base config from pipe (same _AGENTBOX_CONFIG mechanism as re-exec).
	// The parent passes the base sandbox config via a pipe.
	fdStr := os.Getenv(reExecEnvKey)
	if fdStr == "" {
		fmt.Fprintf(os.Stderr, "agentbox: worker missing config fd\n")
		return 1
	}

	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: worker invalid config fd %q: %v\n", fdStr, err)
		return 1
	}

	// Read configuration from the pipe.
	configFile := os.NewFile(uintptr(fd), "config-pipe") //nolint:gosec // fd is validated via strconv.Atoi
	if configFile == nil {
		fmt.Fprintf(os.Stderr, "agentbox: worker cannot open config fd %d\n", fd)
		return 1
	}
	defer func() { _ = configFile.Close() }()

	var baseCfg reExecConfig
	if err := json.NewDecoder(configFile).Decode(&baseCfg); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: worker decode config: %v\n", err)
		return 1
	}

	// Apply one-time base sandbox restrictions.
	// These are applied once at worker startup and inherited by all commands.

	// 1. Process hardening: PR_SET_NO_NEW_PRIVS, disable core dumps.
	if err := workerHardenFn(); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: worker harden: %v\n", err)
		return 1
	}

	// 2. Apply read-only bind mounts for the base config's DenyWrite paths.
	// This must be done before Landlock since mount operations require
	// capabilities that Landlock may restrict.
	wrapCfg := buildWrapConfig(&baseCfg)
	if err := workerBindMountFn(wrapCfg); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: worker bind mounts: %v\n", err)
		return 1
	}

	// 3. Apply Landlock with the FULL Manager config (broadest rules).
	// The worker starts with the widest permissions — per-command tightening
	// is deferred to future optimizations. The key win is avoiding Go runtime
	// restart for each command.
	if err := workerLandlockFn(wrapCfg); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: worker landlock: %v\n", err)
		return 1
	}

	// NOTE: We do NOT apply seccomp to the worker process itself.
	// The worker needs to:
	//   - Create Unix domain sockets for IPC
	//   - fork+exec child processes
	// The standard seccomp filter blocks socket() and other syscalls needed here.
	// Each command child inherits the worker's Landlock+harden restrictions,
	// which is sufficient for v1. Seccomp for individual commands can be added
	// in a future per-command re-exec helper.

	// 4. Connect to the Unix socket created by the parent Manager.
	// The Manager creates the listener before starting the worker process,
	// so we dial and connect to it here.
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: worker connect to %q: %v\n", sockPath, err)
		return 1
	}
	defer func() { _ = conn.Close() }()

	// 5. Main loop: read requests, execute commands, send responses.
	for {
		req, err := decodeRequest(conn)
		if err != nil {
			// EOF or connection error = parent closed connection = shutdown.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			fmt.Fprintf(os.Stderr, "agentbox: worker decode request: %v\n", err)
			break
		}

		resp := executeCommand(req, &baseCfg)

		if err := encodeResponse(conn, resp); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: worker encode response: %v\n", err)
			break
		}
	}

	return 0
}

// buildWrapConfig converts a reExecConfig to a WrapConfig.
func buildWrapConfig(cfg *reExecConfig) *platform.WrapConfig {
	return &platform.WrapConfig{
		WritableRoots:           cfg.WritableRoots,
		DenyWrite:               cfg.DenyWrite,
		DenyRead:                cfg.DenyRead,
		NeedsNetworkRestriction: cfg.NeedsNetworkRestriction,
		ResourceLimits:          cfg.ResourceLimits,
	}
}

// executeCommand runs a single command request within the worker.
// For per-command Landlock tightening, a future optimization could re-exec a
// lightweight helper. For v1, we run commands directly — they inherit the
// worker's broad Landlock restrictions.
//
//nolint:unparam // baseCfg reserved for future per-command sandbox tightening
func executeCommand(req *workerRequest, baseCfg *reExecConfig) *workerResponse {
	// Build the actual command.
	cmd := exec.Command(req.Cmd, req.Args...)
	cmd.Dir = req.Dir
	cmd.Env = envutil.SanitizeEnv(req.Env)

	// Capture stdout/stderr.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Apply per-command resource limits to the child via SysProcAttr.
	// Note: We can't use SysProcAttr.Cloneflags from within a user namespace
	// (we're already in one). But we can set Pdeathsig and will apply
	// resource limits in a future enhancement via setrlimit in the child.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// Kill child if worker dies.
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL

	// Run the command.
	err := cmd.Run()

	resp := &workerResponse{
		ID:     req.ID,
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}

	// Truncate output if MaxOutputBytes is set and exceeded.
	if req.MaxOutputBytes > 0 {
		if len(resp.Stdout) > req.MaxOutputBytes {
			resp.Stdout = resp.Stdout[:req.MaxOutputBytes]
		}
		if len(resp.Stderr) > req.MaxOutputBytes {
			resp.Stderr = resp.Stderr[:req.MaxOutputBytes]
		}
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			resp.ExitCode = exitErr.ExitCode()
		} else {
			resp.Error = err.Error()
			resp.ExitCode = -1
		}
	}

	return resp
}
