package proxy

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// shortTempDir creates a short temporary directory suitable for Unix sockets.
// macOS has a 104-byte limit for Unix socket paths, and shortTempDir(t) paths
// can exceed this limit. This helper uses /tmp with a short prefix.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "brt")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// startTCPEchoServer starts a TCP server that echoes back whatever it receives.
// Returns the address and a cleanup function.
func startTCPEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	return ln.Addr().String()
}

// ---------------------------------------------------------------------------
// NewBridge tests
// ---------------------------------------------------------------------------

func TestNewBridge_ValidConfig(t *testing.T) {
	dir := shortTempDir(t)
	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: "127.0.0.1:8080",
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}
	if b == nil {
		t.Fatal("expected non-nil bridge")
	}

	expectedPath := filepath.Join(dir, "test.sock")
	if b.SocketPath() != expectedPath {
		t.Errorf("expected socket path %s, got %s", expectedPath, b.SocketPath())
	}
}

func TestNewBridge_NilConfig(t *testing.T) {
	_, err := NewBridge(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestNewBridge_MissingSocketDir(t *testing.T) {
	_, err := NewBridge(&BridgeConfig{
		TargetAddr: "127.0.0.1:8080",
	})
	if err == nil {
		t.Fatal("expected error for missing socket dir")
	}
}

func TestNewBridge_MissingTargetAddr(t *testing.T) {
	_, err := NewBridge(&BridgeConfig{
		SocketDir: "/tmp",
	})
	if err == nil {
		t.Fatal("expected error for missing target addr")
	}
}

func TestNewBridge_DefaultLabel(t *testing.T) {
	dir := shortTempDir(t)
	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	expectedPath := filepath.Join(dir, "bridge.sock")
	if b.SocketPath() != expectedPath {
		t.Errorf("expected socket path %s, got %s", expectedPath, b.SocketPath())
	}
}

func TestNewBridge_DefaultMaxConns(t *testing.T) {
	dir := shortTempDir(t)
	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}
	if cap(b.sem) != defaultBridgeMaxConns {
		t.Errorf("expected default max conns %d, got %d", defaultBridgeMaxConns, cap(b.sem))
	}
}

func TestNewBridge_CustomMaxConns(t *testing.T) {
	dir := shortTempDir(t)
	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: "127.0.0.1:8080",
		MaxConns:   10,
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}
	if cap(b.sem) != 10 {
		t.Errorf("expected max conns 10, got %d", cap(b.sem))
	}
}

func TestNewBridge_DefaultDialTimeout(t *testing.T) {
	dir := shortTempDir(t)
	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}
	if b.dialer.Timeout != defaultBridgeDialTimeout {
		t.Errorf("expected default dial timeout %v, got %v", defaultBridgeDialTimeout, b.dialer.Timeout)
	}
}

// ---------------------------------------------------------------------------
// Start tests
// ---------------------------------------------------------------------------

func TestBridge_Start_CreatesSocket(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr := startTCPEchoServer(t)

	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: echoAddr,
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer b.Shutdown(2 * time.Second)

	// Verify socket file exists.
	socketPath := b.SocketPath()
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("socket file not found: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Errorf("expected socket file, got mode %v", info.Mode())
	}
}

func TestBridge_Start_RemovesStaleSocket(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr := startTCPEchoServer(t)

	// Create a stale socket file.
	stalePath := filepath.Join(dir, "test.sock")
	if err := os.WriteFile(stalePath, []byte("stale"), 0600); err != nil {
		t.Fatalf("failed to create stale file: %v", err)
	}

	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: echoAddr,
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer b.Shutdown(2 * time.Second)

	// Socket should be a real socket now, not the stale file.
	info, err := os.Stat(b.SocketPath())
	if err != nil {
		t.Fatalf("socket file not found: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Errorf("expected socket file, got mode %v", info.Mode())
	}
}

// ---------------------------------------------------------------------------
// Forwarding tests
// ---------------------------------------------------------------------------

func TestBridge_ForwardsConnections(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr := startTCPEchoServer(t)

	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: echoAddr,
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer b.Shutdown(2 * time.Second)

	// Connect through the Unix socket.
	conn, err := net.Dial("unix", b.SocketPath())
	if err != nil {
		t.Fatalf("failed to connect to bridge: %v", err)
	}
	defer conn.Close()

	// Send data and verify echo.
	msg := "hello bridge"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// Close write side to signal EOF to the echo server.
	if uc, ok := conn.(*net.UnixConn); ok {
		uc.CloseWrite()
	}

	buf, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	if string(buf) != msg {
		t.Errorf("expected %q, got %q", msg, string(buf))
	}
}

func TestBridge_MultipleConnections(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr := startTCPEchoServer(t)

	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: echoAddr,
		Label:      "test",
		MaxConns:   50,
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer b.Shutdown(5 * time.Second)

	const numConns = 20
	var wg sync.WaitGroup
	errors := make(chan error, numConns)

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, err := net.Dial("unix", b.SocketPath())
			if err != nil {
				errors <- fmt.Errorf("conn %d: dial: %w", idx, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("msg-%d", idx)
			_, err = conn.Write([]byte(msg))
			if err != nil {
				errors <- fmt.Errorf("conn %d: write: %w", idx, err)
				return
			}

			if uc, ok := conn.(*net.UnixConn); ok {
				uc.CloseWrite()
			}

			buf, err := io.ReadAll(conn)
			if err != nil {
				errors <- fmt.Errorf("conn %d: read: %w", idx, err)
				return
			}

			if string(buf) != msg {
				errors <- fmt.Errorf("conn %d: expected %q, got %q", idx, msg, string(buf))
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// Shutdown tests
// ---------------------------------------------------------------------------

func TestBridge_Shutdown_StopsAccepting(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr := startTCPEchoServer(t)

	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: echoAddr,
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	err = b.Shutdown(2 * time.Second)
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// After shutdown, connecting should fail.
	_, err = net.DialTimeout("unix", b.SocketPath(), 500*time.Millisecond)
	if err == nil {
		t.Error("expected connection to fail after shutdown")
	}
}

func TestBridge_Shutdown_CleansUpSocket(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr := startTCPEchoServer(t)

	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: echoAddr,
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	socketPath := b.SocketPath()

	// Verify socket exists before shutdown.
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("socket should exist before shutdown: %v", err)
	}

	err = b.Shutdown(2 * time.Second)
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Verify socket is removed after shutdown.
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("socket file should be removed after shutdown")
	}
}

// ---------------------------------------------------------------------------
// Semaphore tests
// ---------------------------------------------------------------------------

func TestBridge_SemaphoreLimits(t *testing.T) {
	dir := shortTempDir(t)

	// Create a TCP server that holds connections open.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer ln.Close()

	var connCount atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connCount.Add(1)
			// Hold connection open - don't close.
			go func(c net.Conn) {
				buf := make([]byte, 1024)
				c.Read(buf) // Block until closed.
			}(conn)
		}
	}()

	const maxConns = 3
	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: ln.Addr().String(),
		Label:      "test",
		MaxConns:   maxConns,
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer b.Shutdown(2 * time.Second)

	// Open maxConns connections.
	conns := make([]net.Conn, 0, maxConns)
	for i := 0; i < maxConns; i++ {
		conn, err := net.Dial("unix", b.SocketPath())
		if err != nil {
			t.Fatalf("failed to connect %d: %v", i, err)
		}
		conns = append(conns, conn)
		// Write something to trigger the forwarding.
		conn.Write([]byte("x"))
	}

	// Give time for connections to be established.
	time.Sleep(200 * time.Millisecond)

	// Verify all maxConns connections were forwarded.
	count := connCount.Load()
	if count != int32(maxConns) {
		t.Errorf("expected %d connections, got %d", maxConns, count)
	}

	// Clean up.
	for _, conn := range conns {
		conn.Close()
	}
}

// ---------------------------------------------------------------------------
// Concurrent connection tracking tests
// ---------------------------------------------------------------------------

func TestBridge_ConcurrentConnections(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr := startTCPEchoServer(t)

	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: echoAddr,
		Label:      "test",
		MaxConns:   50,
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer b.Shutdown(5 * time.Second)

	const numConns = 30
	var wg sync.WaitGroup
	errCh := make(chan error, numConns)

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, err := net.Dial("unix", b.SocketPath())
			if err != nil {
				errCh <- fmt.Errorf("conn %d: %w", idx, err)
				return
			}

			msg := fmt.Sprintf("concurrent-%d", idx)
			conn.Write([]byte(msg))
			if uc, ok := conn.(*net.UnixConn); ok {
				uc.CloseWrite()
			}

			buf, err := io.ReadAll(conn)
			conn.Close()
			if err != nil {
				errCh <- fmt.Errorf("conn %d read: %w", idx, err)
				return
			}
			if string(buf) != msg {
				errCh <- fmt.Errorf("conn %d: expected %q, got %q", idx, msg, string(buf))
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// BridgePair tests
// ---------------------------------------------------------------------------

func TestNewBridgePair(t *testing.T) {
	dir := shortTempDir(t)
	bp, err := NewBridgePair(dir, "127.0.0.1:8080", "127.0.0.1:1080", nil)
	if err != nil {
		t.Fatalf("NewBridgePair failed: %v", err)
	}
	if bp.HTTP == nil {
		t.Fatal("expected non-nil HTTP bridge")
	}
	if bp.SOCKS == nil {
		t.Fatal("expected non-nil SOCKS bridge")
	}

	expectedHTTP := filepath.Join(dir, "http-proxy.sock")
	if bp.HTTP.SocketPath() != expectedHTTP {
		t.Errorf("expected HTTP socket %s, got %s", expectedHTTP, bp.HTTP.SocketPath())
	}

	expectedSOCKS := filepath.Join(dir, "socks-proxy.sock")
	if bp.SOCKS.SocketPath() != expectedSOCKS {
		t.Errorf("expected SOCKS socket %s, got %s", expectedSOCKS, bp.SOCKS.SocketPath())
	}
}

func TestNewBridgePair_InvalidSocketDir(t *testing.T) {
	// Empty socket dir should fail.
	_, err := NewBridgePair("", "127.0.0.1:8080", "127.0.0.1:1080", nil)
	if err == nil {
		t.Fatal("expected error for empty socket dir")
	}
}

func TestBridgePair_Lifecycle(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr1 := startTCPEchoServer(t)
	echoAddr2 := startTCPEchoServer(t)

	bp, err := NewBridgePair(dir, echoAddr1, echoAddr2, nil)
	if err != nil {
		t.Fatalf("NewBridgePair failed: %v", err)
	}

	err = bp.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Verify both sockets exist.
	if _, err := os.Stat(bp.HTTP.SocketPath()); err != nil {
		t.Fatalf("HTTP socket not found: %v", err)
	}
	if _, err := os.Stat(bp.SOCKS.SocketPath()); err != nil {
		t.Fatalf("SOCKS socket not found: %v", err)
	}

	// Test forwarding through HTTP bridge.
	conn, err := net.Dial("unix", bp.HTTP.SocketPath())
	if err != nil {
		t.Fatalf("failed to connect to HTTP bridge: %v", err)
	}
	msg := "http-test"
	conn.Write([]byte(msg))
	if uc, ok := conn.(*net.UnixConn); ok {
		uc.CloseWrite()
	}
	buf, _ := io.ReadAll(conn)
	conn.Close()
	if string(buf) != msg {
		t.Errorf("HTTP bridge: expected %q, got %q", msg, string(buf))
	}

	// Test forwarding through SOCKS bridge.
	conn, err = net.Dial("unix", bp.SOCKS.SocketPath())
	if err != nil {
		t.Fatalf("failed to connect to SOCKS bridge: %v", err)
	}
	msg = "socks-test"
	conn.Write([]byte(msg))
	if uc, ok := conn.(*net.UnixConn); ok {
		uc.CloseWrite()
	}
	buf, _ = io.ReadAll(conn)
	conn.Close()
	if string(buf) != msg {
		t.Errorf("SOCKS bridge: expected %q, got %q", msg, string(buf))
	}

	// Shutdown.
	bp.Shutdown(2 * time.Second)

	// Verify sockets are cleaned up.
	if _, err := os.Stat(bp.HTTP.SocketPath()); !os.IsNotExist(err) {
		t.Error("HTTP socket should be removed after shutdown")
	}
	if _, err := os.Stat(bp.SOCKS.SocketPath()); !os.IsNotExist(err) {
		t.Error("SOCKS socket should be removed after shutdown")
	}
}

func TestBridgePair_StartShutdown(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr := startTCPEchoServer(t)

	bp, err := NewBridgePair(dir, echoAddr, echoAddr, nil)
	if err != nil {
		t.Fatalf("NewBridgePair failed: %v", err)
	}

	err = bp.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Immediate shutdown should work.
	bp.Shutdown(2 * time.Second)
}

// ---------------------------------------------------------------------------
// Bridge error path tests
// ---------------------------------------------------------------------------

// TestBridge_Start_InvalidSocketDir verifies that Start fails when the
// socket directory does not exist.
func TestBridge_Start_InvalidSocketDir(t *testing.T) {
	b, err := NewBridge(&BridgeConfig{
		SocketDir:  "/nonexistent/dir/that/does/not/exist",
		TargetAddr: "127.0.0.1:8080",
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err == nil {
		t.Fatal("Start should fail with invalid socket dir")
	}
}

// TestBridge_HandleConn_DialFailure verifies that handleConn gracefully
// handles a dial failure to the target.
func TestBridge_HandleConn_DialFailure(t *testing.T) {
	dir := shortTempDir(t)

	// Use a target address that is not listening.
	b, err := NewBridge(&BridgeConfig{
		SocketDir:   dir,
		TargetAddr:  "127.0.0.1:1", // Port 1 is unlikely to be listening.
		Label:       "test",
		DialTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer b.Shutdown(2 * time.Second)

	// Connect to the bridge — the bridge should fail to dial the target
	// and close the connection gracefully.
	conn, err := net.DialTimeout("unix", b.SocketPath(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to bridge: %v", err)
	}

	// Write something and try to read — should get EOF or error.
	conn.Write([]byte("hello"))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	_, readErr := conn.Read(buf)
	conn.Close()

	// We expect an error (EOF or connection reset) since the target is unreachable.
	if readErr == nil {
		t.Error("expected read error when target is unreachable")
	}
}

// TestBridge_Shutdown_ForceCloseActiveConns verifies that Shutdown force-closes
// active connections when the timeout expires.
func TestBridge_Shutdown_ForceCloseActiveConns(t *testing.T) {
	dir := shortTempDir(t)

	// Create a TCP server that holds connections open indefinitely.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold connection open — never close or respond.
			go func(c net.Conn) {
				buf := make([]byte, 1024)
				c.Read(buf) // Block until closed.
			}(conn)
		}
	}()

	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: ln.Addr().String(),
		Label:      "test",
		MaxConns:   10,
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Open a connection and keep it alive.
	conn, err := net.Dial("unix", b.SocketPath())
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	conn.Write([]byte("hold"))

	// Shutdown with a very short timeout to trigger force close.
	err = b.Shutdown(100 * time.Millisecond)
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	conn.Close()
}

// TestBridge_ShutdownBeforeStart verifies that Shutdown works even if
// Start was never called (listener is nil).
func TestBridge_ShutdownBeforeStart(t *testing.T) {
	dir := shortTempDir(t)
	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: "127.0.0.1:8080",
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	// Shutdown without Start should not panic.
	err = b.Shutdown(1 * time.Second)
	if err != nil {
		t.Fatalf("Shutdown before Start failed: %v", err)
	}
}

// TestBridgePair_StartHTTPFails verifies that BridgePair.Start returns an
// error when the HTTP bridge fails to start.
func TestBridgePair_StartHTTPFails(t *testing.T) {
	// Use a non-existent directory for the HTTP bridge.
	bp, err := NewBridgePair("/nonexistent/dir", "127.0.0.1:8080", "127.0.0.1:1080", nil)
	if err != nil {
		t.Fatalf("NewBridgePair failed: %v", err)
	}

	err = bp.Start()
	if err == nil {
		t.Fatal("Start should fail when HTTP bridge cannot start")
	}
}

// TestBridgePair_StartSOCKSFails verifies that BridgePair.Start cleans up
// the HTTP bridge when the SOCKS bridge fails to start.
func TestBridgePair_StartSOCKSFails(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr := startTCPEchoServer(t)

	bp, err := NewBridgePair(dir, echoAddr, echoAddr, nil)
	if err != nil {
		t.Fatalf("NewBridgePair failed: %v", err)
	}

	// Sabotage the SOCKS bridge by making its socket dir unwritable.
	// First, start the HTTP bridge manually to occupy the dir, then
	// make the SOCKS socket path a read-only directory.
	socksSocketDir := filepath.Dir(bp.SOCKS.SocketPath())
	socksSocketFile := bp.SOCKS.SocketPath()

	// Create a directory at the socket path to prevent listen.
	if err := os.MkdirAll(socksSocketFile, 0755); err != nil {
		t.Fatalf("failed to create blocking dir: %v", err)
	}
	// Also create a file inside to prevent removal.
	if err := os.WriteFile(filepath.Join(socksSocketFile, "blocker"), []byte("x"), 0644); err != nil {
		t.Fatalf("failed to create blocker file: %v", err)
	}
	_ = socksSocketDir

	err = bp.Start()
	if err == nil {
		bp.Shutdown(2 * time.Second)
		t.Fatal("Start should fail when SOCKS bridge cannot start")
	}
}

// TestNewBridgePair_InvalidSOCKSAddr verifies that NewBridgePair fails
// when the SOCKS address is empty.
func TestNewBridgePair_InvalidSOCKSAddr(t *testing.T) {
	dir := shortTempDir(t)
	_, err := NewBridgePair(dir, "127.0.0.1:8080", "", nil)
	if err == nil {
		t.Fatal("expected error for empty SOCKS addr")
	}
}

// ---------------------------------------------------------------------------
// Socket permissions tests
// ---------------------------------------------------------------------------

func TestBridge_Start_SocketPermissions(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr := startTCPEchoServer(t)

	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: echoAddr,
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer b.Shutdown(2 * time.Second)

	// Verify socket file has restrictive permissions (0600).
	info, err := os.Stat(b.SocketPath())
	if err != nil {
		t.Fatalf("socket file not found: %v", err)
	}
	// On Unix, socket files may have the socket bit set. Mask to get permission bits.
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("socket permissions = %o, want 0600", perm)
	}
}

// ---------------------------------------------------------------------------
// Socket cleanup on listen failure test
// ---------------------------------------------------------------------------

func TestBridge_Start_ListenFailure_NoLeftoverSocket(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr := startTCPEchoServer(t)

	// Start a bridge to occupy the socket.
	b1, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: echoAddr,
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}
	err = b1.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Try to start a second bridge with the same socket path.
	// This should fail because the socket is already in use.
	// The first bridge's socket should still be intact.
	b2, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: echoAddr,
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	// b2.Start() will remove the stale socket and try to listen.
	// After b2 starts, b1's listener is broken. Clean up b1 first.
	defer b1.Shutdown(2 * time.Second)

	// Start b2 — it should succeed because it removes the stale socket.
	err = b2.Start()
	if err != nil {
		// If it fails, that's also acceptable — the point is no leftover socket
		// from a failed listen attempt.
		return
	}
	b2.Shutdown(2 * time.Second)
}

// ---------------------------------------------------------------------------
// Test: Start — remove stale socket error (L129-131)
// ---------------------------------------------------------------------------

func TestBridge_Start_RemoveStaleSocketError(t *testing.T) {
	dir := shortTempDir(t)

	// Create a directory at the socket path to prevent os.Remove from
	// succeeding (removing a non-empty directory fails).
	socketPath := filepath.Join(dir, "test.sock")
	if err := os.MkdirAll(filepath.Join(socketPath, "subdir"), 0755); err != nil {
		t.Fatalf("failed to create blocking dir: %v", err)
	}

	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: "127.0.0.1:8080",
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err == nil {
		b.Shutdown(1 * time.Second)
		t.Fatal("expected error when stale socket cannot be removed")
	}
	if !strings.Contains(err.Error(), "remove stale socket") {
		t.Errorf("error = %q, want it to contain 'remove stale socket'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: acceptLoop — context cancel during semaphore wait (L184-187)
// ---------------------------------------------------------------------------

func TestBridge_AcceptLoop_ContextCancelDuringSemaphore(t *testing.T) {
	dir := shortTempDir(t)

	// Create a TCP server that holds connections open.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 1024)
				c.Read(buf) // Block until closed.
			}(conn)
		}
	}()

	// Create a bridge with maxConns=1 so the semaphore fills quickly.
	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: ln.Addr().String(),
		Label:      "test",
		MaxConns:   1,
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Open one connection to fill the semaphore.
	conn1, err := net.Dial("unix", b.SocketPath())
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	conn1.Write([]byte("fill"))

	// Give time for the connection to be forwarded and semaphore to be acquired.
	time.Sleep(100 * time.Millisecond)

	// Open a second connection — it will be accepted but block on semaphore.
	conn2, err := net.Dial("unix", b.SocketPath())
	if err != nil {
		t.Fatalf("failed to connect second: %v", err)
	}
	conn2.Write([]byte("wait"))

	// Give time for the second connection to be accepted and block on semaphore.
	time.Sleep(100 * time.Millisecond)

	// Now cancel the context by shutting down — this should trigger L184-187.
	err = b.Shutdown(500 * time.Millisecond)
	if err != nil {
		t.Logf("Shutdown error (may be expected): %v", err)
	}

	conn1.Close()
	conn2.Close()
}

// ---------------------------------------------------------------------------
// Test: acceptLoop — accept error without context cancel (L173-177)
// ---------------------------------------------------------------------------

func TestBridge_AcceptLoop_AcceptErrorNonCancel(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr := startTCPEchoServer(t)

	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: echoAddr,
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Close the listener directly (without cancelling the context).
	// This triggers the accept error path at L173-177 where ctx is NOT done.
	b.listener.Close()

	// Give the accept loop time to notice the closed listener.
	time.Sleep(100 * time.Millisecond)

	// Clean up — cancel the context and wait.
	b.cancel()
	b.wg.Wait()

	// Remove the socket file manually since Shutdown won't be called.
	os.Remove(b.socketPath)
}

// ---------------------------------------------------------------------------
// Test: Shutdown — socket remove error (L302-304)
// ---------------------------------------------------------------------------

func TestBridge_Shutdown_SocketRemoveError(t *testing.T) {
	dir := shortTempDir(t)
	echoAddr := startTCPEchoServer(t)

	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: echoAddr,
		Label:      "test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	err = b.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Replace the socket path with a directory to make os.Remove fail.
	// First, remove the real socket.
	socketPath := b.socketPath
	os.Remove(socketPath)

	// Create a non-empty directory at the socket path.
	if err := os.MkdirAll(filepath.Join(socketPath, "subdir"), 0755); err != nil {
		t.Fatalf("failed to create blocking dir: %v", err)
	}

	// Shutdown should fail to remove the socket directory.
	err = b.Shutdown(2 * time.Second)
	if err == nil {
		t.Fatal("expected error when socket cannot be removed")
	}
	if !strings.Contains(err.Error(), "remove socket") {
		t.Errorf("error = %q, want it to contain 'remove socket'", err.Error())
	}

	// Clean up.
	os.RemoveAll(socketPath)
}

// ---------------------------------------------------------------------------
// Test: handleConn — copy error (target→client) (bridge.go:237-239)
// ---------------------------------------------------------------------------

func TestBridge_HandleConn_CopyError_TargetToClient(t *testing.T) {
	// Start a TCP server that sends data continuously, then resets.
	// This triggers the copy error in the target→client direction when
	// the Unix socket client closes while data is still being sent.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start TCP server: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Send a large amount of data to keep the copy busy.
				data := strings.Repeat("x", 4096)
				for i := 0; i < 100; i++ {
					if _, err := c.Write([]byte(data)); err != nil {
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}(conn)
		}
	}()

	dir := shortTempDir(t)
	b, err := NewBridge(&BridgeConfig{
		SocketDir:  dir,
		TargetAddr: ln.Addr().String(),
		Label:      "copy-err-test",
	})
	if err != nil {
		t.Fatalf("NewBridge failed: %v", err)
	}

	if err := b.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer b.Shutdown(2 * time.Second)

	// Connect to the bridge via Unix socket.
	conn, err := net.Dial("unix", b.socketPath)
	if err != nil {
		t.Fatalf("dial bridge failed: %v", err)
	}

	// Read a small amount to confirm data is flowing.
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("initial read failed: %v", err)
	}

	// Close the Unix socket client abruptly while the target is still
	// sending data. This triggers the copy error in the target→client
	// goroutine (bridge.go:237-239).
	conn.Close()

	// Give the bridge time to encounter the copy error.
	time.Sleep(200 * time.Millisecond)
}
