package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Default values for bridge configuration.
const (
	defaultBridgeMaxConns    = 100
	defaultBridgeDialTimeout = 5 * time.Second
	bridgeCopyBufSize        = 32 * 1024
)

// BridgeConfig configures a Unix socket to TCP bridge.
type BridgeConfig struct {
	// SocketDir is the directory where the Unix socket file will be created.
	SocketDir string

	// TargetAddr is the TCP target address to forward connections to
	// (e.g., "127.0.0.1:8080").
	TargetAddr string

	// Label is a descriptive label used in log messages.
	Label string

	// MaxConns is the maximum number of concurrent connections.
	// Defaults to 100 if zero.
	MaxConns int

	// DialTimeout is the timeout for dialing the TCP target.
	// Defaults to 5s if zero.
	DialTimeout time.Duration

	// Logger is the structured logger. If nil, a no-op logger is used.
	Logger *slog.Logger
}

// Bridge forwards connections from a Unix socket to a TCP address.
// It acts as a replacement for socat, bridging Unix domain sockets
// to TCP endpoints for use in sandboxed environments.
type Bridge struct {
	config      *BridgeConfig
	socketPath  string
	listener    net.Listener
	dialer      net.Dialer
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	sem         chan struct{}
	connMu      sync.Mutex
	activeConns map[net.Conn]struct{}
}

// NewBridge creates a new Bridge with the given configuration.
// Returns an error if required configuration fields are missing.
func NewBridge(cfg *BridgeConfig) (*Bridge, error) {
	if cfg == nil {
		return nil, errors.New("bridge: config is required")
	}
	if cfg.SocketDir == "" {
		return nil, errors.New("bridge: socket dir is required")
	}
	if cfg.TargetAddr == "" {
		return nil, errors.New("bridge: target addr is required")
	}

	maxConns := cfg.MaxConns
	if maxConns <= 0 {
		maxConns = defaultBridgeMaxConns
	}

	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultBridgeDialTimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	label := cfg.Label
	if label == "" {
		label = "bridge"
	}

	resolvedCfg := &BridgeConfig{
		SocketDir:   cfg.SocketDir,
		TargetAddr:  cfg.TargetAddr,
		Label:       label,
		MaxConns:    maxConns,
		DialTimeout: dialTimeout,
		Logger:      logger,
	}

	socketPath := filepath.Join(cfg.SocketDir, label+".sock")

	ctx, cancel := context.WithCancel(context.Background())

	return &Bridge{
		config:      resolvedCfg,
		socketPath:  socketPath,
		dialer:      net.Dialer{Timeout: dialTimeout},
		ctx:         ctx,
		cancel:      cancel,
		sem:         make(chan struct{}, maxConns),
		activeConns: make(map[net.Conn]struct{}),
	}, nil
}

// SocketPath returns the path to the Unix socket file.
func (b *Bridge) SocketPath() string {
	return b.socketPath
}

// Start begins listening on the Unix socket and forwarding connections
// to the configured TCP target address.
func (b *Bridge) Start() error {
	// Remove any stale socket file. Note: there is a small TOCTOU window
	// between Remove and Listen. This is acceptable because the socket path
	// resides in a private temp directory created by the caller with
	// restrictive permissions (0700).
	if err := os.Remove(b.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("bridge: remove stale socket %s: %w", b.socketPath, err)
	}

	ln, err := net.Listen("unix", b.socketPath)
	if err != nil {
		return fmt.Errorf("bridge: listen on %s: %w", b.socketPath, err)
	}

	// Set restrictive permissions on the socket file.
	if err := os.Chmod(b.socketPath, 0600); err != nil {
		_ = ln.Close()
		_ = os.Remove(b.socketPath) // clean up socket file on chmod failure
		return fmt.Errorf("bridge: chmod socket %s: %w", b.socketPath, err)
	}

	b.listener = ln

	b.config.Logger.Info("bridge started",
		"label", b.config.Label,
		"socket", b.socketPath,
		"target", b.config.TargetAddr,
	)

	b.wg.Add(1)
	go b.acceptLoop()

	return nil
}

// acceptLoop accepts incoming connections on the Unix socket and
// dispatches them for forwarding.
func (b *Bridge) acceptLoop() {
	defer b.wg.Done()

	for {
		conn, err := b.listener.Accept()
		if err != nil {
			// Check if we were cancelled (shutdown).
			select {
			case <-b.ctx.Done():
				return
			default:
			}
			b.config.Logger.Debug("bridge: accept error",
				"label", b.config.Label,
				"error", err,
			)
			return
		}

		// Acquire semaphore slot (limit concurrency).
		select {
		case b.sem <- struct{}{}:
			// Got a slot, proceed.
		case <-b.ctx.Done():
			_ = conn.Close() // best-effort cleanup
			return
		}

		b.wg.Add(1)
		go b.handleConn(conn)
	}
}

// handleConn forwards a single connection from the Unix socket to the
// TCP target, performing bidirectional copy.
func (b *Bridge) handleConn(conn net.Conn) {
	defer b.wg.Done()
	defer func() { <-b.sem }() // Release semaphore slot.

	b.trackConn(conn, true)
	defer b.trackConn(conn, false)

	// Dial the TCP target.
	target, err := b.dialer.DialContext(b.ctx, "tcp", b.config.TargetAddr)
	if err != nil {
		b.config.Logger.Debug("bridge: dial target failed",
			"label", b.config.Label,
			"target", b.config.TargetAddr,
			"error", err,
		)
		_ = conn.Close() // best-effort cleanup
		return
	}

	// Bidirectional copy.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, bridgeCopyBufSize)
		if _, err := io.CopyBuffer(target, conn, buf); err != nil {
			b.config.Logger.Debug("bridge: copy error (client→target)", "err", err)
		}
		// Signal the other direction to stop by closing the write side.
		if tc, ok := target.(*net.TCPConn); ok {
			_ = tc.CloseWrite() // best-effort half-close
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, bridgeCopyBufSize)
		if _, err := io.CopyBuffer(conn, target, buf); err != nil {
			b.config.Logger.Debug("bridge: copy error (target→client)", "err", err)
		}
		// Signal the other direction to stop.
		if uc, ok := conn.(*net.UnixConn); ok {
			_ = uc.CloseWrite() // best-effort half-close
		}
	}()

	wg.Wait()
	_ = conn.Close()   // best-effort cleanup
	_ = target.Close() // best-effort cleanup
}

// trackConn adds or removes a connection from the active set.
func (b *Bridge) trackConn(conn net.Conn, add bool) {
	b.connMu.Lock()
	defer b.connMu.Unlock()
	if add {
		b.activeConns[conn] = struct{}{}
	} else {
		delete(b.activeConns, conn)
	}
}

// Shutdown gracefully stops the bridge. It stops accepting new connections,
// waits for active connections to finish within the given timeout, and
// force-closes any remaining connections.
//
// The internal goroutine waiting on wg.Wait() is bounded: if the timeout fires,
// all tracked connections are force-closed, which unblocks the io.Copy goroutines
// and allows wg.Wait() to return. A secondary 2-second wait ensures the goroutine
// completes before socket cleanup proceeds.
func (b *Bridge) Shutdown(timeout time.Duration) error {
	b.cancel()

	// Close the listener to stop accepting new connections.
	if b.listener != nil {
		_ = b.listener.Close() // best-effort cleanup
	}

	// Wait for active connections with timeout.
	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All connections finished gracefully.
	case <-time.After(timeout):
		// Force close remaining connections.
		b.connMu.Lock()
		for conn := range b.activeConns {
			_ = conn.Close() // best-effort cleanup
		}
		b.connMu.Unlock()

		b.config.Logger.Warn("bridge: force closed remaining connections",
			"label", b.config.Label,
		)

		// Wait briefly for the WaitGroup goroutine to complete after
		// force-closing connections, so cleanup below is safe.
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}

	// Clean up the socket file.
	if err := os.Remove(b.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("bridge: remove socket %s: %w", b.socketPath, err)
	}

	b.config.Logger.Info("bridge stopped", "label", b.config.Label)
	return nil
}

// BridgePair manages HTTP and SOCKS5 bridges together.
type BridgePair struct {
	HTTP  *Bridge
	SOCKS *Bridge
}

// NewBridgePair creates a pair of bridges for HTTP and SOCKS5 proxies.
func NewBridgePair(socketDir string, httpAddr, socksAddr string, logger *slog.Logger) (*BridgePair, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	httpBridge, err := NewBridge(&BridgeConfig{
		SocketDir:  socketDir,
		TargetAddr: httpAddr,
		Label:      "http-proxy",
		Logger:     logger,
	})
	if err != nil {
		return nil, fmt.Errorf("bridge pair: create http bridge: %w", err)
	}

	socksBridge, err := NewBridge(&BridgeConfig{
		SocketDir:  socketDir,
		TargetAddr: socksAddr,
		Label:      "socks-proxy",
		Logger:     logger,
	})
	if err != nil {
		return nil, fmt.Errorf("bridge pair: create socks bridge: %w", err)
	}

	return &BridgePair{
		HTTP:  httpBridge,
		SOCKS: socksBridge,
	}, nil
}

// Start starts both HTTP and SOCKS5 bridges.
// If the HTTP bridge starts but the SOCKS5 bridge fails, the HTTP bridge
// is shut down before returning the error.
func (bp *BridgePair) Start() error {
	if err := bp.HTTP.Start(); err != nil {
		return fmt.Errorf("bridge pair: start http: %w", err)
	}

	if err := bp.SOCKS.Start(); err != nil {
		_ = bp.HTTP.Shutdown(5 * time.Second)
		return fmt.Errorf("bridge pair: start socks: %w", err)
	}

	return nil
}

// Shutdown stops both bridges with the given timeout.
func (bp *BridgePair) Shutdown(timeout time.Duration) {
	// Shut down both bridges concurrently.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_ = bp.HTTP.Shutdown(timeout) // best-effort shutdown
	}()

	go func() {
		defer wg.Done()
		_ = bp.SOCKS.Shutdown(timeout) // best-effort shutdown
	}()

	wg.Wait()
}
