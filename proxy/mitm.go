package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MITMRouter determines whether a host should be routed through a MITM proxy.
type MITMRouter struct {
	socketPath string
	domains    []string
	mu         sync.Mutex
	transport  *http.Transport
}

// NewMITMRouter creates a new MITM router. Returns nil if config is nil,
// has no socket path, or has no domains.
func NewMITMRouter(cfg *MITMConfig) *MITMRouter {
	if cfg == nil || cfg.SocketPath == "" || len(cfg.Domains) == 0 {
		return nil
	}
	// Normalize domain patterns to lowercase once at construction time.
	domains := make([]string, len(cfg.Domains))
	for i, d := range cfg.Domains {
		domains[i] = strings.ToLower(d)
	}
	return &MITMRouter{
		socketPath: cfg.SocketPath,
		domains:    domains,
	}
}

// SocketPathForHost returns the MITM proxy socket path if the host matches
// any configured domain pattern, or empty string if no match.
func (r *MITMRouter) SocketPathForHost(host string) string {
	if r == nil {
		return ""
	}
	// Strip port if present.
	h := host
	if strings.LastIndex(h, ":") != -1 {
		stripped, _, err := net.SplitHostPort(host)
		if err == nil && stripped != "" {
			h = stripped
		}
	}
	h = strings.ToLower(h)

	for _, pattern := range r.domains {
		if pattern == h {
			return r.socketPath
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			if len(h) > len(suffix) && strings.HasSuffix(h, suffix) {
				return r.socketPath
			}
		}
	}
	return ""
}

// Transport returns a cached *http.Transport that routes requests through
// the MITM proxy via Unix socket. The transport is created lazily and reused.
func (r *MITMRouter) Transport() *http.Transport {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.transport == nil {
		r.transport = mitmHTTPTransport(r.socketPath)
	}
	return r.transport
}

// dialMITMConnect dials the MITM proxy via Unix socket and sends a CONNECT
// request for the given target host. On success it returns the established
// connection ready for bidirectional data transfer.
func dialMITMConnect(socketPath, targetHost string) (net.Conn, error) {
	mitmConn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("mitm: dial unix %s: %w", socketPath, err)
	}
	return mitmCONNECTHandshake(mitmConn, targetHost)
}

// mitmCONNECTHandshake sends a CONNECT request over conn and reads the
// response. On success it returns the connection ready for bidirectional
// data transfer. On failure it closes conn and returns an error.
func mitmCONNECTHandshake(mitmConn net.Conn, targetHost string) (net.Conn, error) {
	// Reject hosts with CRLF or control characters to prevent header injection.
	if strings.ContainsAny(targetHost, "\r\n\x00") {
		_ = mitmConn.Close()
		return nil, fmt.Errorf("mitm: invalid target host %q: contains control characters", targetHost)
	}

	// Set a deadline for the CONNECT handshake to prevent indefinite blocking.
	_ = mitmConn.SetDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = mitmConn.SetDeadline(time.Time{}) }()

	// Send CONNECT request to the MITM proxy.
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetHost, targetHost)
	if _, err := io.WriteString(mitmConn, connectReq); err != nil {
		_ = mitmConn.Close()
		return nil, fmt.Errorf("mitm: write CONNECT: %w", err)
	}

	// Read the response from the MITM proxy.
	br := bufio.NewReader(mitmConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = mitmConn.Close()
		return nil, fmt.Errorf("mitm: read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_ = mitmConn.Close()
		return nil, fmt.Errorf("mitm: CONNECT returned status %d", resp.StatusCode)
	}

	// If the bufio.Reader has buffered data beyond the HTTP response,
	// wrap the connection so that buffered bytes are read first.
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: mitmConn, br: br}, nil
	}
	return mitmConn, nil
}

// bufferedConn wraps a net.Conn with a bufio.Reader so that any data
// buffered during the HTTP response read is not lost.
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.br.Read(p)
}

// mitmHTTPTransport returns an *http.Transport that routes requests through
// the MITM proxy via Unix socket.
func mitmHTTPTransport(socketPath string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
		DisableKeepAlives: true,
	}
}
