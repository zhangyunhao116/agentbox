package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default timeouts for the HTTP proxy.
const (
	defaultDialTimeout = 10 * time.Second
	defaultIdleTimeout = 60 * time.Second
)

// maxRequestBodySize is the maximum allowed size for incoming request bodies
// forwarded through the HTTP proxy (10 MB).
const maxRequestBodySize = 10 << 20

// hopByHopHeaders lists the hop-by-hop headers that must be removed when
// forwarding HTTP requests through the proxy.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// HTTPConfig configures the HTTP proxy server.
type HTTPConfig struct {
	// Filter is the domain filtering function. If nil, all requests are allowed.
	Filter FilterFunc

	// MITMRouter is an optional MITM router for routing matching domains
	// through an upstream MITM proxy via Unix socket. If nil, no MITM
	// routing is performed.
	MITMRouter *MITMRouter

	// DialTimeout is the timeout for establishing outbound connections.
	// Defaults to 10s if zero.
	DialTimeout time.Duration

	// IdleTimeout is the idle timeout for the proxy HTTP server.
	// Defaults to 60s if zero.
	IdleTimeout time.Duration

	// MaxRequestBodySize is the maximum allowed size in bytes for incoming
	// request bodies. Defaults to maxRequestBodySize (10 MB) if zero.
	MaxRequestBodySize int64

	// Logger is the structured logger. If nil, a no-op logger is used.
	Logger *slog.Logger
}

// HTTPProxy is an HTTP/HTTPS proxy server that supports both regular HTTP
// proxying and CONNECT tunneling for HTTPS.
type HTTPProxy struct {
	config     *HTTPConfig
	server     *http.Server
	dialer     *net.Dialer
	transport  *http.Transport
	mitmRouter *MITMRouter
	addr       net.Addr
	mu         sync.Mutex

	// dialFunc is the function used to establish outbound connections.
	// It defaults to dialContextWithIPCheck. Both the HTTP transport and
	// the CONNECT handler use this function.
	dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

	// resolver is the DNS resolver used by dialContextWithIPCheck.
	// Defaults to net.DefaultResolver. Can be overridden for testing.
	resolver *net.Resolver
}

// NewHTTPProxy creates a new HTTPProxy with the given configuration.
// If cfg is nil, default settings are used.
func NewHTTPProxy(cfg *HTTPConfig) *HTTPProxy {
	if cfg == nil {
		cfg = &HTTPConfig{}
	}

	dialTimeout := cfg.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = defaultDialTimeout
	}

	idleTimeout := cfg.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = defaultIdleTimeout
	}

	maxBodySize := cfg.MaxRequestBodySize
	if maxBodySize <= 0 {
		maxBodySize = maxRequestBodySize
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Store resolved config back.
	resolvedCfg := &HTTPConfig{
		Filter:             cfg.Filter,
		MITMRouter:         cfg.MITMRouter,
		DialTimeout:        dialTimeout,
		IdleTimeout:        idleTimeout,
		MaxRequestBodySize: maxBodySize,
		Logger:             logger,
	}

	dialer := &net.Dialer{
		Timeout: dialTimeout,
	}

	p := &HTTPProxy{
		config:     resolvedCfg,
		dialer:     dialer,
		mitmRouter: cfg.MITMRouter,
		resolver:   net.DefaultResolver,
	}

	p.dialFunc = p.dialContextWithIPCheck

	p.transport = &http.Transport{
		DialContext:       p.dialFunc,
		DisableKeepAlives: true,
	}

	return p
}

// ListenAndServe starts the proxy server on the given address.
// The address format is "host:port" (e.g., ":0" for a random port).
// It returns the actual address the server is listening on.
func (p *HTTPProxy) ListenAndServe(addr string) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: listen: %w", err)
	}

	p.mu.Lock()
	p.addr = ln.Addr()
	p.server = &http.Server{
		Handler:           p,
		IdleTimeout:       p.config.IdleTimeout,
		ReadHeaderTimeout: 10 * time.Second,
	}
	p.mu.Unlock()

	go func() {
		if err := p.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			p.config.Logger.Error("proxy server error", "error", err)
		}
	}()

	return ln.Addr(), nil
}

// Shutdown gracefully shuts down the proxy server.
func (p *HTTPProxy) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	srv := p.server
	p.mu.Unlock()

	if srv == nil {
		return nil
	}

	p.transport.CloseIdleConnections()
	return srv.Shutdown(ctx)
}

// Addr returns the address the proxy server is listening on.
// Returns nil if the server has not been started.
func (p *HTTPProxy) Addr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addr
}

// ServeHTTP dispatches incoming requests to the appropriate handler based on
// the HTTP method. CONNECT requests are handled as HTTPS tunnels; all other
// requests are forwarded as regular HTTP proxy requests.
func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleHTTP forwards a regular HTTP request through the proxy.
func (p *HTTPProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to prevent abuse.
	r.Body = http.MaxBytesReader(w, r.Body, p.config.MaxRequestBodySize)

	// Validate the request URL.
	if r.URL.Host == "" {
		http.Error(w, "proxy: missing host in request URL", http.StatusBadRequest)
		return
	}

	host, port, err := parseHostPort(r.URL.Host, "80")
	if err != nil {
		http.Error(w, fmt.Sprintf("proxy: invalid host: %s", err), http.StatusBadRequest)
		return
	}

	// Validate port number.
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		http.Error(w, fmt.Sprintf("proxy: invalid port %q", port), http.StatusBadRequest)
		return
	}

	// Apply domain filter.
	if p.config.Filter != nil {
		allowed, filterErr := p.config.Filter(r.Context(), host, portNum)
		if filterErr != nil {
			p.config.Logger.Error("filter error", "host", host, "port", port, "error", filterErr)
			http.Error(w, "proxy: filter error", http.StatusInternalServerError)
			return
		}
		if !allowed {
			p.config.Logger.Info("request denied by filter", "host", host, "port", port)
			http.Error(w, "proxy: request denied by filter", http.StatusForbidden)
			return
		}
	}

	// Create the outbound request.
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	removeHopByHopHeaders(outReq.Header)

	// Check if the host should be routed through a MITM proxy.
	transport := p.transport
	if p.mitmRouter != nil {
		if socketPath := p.mitmRouter.SocketPathForHost(host); socketPath != "" {
			transport = p.mitmRouter.Transport()
			p.config.Logger.Debug("http: routing through MITM proxy", "host", host, "socket", socketPath)
		}
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		// Log detailed error internally.
		p.config.Logger.Error("upstream request failed", "host", host, "error", err)
		// Return generic error to client to avoid leaking internal details.
		http.Error(w, "proxy: upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers.
	removeHopByHopHeaders(resp.Header)
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy response body.
	if _, err := io.Copy(w, resp.Body); err != nil {
		p.config.Logger.Debug("http: response body copy error", "err", err)
	}
}

// handleConnect handles CONNECT requests for HTTPS tunneling.
func (p *HTTPProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := parseHostPort(r.Host, "443")
	if err != nil {
		http.Error(w, fmt.Sprintf("proxy: invalid CONNECT host: %s", err), http.StatusBadRequest)
		return
	}

	// Validate port number.
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		http.Error(w, fmt.Sprintf("proxy: invalid port %q", port), http.StatusBadRequest)
		return
	}

	// Apply domain filter.
	if p.config.Filter != nil {
		allowed, filterErr := p.config.Filter(r.Context(), host, portNum)
		if filterErr != nil {
			p.config.Logger.Error("filter error", "host", host, "port", port, "error", filterErr)
			http.Error(w, "proxy: filter error", http.StatusInternalServerError)
			return
		}
		if !allowed {
			p.config.Logger.Info("CONNECT denied by filter", "host", host, "port", port)
			http.Error(w, "proxy: request denied by filter", http.StatusForbidden)
			return
		}
	}

	// Dial the target using the configured dial function.
	// If a MITM router is configured and the host matches, route through
	// the MITM proxy via Unix socket instead.
	targetAddr := net.JoinHostPort(host, port)
	var targetConn net.Conn
	if p.mitmRouter != nil {
		if socketPath := p.mitmRouter.SocketPathForHost(host); socketPath != "" {
			p.config.Logger.Debug("http: CONNECT routing through MITM proxy", "host", host, "socket", socketPath)
			mitmConn, mitmErr := dialMITMConnect(socketPath, targetAddr)
			if mitmErr != nil {
				p.config.Logger.Error("http: MITM dial failed", "host", host, "error", mitmErr)
				http.Error(w, "proxy: MITM proxy unavailable for "+host, http.StatusBadGateway)
				return
			}
			targetConn = mitmConn
		}
	}
	if targetConn == nil {
		var dialErr error
		targetConn, dialErr = p.dialFunc(r.Context(), "tcp", targetAddr)
		if dialErr != nil {
			p.config.Logger.Error("CONNECT dial failed", "target", targetAddr, "error", dialErr)
			http.Error(w, fmt.Sprintf("proxy: dial target: %s", dialErr), http.StatusBadGateway)
			return
		}
	}

	// Hijack the client connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = targetConn.Close() // best-effort cleanup
		http.Error(w, "proxy: hijacking not supported", http.StatusInternalServerError)
		return
	}

	// Hijack BEFORE sending 200 to avoid a race between WriteHeader and Hijack.
	clientConn, bufRW, err := hijacker.Hijack()
	if err != nil {
		_ = targetConn.Close() // best-effort cleanup
		p.config.Logger.Error("proxy: hijack failed", "error", err)
		return
	}

	// Send 200 on the raw connection after successful hijack.
	_, _ = bufRW.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = bufRW.Flush()

	// Bidirectional copy. Use a WaitGroup to ensure both goroutines
	// complete before returning, preventing premature connection cleanup.
	// Use bufRW.Reader for client→target to capture any buffered data.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer func() { _ = targetConn.Close() }() // best-effort cleanup
		defer func() { _ = clientConn.Close() }() // best-effort cleanup
		if _, err := io.Copy(targetConn, bufRW); err != nil {
			p.config.Logger.Debug("http: CONNECT copy error (client→target)", "err", err)
		}
	}()
	go func() {
		defer wg.Done()
		defer func() { _ = clientConn.Close() }() // best-effort cleanup
		defer func() { _ = targetConn.Close() }() // best-effort cleanup
		if _, err := io.Copy(clientConn, targetConn); err != nil {
			p.config.Logger.Debug("http: CONNECT copy error (target→client)", "err", err)
		}
	}()
	wg.Wait()
}

// dialContextWithIPCheck resolves DNS first, validates all resolved IPs against
// the blocked IP list, and then dials the target using a resolved IP address.
// This prevents DNS rebinding attacks by ensuring the connection goes to the
// validated IP.
func (p *HTTPProxy) dialContextWithIPCheck(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := parseHostPort(addr, "")
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid address %q: %w", addr, err)
	}

	// If the host is already an IP address, check it directly.
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("proxy: connection to blocked IP %s denied", ip)
		}
		return p.dialer.DialContext(ctx, network, addr)
	}

	// Resolve DNS.
	ips, err := p.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("proxy: DNS resolution failed for %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("proxy: no IP addresses found for %q", host)
	}

	// Check ALL resolved IPs against the blocked list.
	for _, ipAddr := range ips {
		if isBlockedIP(ipAddr.IP) {
			return nil, fmt.Errorf("proxy: DNS resolved to blocked IP %s for host %q", ipAddr.IP, host)
		}
	}

	// Dial using the first resolved IP to prevent DNS rebinding.
	resolvedAddr := net.JoinHostPort(ips[0].IP.String(), port)
	return p.dialer.DialContext(ctx, network, resolvedAddr)
}

// parseHostPort splits a host:port string. If no port is present, defaultPort
// is used. It handles IPv6 addresses in bracket notation (e.g., [::1]:80).
func parseHostPort(hostport, defaultPort string) (host, port string, err error) {
	if hostport == "" {
		return "", "", errors.New("empty address")
	}

	// Try standard split first.
	host, port, err = net.SplitHostPort(hostport)
	if err != nil {
		// If splitting fails, the input might be a bare host without a port.
		if defaultPort == "" {
			return "", "", fmt.Errorf("missing port in address %q", hostport)
		}
		// Check for IPv6 bracket notation without port.
		if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
			host = hostport[1 : len(hostport)-1]
		} else {
			host = hostport
		}
		port = defaultPort
	}

	if host == "" {
		return "", "", fmt.Errorf("empty host in address %q", hostport)
	}
	if port == "" {
		if defaultPort != "" {
			port = defaultPort
		} else {
			return "", "", fmt.Errorf("empty port in address %q", hostport)
		}
	}

	return host, port, nil
}

// removeHopByHopHeaders removes hop-by-hop headers from the given header map.
// These headers are meaningful only for a single transport-level connection
// and must not be forwarded by proxies.
func removeHopByHopHeaders(h http.Header) {
	for _, header := range hopByHopHeaders {
		h.Del(header)
	}
}
