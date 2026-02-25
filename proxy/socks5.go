package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/zhangyunhao116/agentbox/proxy/internal/socks5"
)

// SOCKS5Config configures the SOCKS5 proxy server.
type SOCKS5Config struct {
	// Filter is the domain filtering function used to allow or deny connections.
	// If nil, all connections are denied by default.
	Filter FilterFunc

	// MITMRouter is an optional MITM router for routing matching domains
	// through an upstream MITM proxy via Unix socket. If nil, no MITM
	// routing is performed.
	MITMRouter *MITMRouter

	// Logger is the structured logger for proxy events.
	// If nil, a default logger is used.
	Logger *slog.Logger

	// Dial is an optional custom dial function for outbound connections.
	// If nil, a default dialer with IP blocking is used.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// SOCKS5Proxy is a SOCKS5 proxy server with domain filtering.
// It wraps the internal socks5 package and integrates domain-based filtering
// and IP blocking to prevent connections to private/internal networks.
type SOCKS5Proxy struct {
	config *SOCKS5Config
	server *socks5.Server
	mu     sync.Mutex
	ln     net.Listener
	addr   net.Addr
	closed atomic.Bool
}

// domainRuleSet implements socks5.RuleSet to enforce domain filtering.
type domainRuleSet struct {
	filter FilterFunc
	logger *slog.Logger
}

// Allow checks whether the SOCKS5 request should be permitted based on
// the configured domain filter. It extracts the host and port from the
// request's destination address and delegates to the filter function.
func (r *domainRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	dest := req.DestAddr
	if dest == nil {
		r.logger.Warn("socks5: request with nil destination address, denying")
		return ctx, false
	}

	// Determine the host: prefer FQDN, fall back to IP string.
	host := dest.FQDN
	if host == "" && dest.IP != nil {
		host = dest.IP.String()
	}
	if host == "" {
		r.logger.Warn("socks5: request with empty host, denying")
		return ctx, false
	}

	port := dest.Port

	if r.filter == nil {
		r.logger.Warn("socks5: no filter configured, denying", "host", host, "port", port)
		return ctx, false
	}

	allowed, err := r.filter(ctx, host, port)
	if err != nil {
		r.logger.Error("socks5: filter error, denying", "host", host, "port", port, "error", err)
		return ctx, false
	}

	if !allowed {
		r.logger.Info("socks5: connection denied by filter", "host", host, "port", port)
	} else {
		r.logger.Debug("socks5: connection allowed", "host", host, "port", port)
	}

	return ctx, allowed
}

// proxyNameResolver implements socks5.NameResolver to resolve DNS names
// at the proxy side (supporting socks5h:// semantics) and check resolved
// IPs against the blocked IP list.
type proxyNameResolver struct {
	logger   *slog.Logger
	resolver *net.Resolver
}

// mitmFQDNKey is a context key used to pass the original FQDN from the
// MITM-aware resolver to the dial function, so the dial function can
// check MITM routing even though it receives a resolved IP address.
type mitmFQDNKey struct{}

// mitmNameResolver wraps a base NameResolver and returns a placeholder IP
// for domains that match the MITM router. This allows the socks5 server
// to proceed to the dial phase where the actual MITM routing occurs.
type mitmNameResolver struct {
	base       socks5.NameResolver
	mitmRouter *MITMRouter
	logger     *slog.Logger
}

// Resolve checks if the name matches a MITM domain. If so, it returns a
// placeholder IP (127.0.0.2) and stores the original FQDN in the context.
// Otherwise, it delegates to the base resolver.
func (r *mitmNameResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if r.mitmRouter != nil {
		if socketPath := r.mitmRouter.SocketPathForHost(name); socketPath != "" {
			r.logger.Debug("socks5: MITM domain detected, using placeholder IP", "name", name)
			// Store the original FQDN in context for the dial function.
			ctx = context.WithValue(ctx, mitmFQDNKey{}, name)
			// Return a placeholder IP; the dial function will route via Unix socket.
			return ctx, net.IPv4(127, 0, 0, 2), nil
		}
	}
	return r.base.Resolve(ctx, name)
}

// Resolve performs DNS resolution for the given name and checks the
// resolved IP against blocked IP ranges. Returns an error if the IP
// is blocked or if DNS resolution fails.
func (r *proxyNameResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addrs, err := resolver.LookupIPAddr(ctx, name)
	if err != nil {
		return ctx, nil, fmt.Errorf("failed to resolve %q: %w", name, err)
	}

	if len(addrs) == 0 {
		return ctx, nil, fmt.Errorf("no addresses found for %q", name)
	}

	// Check ALL resolved IPs against the blocked list.
	for _, addr := range addrs {
		if isBlockedIP(addr.IP) {
			if r.logger != nil {
				r.logger.Info("socks5: resolved IP is blocked", "name", name, "ip", addr.IP.String())
			}
			return ctx, nil, fmt.Errorf("resolved IP %s for %q is blocked", addr.IP, name)
		}
	}

	return ctx, addrs[0].IP, nil
}

// dialWithIPCheck returns a dial function that resolves the target address
// and checks the resolved IP against blocked IP ranges before connecting.
// The resolver parameter controls DNS lookups; if nil, net.DefaultResolver is used.
func dialWithIPCheck(logger *slog.Logger, resolver *net.Resolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}

		// If the host is already an IP, check it directly.
		if ip := net.ParseIP(host); ip != nil {
			if isBlockedIP(ip) {
				logger.Info("socks5: dial blocked IP", "ip", ip.String(), "port", port)
				return nil, fmt.Errorf("connection to blocked IP %s is denied", ip)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}

		// Resolve the hostname and check all resolved IPs.
		ips, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve %q: %w", host, err)
		}

		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses found for %q", host)
		}

		// Reject if ANY resolved IP is blocked (matching HTTP proxy behavior).
		for _, ipAddr := range ips {
			if isBlockedIP(ipAddr.IP) {
				logger.Info("socks5: blocked resolved IP", "host", host, "ip", ipAddr.IP.String())
				return nil, fmt.Errorf("resolved IP %s for %q is blocked", ipAddr.IP, host)
			}
		}

		// All IPs are safe, dial the first one.
		target := net.JoinHostPort(ips[0].IP.String(), port)
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	}
}

// NewSOCKS5Proxy creates a new SOCKS5 proxy server with the given configuration.
// The proxy integrates domain filtering and IP blocking to prevent connections
// to unauthorized destinations.
func NewSOCKS5Proxy(cfg *SOCKS5Config) (*SOCKS5Proxy, error) {
	if cfg == nil {
		cfg = &SOCKS5Config{}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Create a silent logger for the underlying socks5 library to avoid
	// duplicate logging (we handle logging in our RuleSet and Resolver).
	silentLogger := log.New(io.Discard, "", 0)

	// Use custom dial function if provided, otherwise use the default
	// IP-checking dialer.
	dialFn := cfg.Dial
	if dialFn == nil {
		dialFn = dialWithIPCheck(logger, nil)
	}

	// If a MITM router is configured, wrap the dial function to route
	// matching domains through the MITM proxy via Unix socket.
	// The mitmNameResolver stores the original FQDN in context for
	// domains that match, so we check context here.
	if cfg.MITMRouter != nil {
		baseDial := dialFn
		mitmRouter := cfg.MITMRouter
		dialFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Check if the resolver stored an original FQDN for MITM routing.
			if fqdn, ok := ctx.Value(mitmFQDNKey{}).(string); ok && fqdn != "" {
				if socketPath := mitmRouter.SocketPathForHost(fqdn); socketPath != "" {
					logger.Debug("socks5: routing through MITM proxy", "host", fqdn, "socket", socketPath)
					// Reconstruct the target address using the original FQDN (not placeholder IP).
					_, port, _ := net.SplitHostPort(addr)
					targetAddr := net.JoinHostPort(fqdn, port)
					mitmConn, mitmErr := dialMITMConnect(socketPath, targetAddr)
					if mitmErr != nil {
						// Do not fall back to direct connection with placeholder IP.
						return nil, fmt.Errorf("socks5: MITM proxy dial failed for %s: %w", fqdn, mitmErr)
					}
					return mitmConn, nil
				}
			}
			return baseDial(ctx, network, addr)
		}
	}

	// Build the resolver. If a MITM router is configured, wrap the
	// resolver so that MITM-matched domains get a placeholder IP
	// (the actual connection goes through the Unix socket, not the IP).
	var resolver socks5.NameResolver = &proxyNameResolver{logger: logger}
	if cfg.MITMRouter != nil {
		resolver = &mitmNameResolver{
			base:       resolver,
			mitmRouter: cfg.MITMRouter,
			logger:     logger,
		}
	}

	conf := &socks5.Config{
		Rules:    &domainRuleSet{filter: cfg.Filter, logger: logger},
		Resolver: resolver,
		Dial:     dialFn,
		Logger:   silentLogger,
	}

	server, err := socks5.New(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create socks5 server: %w", err)
	}

	return &SOCKS5Proxy{
		config: cfg,
		server: server,
	}, nil
}

// ListenAndServe starts the SOCKS5 proxy server listening on the given address.
// Use ":0" to listen on a random available port. The actual address can be
// retrieved via Addr() after this method returns.
//
// The server runs in a background goroutine. Use Shutdown to stop it.
func (p *SOCKS5Proxy) ListenAndServe(addr string) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	p.mu.Lock()
	p.ln = ln
	p.addr = ln.Addr()
	p.closed.Store(false)
	p.mu.Unlock()

	logger := p.config.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	logger.Info("socks5: proxy started", "addr", ln.Addr().String())

	go func() {
		if err := p.server.Serve(ln); err != nil {
			// Serve returns an error when the listener is closed, which is
			// expected during shutdown. Only log unexpected errors.
			if !p.closed.Load() {
				logger.Debug("socks5: server stopped", "error", err)
			}
		}
	}()

	return ln.Addr(), nil
}

// Shutdown gracefully stops the SOCKS5 proxy server by closing the listener.
// Existing connections may continue until they complete or the context is cancelled.
func (p *SOCKS5Proxy) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	ln := p.ln
	if ln == nil {
		p.mu.Unlock()
		return nil
	}
	p.closed.Store(true)
	p.ln = nil
	addr := p.addr
	p.mu.Unlock()

	logger := p.config.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if addr != nil {
		logger.Info("socks5: proxy shutting down", "addr", addr.String())
	}

	return ln.Close()
}

// Addr returns the network address the proxy is listening on.
// Returns nil if the proxy has not been started.
func (p *SOCKS5Proxy) Addr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addr
}
