package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

// Proxy is the interface for the combined proxy server that provides
// both HTTP and SOCKS5 proxy functionality.
type Proxy interface {
	// Start starts both HTTP and SOCKS5 proxies on random ports.
	// Returns the ports they are listening on.
	Start(ctx context.Context) (httpPort, socksPort int, err error)

	// Close shuts down both proxies gracefully.
	Close() error
}

// MITMConfig configures routing of specific domains through an upstream MITM proxy.
type MITMConfig struct {
	// SocketPath is the Unix socket path to the MITM proxy.
	SocketPath string

	// Domains lists domain patterns to route through the MITM proxy.
	// Supports exact match and wildcard prefix (e.g., "*.example.com").
	Domains []string
}

// Config configures the combined proxy server.
type Config struct {
	// Filter is the domain filter used by both HTTP and SOCKS5 proxies.
	// If nil, all requests are allowed.
	Filter *DomainFilter

	// MITM configures routing of specific domains through an upstream
	// MITM proxy via Unix socket. If nil, no MITM routing is performed.
	MITM *MITMConfig

	// Logger is the structured logger. If nil, a no-op logger is used.
	Logger *slog.Logger
}

// Server combines HTTP and SOCKS5 proxies into a single unit.
// It implements the Proxy interface.
type Server struct {
	config *Config
	http   *HTTPProxy
	socks5 *SOCKS5Proxy
}

// Compile-time check that Server implements Proxy.
var _ Proxy = (*Server)(nil)

// NewServer creates a new Server with the given configuration.
// If cfg is nil, default configuration is used.
func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Resolve the filter function from the DomainFilter.
	var filterFunc FilterFunc
	if cfg.Filter != nil {
		filterFunc = cfg.Filter.Filter
	}

	// Create the MITM router from config.
	mitmRouter := NewMITMRouter(cfg.MITM)

	httpProxy := NewHTTPProxy(&HTTPConfig{
		Filter:     filterFunc,
		MITMRouter: mitmRouter,
		Logger:     logger,
	})

	socks5Proxy, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter:     filterFunc,
		MITMRouter: mitmRouter,
		Logger:     logger,
	})
	if err != nil {
		return nil, fmt.Errorf("proxy: create socks5: %w", err)
	}

	return &Server{
		config: cfg,
		http:   httpProxy,
		socks5: socks5Proxy,
	}, nil
}

// Start starts both HTTP and SOCKS5 proxies on random ports.
// If the HTTP proxy starts successfully but the SOCKS5 proxy fails,
// the HTTP proxy is shut down before returning the error.
func (p *Server) Start(ctx context.Context) (httpPort, socksPort int, err error) {
	if p.http == nil {
		return 0, 0, errors.New("proxy: http proxy not initialized")
	}
	if p.socks5 == nil {
		return 0, 0, errors.New("proxy: socks5 proxy not initialized")
	}

	// Start HTTP proxy on a random port.
	httpAddr, err := p.http.ListenAndServe("127.0.0.1:0")
	if err != nil {
		return 0, 0, fmt.Errorf("proxy: start http: %w", err)
	}

	// Start SOCKS5 proxy on a random port.
	socksAddr, err := p.socks5.ListenAndServe("127.0.0.1:0")
	if err != nil {
		// HTTP started but SOCKS5 failed; shut down HTTP before returning.
		_ = p.http.Shutdown(ctx)
		return 0, 0, fmt.Errorf("proxy: start socks5: %w", err)
	}

	httpPort = portFromAddr(httpAddr)
	socksPort = portFromAddr(socksAddr)

	logger := p.config.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	logger.Info("proxy server started",
		"http_port", httpPort,
		"socks5_port", socksPort,
	)

	return httpPort, socksPort, nil
}

// Close shuts down both HTTP and SOCKS5 proxies.
// Errors from both shutdowns are collected and returned as a combined error.
// A 5-second timeout is applied to prevent indefinite blocking.
func (p *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var errs []error

	if p.http != nil {
		if err := p.http.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("http shutdown: %w", err))
		}
	}

	if p.socks5 != nil {
		if err := p.socks5.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("socks5 shutdown: %w", err))
		}
	}

	return errors.Join(errs...)
}

// portFromAddr extracts the port number from a net.Addr.
// Returns 0 if the address is nil or the port cannot be determined.
func portFromAddr(addr net.Addr) int {
	if addr == nil {
		return 0
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if ok {
		return tcpAddr.Port
	}
	return 0
}
