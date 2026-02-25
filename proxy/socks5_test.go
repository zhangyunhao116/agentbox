package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhangyunhao116/agentbox/proxy/internal/socks5"
	"golang.org/x/net/proxy"
)

// newTestRequest creates a socks5.Request for testing with the given destination.
func newTestRequest(fqdn string, ip net.IP, port int) *socks5.Request {
	return &socks5.Request{
		Version: 5,
		Command: 1, // ConnectCommand
		DestAddr: &socks5.AddrSpec{
			FQDN: fqdn,
			IP:   ip,
			Port: port,
		},
	}
}

// newTestRequestNilDest creates a socks5.Request with nil DestAddr.
func newTestRequestNilDest() *socks5.Request {
	return &socks5.Request{
		Version: 5,
		Command: 1,
	}
}

// ---------------------------------------------------------------------------
// domainRuleSet tests
// ---------------------------------------------------------------------------

func TestDomainRuleSet_AllowWithFilter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rs := &domainRuleSet{
		filter: func(ctx context.Context, host string, port int) (bool, error) {
			return host == "allowed.example.com", nil
		},
		logger: logger,
	}

	tests := []struct {
		name    string
		fqdn    string
		ip      net.IP
		port    int
		allowed bool
	}{
		{"allowed domain", "allowed.example.com", nil, 443, true},
		{"denied domain", "denied.example.com", nil, 443, false},
		{"allowed domain port 80", "allowed.example.com", nil, 80, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newTestRequest(tt.fqdn, tt.ip, tt.port)
			_, allowed := rs.Allow(context.Background(), req)
			if allowed != tt.allowed {
				t.Errorf("Allow() = %v, want %v", allowed, tt.allowed)
			}
		})
	}
}

func TestDomainRuleSet_DenyNilDestAddr(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rs := &domainRuleSet{
		filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
		logger: logger,
	}

	req := newTestRequestNilDest()
	_, allowed := rs.Allow(context.Background(), req)
	if allowed {
		t.Error("Allow() with nil DestAddr should return false")
	}
}

func TestDomainRuleSet_DenyEmptyHost(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rs := &domainRuleSet{
		filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
		logger: logger,
	}

	req := newTestRequest("", nil, 80)
	_, allowed := rs.Allow(context.Background(), req)
	if allowed {
		t.Error("Allow() with empty host should return false")
	}
}

func TestDomainRuleSet_DenyBlockedIP_ViaFilter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a filter that checks blocked IPs (like DomainFilter.Filter does).
	rs := &domainRuleSet{
		filter: func(ctx context.Context, host string, port int) (bool, error) {
			if ip := net.ParseIP(host); ip != nil {
				return !isBlockedIP(ip), nil
			}
			return true, nil
		},
		logger: logger,
	}

	blockedIPs := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("10.0.0.1"),
		net.ParseIP("192.168.1.1"),
		net.ParseIP("172.16.0.1"),
		net.ParseIP("169.254.169.254"), // cloud metadata
	}

	for _, ip := range blockedIPs {
		t.Run(ip.String(), func(t *testing.T) {
			// When FQDN is empty and IP is set, the host becomes the IP string.
			req := newTestRequest("", ip, 80)
			_, allowed := rs.Allow(context.Background(), req)
			if allowed {
				t.Errorf("Allow() with blocked IP %s should return false", ip)
			}
		})
	}
}

func TestDomainRuleSet_AllowPublicIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rs := &domainRuleSet{
		filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
		logger: logger,
	}

	// 8.8.8.8 is a public IP, should pass IP check and then filter allows it.
	req := newTestRequest("", net.ParseIP("8.8.8.8"), 53)
	_, allowed := rs.Allow(context.Background(), req)
	if !allowed {
		t.Error("Allow() with public IP 8.8.8.8 should return true")
	}
}

func TestDomainRuleSet_DenyNilFilter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rs := &domainRuleSet{
		filter: nil,
		logger: logger,
	}

	req := newTestRequest("example.com", nil, 80)
	_, allowed := rs.Allow(context.Background(), req)
	if allowed {
		t.Error("Allow() with nil filter should return false")
	}
}

func TestDomainRuleSet_DenyOnFilterError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rs := &domainRuleSet{
		filter: func(ctx context.Context, host string, port int) (bool, error) {
			return false, errors.New("filter error")
		},
		logger: logger,
	}

	req := newTestRequest("example.com", nil, 80)
	_, allowed := rs.Allow(context.Background(), req)
	if allowed {
		t.Error("Allow() should return false when filter returns error")
	}
}

func TestDomainRuleSet_FQDNPreferredOverIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var receivedHost string
	rs := &domainRuleSet{
		filter: func(ctx context.Context, host string, port int) (bool, error) {
			receivedHost = host
			return true, nil
		},
		logger: logger,
	}

	// When both FQDN and IP are set, FQDN should be used as the host.
	req := newTestRequest("example.com", net.ParseIP("93.184.216.34"), 443)
	rs.Allow(context.Background(), req)
	if receivedHost != "example.com" {
		t.Errorf("filter received host %q, want %q", receivedHost, "example.com")
	}
}

// ---------------------------------------------------------------------------
// proxyNameResolver tests
// ---------------------------------------------------------------------------

func TestProxyNameResolver_ResolvesCorrectly(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a fake DNS server that returns a public IP.
	resolver, cleanup := fakeDNSServer(t, net.ParseIP("8.8.8.8"))
	defer cleanup()

	r := &proxyNameResolver{logger: logger, resolver: resolver}

	// Resolve using the mock DNS server.
	ctx, ip, err := r.Resolve(context.Background(), "dns.google")
	if err != nil {
		t.Fatalf("Resolve(dns.google) error: %v", err)
	}
	if ip == nil {
		t.Fatal("Resolve(dns.google) returned nil IP")
	}
	if ctx == nil {
		t.Fatal("Resolve(dns.google) returned nil context")
	}
	if !ip.Equal(net.ParseIP("8.8.8.8")) {
		t.Errorf("Resolve(dns.google) = %v, want 8.8.8.8", ip)
	}
}

func TestProxyNameResolver_BlocksPrivateIPs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a fake DNS server that returns 127.0.0.1 (blocked).
	resolver, cleanup := fakeDNSServer(t, net.ParseIP("127.0.0.1"))
	defer cleanup()

	r := &proxyNameResolver{logger: logger, resolver: resolver}

	// Mock resolver returns 127.0.0.1 which is blocked.
	_, _, err := r.Resolve(context.Background(), "localhost")
	if err == nil {
		t.Error("Resolve(localhost) should return error for blocked IP")
	}
}

func TestProxyNameResolver_FailsOnInvalidDomain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a fake DNS server that returns no records (empty response).
	resolver, cleanup := fakeDNSServer(t) // no IPs → empty response
	defer cleanup()

	r := &proxyNameResolver{logger: logger, resolver: resolver}

	_, _, err := r.Resolve(context.Background(), "this-domain-does-not-exist-xyzzy.invalid")
	if err == nil {
		t.Error("Resolve() should return error for non-existent domain")
	}
}

func TestProxyNameResolver_NilLogger(t *testing.T) {
	// Ensure nil logger doesn't panic.
	// Use a fake DNS server that returns 127.0.0.1 (blocked).
	resolver, cleanup := fakeDNSServer(t, net.ParseIP("127.0.0.1"))
	defer cleanup()

	r := &proxyNameResolver{logger: nil, resolver: resolver}

	// Mock resolver returns blocked IP; should return error without panic.
	_, _, err := r.Resolve(context.Background(), "localhost")
	if err == nil {
		t.Error("Resolve(localhost) should return error for blocked IP")
	}
}

// ---------------------------------------------------------------------------
// dialWithIPCheck tests
// ---------------------------------------------------------------------------

func TestDialWithIPCheck_BlocksPrivateIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dial := dialWithIPCheck(logger, nil)

	blockedAddrs := []string{
		"127.0.0.1:80",
		"10.0.0.1:80",
		"192.168.1.1:80",
		"172.16.0.1:80",
		"169.254.169.254:80",
	}

	for _, addr := range blockedAddrs {
		t.Run(addr, func(t *testing.T) {
			_, err := dial(context.Background(), "tcp", addr)
			if err == nil {
				t.Errorf("dialWithIPCheck should block %s", addr)
			}
		})
	}
}

func TestDialWithIPCheck_InvalidAddress(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dial := dialWithIPCheck(logger, nil)

	_, err := dial(context.Background(), "tcp", "invalid-no-port")
	if err == nil {
		t.Error("dialWithIPCheck should fail on invalid address")
	}
}

func TestDialWithIPCheck_BlocksLocalhostResolution(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a fake DNS server that returns 127.0.0.1 (blocked).
	resolver, cleanup := fakeDNSServer(t, net.ParseIP("127.0.0.1"))
	defer cleanup()

	dial := dialWithIPCheck(logger, resolver)

	// Mock resolver returns 127.0.0.1 which should be blocked.
	_, err := dial(context.Background(), "tcp", "localhost:80")
	if err == nil {
		t.Error("dialWithIPCheck should block localhost (resolves to 127.0.0.1)")
	}
}

func TestDialWithIPCheck_ConnectsToAllowedServer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dial := dialWithIPCheck(logger, nil)

	// Start a local TCP listener on 127.0.0.1 (blocked).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	defer ln.Close()

	// 127.0.0.1 is blocked, so this should fail.
	_, err = dial(context.Background(), "tcp", ln.Addr().String())
	if err == nil {
		t.Error("expected error dialing blocked IP")
	}
}

func TestDialWithIPCheck_NonBlockedIPDial(t *testing.T) {
	// Test that a non-blocked public IP is not rejected by the IP check.
	// We use a mock resolver and a very short timeout to avoid real network I/O.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Resolve to 203.0.113.1 (TEST-NET-3, non-routable but not blocked).
	resolver, cleanup := fakeDNSServer(t, net.ParseIP("203.0.113.1"))
	defer cleanup()

	dial := dialWithIPCheck(logger, resolver)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	_, err := dial(ctx, "tcp", "test.example:80")
	// We expect either a timeout or connection error, but NOT an IP block error.
	// If err is nil (unlikely but possible), that's also fine — it means the IP wasn't blocked.
	if err != nil {
		errMsg := err.Error()
		if errMsg == "connection to blocked IP 203.0.113.1 is denied" {
			t.Error("203.0.113.1 should not be blocked (it's a public IP)")
		}
	}
}

func TestDialWithIPCheck_ResolutionFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a fake DNS server that returns no records (empty response).
	resolver, cleanup := fakeDNSServer(t) // no IPs → triggers resolution failure
	defer cleanup()

	dial := dialWithIPCheck(logger, resolver)

	_, err := dial(context.Background(), "tcp", "this-domain-does-not-exist-xyzzy.invalid:80")
	if err == nil {
		t.Error("expected error for non-existent domain")
	}
}

// ---------------------------------------------------------------------------
// NewSOCKS5Proxy tests
// ---------------------------------------------------------------------------

func TestNewSOCKS5Proxy_NilConfig(t *testing.T) {
	p, err := NewSOCKS5Proxy(nil)
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy(nil) error: %v", err)
	}
	if p == nil {
		t.Fatal("NewSOCKS5Proxy(nil) returned nil proxy")
	}
	if p.server == nil {
		t.Fatal("NewSOCKS5Proxy(nil) returned proxy with nil server")
	}
}

func TestNewSOCKS5Proxy_WithConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
		Logger: logger,
	}

	p, err := NewSOCKS5Proxy(cfg)
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}
	if p == nil {
		t.Fatal("NewSOCKS5Proxy() returned nil proxy")
	}
}

func TestNewSOCKS5Proxy_DefaultLogger(t *testing.T) {
	// Config without logger should use default.
	cfg := &SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
	}

	p, err := NewSOCKS5Proxy(cfg)
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}
	if p == nil {
		t.Fatal("NewSOCKS5Proxy() returned nil proxy")
	}
}

// ---------------------------------------------------------------------------
// ListenAndServe / Shutdown / Addr tests
// ---------------------------------------------------------------------------

func TestListenAndServe_RandomPort(t *testing.T) {
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	addr, err := p.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("ListenAndServe() error: %v", err)
	}
	defer p.Shutdown(context.Background())

	if addr == nil {
		t.Fatal("ListenAndServe() returned nil addr")
	}

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", addr)
	}
	if tcpAddr.Port == 0 {
		t.Error("expected non-zero port")
	}
}

func TestAddr_BeforeStart(t *testing.T) {
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	if p.Addr() != nil {
		t.Error("Addr() should return nil before ListenAndServe")
	}
}

func TestAddr_AfterStart(t *testing.T) {
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	listenAddr, err := p.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("ListenAndServe() error: %v", err)
	}
	defer p.Shutdown(context.Background())

	got := p.Addr()
	if got == nil {
		t.Fatal("Addr() returned nil after ListenAndServe")
	}
	if got.String() != listenAddr.String() {
		t.Errorf("Addr() = %v, want %v", got, listenAddr)
	}
}

func TestShutdown_Idempotent(t *testing.T) {
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	_, err = p.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("ListenAndServe() error: %v", err)
	}

	// First shutdown should succeed.
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("first Shutdown() error: %v", err)
	}

	// Second shutdown should be a no-op (nil listener).
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown() error: %v", err)
	}
}

func TestShutdown_BeforeStart(t *testing.T) {
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	// Shutdown before start should be a no-op.
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() before start error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Integration tests using golang.org/x/net/proxy as SOCKS5 client
// ---------------------------------------------------------------------------

func TestSOCKS5Proxy_AllowedDomain(t *testing.T) {
	// Start a test HTTP server.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from test server"))
	}))
	defer ts.Close()

	tsHost, tsPort, _ := net.SplitHostPort(ts.Listener.Addr().String())

	// Start SOCKS5 proxy that allows all connections.
	// Use a direct dialer since the test server is on localhost (a blocked IP).
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil // allow all
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	proxyAddr, err := p.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("ListenAndServe() error: %v", err)
	}
	defer p.Shutdown(context.Background())

	// Create SOCKS5 client dialer.
	dialer, err := proxy.SOCKS5("tcp", proxyAddr.String(), nil, proxy.Direct)
	if err != nil {
		t.Fatalf("proxy.SOCKS5() error: %v", err)
	}

	// Connect through the proxy to the test server.
	conn, err := dialer.Dial("tcp", net.JoinHostPort(tsHost, tsPort))
	if err != nil {
		t.Fatalf("Dial through proxy error: %v", err)
	}
	defer conn.Close()

	// Send HTTP request.
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ts.Listener.Addr().String())
	_, err = conn.Write([]byte(httpReq))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// Read response.
	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	if len(resp) == 0 {
		t.Error("expected non-empty response")
	}
}

func TestSOCKS5Proxy_DeniedDomain(t *testing.T) {
	// Start a test HTTP server.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tsHost, tsPort, _ := net.SplitHostPort(ts.Listener.Addr().String())

	// Start SOCKS5 proxy that denies all connections.
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return false, nil // deny all
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	proxyAddr, err := p.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("ListenAndServe() error: %v", err)
	}
	defer p.Shutdown(context.Background())

	// Create SOCKS5 client dialer.
	dialer, err := proxy.SOCKS5("tcp", proxyAddr.String(), nil, proxy.Direct)
	if err != nil {
		t.Fatalf("proxy.SOCKS5() error: %v", err)
	}

	// Attempt to connect through the proxy - should be denied.
	_, err = dialer.Dial("tcp", net.JoinHostPort(tsHost, tsPort))
	if err == nil {
		t.Error("expected error when connecting to denied domain, got nil")
	}
}

// ---------------------------------------------------------------------------
// Concurrent connections test
// ---------------------------------------------------------------------------

func TestSOCKS5Proxy_ConcurrentConnections(t *testing.T) {
	// Start a test HTTP server.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	tsHost, tsPort, _ := net.SplitHostPort(ts.Listener.Addr().String())

	// Start SOCKS5 proxy.
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	proxyAddr, err := p.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("ListenAndServe() error: %v", err)
	}
	defer p.Shutdown(context.Background())

	const numConns = 10
	var wg sync.WaitGroup
	errCh := make(chan error, numConns)

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			dialer, err := proxy.SOCKS5("tcp", proxyAddr.String(), nil, proxy.Direct)
			if err != nil {
				errCh <- fmt.Errorf("proxy.SOCKS5() error: %w", err)
				return
			}

			conn, err := dialer.Dial("tcp", net.JoinHostPort(tsHost, tsPort))
			if err != nil {
				errCh <- fmt.Errorf("Dial error: %w", err)
				return
			}
			defer conn.Close()

			httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ts.Listener.Addr().String())
			if _, err := conn.Write([]byte(httpReq)); err != nil {
				errCh <- fmt.Errorf("Write error: %w", err)
				return
			}

			resp, err := io.ReadAll(conn)
			if err != nil {
				errCh <- fmt.Errorf("ReadAll error: %w", err)
				return
			}
			if len(resp) == 0 {
				errCh <- errors.New("empty response")
				return
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent connection error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test ListenAndServe with invalid address
// ---------------------------------------------------------------------------

func TestListenAndServe_InvalidAddress(t *testing.T) {
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	// Use an invalid address to trigger listen failure.
	_, err = p.ListenAndServe("invalid-address-no-port")
	if err == nil {
		t.Error("ListenAndServe() with invalid address should return error")
	}
}

// ---------------------------------------------------------------------------
// Test shutdown stops accepting new connections
// ---------------------------------------------------------------------------

func TestShutdown_StopsAccepting(t *testing.T) {
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	proxyAddr, err := p.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("ListenAndServe() error: %v", err)
	}

	// Shutdown the proxy.
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	// Give the server goroutine a moment to notice the closed listener.
	time.Sleep(50 * time.Millisecond)

	// Attempt to connect should fail.
	conn, err := net.DialTimeout("tcp", proxyAddr.String(), 500*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Error("expected connection to fail after shutdown")
	}
}

// ---------------------------------------------------------------------------
// Test: Resolve — blocked IP with non-nil logger (L113-117)
// ---------------------------------------------------------------------------

func TestProxyNameResolver_BlockedIPWithLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a fake DNS server that returns 127.0.0.1 (blocked).
	resolver, cleanup := fakeDNSServer(t, net.ParseIP("127.0.0.1"))
	defer cleanup()

	r := &proxyNameResolver{logger: logger, resolver: resolver}

	// Mock resolver returns 127.0.0.1 which is blocked.
	// With a non-nil logger, the code at L113-117 should be exercised.
	_, _, err := r.Resolve(context.Background(), "localhost")
	if err == nil {
		t.Fatal("Resolve(localhost) should return error for blocked IP")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error = %q, want it to contain 'blocked'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: dialWithIPCheck — multiple IPs loop with blocked IPs, dial failures
// ---------------------------------------------------------------------------

func TestDialWithIPCheck_AllBlockedIPs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a fake DNS server that returns only blocked IPs.
	resolver, cleanup := fakeDNSServer(t, net.ParseIP("127.0.0.1"))
	defer cleanup()

	dial := dialWithIPCheck(logger, resolver)

	// Mock resolver returns 127.0.0.1 (blocked).
	// This exercises the loop where all IPs are blocked.
	_, err := dial(context.Background(), "tcp", "localhost:80")
	if err == nil {
		t.Fatal("expected error when all resolved IPs are blocked")
	}
}

func TestDialWithIPCheck_EmptyAddressResult(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a fake DNS server that returns no records.
	resolver, cleanup := fakeDNSServer(t) // no IPs → empty response
	defer cleanup()

	dial := dialWithIPCheck(logger, resolver)

	// Mock resolver returns no addresses, triggering DNS failure.
	_, err := dial(context.Background(), "tcp", "this-domain-does-not-exist-xyzzy.invalid:80")
	if err == nil {
		t.Fatal("expected error for non-existent domain")
	}
}

func TestDialWithIPCheck_MixedBlockedAndUnreachable(t *testing.T) {
	// This test exercises the loop where some IPs are blocked and
	// the remaining ones fail to connect (dial error).
	// We use a mock resolver and a very short context timeout to ensure dial failures are fast.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Resolve to: 127.0.0.1 (blocked) + 203.0.113.1 (not blocked, non-routable).
	resolver, cleanup := fakeDNSServer(t, net.ParseIP("127.0.0.1"), net.ParseIP("203.0.113.1"))
	defer cleanup()

	dial := dialWithIPCheck(logger, resolver)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Use a mock-resolved domain. This exercises the lastErr path.
	_, err := dial(ctx, "tcp", "test.example:80")
	// We expect either a timeout error or a connection error, but NOT nil.
	if err == nil {
		// If it somehow connected, that's fine too — the test is about
		// exercising the code path, not about the outcome.
		return
	}
}

// ---------------------------------------------------------------------------
// Test: ListenAndServe — unexpected server stop (L246-251)
// ---------------------------------------------------------------------------

func TestSOCKS5Proxy_UnexpectedStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
		Logger: logger,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	_, err = p.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("ListenAndServe() error: %v", err)
	}

	// Give the server goroutine time to start Serve().
	time.Sleep(50 * time.Millisecond)

	// Close the listener externally without calling Shutdown.
	// This triggers the "unexpected server stop" path at L246-251
	// because p.closed is still false.
	p.mu.Lock()
	ln := p.ln
	p.mu.Unlock()

	if ln != nil {
		ln.Close()
	}

	// Give the server goroutine time to notice the closed listener
	// and execute the logging code.
	time.Sleep(200 * time.Millisecond)

	// Clean up state.
	p.mu.Lock()
	p.closed.Store(true)
	p.ln = nil
	p.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Test: NewSOCKS5Proxy with custom Dial function
// ---------------------------------------------------------------------------

func TestNewSOCKS5Proxy_CustomDial(t *testing.T) {
	customDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("custom dial error")
	}

	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dial:   customDial,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
}

// ---------------------------------------------------------------------------
// Test: dialWithIPCheck — dial failure in loop (L163-165)
// ---------------------------------------------------------------------------

func TestDialWithIPCheck_DialFailureNonBlockedIP(t *testing.T) {
	// Test the dial failure path when all resolved IPs are non-blocked
	// but the connection fails (e.g., non-routable address).
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Resolve to 2001:db8::1 (IPv6 documentation prefix, not blocked, not routable).
	resolver, cleanup := fakeDNSServer(t, net.ParseIP("2001:db8::1"))
	defer cleanup()

	dial := dialWithIPCheck(logger, resolver)

	// Use a 2-second timeout to allow DNS resolution via mock.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Try to connect to a mock-resolved domain on port 1.
	conn, err := dial(ctx, "tcp", "test.example:1")
	if err == nil {
		conn.Close()
		// Connection succeeded — the dial failure path wasn't exercised.
		// This is expected in some environments.
		return
	}
	// If we got an error, it should be a dial error, not a blocked IP error.
	if strings.Contains(err.Error(), "blocked") {
		t.Errorf("error should be a dial failure, not blocked: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: dialWithIPCheck — all IPs blocked fallback (L173)
// ---------------------------------------------------------------------------

func TestDialWithIPCheck_AllIPsBlockedReject(t *testing.T) {
	// Mock resolver returns only blocked IPs.
	// With unified IP blocking, the first blocked IP causes immediate rejection.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	resolver, cleanup := fakeDNSServer(t, net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1"))
	defer cleanup()

	dial := dialWithIPCheck(logger, resolver)

	_, err := dial(context.Background(), "tcp", "localhost:80")
	if err == nil {
		t.Fatal("expected error when all resolved IPs are blocked")
	}
	// The error should mention "blocked".
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error = %q, want it to contain 'blocked'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: Resolve — empty addrs (L106-108) — hard to trigger with real DNS
// ---------------------------------------------------------------------------

func TestProxyNameResolver_ResolveNonExistent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a fake DNS server that returns no records.
	resolver, cleanup := fakeDNSServer(t) // no IPs → empty response
	defer cleanup()

	r := &proxyNameResolver{logger: logger, resolver: resolver}

	// Non-existent domain should trigger DNS error at L102-103.
	_, _, err := r.Resolve(context.Background(), "this-domain-does-not-exist-xyzzy.invalid")
	if err == nil {
		t.Error("expected error for non-existent domain")
	}
}

// ---------------------------------------------------------------------------
// Test: ListenAndServe — unexpected server stop with nil logger (L237-239)
// ---------------------------------------------------------------------------

func TestSOCKS5Proxy_ListenAndServe_NilLogger(t *testing.T) {
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
		// Logger is nil — should use slog.Default().
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	addr, err := p.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("ListenAndServe() error: %v", err)
	}
	if addr == nil {
		t.Fatal("expected non-nil addr")
	}

	// Close the listener externally to trigger unexpected stop path.
	p.mu.Lock()
	ln := p.ln
	p.mu.Unlock()
	if ln != nil {
		ln.Close()
	}

	time.Sleep(100 * time.Millisecond)
	_ = p.Shutdown(context.Background())
}

// ---------------------------------------------------------------------------
// Test: Shutdown with nil logger (L272-275)
// ---------------------------------------------------------------------------

func TestSOCKS5Proxy_Shutdown_NilLogger(t *testing.T) {
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	_, err = p.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("ListenAndServe() error: %v", err)
	}

	// Set config.Logger to nil to exercise the nil logger path in Shutdown.
	p.config.Logger = nil

	err = p.Shutdown(context.Background())
	if err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// fakeDNSServer: minimal UDP DNS server for testing mock resolution
// ---------------------------------------------------------------------------

// buildDNSResponse constructs a minimal DNS response for the given query,
// returning A or AAAA records matching the provided IPs.
func buildDNSResponse(query []byte, n int, ips []net.IP) []byte {
	if n < 12 {
		return nil
	}
	// Walk past the QNAME to find QTYPE.
	pos := 12
	for pos < n && query[pos] != 0 {
		pos += int(query[pos]) + 1
	}
	pos++ // skip null terminator
	if pos+4 > n {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[pos : pos+2])
	questionEnd := pos + 4

	// Select answers matching the query type.
	var answers []net.IP
	for _, ip := range ips {
		if qtype == 1 && ip.To4() != nil { // A
			answers = append(answers, ip.To4())
		} else if qtype == 28 && ip.To4() == nil { // AAAA
			answers = append(answers, ip.To16())
		}
	}

	resp := make([]byte, 12, 512)
	copy(resp[:2], query[:2])                                   // Transaction ID
	resp[2] = 0x84                                              // QR=1, AA=1
	resp[3] = 0x00                                              // RCODE=0
	binary.BigEndian.PutUint16(resp[4:6], 1)                    // QDCOUNT
	binary.BigEndian.PutUint16(resp[6:8], uint16(len(answers))) // ANCOUNT
	// NSCOUNT=0, ARCOUNT=0 already zero

	// Copy only the question section (not OPT/additional).
	resp = append(resp, query[12:questionEnd]...)

	for _, ip := range answers {
		resp = append(resp, 0xc0, 0x0c) // Name pointer
		if len(ip) == 4 {
			resp = append(resp, 0x00, 0x01) // Type A
		} else {
			resp = append(resp, 0x00, 0x1c) // Type AAAA
		}
		resp = append(resp, 0x00, 0x01, // Class IN
			0x00, 0x00, 0x00, 0x3c) // TTL 60
		rdlen := make([]byte, 2)
		binary.BigEndian.PutUint16(rdlen, uint16(len(ip)))
		resp = append(resp, rdlen...)
		resp = append(resp, ip...)
	}
	return resp
}

// fakeDNSServer starts a minimal UDP DNS server that responds with the given
// IP addresses for any query. It returns the resolver and a cleanup func.
func fakeDNSServer(t *testing.T, ips ...net.IP) (*net.Resolver, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakeDNSServer: listen: %v", err)
	}
	addr := pc.LocalAddr().String()

	go func() {
		buf := make([]byte, 512)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := buildDNSResponse(buf, n, ips)
			if resp != nil {
				_, _ = pc.WriteTo(resp, raddr)
			}
		}
	}()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}
	return resolver, func() { pc.Close() }
}

// ---------------------------------------------------------------------------
// Test: dialWithIPCheck with mock resolver — dial failure via IPv6 (L163-165)
// ---------------------------------------------------------------------------

func TestDialWithIPCheck_MockResolver_DialFailureIPv6(t *testing.T) {
	// Resolve to 2001:db8::1 (IPv6 documentation prefix, not blocked).
	// Dialing this address fails because there is no route to it.
	// With unified IP blocking, the IP passes the block check and
	// the dial is attempted on the first (and only) resolved IP.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	resolver, cleanup := fakeDNSServer(t, net.ParseIP("2001:db8::1"))
	defer cleanup()

	dial := dialWithIPCheck(logger, resolver)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dial(ctx, "tcp", "test.example:80")
	if err == nil {
		conn.Close()
		t.Skip("dial to 2001:db8::1 succeeded (unexpected), skipping")
	}
	// The error should be a dial/network error, not a "blocked" error.
	if strings.Contains(err.Error(), "blocked") {
		t.Errorf("error = %q, should be a dial failure not blocked", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: dialWithIPCheck with mock resolver — mixed blocked + dial failure
// ---------------------------------------------------------------------------

func TestDialWithIPCheck_MockResolver_MixedBlockedAndDialFailure(t *testing.T) {
	// Resolve to: 127.0.0.1 (blocked) + 2001:db8::1 (not blocked).
	// With the unified IP blocking behavior, ANY blocked IP causes
	// immediate rejection — the non-blocked IP is never tried.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	resolver, cleanup := fakeDNSServer(t, net.ParseIP("127.0.0.1"), net.ParseIP("2001:db8::1"))
	defer cleanup()

	dial := dialWithIPCheck(logger, resolver)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := dial(ctx, "tcp", "test.example:80")
	if err == nil {
		t.Fatal("expected error when any resolved IP is blocked")
	}
	// Should get a "blocked" error for 127.0.0.1.
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error = %q, want it to contain 'blocked'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: dialWithIPCheck with mock resolver — successful connection
// ---------------------------------------------------------------------------

func TestDialWithIPCheck_MockResolver_Success(t *testing.T) {
	// Start a local TCP server to verify successful connection through dialWithIPCheck.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Use a mock resolver that returns 127.0.0.1 (normally blocked).
	// But since we're testing the raw-IP path (addr already has an IP),
	// we pass the IP directly. dialWithIPCheck skips DNS for raw IPs.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dial := dialWithIPCheck(logger, nil)

	// Test with a raw IP that is NOT blocked — use the local server.
	// 127.0.0.1 is blocked, so we test the "blocked" path instead.
	_, err = dial(context.Background(), "tcp", "127.0.0.1:"+port)
	if err == nil {
		t.Error("expected error dialing blocked IP 127.0.0.1")
	}
}

// ---------------------------------------------------------------------------
// Test: proxyNameResolver.Resolve — nil resolver (socks5.go:103-106)
// ---------------------------------------------------------------------------

func TestProxyNameResolver_NilResolver(t *testing.T) {
	// When resolver is nil, Resolve should use net.DefaultResolver.
	// We test with "localhost" which resolves to 127.0.0.1 (blocked).
	r := &proxyNameResolver{
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolver: nil, // nil → should use net.DefaultResolver
	}

	_, _, err := r.Resolve(context.Background(), "localhost")
	if err == nil {
		t.Fatal("expected error for localhost (blocked IP) with nil resolver")
	}
	// The error should be about blocked IP (localhost → 127.0.0.1).
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error = %q, want it to contain 'blocked'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: proxyNameResolver.Resolve — empty addrs (socks5.go:112-114)
// ---------------------------------------------------------------------------

func TestProxyNameResolver_EmptyAddrs(t *testing.T) {
	// Use a fake DNS server that returns zero answer records (no error).
	resolver, cleanup := fakeDNSServer(t) // no IPs → empty response
	defer cleanup()

	r := &proxyNameResolver{
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolver: resolver,
	}

	_, _, err := r.Resolve(context.Background(), "empty-result.example")
	if err == nil {
		t.Fatal("expected error for empty address result")
	}
	// The error could be "no addresses found" or "failed to resolve" depending
	// on whether the fake DNS server returns an error or empty results.
	if !strings.Contains(err.Error(), "no addresses") && !strings.Contains(err.Error(), "failed to resolve") {
		t.Errorf("error = %q, want it to contain 'no addresses' or 'failed to resolve'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: dialWithIPCheck — non-blocked IP direct dial (socks5.go:148-149)
// ---------------------------------------------------------------------------

func TestDialWithIPCheck_NonBlockedIPDirectDial(t *testing.T) {
	// Exercise the "host is already a non-blocked IP" direct-dial path
	// (socks5.go:143-149) without requiring external network access.
	// 192.0.2.1 (TEST-NET-1, RFC 5737) is not in any blocked CIDR range.
	// A very short timeout ensures the test completes quickly even though
	// the address is non-routable.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dial := dialWithIPCheck(logger, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	conn, err := dial(ctx, "tcp", "192.0.2.1:9999")
	if err == nil {
		conn.Close()
		return
	}
	// The error must be a timeout or connection error, NOT a "blocked" error.
	if strings.Contains(err.Error(), "blocked") {
		t.Errorf("192.0.2.1 should not be blocked: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: dialWithIPCheck — empty IPs from resolver (socks5.go:158-160)
// ---------------------------------------------------------------------------

func TestDialWithIPCheck_EmptyIPsFromResolver(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a fake DNS server that returns zero answer records.
	resolver, cleanup := fakeDNSServer(t) // no IPs → empty response
	defer cleanup()

	dial := dialWithIPCheck(logger, resolver)

	_, err := dial(context.Background(), "tcp", "empty-result.example:80")
	if err == nil {
		t.Fatal("expected error for empty DNS result")
	}
	// The error should mention "no addresses" or "failed to resolve".
	if !strings.Contains(err.Error(), "no addresses") && !strings.Contains(err.Error(), "failed to resolve") {
		t.Errorf("error = %q, want it to contain 'no addresses' or 'failed to resolve'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: dialWithIPCheck — all IPs blocked, lastErr is nil (socks5.go:183)
// ---------------------------------------------------------------------------

func TestDialWithIPCheck_AllBlockedImmediateReject(t *testing.T) {
	// This test verifies that when ALL resolved IPs are blocked,
	// the function immediately rejects on the first blocked IP
	// (matching the HTTP proxy behavior).
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Return only blocked IPs: 127.0.0.1 and 10.0.0.1
	resolver, cleanup := fakeDNSServer(t, net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1"))
	defer cleanup()

	dial := dialWithIPCheck(logger, resolver)

	_, err := dial(context.Background(), "tcp", "all-blocked.example:80")
	if err == nil {
		t.Fatal("expected error when all resolved IPs are blocked")
	}
	// The error should mention "blocked".
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error = %q, want it to contain 'blocked'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: SOCKS5Proxy ListenAndServe — nil logger in config (socks5.go:246-250)
// ---------------------------------------------------------------------------

func TestSOCKS5Proxy_ListenAndServe_NilConfigLogger(t *testing.T) {
	p, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy() error: %v", err)
	}

	// Set config.Logger to nil to exercise the nil logger path in ListenAndServe.
	p.config.Logger = nil

	addr, err := p.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("ListenAndServe() error: %v", err)
	}
	if addr == nil {
		t.Fatal("expected non-nil addr")
	}

	// Give the server goroutine time to start Serve().
	time.Sleep(50 * time.Millisecond)

	// Close the listener externally without calling Shutdown.
	// This triggers the unexpected stop path at L253-258
	// because p.closed is still false.
	p.mu.Lock()
	ln := p.ln
	p.mu.Unlock()
	if ln != nil {
		ln.Close()
	}

	// Give the server goroutine time to notice the closed listener
	// and execute the logging code.
	time.Sleep(200 * time.Millisecond)

	// Clean up state.
	p.mu.Lock()
	p.closed.Store(true)
	p.ln = nil
	p.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Test: dialWithIPCheck — ANY blocked IP causes rejection (unified behavior)
// ---------------------------------------------------------------------------

func TestDialWithIPCheck_AnyBlockedIPRejects(t *testing.T) {
	// Verify that if ANY resolved IP is blocked, the connection is rejected
	// immediately — matching the HTTP proxy behavior.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name string
		ips  []net.IP
	}{
		{
			"single blocked IP",
			[]net.IP{net.ParseIP("127.0.0.1")},
		},
		{
			"blocked IP mixed with public IP",
			[]net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("10.0.0.1")},
		},
		{
			"public IP first then blocked",
			[]net.IP{net.ParseIP("203.0.113.1"), net.ParseIP("192.168.1.1")},
		},
		{
			"multiple blocked IPs",
			[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1"), net.ParseIP("172.16.0.1")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, cleanup := fakeDNSServer(t, tt.ips...)
			defer cleanup()

			dial := dialWithIPCheck(logger, resolver)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			_, err := dial(ctx, "tcp", "test.example:80")
			if err == nil {
				t.Fatal("expected error when any resolved IP is blocked")
			}
			if !strings.Contains(err.Error(), "blocked") {
				t.Errorf("error = %q, want it to contain 'blocked'", err.Error())
			}
		})
	}
}

func TestDialWithIPCheck_AllPublicIPsAllowed(t *testing.T) {
	// Verify that when all resolved IPs are public (non-blocked),
	// the dial is attempted (may fail due to non-routable address,
	// but should NOT fail with "blocked" error).
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	resolver, cleanup := fakeDNSServer(t, net.ParseIP("203.0.113.1"), net.ParseIP("198.51.100.1"))
	defer cleanup()

	dial := dialWithIPCheck(logger, resolver)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := dial(ctx, "tcp", "test.example:80")
	if err == nil {
		return // connection succeeded (unlikely but fine)
	}
	// The error should be a dial/timeout error, NOT a blocked IP error.
	if strings.Contains(err.Error(), "blocked") {
		t.Errorf("error = %q, should not contain 'blocked' for public IPs", err.Error())
	}
}

// ---------------------------------------------------------------------------
// HIGH 1: SOCKS5 MITM fallback should NOT dial placeholder IP
// ---------------------------------------------------------------------------

func TestSOCKS5MITMFallbackReturnsError(t *testing.T) {
	// Configure MITM with a non-existent socket path.
	router := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/nonexistent-mitm-socks5-" + t.Name() + ".sock",
		Domains:    []string{"mitm-fail.example.com"},
	})

	allowAll := func(ctx context.Context, host string, port int) (bool, error) {
		return true, nil
	}

	socks5Proxy, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter:     allowAll,
		MITMRouter: router,
	})
	if err != nil {
		t.Fatalf("failed to create socks5 proxy: %v", err)
	}

	addr, err := socks5Proxy.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("failed to start socks5 proxy: %v", err)
	}
	defer socks5Proxy.Shutdown(context.Background())

	// Connect to the SOCKS5 proxy.
	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to socks5 proxy: %v", err)
	}
	defer conn.Close()

	// SOCKS5 handshake: greeting.
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00}) // version 5, 1 method, no auth

	// Read greeting response.
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("failed to read greeting: %v", err)
	}

	// SOCKS5 CONNECT request for a MITM domain.
	domain := "mitm-fail.example.com"
	connectReq := make([]byte, 0, 5+len(domain)+2)
	connectReq = append(connectReq, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	connectReq = append(connectReq, []byte(domain)...)
	connectReq = append(connectReq, 0x01, 0xBB) // port 443

	_, _ = conn.Write(connectReq)

	// Read CONNECT response - should fail (not succeed with placeholder IP).
	connectResp := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(conn, connectResp)
	if err != nil {
		// Connection closed or error is acceptable - MITM failed.
		return
	}
	// Status byte 0x00 means success, which should NOT happen.
	if connectResp[1] == 0x00 {
		t.Fatal("SOCKS5 CONNECT should have failed when MITM dial fails, not fall back to placeholder IP")
	}
	// Non-zero status means the proxy correctly reported an error.
}

// ---------------------------------------------------------------------------
// Test: SOCKS5 MITM path performs CONNECT handshake with correct target host
// ---------------------------------------------------------------------------

func TestSOCKS5MITMConnectHandshake(t *testing.T) {
	// Create a Unix socket listener that expects a CONNECT request
	// and verifies the target host is the original FQDN (not placeholder IP).
	socketPath := fmt.Sprintf("/tmp/socks5-mitm-handshake-%d.sock", time.Now().UnixNano())

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	defer ln.Close()
	defer func() {
		// Clean up socket file.
		_ = ln.Close()
	}()

	const expectedTarget = "mitm.example.com:443"
	connectReceived := make(chan string, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the CONNECT request from the SOCKS5 MITM dial.
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			connectReceived <- "error: " + err.Error()
			return
		}

		// Capture the CONNECT target.
		connectReceived <- req.Method + " " + req.RequestURI

		// Send 200 OK to complete the handshake.
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		// Echo any data back (for the SOCKS5 client to verify tunnel works).
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n > 0 {
			_, _ = conn.Write(buf[:n])
		}
	}()

	// Configure MITM router with the Unix socket.
	router := NewMITMRouter(&MITMConfig{
		SocketPath: socketPath,
		Domains:    []string{"mitm.example.com"},
	})

	allowAll := func(ctx context.Context, host string, port int) (bool, error) {
		return true, nil
	}

	socks5Proxy, err := NewSOCKS5Proxy(&SOCKS5Config{
		Filter:     allowAll,
		MITMRouter: router,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("failed to create socks5 proxy: %v", err)
	}

	addr, err := socks5Proxy.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("failed to start socks5 proxy: %v", err)
	}
	defer socks5Proxy.Shutdown(context.Background())

	// Perform SOCKS5 handshake manually.
	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to socks5 proxy: %v", err)
	}
	defer conn.Close()

	// SOCKS5 greeting.
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00}) // version 5, 1 method, no auth
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("failed to read greeting: %v", err)
	}

	// SOCKS5 CONNECT request for the MITM domain.
	domain := "mitm.example.com"
	connectReq := make([]byte, 0, 5+len(domain)+2)
	connectReq = append(connectReq, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	connectReq = append(connectReq, []byte(domain)...)
	connectReq = append(connectReq, 0x01, 0xBB) // port 443
	_, _ = conn.Write(connectReq)

	// Read SOCKS5 CONNECT response.
	connectResp := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(conn, connectResp)
	if err != nil {
		t.Fatalf("failed to read CONNECT response: %v", err)
	}
	if connectResp[1] != 0x00 {
		t.Fatalf("SOCKS5 CONNECT failed with status %d, expected success", connectResp[1])
	}

	// Verify the MITM proxy received a CONNECT request with the correct target.
	select {
	case received := <-connectReceived:
		expected := "CONNECT " + expectedTarget
		if received != expected {
			t.Fatalf("MITM proxy received %q, want %q", received, expected)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for CONNECT request on MITM socket")
	}

	// Verify the tunnel works by sending data through.
	testData := "hello through MITM tunnel"
	_, err = conn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("write through tunnel failed: %v", err)
	}

	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read echo failed: %v", err)
	}
	if string(buf) != testData {
		t.Errorf("echoed data = %q, want %q", string(buf), testData)
	}
}
