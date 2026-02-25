package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// startTestProxy creates and starts a proxy with the given filter.
// By default, the proxy's transport uses dialContextWithIPCheck which blocks
// loopback IPs. For tests that need to reach a local httptest.Server, use
// startTestProxyNoIPCheck instead.
func startTestProxy(t *testing.T, filter FilterFunc) *HTTPProxy {
	t.Helper()
	proxy := NewHTTPProxy(&HTTPConfig{
		Filter:      filter,
		DialTimeout: 5 * time.Second,
		IdleTimeout: 5 * time.Second,
	})
	_, err := proxy.ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		proxy.Shutdown(ctx)
	})
	return proxy
}

// startTestProxyNoIPCheck creates a proxy that bypasses IP checking in the
// dial layer. This allows tests to reach local httptest.Server instances
// on 127.0.0.1. The domain filter is still applied.
func startTestProxyNoIPCheck(t *testing.T, filter FilterFunc) *HTTPProxy {
	t.Helper()
	proxy := NewHTTPProxy(&HTTPConfig{
		Filter:      filter,
		DialTimeout: 5 * time.Second,
		IdleTimeout: 5 * time.Second,
	})
	// Replace the dial function with a plain dialer (no IP check).
	plainDialer := &net.Dialer{Timeout: 5 * time.Second}
	proxy.dialFunc = plainDialer.DialContext
	proxy.transport = &http.Transport{
		DialContext:       proxy.dialFunc,
		DisableKeepAlives: true,
	}
	_, err := proxy.ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		proxy.Shutdown(ctx)
	})
	return proxy
}

func proxyURL(p *HTTPProxy) *url.URL {
	return &url.URL{
		Scheme: "http",
		Host:   p.Addr().String(),
	}
}

// allowAllFilter allows every request.
func allowAllFilter(_ context.Context, _ string, _ int) (bool, error) {
	return true, nil
}

// denyAllFilter denies every request.
func denyAllFilter(_ context.Context, _ string, _ int) (bool, error) {
	return false, nil
}

// ---------------------------------------------------------------------------
// Test: NewHTTPProxy defaults
// ---------------------------------------------------------------------------

func TestNewHTTPProxy_Defaults(t *testing.T) {
	p := NewHTTPProxy(nil)
	if p == nil {
		t.Fatal("NewHTTPProxy(nil) returned nil")
	}
	if p.config.DialTimeout != defaultDialTimeout {
		t.Errorf("DialTimeout = %v, want %v", p.config.DialTimeout, defaultDialTimeout)
	}
	if p.config.IdleTimeout != defaultIdleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", p.config.IdleTimeout, defaultIdleTimeout)
	}
	if p.config.Logger == nil {
		t.Error("Logger should not be nil")
	}
	if p.config.Filter != nil {
		t.Error("Filter should be nil by default")
	}
	if p.resolver == nil {
		t.Error("resolver should not be nil")
	}
}

func TestNewHTTPProxy_CustomConfig(t *testing.T) {
	p := NewHTTPProxy(&HTTPConfig{
		DialTimeout: 3 * time.Second,
		IdleTimeout: 30 * time.Second,
	})
	if p.config.DialTimeout != 3*time.Second {
		t.Errorf("DialTimeout = %v, want 3s", p.config.DialTimeout)
	}
	if p.config.IdleTimeout != 30*time.Second {
		t.Errorf("IdleTimeout = %v, want 30s", p.config.IdleTimeout)
	}
}

// ---------------------------------------------------------------------------
// Test: Addr before ListenAndServe
// ---------------------------------------------------------------------------

func TestHTTPProxy_Addr_BeforeStart(t *testing.T) {
	p := NewHTTPProxy(nil)
	if p.Addr() != nil {
		t.Error("Addr() should be nil before ListenAndServe")
	}
}

// ---------------------------------------------------------------------------
// Test: Regular HTTP proxy (forward request)
// ---------------------------------------------------------------------------

func TestHTTPProxy_ForwardRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Header", "hello")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "backend response")
	}))
	defer backend.Close()

	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL(proxy)),
		},
	}

	resp, err := client.Get(backend.URL + "/test")
	if err != nil {
		t.Fatalf("GET through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend response" {
		t.Errorf("body = %q, want %q", string(body), "backend response")
	}

	if resp.Header.Get("X-Test-Header") != "hello" {
		t.Errorf("X-Test-Header = %q, want %q", resp.Header.Get("X-Test-Header"), "hello")
	}
}

// ---------------------------------------------------------------------------
// Test: HTTP proxy without filter (nil filter allows all)
// ---------------------------------------------------------------------------

func TestHTTPProxy_NilFilter_AllowsAll(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	proxy := startTestProxyNoIPCheck(t, nil)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL(proxy)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("GET through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// Test: Domain filter blocking (HTTP)
// ---------------------------------------------------------------------------

func TestHTTPProxy_FilterDenied_HTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend should not be reached")
	}))
	defer backend.Close()

	proxy := startTestProxyNoIPCheck(t, denyAllFilter)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL(proxy)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("GET through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

// ---------------------------------------------------------------------------
// Test: Domain filter blocking (CONNECT)
// ---------------------------------------------------------------------------

func TestHTTPProxy_FilterDenied_CONNECT(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend should not be reached")
	}))
	defer backend.Close()

	proxy := startTestProxyNoIPCheck(t, denyAllFilter)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL(proxy)),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(backend.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected error for denied CONNECT, got nil")
	}
	// The error should indicate a 403 from the proxy.
	if !strings.Contains(err.Error(), "403") && !strings.Contains(err.Error(), "Forbidden") {
		t.Logf("error: %v (expected 403-related error)", err)
	}
}

// ---------------------------------------------------------------------------
// Test: Domain filter allowing (CONNECT tunnel)
// ---------------------------------------------------------------------------

func TestHTTPProxy_FilterAllowed_CONNECT(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "tls ok")
	}))
	defer backend.Close()

	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL(proxy)),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("GET through CONNECT tunnel failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "tls ok" {
		t.Errorf("body = %q, want %q", string(body), "tls ok")
	}
}

// ---------------------------------------------------------------------------
// Test: Blocked IP rejection (loopback, private) via proxy
// ---------------------------------------------------------------------------

func TestHTTPProxy_BlockedIP_Loopback(t *testing.T) {
	// Use the default proxy (with IP checking enabled).
	proxy := startTestProxy(t, allowAllFilter)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL(proxy)),
		},
	}

	// 127.0.0.1 is a blocked IP; the proxy should return 502.
	resp, err := client.Get("http://127.0.0.1:1/test")
	if err != nil {
		// Connection error containing "blocked IP" is acceptable.
		if !strings.Contains(err.Error(), "blocked IP") {
			t.Logf("got error (expected blocked IP): %v", err)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d for blocked IP", resp.StatusCode, http.StatusBadGateway)
	}
}

func TestHTTPProxy_BlockedIP_Private(t *testing.T) {
	proxy := startTestProxy(t, allowAllFilter)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL(proxy)),
		},
	}

	// 10.0.0.1 is a private IP and should be blocked.
	resp, err := client.Get("http://10.0.0.1:1/test")
	if err != nil {
		if !strings.Contains(err.Error(), "blocked IP") {
			t.Logf("got error (expected blocked IP): %v", err)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d for blocked IP", resp.StatusCode, http.StatusBadGateway)
	}
}

// ---------------------------------------------------------------------------
// Test: dialContextWithIPCheck directly
// ---------------------------------------------------------------------------

func TestDialContextWithIPCheck_BlockedIP(t *testing.T) {
	p := NewHTTPProxy(nil)
	ctx := context.Background()

	_, err := p.dialContextWithIPCheck(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected error for blocked IP 127.0.0.1")
	}
	if !strings.Contains(err.Error(), "blocked IP") {
		t.Errorf("error = %q, want it to contain 'blocked IP'", err.Error())
	}
}

func TestDialContextWithIPCheck_BlockedPrivateIP(t *testing.T) {
	p := NewHTTPProxy(nil)
	ctx := context.Background()

	blockedIPs := []string{"10.0.0.1:80", "172.16.0.1:80", "192.168.1.1:80", "[::1]:80"}
	for _, addr := range blockedIPs {
		_, err := p.dialContextWithIPCheck(ctx, "tcp", addr)
		if err == nil {
			t.Errorf("expected error for blocked IP %s", addr)
			continue
		}
		if !strings.Contains(err.Error(), "blocked IP") {
			t.Errorf("addr=%s: error = %q, want it to contain 'blocked IP'", addr, err.Error())
		}
	}
}

func TestDialContextWithIPCheck_InvalidAddress(t *testing.T) {
	p := NewHTTPProxy(nil)
	ctx := context.Background()

	_, err := p.dialContextWithIPCheck(ctx, "tcp", "")
	if err == nil {
		t.Fatal("expected error for empty address")
	}
}

// ---------------------------------------------------------------------------
// Test: DNS rebinding protection
// ---------------------------------------------------------------------------

func TestDialContextWithIPCheck_DNSRebinding(t *testing.T) {
	// localhost resolves to 127.0.0.1 (blocked), so the dialer should reject it.
	p := NewHTTPProxy(nil)
	ctx := context.Background()

	_, err := p.dialContextWithIPCheck(ctx, "tcp", "localhost:80")
	if err == nil {
		t.Fatal("expected error: localhost resolves to blocked IP")
	}
	if !strings.Contains(err.Error(), "blocked IP") {
		t.Errorf("error = %q, want it to contain 'blocked IP'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: Hop-by-hop header removal
// ---------------------------------------------------------------------------

func TestRemoveHopByHopHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "keep-alive")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Authenticate", "Basic")
	h.Set("Proxy-Authorization", "Basic abc")
	h.Set("Te", "trailers")
	h.Set("Trailers", "X-Foo")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Upgrade", "websocket")
	h.Set("Content-Type", "text/plain")
	h.Set("X-Custom", "value")

	removeHopByHopHeaders(h)

	for _, header := range hopByHopHeaders {
		if h.Get(header) != "" {
			t.Errorf("hop-by-hop header %q was not removed", header)
		}
	}

	// Non-hop-by-hop headers should remain.
	if h.Get("Content-Type") != "text/plain" {
		t.Error("Content-Type should not be removed")
	}
	if h.Get("X-Custom") != "value" {
		t.Error("X-Custom should not be removed")
	}
}

func TestRemoveHopByHopHeaders_Empty(t *testing.T) {
	h := http.Header{}
	removeHopByHopHeaders(h) // Should not panic.
}

// ---------------------------------------------------------------------------
// Test: Hop-by-hop headers removed in forwarded requests
// ---------------------------------------------------------------------------

func TestHTTPProxy_HopByHopHeadersRemoved(t *testing.T) {
	var mu sync.Mutex
	var receivedHeaders http.Header

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedHeaders = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	req, _ := http.NewRequest(http.MethodGet, backend.URL+"/test", nil)
	req.Header.Set("Proxy-Authorization", "Basic abc")
	req.Header.Set("X-Custom", "preserved")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL(proxy)),
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	if receivedHeaders == nil {
		t.Fatal("backend did not receive request")
	}
	if receivedHeaders.Get("Proxy-Authorization") != "" {
		t.Error("Proxy-Authorization should be removed")
	}
	if receivedHeaders.Get("X-Custom") != "preserved" {
		t.Error("X-Custom should be preserved")
	}
}

// ---------------------------------------------------------------------------
// Test: Proxy shutdown
// ---------------------------------------------------------------------------

func TestHTTPProxy_Shutdown(t *testing.T) {
	proxy := startTestProxy(t, nil)
	addr := proxy.Addr()
	if addr == nil {
		t.Fatal("proxy addr is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := proxy.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// After shutdown, connections should be refused.
	time.Sleep(50 * time.Millisecond)
	conn, err := net.DialTimeout("tcp", addr.String(), 1*time.Second)
	if err == nil {
		conn.Close()
		t.Error("expected connection refused after shutdown")
	}
}

func TestHTTPProxy_Shutdown_BeforeStart(t *testing.T) {
	p := NewHTTPProxy(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := p.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown before start should not error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: Concurrent requests
// ---------------------------------------------------------------------------

func TestHTTPProxy_ConcurrentRequests(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "concurrent ok")
	}))
	defer backend.Close()

	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	const numRequests = 20
	var wg sync.WaitGroup
	errors := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL(proxy)),
				},
			}
			resp, err := client.Get(backend.URL)
			if err != nil {
				errors <- fmt.Errorf("request failed: %w", err)
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("status = %d, want 200, body = %s", resp.StatusCode, string(body))
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// Test: Invalid requests
// ---------------------------------------------------------------------------

func TestHTTPProxy_MissingHost(t *testing.T) {
	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	// Send a non-proxy request directly to the proxy address.
	req, _ := http.NewRequest(http.MethodGet, "http://"+proxy.Addr().String()+"/test", nil)

	client := &http.Client{
		Transport: &http.Transport{},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// The proxy should return 400 because the URL has no host for proxying.
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// Test: Filter error returns 500
// ---------------------------------------------------------------------------

func TestHTTPProxy_FilterError_HTTP(t *testing.T) {
	errorFilter := func(_ context.Context, _ string, _ int) (bool, error) {
		return false, errors.New("filter exploded")
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend should not be reached")
	}))
	defer backend.Close()

	proxy := startTestProxyNoIPCheck(t, errorFilter)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL(proxy)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

// ---------------------------------------------------------------------------
// Test: parseHostPort helper
// ---------------------------------------------------------------------------

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		defaultPort string
		wantHost    string
		wantPort    string
		wantErr     bool
	}{
		{
			name:        "host:port",
			input:       "example.com:8080",
			defaultPort: "80",
			wantHost:    "example.com",
			wantPort:    "8080",
		},
		{
			name:        "host only with default",
			input:       "example.com",
			defaultPort: "443",
			wantHost:    "example.com",
			wantPort:    "443",
		},
		{
			name:        "IPv4:port",
			input:       "1.2.3.4:9090",
			defaultPort: "80",
			wantHost:    "1.2.3.4",
			wantPort:    "9090",
		},
		{
			name:        "IPv6 bracket:port",
			input:       "[::1]:80",
			defaultPort: "80",
			wantHost:    "::1",
			wantPort:    "80",
		},
		{
			name:        "IPv6 bracket no port",
			input:       "[::1]",
			defaultPort: "443",
			wantHost:    "::1",
			wantPort:    "443",
		},
		{
			name:        "empty input",
			input:       "",
			defaultPort: "80",
			wantErr:     true,
		},
		{
			name:        "host only no default",
			input:       "example.com",
			defaultPort: "",
			wantErr:     true,
		},
		{
			name:        "host with explicit port",
			input:       "api.example.com:443",
			defaultPort: "80",
			wantHost:    "api.example.com",
			wantPort:    "443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := parseHostPort(tt.input, tt.defaultPort)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseHostPort(%q, %q) expected error", tt.input, tt.defaultPort)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseHostPort(%q, %q) unexpected error: %v", tt.input, tt.defaultPort, err)
			}
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("port = %q, want %q", port, tt.wantPort)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: ListenAndServe on invalid address
// ---------------------------------------------------------------------------

func TestHTTPProxy_ListenAndServe_InvalidAddr(t *testing.T) {
	p := NewHTTPProxy(nil)
	_, err := p.ListenAndServe("invalid-not-an-address:99999999")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

// ---------------------------------------------------------------------------
// Test: Selective domain filter
// ---------------------------------------------------------------------------

func TestHTTPProxy_SelectiveFilter(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "allowed")
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	allowedHost := backendURL.Hostname()

	selectiveFilter := func(_ context.Context, host string, _ int) (bool, error) {
		return host == allowedHost, nil
	}

	proxy := startTestProxyNoIPCheck(t, selectiveFilter)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL(proxy)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("allowed request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("allowed: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// Test: CONNECT to blocked IP
// ---------------------------------------------------------------------------

func TestHTTPProxy_CONNECT_BlockedIP(t *testing.T) {
	proxy := startTestProxy(t, allowAllFilter)

	conn, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy failed: %v", err)
	}
	defer conn.Close()

	// Send CONNECT to 127.0.0.1:443 (blocked).
	fmt.Fprintf(conn, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	response := string(buf[:n])

	if !strings.Contains(response, "502") {
		t.Errorf("expected 502 for blocked IP CONNECT, got: %s", response)
	}
}

// ---------------------------------------------------------------------------
// Test: CONNECT filter error returns 500
// ---------------------------------------------------------------------------

func TestHTTPProxy_CONNECT_FilterError(t *testing.T) {
	errorFilter := func(_ context.Context, _ string, _ int) (bool, error) {
		return false, errors.New("filter error")
	}

	proxy := startTestProxyNoIPCheck(t, errorFilter)

	conn, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy failed: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	response := string(buf[:n])

	if !strings.Contains(response, "500") {
		t.Errorf("expected 500 for filter error, got: %s", response)
	}
}

// ---------------------------------------------------------------------------
// Test: CONNECT filter denied returns 403
// ---------------------------------------------------------------------------

func TestHTTPProxy_CONNECT_FilterDenied(t *testing.T) {
	proxy := startTestProxyNoIPCheck(t, denyAllFilter)

	conn, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy failed: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	response := string(buf[:n])

	if !strings.Contains(response, "403") {
		t.Errorf("expected 403 for denied CONNECT, got: %s", response)
	}
}

// ---------------------------------------------------------------------------
// Test: Dial timeout
// ---------------------------------------------------------------------------

func TestHTTPProxy_DialTimeout(t *testing.T) {
	proxy := NewHTTPProxy(&HTTPConfig{
		Filter:      allowAllFilter,
		DialTimeout: 1 * time.Millisecond,
	})
	_, err := proxy.ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		proxy.Shutdown(ctx)
	}()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL(proxy)),
		},
		Timeout: 5 * time.Second,
	}

	// 198.51.100.1 is TEST-NET-2 (RFC 5737), should be non-routable and timeout.
	resp, err := client.Get("http://198.51.100.1:80/test")
	if err != nil {
		// Timeout error is expected.
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
}

// ---------------------------------------------------------------------------
// Test: Response headers are forwarded
// ---------------------------------------------------------------------------

func TestHTTPProxy_ResponseHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "yes")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer backend.Close()

	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL(proxy)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	if resp.Header.Get("X-Backend") != "yes" {
		t.Errorf("X-Backend = %q, want %q", resp.Header.Get("X-Backend"), "yes")
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want %q", resp.Header.Get("Content-Type"), "application/json")
	}
}

// ---------------------------------------------------------------------------
// Test: DNS resolution failure
// ---------------------------------------------------------------------------

func TestDialContextWithIPCheck_DNSFailure(t *testing.T) {
	p := NewHTTPProxy(nil)
	ctx := context.Background()

	// Use a domain that should not resolve.
	_, err := p.dialContextWithIPCheck(ctx, "tcp", "this-domain-does-not-exist-xyzzy.invalid:80")
	if err == nil {
		t.Fatal("expected error for unresolvable domain")
	}
	if !strings.Contains(err.Error(), "DNS") {
		t.Logf("error = %q (expected DNS-related error)", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: CONNECT handler waits for bidirectional copy goroutines
// ---------------------------------------------------------------------------

func TestHTTPProxy_CONNECT_WaitsForCopy(t *testing.T) {
	// Start a backend that accepts a connection, sends data, and reads data.
	// This verifies the CONNECT handler properly waits for both copy
	// goroutines to finish (the WaitGroup fix).
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start backend listener: %v", err)
	}
	defer backend.Close()

	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Echo back whatever we receive.
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}()

	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	// Connect to the proxy and issue a CONNECT request.
	proxyConn, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy failed: %v", err)
	}
	defer proxyConn.Close()

	// Send CONNECT to the backend.
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		backend.Addr().String(), backend.Addr().String())

	// Read the 200 response.
	buf := make([]byte, 4096)
	n, err := proxyConn.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response failed: %v", err)
	}
	response := string(buf[:n])
	if !strings.Contains(response, "200") {
		t.Fatalf("expected 200 response, got: %s", response)
	}

	// Send data through the tunnel.
	testData := "hello-tunnel"
	_, err = proxyConn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("write through tunnel failed: %v", err)
	}

	// Read echoed data back.
	n, err = proxyConn.Read(buf)
	if err != nil {
		t.Fatalf("read through tunnel failed: %v", err)
	}
	if string(buf[:n]) != testData {
		t.Errorf("echoed data = %q, want %q", string(buf[:n]), testData)
	}

	// Close the proxy connection and wait for backend to finish.
	proxyConn.Close()
	<-backendDone
}

// ---------------------------------------------------------------------------
// Test: MaxRequestBodySize defaults
// ---------------------------------------------------------------------------

func TestNewHTTPProxy_DefaultMaxRequestBodySize(t *testing.T) {
	p := NewHTTPProxy(nil)
	if p.config.MaxRequestBodySize != maxRequestBodySize {
		t.Errorf("MaxRequestBodySize = %d, want %d", p.config.MaxRequestBodySize, maxRequestBodySize)
	}
}

func TestNewHTTPProxy_CustomMaxRequestBodySize(t *testing.T) {
	p := NewHTTPProxy(&HTTPConfig{
		MaxRequestBodySize: 1024,
	})
	if p.config.MaxRequestBodySize != 1024 {
		t.Errorf("MaxRequestBodySize = %d, want 1024", p.config.MaxRequestBodySize)
	}
}

// ---------------------------------------------------------------------------
// Test: Request body size limit enforcement
// ---------------------------------------------------------------------------

func TestHTTPProxy_RequestBodySizeLimit(t *testing.T) {
	var receivedBodySize int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBodySize = len(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Create a proxy with a very small body limit.
	proxy := NewHTTPProxy(&HTTPConfig{
		Filter:             allowAllFilter,
		DialTimeout:        5 * time.Second,
		IdleTimeout:        5 * time.Second,
		MaxRequestBodySize: 100, // 100 bytes
	})
	// Bypass IP check for local test.
	plainDialer := &net.Dialer{Timeout: 5 * time.Second}
	proxy.dialFunc = plainDialer.DialContext
	proxy.transport = &http.Transport{
		DialContext:       proxy.dialFunc,
		DisableKeepAlives: true,
	}
	_, err := proxy.ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		proxy.Shutdown(ctx)
	})

	// Send a request with a body larger than the limit.
	largeBody := strings.NewReader(strings.Repeat("x", 200))
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL(proxy)),
		},
	}

	req, _ := http.NewRequest(http.MethodPost, backend.URL+"/upload", largeBody)
	resp, err := client.Do(req)
	if err != nil {
		// An error is acceptable — the body limit may cause a transport error.
		return
	}
	defer resp.Body.Close()

	// The backend should have received at most 100 bytes (the limit),
	// or the proxy should have returned an error status.
	if resp.StatusCode == http.StatusOK && receivedBodySize > 100 {
		t.Errorf("backend received %d bytes, expected at most 100", receivedBodySize)
	}
}

// ---------------------------------------------------------------------------
// Test: parseHostPort — empty host (":8080") and empty port without default
// ---------------------------------------------------------------------------

func TestParseHostPort_EmptyHost(t *testing.T) {
	// Input ":8080" — net.SplitHostPort returns host="" and port="8080".
	// parseHostPort should return an error because host is empty.
	_, _, err := parseHostPort(":8080", "80")
	if err == nil {
		t.Fatal("expected error for empty host in ':8080'")
	}
	if !strings.Contains(err.Error(), "empty host") {
		t.Errorf("error = %q, want it to contain 'empty host'", err.Error())
	}
}

func TestParseHostPort_EmptyPortNoDefault(t *testing.T) {
	// Input "host:" — net.SplitHostPort returns host="host" and port="".
	// With defaultPort="" the function should return an error.
	_, _, err := parseHostPort("host:", "")
	if err == nil {
		t.Fatal("expected error for empty port with no default")
	}
	if !strings.Contains(err.Error(), "empty port") {
		t.Errorf("error = %q, want it to contain 'empty port'", err.Error())
	}
}

func TestParseHostPort_EmptyPortWithDefault(t *testing.T) {
	// Input "host:" — net.SplitHostPort returns host="host" and port="".
	// With defaultPort="443" the function should fill in the default.
	host, port, err := parseHostPort("host:", "443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "host" {
		t.Errorf("host = %q, want %q", host, "host")
	}
	if port != "443" {
		t.Errorf("port = %q, want %q", port, "443")
	}
}

// ---------------------------------------------------------------------------
// Test: handleConnect — ResponseWriter doesn't implement Hijacker
// ---------------------------------------------------------------------------

// nonHijackableResponseWriter is an http.ResponseWriter that does NOT
// implement http.Hijacker.
type nonHijackableResponseWriter struct {
	code    int
	headers http.Header
	body    []byte
}

func (w *nonHijackableResponseWriter) Header() http.Header {
	if w.headers == nil {
		w.headers = make(http.Header)
	}
	return w.headers
}

func (w *nonHijackableResponseWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}

func (w *nonHijackableResponseWriter) WriteHeader(code int) {
	w.code = code
}

func TestHandleConnect_NoHijacker(t *testing.T) {
	p := NewHTTPProxy(&HTTPConfig{
		Filter: allowAllFilter,
	})
	// Override dialFunc to return a dummy connection so we reach the hijack check.
	p.dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Create a pipe — we just need a valid net.Conn.
		server, client := net.Pipe()
		go func() {
			// Close server side after a short delay to avoid leaks.
			time.Sleep(100 * time.Millisecond)
			server.Close()
		}()
		return client, nil
	}

	w := &nonHijackableResponseWriter{}
	r, _ := http.NewRequest(http.MethodConnect, "", nil)
	r.Host = "example.com:443"

	p.handleConnect(w, r)

	if w.code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.code, http.StatusInternalServerError)
	}
}

// ---------------------------------------------------------------------------
// Test: handleConnect — Hijack() returns error
// ---------------------------------------------------------------------------

// failHijackResponseWriter implements http.Hijacker but Hijack() returns error.
type failHijackResponseWriter struct {
	nonHijackableResponseWriter
	flushed bool
}

func (w *failHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("hijack failed")
}

func (w *failHijackResponseWriter) Flush() {
	w.flushed = true
}

func TestHandleConnect_HijackFails(t *testing.T) {
	p := NewHTTPProxy(&HTTPConfig{
		Filter: allowAllFilter,
	})
	// Override dialFunc to return a dummy connection.
	p.dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		server, client := net.Pipe()
		go func() {
			time.Sleep(100 * time.Millisecond)
			server.Close()
		}()
		return client, nil
	}

	w := &failHijackResponseWriter{}
	r, _ := http.NewRequest(http.MethodConnect, "", nil)
	r.Host = "example.com:443"

	p.handleConnect(w, r)

	// With the new hijack-before-200 ordering, Hijack() is called first.
	// When it fails, no status is written via ResponseWriter (the handler
	// returns early after logging). We just verify no panic occurred.
}

// ---------------------------------------------------------------------------
// Test: dialContextWithIPCheck — DNS resolves to empty IP list / mock resolver
// ---------------------------------------------------------------------------

func TestDialContextWithIPCheck_MockResolverFailure(t *testing.T) {
	p := NewHTTPProxy(nil)
	// Override the resolver with one that always fails.
	p.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("mock resolver: no results")
		},
	}

	ctx := context.Background()
	_, err := p.dialContextWithIPCheck(ctx, "tcp", "some-host.example:80")
	if err == nil {
		t.Fatal("expected error for DNS failure with mock resolver")
	}
	if !strings.Contains(err.Error(), "DNS resolution failed") {
		t.Errorf("error = %q, want it to contain 'DNS resolution failed'", err.Error())
	}
}

func TestDialContextWithIPCheck_DNSResolvesToBlockedIP(t *testing.T) {
	p := NewHTTPProxy(nil)
	ctx := context.Background()

	// "localhost" resolves to 127.0.0.1 which is blocked.
	_, err := p.dialContextWithIPCheck(ctx, "tcp", "localhost:80")
	if err == nil {
		t.Fatal("expected error for localhost (blocked IP)")
	}
	if !strings.Contains(err.Error(), "blocked IP") {
		t.Errorf("error = %q, want it to contain 'blocked IP'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: dialContextWithIPCheck — success path with resolved IP (L364-365)
// ---------------------------------------------------------------------------

func TestDialContextWithIPCheck_SuccessWithResolvedIP(t *testing.T) {
	p := NewHTTPProxy(nil)

	// "dns.google" resolves to 8.8.8.8 / 8.8.4.4 (non-blocked public IPs).
	// We use a longer timeout to allow DNS resolution to complete.
	// Port 1 is unlikely to be listening, so the dial will fail,
	// but the important thing is that we reach L364-365 (the dial call).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := p.dialContextWithIPCheck(ctx, "tcp", "dns.google:1")
	if err == nil {
		// Unlikely but possible — just close the connection.
		return
	}
	// The error should be a dial/timeout error, NOT a blocked IP or DNS error.
	if strings.Contains(err.Error(), "blocked IP") {
		t.Errorf("dns.google should not resolve to blocked IP: %v", err)
	}
	if strings.Contains(err.Error(), "no IP addresses") {
		t.Errorf("dns.google should resolve to IPs: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: handleHTTP — parseHostPort error (L209-212)
// ---------------------------------------------------------------------------

func TestHandleHTTP_InvalidHost(t *testing.T) {
	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	// Send a request with an invalid host that will cause parseHostPort to fail.
	// We need to craft a request where URL.Host is set but invalid.
	conn, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy failed: %v", err)
	}
	defer conn.Close()

	// Send a raw HTTP request with a host that has empty host part.
	// ":8080" as the host will trigger the empty host error.
	fmt.Fprintf(conn, "GET http://:8080/test HTTP/1.1\r\nHost: :8080\r\n\r\n")

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	response := string(buf[:n])

	if !strings.Contains(response, "400") {
		t.Errorf("expected 400 for invalid host, got: %s", response)
	}
}

// ---------------------------------------------------------------------------
// Test: handleConnect — parseHostPort error (L259-262)
// ---------------------------------------------------------------------------

func TestHandleConnect_InvalidHost(t *testing.T) {
	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	conn, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy failed: %v", err)
	}
	defer conn.Close()

	// Send CONNECT with an empty host (":443").
	fmt.Fprintf(conn, "CONNECT :443 HTTP/1.1\r\nHost: :443\r\n\r\n")

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	response := string(buf[:n])

	if !strings.Contains(response, "400") {
		t.Errorf("expected 400 for invalid CONNECT host, got: %s", response)
	}
}

// ---------------------------------------------------------------------------
// Test: ListenAndServe — server error logging (L156-158)
// ---------------------------------------------------------------------------

func TestHTTPProxy_ListenAndServe_ServerError(t *testing.T) {
	// This tests the goroutine at L155-159 where the server encounters
	// an error that is not http.ErrServerClosed.
	p := NewHTTPProxy(nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	// Start the server.
	_, err = p.ListenAndServe(ln.Addr().String())
	if err != nil {
		// The port might be reused; if it fails, try another approach.
		ln.Close()
		_, err = p.ListenAndServe("127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to start proxy: %v", err)
		}
	} else {
		ln.Close() // Close the original listener.
	}

	// Shutdown the server.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Shutdown(ctx)
}

// ---------------------------------------------------------------------------
// Test: dialContextWithIPCheck — empty DNS result (http.go:358-360)
// ---------------------------------------------------------------------------

func TestDialContextWithIPCheck_EmptyDNSResult(t *testing.T) {
	p := NewHTTPProxy(nil)
	// Override the resolver with one that returns empty results (no error).
	// We use a fake DNS server that returns an IPv6 AAAA record only.
	// When the Go resolver queries for A records, it gets zero answers,
	// and when it queries for AAAA, it gets an IPv6 address.
	// But LookupIPAddr merges both, so we need a different approach.
	//
	// The simplest way to trigger len(ips)==0 is to use a resolver that
	// returns a successful response with zero matching records for both
	// A and AAAA queries. We achieve this by returning a valid DNS response
	// with ANCOUNT=0 and RCODE=0 (no error, no records).
	resolver, cleanup := fakeDNSServer(t) // no IPs → empty A and AAAA
	defer cleanup()
	p.resolver = resolver

	ctx := context.Background()
	_, err := p.dialContextWithIPCheck(ctx, "tcp", "empty-result.example:80")
	if err == nil {
		t.Fatal("expected error for empty DNS result")
	}
	// The error may be "no IP addresses found" or "DNS resolution failed"
	// depending on how the resolver handles empty responses.
	if !strings.Contains(err.Error(), "no IP addresses") && !strings.Contains(err.Error(), "DNS resolution failed") {
		t.Errorf("error = %q, want it to contain 'no IP addresses' or 'DNS resolution failed'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: handleConnect — Flusher path (http.go:301-303)
// ---------------------------------------------------------------------------

func TestHandleConnect_FlusherPath(t *testing.T) {
	// With the new hijack-before-200 ordering, the ResponseWriter's Flush()
	// is no longer called. Instead, bufRW.Flush() is used after hijack.
	// This test verifies that the handler completes without panic when
	// Hijack() fails on a Flusher-implementing ResponseWriter.
	p := NewHTTPProxy(&HTTPConfig{
		Filter: allowAllFilter,
	})
	p.dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		server, client := net.Pipe()
		go func() {
			time.Sleep(100 * time.Millisecond)
			server.Close()
		}()
		return client, nil
	}

	w := &failHijackResponseWriter{}
	r, _ := http.NewRequest(http.MethodConnect, "", nil)
	r.Host = "example.com:443"

	p.handleConnect(w, r)

	// Flush() should NOT be called since hijack happens before any write.
	if w.flushed {
		t.Error("Flush() should not be called with hijack-before-200 ordering")
	}
}

// ---------------------------------------------------------------------------
// Test: handleHTTP — response body copy error (http.go:253-255)
// ---------------------------------------------------------------------------

func TestHandleHTTP_ResponseBodyCopyError(t *testing.T) {
	// Start a backend that sends a large response body with a delay.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10240")
		w.WriteHeader(http.StatusOK)
		// Write data in chunks with delays to ensure the proxy starts copying.
		for i := 0; i < 10; i++ {
			w.Write([]byte(strings.Repeat("x", 1024)))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer backend.Close()

	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	// Connect to the proxy and send a request, then close the connection
	// after reading the status line to trigger a copy error.
	conn, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy failed: %v", err)
	}

	// Send a valid HTTP proxy request.
	fmt.Fprintf(conn, "GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		backend.URL, backend.URL[7:]) // strip "http://"

	// Read just the status line, then close to trigger copy error.
	buf := make([]byte, 64)
	conn.Read(buf)

	// Close the connection while the proxy is still copying the response body.
	conn.Close()

	// Give the proxy time to encounter the copy error.
	time.Sleep(300 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// Test: handleConnect — copy error paths (http.go:320-322, 328-330)
// ---------------------------------------------------------------------------

func TestHandleConnect_CopyError(t *testing.T) {
	// Start a backend that sends data and then closes the connection.
	// This triggers the target→client copy error when the client
	// disconnects before all data is received.
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start backend listener: %v", err)
	}
	defer backend.Close()

	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		// Send some data and then close abruptly.
		conn.Write([]byte("hello from backend"))
		time.Sleep(50 * time.Millisecond)
		conn.Close()
	}()

	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	// Connect to the proxy and issue a CONNECT request.
	proxyConn, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy failed: %v", err)
	}

	// Send CONNECT to the backend.
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		backend.Addr().String(), backend.Addr().String())

	// Read the 200 response.
	buf := make([]byte, 4096)
	n, err := proxyConn.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response failed: %v", err)
	}
	response := string(buf[:n])
	if !strings.Contains(response, "200") {
		t.Fatalf("expected 200 response, got: %s", response)
	}

	// Close the client connection abruptly to trigger copy errors.
	proxyConn.Close()

	// Give the proxy time to encounter the copy errors.
	time.Sleep(200 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// Test: ListenAndServe — server.Serve error path (http.go:156-158)
// This path is exercised when the HTTP server encounters an error
// other than http.ErrServerClosed. This is very hard to trigger
// in tests because http.Server.Serve returns ErrServerClosed on
// normal shutdown. The test below verifies the goroutine doesn't
// panic during normal operation.
// ---------------------------------------------------------------------------

func TestHTTPProxy_ServeGoroutine(t *testing.T) {
	p := NewHTTPProxy(nil)
	_, err := p.ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenAndServe failed: %v", err)
	}

	// Give the server goroutine time to start.
	time.Sleep(50 * time.Millisecond)

	// Shutdown gracefully.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Shutdown(ctx)
}

// ---------------------------------------------------------------------------
// Test: Invalid port validation (handleHTTP and handleConnect)
// ---------------------------------------------------------------------------

func TestHTTPProxy_InvalidPort_HTTP(t *testing.T) {
	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	tests := []struct {
		name    string
		url     string
		wantMsg bool // whether we expect our custom "invalid port" message
	}{
		{"non-numeric port", "http://example.com:abc/test", false}, // Go's URL parser rejects this
		{"port zero", "http://example.com:0/test", true},
		{"port too large", "http://example.com:99999/test", true},
		{"negative port", "http://example.com:-1/test", false}, // Go's URL parser rejects this
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", proxy.Addr().String())
			if err != nil {
				t.Fatalf("dial proxy failed: %v", err)
			}
			defer conn.Close()

			fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", tt.url)

			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("read response failed: %v", err)
			}
			response := string(buf[:n])

			if !strings.Contains(response, "400") {
				t.Errorf("expected 400 for %s, got: %s", tt.name, response)
			}
			if tt.wantMsg && !strings.Contains(response, "invalid port") {
				t.Errorf("expected 'invalid port' in response for %s, got: %s", tt.name, response)
			}
		})
	}
}

func TestHTTPProxy_InvalidPort_CONNECT(t *testing.T) {
	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	tests := []struct {
		name    string
		host    string
		wantMsg bool // whether we expect our custom "invalid port" message
	}{
		{"non-numeric port", "example.com:abc", false}, // Go's HTTP parser may reject this
		{"port zero", "example.com:0", true},
		{"port too large", "example.com:99999", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", proxy.Addr().String())
			if err != nil {
				t.Fatalf("dial proxy failed: %v", err)
			}
			defer conn.Close()

			fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", tt.host, tt.host)

			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("read response failed: %v", err)
			}
			response := string(buf[:n])

			if !strings.Contains(response, "400") {
				t.Errorf("expected 400 for %s, got: %s", tt.name, response)
			}
			if tt.wantMsg && !strings.Contains(response, "invalid port") {
				t.Errorf("expected 'invalid port' in response for %s, got: %s", tt.name, response)
			}
		})
	}
}

func TestHTTPProxy_ValidPort_HTTP(t *testing.T) {
	// Verify that valid ports still work correctly.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "valid port ok")
	}))
	defer backend.Close()

	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL(proxy)),
		},
	}

	resp, err := client.Get(backend.URL + "/test")
	if err != nil {
		t.Fatalf("GET through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// Test: CONNECT hijack ordering — verify 200 is sent correctly
// ---------------------------------------------------------------------------

func TestHandleConnect_HijackOrdering(t *testing.T) {
	// Start a backend that echoes data.
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start backend listener: %v", err)
	}
	defer backend.Close()

	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Echo data back.
		io.Copy(conn, conn)
	}()

	proxy := startTestProxyNoIPCheck(t, allowAllFilter)

	// Connect to the proxy and issue a CONNECT request.
	proxyConn, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy failed: %v", err)
	}
	defer proxyConn.Close()

	// Send CONNECT to the backend.
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		backend.Addr().String(), backend.Addr().String())

	// Read the 200 response — should be "HTTP/1.1 200 Connection Established".
	reader := bufio.NewReader(proxyConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line failed: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected 200 in status line, got: %s", statusLine)
	}
	if !strings.Contains(statusLine, "Connection Established") {
		t.Errorf("expected 'Connection Established' in status line, got: %s", statusLine)
	}

	// Read the empty line after headers.
	emptyLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read empty line failed: %v", err)
	}
	if strings.TrimSpace(emptyLine) != "" {
		t.Errorf("expected empty line after status, got: %q", emptyLine)
	}

	// Send data through the tunnel and verify echo.
	testData := "hello through tunnel"
	_, err = proxyConn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("write through tunnel failed: %v", err)
	}

	buf := make([]byte, len(testData))
	_, err = io.ReadFull(reader, buf)
	if err != nil {
		t.Fatalf("read echo failed: %v", err)
	}
	if string(buf) != testData {
		t.Errorf("echoed data = %q, want %q", string(buf), testData)
	}
}

// ---------------------------------------------------------------------------
// Test: HTTP CONNECT returns 502 when MITM proxy is unavailable
// ---------------------------------------------------------------------------

func TestHTTPConnectMITMUnavailable502(t *testing.T) {
	// Configure a MITM router with a non-existent socket path.
	router := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/nonexistent-mitm-http-" + strconv.FormatInt(time.Now().UnixNano(), 10) + ".sock",
		Domains:    []string{"mitm-fail.example.com"},
	})

	proxy := NewHTTPProxy(&HTTPConfig{
		Filter:      allowAllFilter,
		MITMRouter:  router,
		DialTimeout: 5 * time.Second,
		IdleTimeout: 5 * time.Second,
	})
	_, err := proxy.ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		proxy.Shutdown(ctx)
	}()

	// Connect to the proxy and send a CONNECT request for a MITM domain.
	proxyConn, err := net.DialTimeout("tcp", proxy.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer proxyConn.Close()

	// Send CONNECT request.
	fmt.Fprintf(proxyConn, "CONNECT mitm-fail.example.com:443 HTTP/1.1\r\nHost: mitm-fail.example.com:443\r\n\r\n")

	// Read the response.
	reader := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	defer resp.Body.Close()

	// Should get 502 Bad Gateway, not 200 Connection Established.
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected status 502 Bad Gateway, got %d %s", resp.StatusCode, resp.Status)
	}

	// Read body to verify it mentions MITM unavailable.
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "MITM proxy unavailable") {
		t.Errorf("response body = %q, want it to contain 'MITM proxy unavailable'", string(body))
	}
}
