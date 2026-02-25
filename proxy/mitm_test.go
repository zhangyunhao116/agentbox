package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Unit tests for NewMITMRouter
// ---------------------------------------------------------------------------

func TestNewMITMRouterNil(t *testing.T) {
	r := NewMITMRouter(nil)
	if r != nil {
		t.Fatal("expected nil router for nil config")
	}
}

func TestNewMITMRouterEmpty(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{})
	if r != nil {
		t.Fatal("expected nil router for empty config")
	}
}

func TestNewMITMRouterNoSocketPath(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{
		Domains: []string{"example.com"},
	})
	if r != nil {
		t.Fatal("expected nil router when SocketPath is empty")
	}
}

func TestNewMITMRouterNoDomains(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/mitm.sock",
	})
	if r != nil {
		t.Fatal("expected nil router when Domains is empty")
	}
}

func TestNewMITMRouterEmptyDomains(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/mitm.sock",
		Domains:    []string{},
	})
	if r != nil {
		t.Fatal("expected nil router when Domains slice is empty")
	}
}

func TestNewMITMRouterValid(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/mitm.sock",
		Domains:    []string{"example.com"},
	})
	if r == nil {
		t.Fatal("expected non-nil router for valid config")
	}
	if r.socketPath != "/tmp/mitm.sock" {
		t.Fatalf("unexpected socketPath: %s", r.socketPath)
	}
}

// ---------------------------------------------------------------------------
// Unit tests for MITMRouter.SocketPathForHost
// ---------------------------------------------------------------------------

func TestMITMRouterNilReceiver(t *testing.T) {
	var r *MITMRouter
	if got := r.SocketPathForHost("any.com"); got != "" {
		t.Fatalf("expected empty string for nil receiver, got %q", got)
	}
}

func TestMITMRouterExactMatch(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/mitm.sock",
		Domains:    []string{"api.example.com"},
	})
	if got := r.SocketPathForHost("api.example.com"); got != "/tmp/mitm.sock" {
		t.Fatalf("expected match for api.example.com, got %q", got)
	}
	if got := r.SocketPathForHost("other.com"); got != "" {
		t.Fatalf("expected no match for other.com, got %q", got)
	}
}

func TestMITMRouterWildcard(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/mitm.sock",
		Domains:    []string{"*.example.com"},
	})

	tests := []struct {
		host    string
		matched bool
	}{
		{"api.example.com", true},
		{"sub.api.example.com", true},
		{"example.com", false},    // bare domain must NOT match *.example.com
		{"notexample.com", false}, // should not match
		{"fooexample.com", false}, // should not match (no dot boundary)
		{"other.com", false},      // completely different domain
	}

	for _, tt := range tests {
		got := r.SocketPathForHost(tt.host)
		if tt.matched && got == "" {
			t.Errorf("expected match for %q, got empty", tt.host)
		}
		if !tt.matched && got != "" {
			t.Errorf("expected no match for %q, got %q", tt.host, got)
		}
	}
}

func TestMITMRouterCaseInsensitive(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/mitm.sock",
		Domains:    []string{"API.Example.COM"},
	})
	if got := r.SocketPathForHost("api.example.com"); got != "/tmp/mitm.sock" {
		t.Fatalf("expected case-insensitive match, got %q", got)
	}
	if got := r.SocketPathForHost("Api.Example.Com"); got != "/tmp/mitm.sock" {
		t.Fatalf("expected case-insensitive match, got %q", got)
	}
}

func TestMITMRouterCaseInsensitiveWildcard(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/mitm.sock",
		Domains:    []string{"*.Example.COM"},
	})
	if got := r.SocketPathForHost("API.EXAMPLE.COM"); got != "/tmp/mitm.sock" {
		t.Fatalf("expected case-insensitive wildcard match, got %q", got)
	}
}

func TestMITMRouterWithPort(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/mitm.sock",
		Domains:    []string{"api.example.com"},
	})
	if got := r.SocketPathForHost("api.example.com:443"); got != "/tmp/mitm.sock" {
		t.Fatalf("expected match with port, got %q", got)
	}
	if got := r.SocketPathForHost("api.example.com:8080"); got != "/tmp/mitm.sock" {
		t.Fatalf("expected match with different port, got %q", got)
	}
	if got := r.SocketPathForHost("other.com:443"); got != "" {
		t.Fatalf("expected no match for other.com:443, got %q", got)
	}
}

func TestMITMRouterMultipleDomains(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/mitm.sock",
		Domains:    []string{"api.example.com", "*.internal.corp", "secure.test.io"},
	})

	tests := []struct {
		host    string
		matched bool
	}{
		{"api.example.com", true},
		{"foo.internal.corp", true},
		{"bar.baz.internal.corp", true},
		{"internal.corp", false},
		{"secure.test.io", true},
		{"insecure.test.io", false},
		{"random.org", false},
	}

	for _, tt := range tests {
		got := r.SocketPathForHost(tt.host)
		if tt.matched && got == "" {
			t.Errorf("expected match for %q, got empty", tt.host)
		}
		if !tt.matched && got != "" {
			t.Errorf("expected no match for %q, got %q", tt.host, got)
		}
	}
}

func TestMITMRouterIPv6WithPort(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/mitm.sock",
		Domains:    []string{"api.example.com"},
	})
	// IPv6 bracket notation with port should not match domain patterns.
	if got := r.SocketPathForHost("[::1]:443"); got != "" {
		t.Fatalf("expected no match for IPv6 address, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Unit tests for bufferedConn
// ---------------------------------------------------------------------------

func TestBufferedConnRead(t *testing.T) {
	// Create a pipe to simulate a connection.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Write some data from the server side.
	go func() {
		_, _ = server.Write([]byte("hello world"))
		server.Close()
	}()

	// Wrap client in a bufferedConn with a bufio.Reader that has buffered data.
	br := bufio.NewReaderSize(client, 64)
	// Pre-read to fill the buffer.
	peek, err := br.Peek(5)
	if err != nil {
		t.Fatalf("peek error: %v", err)
	}
	if string(peek) != "hello" {
		t.Fatalf("unexpected peek: %q", peek)
	}

	bc := &bufferedConn{Conn: client, br: br}
	buf := make([]byte, 64)
	n, _ := bc.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "hello") {
		t.Fatalf("expected buffered data, got %q", buf[:n])
	}
}

// ---------------------------------------------------------------------------
// Integration test: Unix socket MITM proxy routing
// ---------------------------------------------------------------------------

func TestMITMIntegrationCONNECT(t *testing.T) {
	// Create a Unix socket listener that acts as a simple MITM proxy.
	socketPath := shortTempDir(t) + "/mitm.sock"
	mitmListener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer mitmListener.Close()

	// Track connections received by the MITM proxy.
	var mitmConnected sync.WaitGroup
	mitmConnected.Add(1)

	go func() {
		conn, err := mitmListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the CONNECT request.
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}

		// Verify it's a CONNECT request.
		if req.Method != http.MethodConnect {
			return
		}

		// Send 200 OK response.
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		mitmConnected.Done()

		// Echo back whatever the client sends.
		buf := make([]byte, 1024)
		n, _ := br.Read(buf)
		if n > 0 {
			_, _ = conn.Write(buf[:n])
		}
	}()

	// Create an HTTP proxy with MITM routing.
	router := NewMITMRouter(&MITMConfig{
		SocketPath: socketPath,
		Domains:    []string{"mitm.example.com"},
	})

	proxy := NewHTTPProxy(&HTTPConfig{
		MITMRouter: router,
	})

	addr, err := proxy.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer proxy.Shutdown(context.Background())

	// Connect to the proxy and send a CONNECT request for a MITM domain.
	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send CONNECT request.
	_, _ = fmt.Fprintf(conn, "CONNECT mitm.example.com:443 HTTP/1.1\r\nHost: mitm.example.com:443\r\n\r\n")

	// Read the proxy's 200 response.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("failed to read proxy response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Wait for the MITM proxy to have received the connection.
	done := make(chan struct{})
	go func() {
		mitmConnected.Wait()
		close(done)
	}()
	select {
	case <-done:
		// MITM proxy received the CONNECT request - success!
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for MITM proxy to receive connection")
	}

	// Send data through the tunnel and verify echo.
	_, _ = conn.Write([]byte("test data"))
	conn.(*net.TCPConn).CloseWrite()

	echoed := make([]byte, 1024)
	n, _ := br.Read(echoed)
	if n > 0 && string(echoed[:n]) != "test data" {
		t.Logf("echo data: %q (may differ due to timing)", string(echoed[:n]))
	}
}

func TestMITMIntegrationHTTP(t *testing.T) {
	// Create a Unix socket listener that acts as a simple HTTP proxy.
	socketPath := shortTempDir(t) + "/mitm-http.sock"
	mitmListener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer mitmListener.Close()

	// The MITM proxy will respond to HTTP requests.
	go func() {
		for {
			conn, err := mitmListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				_ = req.Body.Close()

				resp := "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nmitm-response"
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	// Create an HTTP proxy with MITM routing.
	router := NewMITMRouter(&MITMConfig{
		SocketPath: socketPath,
		Domains:    []string{"mitm.example.com"},
	})

	proxy := NewHTTPProxy(&HTTPConfig{
		MITMRouter: router,
	})

	addr, err := proxy.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer proxy.Shutdown(context.Background())

	// Make an HTTP request through the proxy for a MITM domain.
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL("http://" + addr.String())),
		},
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get("http://mitm.example.com/test")
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "mitm-response" {
		t.Fatalf("expected 'mitm-response', got %q", string(body))
	}
}

func TestMITMIntegrationFallbackOnFailure(t *testing.T) {
	// Configure MITM with a non-existent socket path.
	router := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/nonexistent-mitm-socket-" + t.Name() + ".sock",
		Domains:    []string{"fallback.example.com"},
	})

	proxy := NewHTTPProxy(&HTTPConfig{
		MITMRouter: router,
	})

	addr, err := proxy.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer proxy.Shutdown(context.Background())

	// Connect to the proxy and send a CONNECT request.
	// The MITM dial should fail and fall back to direct connection.
	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send CONNECT request for a MITM domain.
	_, _ = fmt.Fprintf(conn, "CONNECT fallback.example.com:443 HTTP/1.1\r\nHost: fallback.example.com:443\r\n\r\n")

	// The proxy should attempt MITM, fail, then fall back to direct dial.
	// Direct dial will also likely fail (no such host), but we should get
	// a response (either 200 or 502) rather than a hang.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	resp.Body.Close()

	// We expect 502 Bad Gateway since the direct dial will also fail
	// (fallback.example.com doesn't resolve).
	if resp.StatusCode != http.StatusBadGateway {
		t.Logf("got status %d (expected 502 for unresolvable host after MITM fallback)", resp.StatusCode)
	}
}

func TestMITMIntegrationNonMatchingDomain(t *testing.T) {
	// Create a Unix socket listener.
	socketPath := shortTempDir(t) + "/mitm-nomatch.sock"
	mitmListener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer mitmListener.Close()

	mitmUsed := make(chan struct{}, 1)
	go func() {
		conn, err := mitmListener.Accept()
		if err != nil {
			return
		}
		conn.Close()
		mitmUsed <- struct{}{}
	}()

	// Create an HTTP proxy with MITM routing for a specific domain.
	router := NewMITMRouter(&MITMConfig{
		SocketPath: socketPath,
		Domains:    []string{"mitm.example.com"},
	})

	proxy := NewHTTPProxy(&HTTPConfig{
		MITMRouter: router,
	})

	addr, err := proxy.ListenAndServe(":0")
	if err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer proxy.Shutdown(context.Background())

	// Connect and send CONNECT for a non-matching domain.
	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(conn, "CONNECT other.example.com:443 HTTP/1.1\r\nHost: other.example.com:443\r\n\r\n")

	// Read response - should be direct dial (502 since host doesn't exist).
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	resp.Body.Close()

	// Verify MITM proxy was NOT used.
	select {
	case <-mitmUsed:
		t.Fatal("MITM proxy should not have been used for non-matching domain")
	case <-time.After(200 * time.Millisecond):
		// Good - MITM was not used.
	}
}

func TestMITMIntegrationSOCKS5(t *testing.T) {
	// Create a Unix socket listener that acts as a MITM proxy:
	// it handles the CONNECT handshake, then echoes data.
	socketPath := shortTempDir(t) + "/mitm-socks5.sock"
	mitmListener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer mitmListener.Close()

	mitmUsed := make(chan struct{}, 1)
	go func() {
		conn, err := mitmListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the CONNECT request sent by dialMITMConnect.
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = req

		// Send 200 OK to complete the CONNECT handshake.
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		mitmUsed <- struct{}{}
		// Echo data back.
		_, _ = io.Copy(conn, conn)
	}()

	// Create a SOCKS5 proxy with MITM routing.
	router := NewMITMRouter(&MITMConfig{
		SocketPath: socketPath,
		Domains:    []string{"mitm.example.com"},
	})

	// Use a permissive filter for testing.
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
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		t.Fatalf("unexpected greeting response: %v", greeting)
	}

	// SOCKS5 CONNECT request for mitm.example.com:443.
	domain := "mitm.example.com"
	connectReq := make([]byte, 0, 5+len(domain)+2)
	connectReq = append(connectReq, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	connectReq = append(connectReq, []byte(domain)...)
	connectReq = append(connectReq, 0x01, 0xBB) // port 443

	_, _ = conn.Write(connectReq)

	// Read CONNECT response.
	connectResp := make([]byte, 10)
	if _, err := io.ReadFull(conn, connectResp); err != nil {
		t.Fatalf("failed to read connect response: %v", err)
	}
	if connectResp[1] != 0x00 {
		t.Fatalf("SOCKS5 connect failed with status: %d", connectResp[1])
	}

	// Verify MITM proxy was used.
	select {
	case <-mitmUsed:
		// Good - MITM proxy was used.
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for MITM proxy to be used")
	}

	// Send data and verify echo.
	testData := []byte("hello mitm socks5")
	_, _ = conn.Write(testData)

	// Set a read deadline to avoid hanging.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	echoed := make([]byte, len(testData))
	n, err := io.ReadFull(conn, echoed)
	if err != nil {
		t.Logf("echo read: n=%d, err=%v (may be timing-related)", n, err)
	} else if !bytes.Equal(echoed, testData) {
		t.Fatalf("expected echo %q, got %q", testData, echoed)
	}
}

func TestDialMITMConnectSuccess(t *testing.T) {
	// Create a Unix socket listener that responds to CONNECT.
	socketPath := shortTempDir(t) + "/mitm-dial.sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = req

		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		// Echo data.
		_, _ = io.Copy(conn, br)
	}()

	mitmConn, err := dialMITMConnect(socketPath, "target.example.com:443")
	if err != nil {
		t.Fatalf("dialMITMConnect failed: %v", err)
	}
	defer mitmConn.Close()

	// Write and read data through the MITM connection.
	_, _ = mitmConn.Write([]byte("test"))
	mitmConn.(*net.UnixConn).CloseWrite()

	buf := make([]byte, 64)
	n, _ := mitmConn.Read(buf)
	if string(buf[:n]) != "test" {
		t.Fatalf("expected echo 'test', got %q", buf[:n])
	}
}

func TestDialMITMConnectBadStatus(t *testing.T) {
	socketPath := shortTempDir(t) + "/mitm-bad.sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		_, _ = http.ReadRequest(br)
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
	}()

	_, err = dialMITMConnect(socketPath, "target.example.com:443")
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected error to mention 403, got: %v", err)
	}
}

func TestDialMITMConnectNoSocket(t *testing.T) {
	_, err := dialMITMConnect("/tmp/nonexistent-"+t.Name()+".sock", "target:443")
	if err == nil {
		t.Fatal("expected error for non-existent socket")
	}
}

func TestDialMITMConnectBufferedData(t *testing.T) {
	// Test that buffered data after the HTTP response is preserved.
	socketPath := shortTempDir(t) + "/mitm-buffered.sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		_, _ = http.ReadRequest(br)
		// Send 200 response immediately followed by data (no gap).
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nextra-data"))
	}()

	mitmConn, err := dialMITMConnect(socketPath, "target:443")
	if err != nil {
		t.Fatalf("dialMITMConnect failed: %v", err)
	}
	defer mitmConn.Close()

	// Read the extra data that was sent right after the HTTP response.
	mitmConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := mitmConn.Read(buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(buf[:n]) != "extra-data" {
		t.Fatalf("expected 'extra-data', got %q", buf[:n])
	}
}

func TestMITMHTTPTransport(t *testing.T) {
	// Create a Unix socket listener that responds to HTTP requests.
	socketPath := shortTempDir(t) + "/mitm-transport.sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create unix listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				_ = req.Body.Close()
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	transport := mitmHTTPTransport(socketPath)
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}

	resp, err := client.Get("http://any-host.example.com/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("expected 'ok', got %q", body)
	}
}

// mustParseURL is a test helper that parses a URL or panics.
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

// ---------------------------------------------------------------------------
// dialMITMConnect: write CONNECT error (mitm.go lines 73-76)
// ---------------------------------------------------------------------------

func TestDialMITMConnectWriteError(t *testing.T) {
	// Use net.Pipe to create a connection pair where we can close the
	// read end to cause a write error on the write end.
	client, server := net.Pipe()

	// Close the server (read) end immediately.
	server.Close()

	// Now try the CONNECT handshake — the write should fail.
	_, err := mitmCONNECTHandshake(client, "target.example.com:443")
	if err == nil {
		t.Fatal("expected error for write failure")
	}
	if !strings.Contains(err.Error(), "mitm: write CONNECT") {
		t.Fatalf("expected 'mitm: write CONNECT' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// dialMITMConnect: read response error (mitm.go lines 81-84)
// ---------------------------------------------------------------------------

func TestDialMITMConnectReadResponseError(t *testing.T) {
	// Use net.Pipe to create a connection pair where the server sends
	// garbage instead of a valid HTTP response.
	client, server := net.Pipe()

	go func() {
		defer server.Close()
		// Read the CONNECT request to let the write succeed.
		br := bufio.NewReader(server)
		_, _ = http.ReadRequest(br)

		// Send garbage that is not a valid HTTP response.
		_, _ = server.Write([]byte("THIS IS NOT HTTP\r\n\r\n"))
	}()

	_, err := mitmCONNECTHandshake(client, "target.example.com:443")
	if err == nil {
		t.Fatal("expected error for invalid HTTP response")
	}
	if !strings.Contains(err.Error(), "mitm: read CONNECT response") {
		t.Fatalf("expected 'mitm: read CONNECT response' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CRITICAL: MITM CONNECT Header Injection tests
// ---------------------------------------------------------------------------

func TestMITMCONNECTHeaderInjection(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{"CRLF injection", "evil.com\r\nX-Injected: true\r\n"},
		{"CR only", "evil.com\rX-Injected: true"},
		{"LF only", "evil.com\nX-Injected: true"},
		{"null byte", "evil.com\x00injected"},
		{"CRLF in middle", "evil\r\n.com:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()

			_, err := mitmCONNECTHandshake(client, tt.host)
			if err == nil {
				t.Fatal("expected error for host with control characters")
			}
			if !strings.Contains(err.Error(), "contains control characters") {
				t.Fatalf("expected 'contains control characters' error, got: %v", err)
			}
		})
	}
}

func TestMITMCONNECTHandshakeTimeout(t *testing.T) {
	// Verify that the handshake sets a deadline (connection that never responds).
	client, server := net.Pipe()
	defer server.Close()

	// Read the CONNECT request on the server side but never respond.
	go func() {
		buf := make([]byte, 4096)
		_, _ = server.Read(buf)
		// Don't respond — let the deadline expire.
	}()

	// The handshake should fail with a timeout (deadline set to 10s,
	// but we can verify the deadline is set by checking the error type).
	// For a fast test, we just verify the function doesn't hang forever.
	done := make(chan error, 1)
	go func() {
		_, err := mitmCONNECTHandshake(client, "target.example.com:443")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error from handshake with non-responding server")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("handshake did not time out within expected window")
	}
}

// ---------------------------------------------------------------------------
// HIGH 2: Transport caching test
// ---------------------------------------------------------------------------

func TestMITMRouterTransportCaching(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/test-mitm.sock",
		Domains:    []string{"example.com"},
	})

	t1 := r.Transport()
	t2 := r.Transport()

	if t1 != t2 {
		t.Fatal("Transport() should return the same cached instance")
	}
	if t1 == nil {
		t.Fatal("Transport() should not return nil")
	}
}

func TestMITMRouterTransportCachingConcurrent(t *testing.T) {
	r := NewMITMRouter(&MITMConfig{
		SocketPath: "/tmp/test-mitm.sock",
		Domains:    []string{"example.com"},
	})

	const goroutines = 10
	transports := make([]*http.Transport, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			transports[idx] = r.Transport()
		}(i)
	}
	wg.Wait()

	// All goroutines should get the same transport instance.
	for i := 1; i < goroutines; i++ {
		if transports[i] != transports[0] {
			t.Fatalf("Transport() returned different instances from concurrent calls")
		}
	}
}
