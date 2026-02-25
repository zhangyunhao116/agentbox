package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// buildGreeting builds a SOCKS5 client greeting message.
func buildGreeting(version uint8, methods ...uint8) []byte {
	buf := make([]byte, 0, 2+len(methods))
	buf = append(buf, version, uint8(len(methods)))
	buf = append(buf, methods...)
	return buf
}

// buildRequest builds a SOCKS5 CONNECT request with the given address type.
func buildRequest(cmd, addrType uint8, addr []byte, port uint16) []byte {
	buf := make([]byte, 0, 4+len(addr)+2)
	buf = append(buf, socks5Version, cmd, 0x00, addrType)
	buf = append(buf, addr...)
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, port)
	buf = append(buf, p...)
	return buf
}

// buildIPv4Request builds a full SOCKS5 handshake (greeting + CONNECT to IPv4).
func buildIPv4Request(ip net.IP, port uint16) []byte {
	greeting := buildGreeting(socks5Version, noAuth)
	req := buildRequest(connectCommand, ipv4Address, ip.To4(), port)
	buf := make([]byte, 0, len(greeting)+len(req))
	buf = append(buf, greeting...)
	buf = append(buf, req...)
	return buf
}

// denyAllRuleSet denies every request.
type denyAllRuleSet struct{}

func (d *denyAllRuleSet) Allow(ctx context.Context, _ *Request) (context.Context, bool) {
	return ctx, false
}

// failResolver always returns an error.
type failResolver struct{}

func (f *failResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, nil, errors.New("resolve failed")
}

// staticResolver resolves every name to a fixed IP.
type staticResolver struct{ ip net.IP }

func (s *staticResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, s.ip, nil
}

// failDialer always returns an error when dialing.
func failDialer(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, errors.New("dial failed")
}

// echoServer accepts one connection, echoes data back, then closes.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	return ln
}

// ---------------------------------------------------------------------------
// Tests: New()
// ---------------------------------------------------------------------------

func TestNew_NilConfig(t *testing.T) {
	s, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil) error: %v", err)
	}
	if s == nil {
		t.Fatal("New(nil) returned nil server")
	}
}

func TestNew_DefaultConfig(t *testing.T) {
	s, err := New(&Config{})
	if err != nil {
		t.Fatalf("New(&Config{}) error: %v", err)
	}
	if s == nil {
		t.Fatal("New(&Config{}) returned nil server")
	}
}

func TestNew_CustomConfig(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	s, err := New(&Config{
		Rules:    PermitAll(),
		Resolver: &DNSResolver{},
		Dial:     failDialer,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("New(custom) error: %v", err)
	}
	if s == nil {
		t.Fatal("New(custom) returned nil server")
	}
}

// ---------------------------------------------------------------------------
// Tests: DNSResolver
// ---------------------------------------------------------------------------

func TestDNSResolver_ValidDomain(t *testing.T) {
	r := &DNSResolver{}
	ctx, ip, err := r.Resolve(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("Resolve(localhost) error: %v", err)
	}
	if ip == nil {
		t.Fatal("Resolve(localhost) returned nil IP")
	}
	if ctx == nil {
		t.Fatal("Resolve(localhost) returned nil context")
	}
}

func TestDNSResolver_InvalidDomain(t *testing.T) {
	r := &DNSResolver{}
	_, _, err := r.Resolve(context.Background(), "this.domain.does.not.exist.invalid.")
	if err == nil {
		t.Fatal("Resolve(invalid) expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: PermitAll
// ---------------------------------------------------------------------------

func TestPermitAll(t *testing.T) {
	rs := PermitAll()
	ctx, ok := rs.Allow(context.Background(), &Request{})
	if !ok {
		t.Fatal("PermitAll should allow")
	}
	if ctx == nil {
		t.Fatal("PermitAll returned nil context")
	}
}

// ---------------------------------------------------------------------------
// Tests: AddrSpec
// ---------------------------------------------------------------------------

func TestAddrSpec_StringFQDN(t *testing.T) {
	a := &AddrSpec{FQDN: "example.com", Port: 443}
	if got := a.String(); got != "example.com:443" {
		t.Fatalf("String() = %q, want %q", got, "example.com:443")
	}
}

func TestAddrSpec_StringIP(t *testing.T) {
	a := &AddrSpec{IP: net.ParseIP("1.2.3.4"), Port: 80}
	if got := a.String(); got != "1.2.3.4:80" {
		t.Fatalf("String() = %q, want %q", got, "1.2.3.4:80")
	}
}

func TestAddrSpec_Address(t *testing.T) {
	a := &AddrSpec{FQDN: "example.com", Port: 8080}
	if got := a.Address(); got != "example.com:8080" {
		t.Fatalf("Address() = %q, want %q", got, "example.com:8080")
	}
}

func TestAddrSpec_StringIPv6(t *testing.T) {
	a := &AddrSpec{IP: net.ParseIP("::1"), Port: 443}
	if got := a.String(); got != "::1:443" {
		t.Fatalf("String() = %q, want %q", got, "::1:443")
	}
	if got := a.Address(); got != "[::1]:443" {
		t.Fatalf("Address() = %q, want %q", got, "[::1]:443")
	}
}

// ---------------------------------------------------------------------------
// Tests: ServeConn — valid CONNECT
// ---------------------------------------------------------------------------

func TestServeConn_ValidConnect(t *testing.T) {
	echo := echoServer(t)
	defer echo.Close()

	addr := echo.Addr().(*net.TCPAddr)

	s, _ := New(&Config{
		Logger: log.New(io.Discard, "", 0),
	})

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send greeting.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response (2 bytes).
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting response: %v", err)
	}
	if greetResp[0] != socks5Version || greetResp[1] != noAuth {
		t.Fatalf("unexpected greeting response: %v", greetResp)
	}

	// Send CONNECT request.
	reqBytes := buildRequest(connectCommand, ipv4Address, addr.IP.To4(), uint16(addr.Port))
	if _, err := client.Write(reqBytes); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read connect response (10 bytes).
	connResp := make([]byte, 10)
	if _, err := io.ReadFull(client, connResp); err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if connResp[1] != successReply {
		t.Fatalf("expected success reply, got %d", connResp[1])
	}

	// Send data through the proxy and verify echo.
	payload := []byte("hello socks5")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(client, echoed); err != nil {
		t.Fatalf("read echoed data: %v", err)
	}
	if !bytes.Equal(payload, echoed) {
		t.Fatalf("echoed data mismatch: got %q, want %q", echoed, payload)
	}

	client.Close()
	<-done
}

// ---------------------------------------------------------------------------
// Tests: ServeConn — invalid version
// ---------------------------------------------------------------------------

func TestServeConn_InvalidVersion(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send version 4 greeting. The write may partially succeed or fail
	// because the server closes the connection after reading the version byte.
	_, _ = client.Write(buildGreeting(4, noAuth))

	err := <-done
	if err == nil || !strings.Contains(err.Error(), "unsupported SOCKS version") {
		t.Fatalf("expected unsupported version error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: ServeConn — unsupported command (BIND=2)
// ---------------------------------------------------------------------------

func TestServeConn_UnsupportedCommand(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send greeting.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send BIND request (command=2).
	reqBytes := buildRequest(2, ipv4Address, net.IPv4(1, 2, 3, 4).To4(), 80)
	if _, err := client.Write(reqBytes); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read error reply.
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != commandNotSupported {
		t.Fatalf("expected commandNotSupported (%d), got %d", commandNotSupported, reply[1])
	}

	err := <-done
	if err == nil || !strings.Contains(err.Error(), "unsupported command") {
		t.Fatalf("expected unsupported command error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: ServeConn — unsupported address type
// ---------------------------------------------------------------------------

func TestServeConn_UnsupportedAddrType(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send greeting.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send request header with unsupported address type 0x05.
	// Only send the 4-byte header so readRequest fails immediately at the
	// switch default case, without leftover unread bytes in the pipe.
	_, _ = client.Write([]byte{socks5Version, connectCommand, 0x00, 0x05})

	// [M3] Verify that a failure reply is sent back to the client.
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != serverFailure {
		t.Fatalf("expected serverFailure (%d), got %d", serverFailure, reply[1])
	}

	err := <-done
	if err == nil || !strings.Contains(err.Error(), "unsupported address type") {
		t.Fatalf("expected unsupported address type error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: ServeConn — FQDN address type
// ---------------------------------------------------------------------------

func TestServeConn_FQDNAddress(t *testing.T) {
	echo := echoServer(t)
	defer echo.Close()

	addr := echo.Addr().(*net.TCPAddr)

	s, _ := New(&Config{
		Resolver: &staticResolver{ip: addr.IP},
		Logger:   log.New(io.Discard, "", 0),
	})

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send greeting.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send FQDN CONNECT request.
	fqdn := "example.com"
	fqdnBytes := []byte(fqdn)
	addrData := append([]byte{uint8(len(fqdnBytes))}, fqdnBytes...)
	reqBytes := buildRequest(connectCommand, fqdnAddress, addrData, uint16(addr.Port))
	if _, err := client.Write(reqBytes); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read connect response.
	connResp := make([]byte, 10)
	if _, err := io.ReadFull(client, connResp); err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if connResp[1] != successReply {
		t.Fatalf("expected success, got %d", connResp[1])
	}

	client.Close()
	<-done
}

// ---------------------------------------------------------------------------
// Tests: ServeConn — IPv6 address type
// ---------------------------------------------------------------------------

func TestServeConn_IPv6Address(t *testing.T) {
	// Listen on IPv6 loopback.
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available")
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	addr := ln.Addr().(*net.TCPAddr)

	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send greeting.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send IPv6 CONNECT request.
	ip6 := addr.IP.To16()
	reqBytes := buildRequest(connectCommand, ipv6Address, ip6, uint16(addr.Port))
	if _, err := client.Write(reqBytes); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read connect response.
	connResp := make([]byte, 10)
	if _, err := io.ReadFull(client, connResp); err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if connResp[1] != successReply {
		t.Fatalf("expected success, got %d", connResp[1])
	}

	client.Close()
	<-done
}

// ---------------------------------------------------------------------------
// Tests: ServeConn — rule denies connection
// ---------------------------------------------------------------------------

func TestServeConn_RuleDenied(t *testing.T) {
	s, _ := New(&Config{
		Rules:  &denyAllRuleSet{},
		Logger: log.New(io.Discard, "", 0),
	})

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send greeting.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send CONNECT request.
	reqBytes := buildRequest(connectCommand, ipv4Address, net.IPv4(1, 2, 3, 4).To4(), 80)
	if _, err := client.Write(reqBytes); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read error reply.
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != ruleFailure {
		t.Fatalf("expected ruleFailure (%d), got %d", ruleFailure, reply[1])
	}

	err := <-done
	if err == nil || !strings.Contains(err.Error(), "denied by rules") {
		t.Fatalf("expected denied error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: ServeConn — dial failure
// ---------------------------------------------------------------------------

func TestServeConn_DialFailure(t *testing.T) {
	s, _ := New(&Config{
		Dial:   failDialer,
		Logger: log.New(io.Discard, "", 0),
	})

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send greeting.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send CONNECT request.
	reqBytes := buildRequest(connectCommand, ipv4Address, net.IPv4(1, 2, 3, 4).To4(), 80)
	if _, err := client.Write(reqBytes); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read error reply.
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != serverFailure {
		t.Fatalf("expected serverFailure (%d), got %d", serverFailure, reply[1])
	}

	err := <-done
	if err == nil || !strings.Contains(err.Error(), "failed to dial") {
		t.Fatalf("expected dial failure error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: ServeConn — resolver failure
// ---------------------------------------------------------------------------

func TestServeConn_ResolverFailure(t *testing.T) {
	s, _ := New(&Config{
		Resolver: &failResolver{},
		Logger:   log.New(io.Discard, "", 0),
	})

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send greeting.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send FQDN CONNECT request.
	fqdn := "fail.example.com"
	fqdnBytes := []byte(fqdn)
	addrData := append([]byte{uint8(len(fqdnBytes))}, fqdnBytes...)
	reqBytes := buildRequest(connectCommand, fqdnAddress, addrData, 80)
	if _, err := client.Write(reqBytes); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read error reply.
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != serverFailure {
		t.Fatalf("expected serverFailure (%d), got %d", serverFailure, reply[1])
	}

	err := <-done
	if err == nil || !strings.Contains(err.Error(), "failed to resolve") {
		t.Fatalf("expected resolve failure error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: Serve — accepts connections
// ---------------------------------------------------------------------------

func TestServe_AcceptsConnections(t *testing.T) {
	echo := echoServer(t)
	defer echo.Close()

	addr := echo.Addr().(*net.TCPAddr)

	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		_ = s.Serve(ln)
	}()

	// Connect to the SOCKS5 server.
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	defer conn.Close()

	// Send greeting + CONNECT.
	req := buildIPv4Request(addr.IP.To4(), uint16(addr.Port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Read connect response.
	connResp := make([]byte, 10)
	if _, err := io.ReadFull(conn, connResp); err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if connResp[1] != successReply {
		t.Fatalf("expected success, got %d", connResp[1])
	}

	// Verify echo.
	payload := []byte("serve test")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(payload, echoed) {
		t.Fatalf("echo mismatch: got %q, want %q", echoed, payload)
	}

	ln.Close()
}

// ---------------------------------------------------------------------------
// Tests: Serve — listener closed returns nil
// ---------------------------------------------------------------------------

func TestServe_ListenerClosed(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- s.Serve(ln)
	}()

	// Close the listener immediately.
	ln.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error on closed listener: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after listener close")
	}
}

// ---------------------------------------------------------------------------
// Tests: Short reads / malformed packets
// ---------------------------------------------------------------------------

func TestServeConn_ShortRead_VersionOnly(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send only version byte, then close.
	_, _ = client.Write([]byte{socks5Version})
	client.Close()

	err := <-done
	if err == nil {
		t.Fatal("expected error on short read")
	}
}

func TestServeConn_ShortRead_NoMethods(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send version + nMethods=2 but only 1 method byte, then close.
	_, _ = client.Write([]byte{socks5Version, 2, noAuth})
	client.Close()

	err := <-done
	if err == nil {
		t.Fatal("expected error on short methods read")
	}
}

func TestServeConn_ShortRead_RequestHeader(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send valid greeting, then only 2 bytes of request header, then close.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send partial request header and close.
	_, _ = client.Write([]byte{socks5Version, connectCommand})
	client.Close()

	err := <-done
	if err == nil {
		t.Fatal("expected error on short request header")
	}
}

func TestServeConn_ShortRead_IPv4Address(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Valid greeting + request header with IPv4 type but only 2 bytes of IP.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write: %v", err)
	}

	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Partial IPv4 request.
	_, _ = client.Write([]byte{socks5Version, connectCommand, 0x00, ipv4Address, 1, 2})
	client.Close()

	err := <-done
	if err == nil {
		t.Fatal("expected error on short IPv4 read")
	}
}

func TestServeConn_ShortRead_Port(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Valid greeting + full IPv4 address but only 1 byte of port.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write: %v", err)
	}

	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Full header + IPv4 + only 1 byte of port.
	_, _ = client.Write([]byte{socks5Version, connectCommand, 0x00, ipv4Address, 1, 2, 3, 4, 0})
	client.Close()

	err := <-done
	if err == nil {
		t.Fatal("expected error on short port read")
	}
}

func TestServeConn_EmptyRead(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Close immediately — no data.
	client.Close()

	err := <-done
	if err == nil {
		t.Fatal("expected error on empty read")
	}
}

// ---------------------------------------------------------------------------
// Tests: No acceptable auth method
// ---------------------------------------------------------------------------

func TestServeConn_NoAcceptableAuth(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send greeting with only UserPass method (0x02), no NoAuth.
	if _, err := client.Write(buildGreeting(socks5Version, 0x02)); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read rejection response.
	resp := make([]byte, 2)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp[1] != noAcceptable {
		t.Fatalf("expected noAcceptable (0xFF), got %d", resp[1])
	}

	err := <-done
	if err == nil || !strings.Contains(err.Error(), "no acceptable auth") {
		t.Fatalf("expected no acceptable auth error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: Short read on FQDN
// ---------------------------------------------------------------------------

func TestServeConn_ShortRead_FQDNLength(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write: %v", err)
	}

	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// FQDN type with length=10 but only 3 bytes of data, then close.
	_, _ = client.Write([]byte{socks5Version, connectCommand, 0x00, fqdnAddress, 10, 'a', 'b', 'c'})
	client.Close()

	err := <-done
	if err == nil {
		t.Fatal("expected error on short FQDN read")
	}
}

func TestServeConn_ShortRead_IPv6Address(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write: %v", err)
	}

	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// IPv6 type but only 4 bytes of address, then close.
	_, _ = client.Write([]byte{socks5Version, connectCommand, 0x00, ipv6Address, 0, 0, 0, 1})
	client.Close()

	err := <-done
	if err == nil {
		t.Fatal("expected error on short IPv6 read")
	}
}

// ---------------------------------------------------------------------------
// Tests: sendReply helper (via coverage of error paths)
// ---------------------------------------------------------------------------

func TestSendReply_WriterError(t *testing.T) {
	// sendReply now returns an error; verify it propagates.
	w := &failWriter{}
	err := sendReply(w, serverFailure)
	if err == nil {
		t.Fatal("expected error from sendReply on failing writer")
	}
}

type failWriter struct{}

func (f *failWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}

// ---------------------------------------------------------------------------
// Tests: readByte edge case
// ---------------------------------------------------------------------------

func TestReadByte_EOF(t *testing.T) {
	r := bytes.NewReader(nil)
	_, err := readByte(r)
	if err == nil {
		t.Fatal("expected error on empty reader")
	}
}

// ---------------------------------------------------------------------------
// Tests: greeting write failure
// ---------------------------------------------------------------------------

func TestServeConn_GreetingWriteFailure(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send valid greeting, then close immediately so the server's
	// greeting response write fails.
	_, _ = client.Write(buildGreeting(socks5Version, noAuth))
	client.Close()

	err := <-done
	if err == nil {
		t.Fatal("expected error on greeting write failure")
	}
}

// ---------------------------------------------------------------------------
// Tests: success reply write failure
// ---------------------------------------------------------------------------

func TestServeConn_SuccessReplyWriteFailure(t *testing.T) {
	echo := echoServer(t)
	defer echo.Close()

	addr := echo.Addr().(*net.TCPAddr)

	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})

	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send greeting.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send CONNECT request, then close immediately so the success reply write fails.
	reqBytes := buildRequest(connectCommand, ipv4Address, addr.IP.To4(), uint16(addr.Port))
	_, _ = client.Write(reqBytes)
	client.Close()

	err := <-done
	// The error could be about the success reply write or about reading the request
	// (depending on timing). Either way, it should be an error.
	if err == nil {
		t.Fatal("expected error on success reply write failure")
	}
}

// ---------------------------------------------------------------------------
// Tests: version mismatch in request header
// ---------------------------------------------------------------------------

func TestServeConn_VersionMismatchInRequest(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send valid greeting.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send only the 4-byte request header with wrong version (4 instead of 5).
	// readRequest reads exactly 4 bytes for the header, detects the version
	// mismatch, and returns an error. Sending only 4 bytes avoids a deadlock
	// on the synchronous net.Pipe.
	_, _ = client.Write([]byte{4, connectCommand, 0x00, ipv4Address})

	// Read the failure reply sent by ServeConn after readRequest fails.
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != serverFailure {
		t.Fatalf("expected serverFailure (%d), got %d", serverFailure, reply[1])
	}

	err := <-done
	if err == nil || !strings.Contains(err.Error(), "unsupported version in request") {
		t.Fatalf("expected version mismatch error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: FQDN length read failure
// ---------------------------------------------------------------------------

func TestServeConn_ShortRead_FQDNLengthByte(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})
	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send valid greeting.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send request header with FQDN type but no length byte, then close.
	_, _ = client.Write([]byte{socks5Version, connectCommand, 0x00, fqdnAddress})
	client.Close()

	err := <-done
	if err == nil {
		t.Fatal("expected error on FQDN length byte read failure")
	}
}

// ---------------------------------------------------------------------------
// Tests: Serve — non-closed accept error is returned [M2]
// ---------------------------------------------------------------------------

// errorListener is a net.Listener that returns a custom error on Accept.
type errorListener struct {
	err error
}

func (e *errorListener) Accept() (net.Conn, error) { return nil, e.err }
func (e *errorListener) Close() error              { return nil }
func (e *errorListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestServe_AcceptErrorReturned(t *testing.T) {
	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})

	acceptErr := errors.New("temporary accept failure")
	ln := &errorListener{err: acceptErr}

	err := s.Serve(ln)
	if err == nil {
		t.Fatal("expected error from Serve on non-closed accept error")
	}
	if !strings.Contains(err.Error(), "temporary accept failure") {
		t.Fatalf("expected accept error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: Half-close proxy behavior [H1]
// ---------------------------------------------------------------------------

// halfCloseRecorder wraps a net.Conn and records whether CloseWrite was called.
type halfCloseRecorder struct {
	net.Conn
	closeWriteCalled bool
}

func (h *halfCloseRecorder) CloseWrite() error {
	h.closeWriteCalled = true
	return nil
}

func TestProxy_HalfClose(t *testing.T) {
	// Create two pairs of pipes to simulate the proxy connections.
	// "client" side: clientEnd <-> proxyClientSide
	// "target" side: proxyTargetSide <-> targetEnd
	clientEnd, proxyClientSide := net.Pipe()
	proxyTargetSide, targetEnd := net.Pipe()
	defer clientEnd.Close()
	defer targetEnd.Close()

	clientRec := &halfCloseRecorder{Conn: proxyClientSide}
	targetRec := &halfCloseRecorder{Conn: proxyTargetSide}

	s, _ := New(&Config{Logger: log.New(io.Discard, "", 0)})

	done := make(chan struct{})
	go func() {
		s.proxy(clientRec, targetRec)
		close(done)
	}()

	// Write from client side, then close to signal EOF.
	payload := []byte("hello from client")
	if _, err := clientEnd.Write(payload); err != nil {
		t.Fatalf("write to client end: %v", err)
	}
	clientEnd.Close()

	// Read from target side — should get the payload.
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(targetEnd, buf); err != nil {
		t.Fatalf("read from target end: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", buf, payload)
	}

	// Close target side to unblock the other direction.
	targetEnd.Close()

	// Wait for proxy to finish.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not finish in time")
	}

	// Verify CloseWrite was called on the target side (after client->target copy finished).
	if !targetRec.closeWriteCalled {
		t.Fatal("expected CloseWrite to be called on target connection")
	}
	// Verify CloseWrite was called on the client side (after target->client copy finished).
	if !clientRec.closeWriteCalled {
		t.Fatal("expected CloseWrite to be called on client connection")
	}
}

// ---------------------------------------------------------------------------
// Tests: FQDN resolution clears FQDN for dialing [M1]
// ---------------------------------------------------------------------------

func TestHandleConnect_FQDNResolvesToIP(t *testing.T) {
	echo := echoServer(t)
	defer echo.Close()

	addr := echo.Addr().(*net.TCPAddr)

	// Track what address was dialed.
	var dialedAddr string
	s, _ := New(&Config{
		Resolver: &staticResolver{ip: addr.IP},
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialedAddr = address
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		},
		Logger: log.New(io.Discard, "", 0),
	})

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send greeting.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send FQDN CONNECT request.
	fqdn := "example.com"
	fqdnBytes := []byte(fqdn)
	addrData := append([]byte{uint8(len(fqdnBytes))}, fqdnBytes...)
	reqBytes := buildRequest(connectCommand, fqdnAddress, addrData, uint16(addr.Port))
	if _, err := client.Write(reqBytes); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read connect response.
	connResp := make([]byte, 10)
	if _, err := io.ReadFull(client, connResp); err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if connResp[1] != successReply {
		t.Fatalf("expected success, got %d", connResp[1])
	}

	// Verify the dialed address uses the resolved IP, not the FQDN.
	if strings.Contains(dialedAddr, "example.com") {
		t.Fatalf("expected dial to use resolved IP, but got FQDN in address: %s", dialedAddr)
	}
	expectedAddr := fmt.Sprintf("%s:%d", addr.IP, addr.Port)
	if dialedAddr != expectedAddr {
		t.Fatalf("dialed address = %q, want %q", dialedAddr, expectedAddr)
	}

	client.Close()
	<-done
}

// ---------------------------------------------------------------------------
// Test: readRequest — IPv6 address type parsing (socks5.go:310-315)
// This test covers the IPv6 address parsing path without requiring
// actual IPv6 network support.
// ---------------------------------------------------------------------------

func TestServeConn_IPv6Address_NoIPv6Network(t *testing.T) {
	// Start a TCP echo server on IPv4 that we'll redirect IPv6 requests to.
	echoLn := echoServer(t)
	defer echoLn.Close()

	s, _ := New(&Config{
		Logger: log.New(io.Discard, "", 0),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Redirect all dials to the echo server regardless of address.
			return net.Dial("tcp", echoLn.Addr().String())
		},
	})

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- s.ServeConn(server)
	}()

	// Send greeting.
	if _, err := client.Write(buildGreeting(socks5Version, noAuth)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read greeting response.
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(client, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send IPv6 CONNECT request with ::1 address.
	ip6 := net.ParseIP("::1").To16()
	reqBytes := buildRequest(connectCommand, ipv6Address, ip6, 8080)
	if _, err := client.Write(reqBytes); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read connect response.
	connResp := make([]byte, 10)
	if _, err := io.ReadFull(client, connResp); err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if connResp[1] != successReply {
		t.Fatalf("expected success reply, got %d", connResp[1])
	}

	// Send data through the tunnel and verify echo.
	msg := []byte("ipv6 test data")
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("write data: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}

	client.Close()
	<-done
}
