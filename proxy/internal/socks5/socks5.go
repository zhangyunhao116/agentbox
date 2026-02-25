// Package socks5 implements a minimal SOCKS5 proxy server supporting only
// the CONNECT command with no-auth. It exposes only the subset of the SOCKS5
// protocol that agentbox requires.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// SOCKS5 protocol constants.
const (
	socks5Version        = uint8(5)
	noAuth               = uint8(0)
	noAcceptable         = uint8(0xFF)
	connectCommand       = uint8(1)
	ipv4Address          = uint8(1)
	fqdnAddress          = uint8(3)
	ipv6Address          = uint8(4)
	successReply         = uint8(0)
	serverFailure        = uint8(1)
	ruleFailure          = uint8(2)
	commandNotSupported  = uint8(7)
	addrTypeNotSupported = uint8(8)
)

// AddrSpec holds the destination address from a SOCKS5 request.
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

// String returns a human-readable representation of the address.
func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s:%d", a.FQDN, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns the address suitable for dialing (host:port).
// For IPv6 addresses, the IP is enclosed in brackets.
func (a *AddrSpec) Address() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s:%d", a.FQDN, a.Port)
	}
	if a.IP.To4() != nil {
		return fmt.Sprintf("%s:%d", a.IP, a.Port)
	}
	// IPv6: must use brackets for net.Dial compatibility.
	return fmt.Sprintf("[%s]:%d", a.IP, a.Port)
}

// Request represents a parsed SOCKS5 client request.
type Request struct {
	Version  uint8
	Command  uint8
	DestAddr *AddrSpec
}

// RuleSet controls access to the SOCKS5 proxy.
type RuleSet interface {
	Allow(ctx context.Context, req *Request) (context.Context, bool)
}

// NameResolver resolves domain names to IP addresses.
type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// Config for the SOCKS5 server.
type Config struct {
	Rules    RuleSet
	Resolver NameResolver
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	Logger   *log.Logger
}

// Server is a minimal SOCKS5 proxy server supporting only CONNECT.
type Server struct {
	config *Config
}

// New creates a new SOCKS5 server with the given configuration.
// If conf is nil, a default configuration is used. Nil fields in the
// config are replaced with sensible defaults: PermitAll rules, a DNS
// resolver, and a standard net.Dialer.
func New(conf *Config) (*Server, error) {
	if conf == nil {
		conf = &Config{}
	}
	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}
	if conf.Resolver == nil {
		conf.Resolver = &DNSResolver{}
	}
	if conf.Dial == nil {
		var d net.Dialer
		conf.Dial = d.DialContext
	}
	if conf.Logger == nil {
		conf.Logger = log.Default()
	}
	return &Server{config: conf}, nil
}

// Serve accepts connections on the listener and handles each one in a
// new goroutine. It returns nil when the listener is closed.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			// Closed listener is a normal shutdown signal.
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			_ = s.ServeConn(conn)
		}()
	}
}

// ServeConn handles a single SOCKS5 connection from greeting through
// proxying. The connection is always closed before returning.
func (s *Server) ServeConn(conn net.Conn) error {
	defer conn.Close() //nolint:errcheck // best-effort close

	// 1. Read client greeting.
	version, err := readByte(conn)
	if err != nil {
		return fmt.Errorf("failed to read version: %w", err)
	}
	if version != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	nMethods, err := readByte(conn)
	if err != nil {
		return fmt.Errorf("failed to read nMethods: %w", err)
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("failed to read methods: %w", err)
	}

	// We only support NoAuth (0x00). Check if client offers it.
	hasNoAuth := false
	for _, m := range methods {
		if m == noAuth {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		_, _ = conn.Write([]byte{socks5Version, noAcceptable})
		return errors.New("no acceptable auth method")
	}

	// Send greeting response: NoAuth selected.
	if _, err := conn.Write([]byte{socks5Version, noAuth}); err != nil {
		return fmt.Errorf("failed to send greeting: %w", err)
	}

	// 2. Read client request.
	req, err := readRequest(conn)
	if err != nil {
		_ = sendReply(conn, serverFailure)
		return fmt.Errorf("failed to read request: %w", err)
	}

	// 3. Only CONNECT is supported.
	if req.Command != connectCommand {
		_ = sendReply(conn, commandNotSupported)
		return fmt.Errorf("unsupported command: %d", req.Command)
	}

	// 4. Handle CONNECT.
	return s.handleConnect(conn, req)
}

// handleConnect processes a CONNECT request: resolves the destination,
// checks rules, dials the target, and proxies data bidirectionally.
func (s *Server) handleConnect(conn net.Conn, req *Request) error {
	ctx := context.Background()

	// Resolve FQDN if present. We keep the original FQDN in req.DestAddr
	// so that rule checks can filter by domain name. A separate dialAddr
	// is used for the outbound connection to avoid DNS rebinding.
	dest := req.DestAddr
	dialAddr := dest.Address()
	if dest.FQDN != "" {
		rCtx, ip, err := s.config.Resolver.Resolve(ctx, dest.FQDN)
		if err != nil {
			_ = sendReply(conn, serverFailure)
			return fmt.Errorf("failed to resolve %q: %w", dest.FQDN, err)
		}
		ctx = rCtx
		dest.IP = ip
		// Build dial address from resolved IP (not FQDN) to prevent rebinding.
		dialAddr = (&AddrSpec{IP: ip, Port: dest.Port}).Address()
	}

	// Check rules (req.DestAddr still has the original FQDN for domain filtering).
	rCtx, ok := s.config.Rules.Allow(ctx, req)
	if !ok {
		_ = sendReply(conn, ruleFailure)
		return errors.New("connection denied by rules")
	}
	ctx = rCtx

	// Dial target using the resolved address.
	target, err := s.config.Dial(ctx, "tcp", dialAddr)
	if err != nil {
		_ = sendReply(conn, serverFailure)
		return fmt.Errorf("failed to dial %s: %w", dest.Address(), err)
	}
	defer target.Close() //nolint:errcheck // best-effort close

	// Send success reply (bind addr 0.0.0.0:0).
	if _, err := conn.Write([]byte{
		socks5Version, successReply, 0x00, ipv4Address,
		0, 0, 0, 0, // bind IP
		0, 0, // bind port
	}); err != nil {
		return fmt.Errorf("failed to send success reply: %w", err)
	}

	// Bidirectional proxy. Wait for both directions to finish, using
	// half-close to signal EOF to the opposite side.
	s.proxy(conn, target)
	return nil
}

// proxy copies data bidirectionally between conn and target. After each
// direction finishes, it performs a half-close on the destination side
// (if supported) so the remote peer sees EOF without tearing down the
// full connection.
func (s *Server) proxy(conn, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	halfClose := func(c net.Conn) {
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, conn)
		halfClose(target)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, target)
		halfClose(conn)
	}()
	wg.Wait()
}

// readRequest parses a SOCKS5 request from the connection.
//
//nolint:gosec // G602 false positive: header is a fixed [4]byte array, indices are always valid.
func readRequest(conn io.Reader) (*Request, error) {
	// Header: version, command, reserved, addrType
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, fmt.Errorf("failed to read request header: %w", err)
	}

	if header[0] != socks5Version {
		return nil, fmt.Errorf("unsupported version in request: %d", header[0])
	}

	req := &Request{
		Version: header[0],
		Command: header[1],
	}

	addrType := header[3]
	addr := &AddrSpec{}

	switch addrType {
	case ipv4Address:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return nil, fmt.Errorf("failed to read IPv4 address: %w", err)
		}
		addr.IP = net.IP(ip)

	case fqdnAddress:
		fqdnLen, err := readByte(conn)
		if err != nil {
			return nil, fmt.Errorf("failed to read FQDN length: %w", err)
		}
		fqdn := make([]byte, fqdnLen)
		if _, err := io.ReadFull(conn, fqdn); err != nil {
			return nil, fmt.Errorf("failed to read FQDN: %w", err)
		}
		addr.FQDN = string(fqdn)

	case ipv6Address:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return nil, fmt.Errorf("failed to read IPv6 address: %w", err)
		}
		addr.IP = net.IP(ip)

	default:
		return nil, fmt.Errorf("unsupported address type: %d", addrType)
	}

	// Read port (2 bytes, big-endian).
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, fmt.Errorf("failed to read port: %w", err)
	}
	addr.Port = int(binary.BigEndian.Uint16(portBuf))

	req.DestAddr = addr
	return req, nil
}

// sendReply writes a minimal SOCKS5 reply with the given status code.
func sendReply(conn io.Writer, status uint8) error {
	// [version, status, reserved, addrType=IPv4, 0.0.0.0, port=0]
	_, err := conn.Write([]byte{
		socks5Version, status, 0x00, ipv4Address,
		0, 0, 0, 0,
		0, 0,
	})
	return err
}

// readByte reads a single byte from the reader.
func readByte(r io.Reader) (uint8, error) {
	buf := []byte{0}
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	return buf[0], nil
}

// DNSResolver implements NameResolver using the system DNS resolver.
type DNSResolver struct{}

// Resolve resolves the given domain name to an IP address using
// net.ResolveIPAddr.
func (d *DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, addr.IP, nil
}

// permitAllRuleSet is a RuleSet that allows all requests.
type permitAllRuleSet struct{}

func (p *permitAllRuleSet) Allow(ctx context.Context, _ *Request) (context.Context, bool) {
	return ctx, true
}

// PermitAll returns a RuleSet that allows every request.
func PermitAll() RuleSet {
	return &permitAllRuleSet{}
}
