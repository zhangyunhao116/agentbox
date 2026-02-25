# agentbox: Network Isolation Architecture & HTTP Proxy Implementation

> **Status**: Implemented  
> **Author**: Agent  
> **Date**: 2026-02-16  
> **Scope**: Network isolation architecture, HTTP proxy implementation

> Series: [03a](03a-network-architecture.md) | [03b](03b-socks-domain-env.md) | [03c](03c-bridge-fs.md) | [03d](03d-symlink-monitoring.md)

> **This file is part 1 of the 03-network-and-fs series**
> - 📄 Current: 03a — Network Isolation Architecture & HTTP Proxy Implementation
> - 📄 [03b-socks-domain-env.md](03b-socks-domain-env.md) — SOCKS5 Proxy, Domain Filtering & Environment Variable Injection
> - 📄 [03c-bridge-fs.md](03c-bridge-fs.md) — Linux Network Bridge & Filesystem Strategy
> - 📄 [03d-symlink-monitoring.md](03d-symlink-monitoring.md) — Symlink Protection & Violation Monitoring

---

## 1. Network Isolation Architecture

### 1.1 Overall Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Host Process                                   │
│                                                                             │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐          │
│  │   Manager     │───▶│  HTTP Proxy      │───▶│  Domain Filter   │          │
│  │              │    │  (:0 auto-port)  │    │  Engine          │          │
│  │  NewManager()│    └──────────────────┘    │                  │          │
│  │  Wrap()      │    ┌──────────────────┐    │  denied > allowed│          │
│  │  Cleanup()   │───▶│  SOCKS5 Proxy    │───▶│  > OnRequest     │          │
│  └──────────────┘    │  (:0 auto-port)  │    │  > deny          │          │
│                      └──────────────────┘    └──────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  Linux: Network Namespace (--unshare-net)                                   │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────┐          │
│  │  Unix Socket Bridge (Go goroutine, replaces socat)           │          │
│  │                                                              │          │
│  │  TCP :3128 ──▶ Unix Socket ──▶ Host HTTP Proxy              │          │
│  │  TCP :1080 ──▶ Unix Socket ──▶ Host SOCKS5 Proxy            │          │
│  └──────────────────────────────────────────────────────────────┘          │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────┐          │
│  │  Sandboxed Process                                           │          │
│  │  HTTP_PROXY=http://127.0.0.1:<httpPort>                      │          │
│  │  ALL_PROXY=socks5h://127.0.0.1:<socksPort>                  │          │
│  └──────────────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  macOS: Seatbelt (sandbox-exec)                                             │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────┐          │
│  │  SBPL: (deny default) (deny network*)                        │          │
│  │  Allow: localhost:* for proxy                                │          │
│  │  Allow: local UDP for DNS                                    │          │
│  └──────────────────────────────────────────────────────────────┘          │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────┐          │
│  │  Sandboxed Process                                           │          │
│  │  HTTP_PROXY=http://127.0.0.1:<httpPort>                      │          │
│  │  ALL_PROXY=socks5h://127.0.0.1:<socksPort>                  │          │
│  └──────────────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Why Dual Proxies (HTTP + SOCKS5)

| Protocol | HTTP Proxy | SOCKS5 Proxy | Notes |
|----------|-----------|-------------|-------|
| HTTP | ✅ Native | ✅ Via SOCKS | Most tools prefer HTTP_PROXY |
| HTTPS | ✅ CONNECT tunnel | ✅ Via SOCKS | curl/wget/npm use CONNECT |
| SSH | ❌ Not supported | ✅ Native | git clone ssh:// requires SOCKS |
| Database | ❌ Not supported | ✅ Native | PostgreSQL/MySQL TCP connections |
| gRPC | ❌ Not supported | ✅ Native | Long-lived TCP streams |
| FTP | ❌ Not supported | ✅ Native | Legacy file transfer |

**Core rationale**: HTTP proxy handles only HTTP/HTTPS traffic (via CONNECT tunneling), while SOCKS5 is a general-purpose TCP proxy. Together they cover all network scenarios.

### 1.3 Traffic Path Details

**HTTP/HTTPS traffic** (curl, wget, npm, pip, etc.):
```
Process → HTTP_PROXY=127.0.0.1:<port> → HTTP Proxy → Domain Filter → Target
                                           │
                                     CONNECT tunnel (HTTPS)
                                     or direct forward (HTTP)
```

**SSH/Git SSH traffic** (git clone ssh://):
```
Process → GIT_SSH_COMMAND="ssh -o ProxyCommand=..." → SOCKS5 Proxy → Domain Filter → Target
```

**General TCP traffic** (databases, gRPC, etc.):
```
Process → ALL_PROXY=socks5h://127.0.0.1:<port> → SOCKS5 Proxy → Domain Filter → Target
```

**DNS resolution path**:
- HTTP CONNECT: proxy-side resolution (client sends domain, proxy resolves DNS)
- SOCKS5: uses `socks5h://` protocol prefix, forcing proxy-side resolution (prevents DNS leaks)

---

## 2. Proxy Server (proxy/proxy.go)

### 2.1 Core Types

The combined proxy server is managed through the `Proxy` interface and `Server` implementation:

```go
package proxy

// Proxy is the interface for the combined proxy server.
type Proxy interface {
    Start(ctx context.Context) (httpPort, socksPort int, err error)
    Close() error
}

// Config configures the combined proxy server.
type Config struct {
    // Filter is the domain filter used by both HTTP and SOCKS5 proxies.
    // If nil, all requests are allowed.
    Filter *DomainFilter

    // Logger is the structured logger. If nil, a no-op logger is used.
    Logger *slog.Logger
}

// Server combines HTTP and SOCKS5 proxies into a single unit.
type Server struct {
    config *Config
    http   *HTTPProxy
    socks5 *SOCKS5Proxy
}

// NewServer creates a new Server with the given configuration.
func NewServer(cfg *Config) (*Server, error)
```

### 2.2 Server Lifecycle

**`NewServer(cfg *Config) (*Server, error)`**:
- If `cfg` is nil, uses empty `Config{}`
- Creates a no-op logger if `Logger` is nil
- Resolves `FilterFunc` from `cfg.Filter.Filter` if filter is non-nil
- Creates `HTTPProxy` with `NewHTTPProxy(&HTTPConfig{...})`
- Creates `SOCKS5Proxy` with `NewSOCKS5Proxy(&SOCKS5Config{...})`
- Returns error if SOCKS5 creation fails

**`Start(ctx context.Context) (httpPort, socksPort int, err error)`**:
- Validates both proxies are initialized (returns error if nil)
- Starts HTTP proxy on `:0` (random port)
- Starts SOCKS5 proxy on `:0` (random port)
- If SOCKS5 fails after HTTP started, shuts down HTTP before returning error
- Returns actual ports via `portFromAddr()`

**`Close() error`**:
- Creates a **5-second timeout** context
- Shuts down HTTP proxy, collects error
- Shuts down SOCKS5 proxy, collects error
- Returns combined error via `errors.Join(errs...)`

---

## 3. HTTP Proxy Implementation (proxy/http.go)

### 3.1 Design Choice: Standard Library `net/http`

| Option | Pros | Cons |
|--------|------|------|
| **Standard library net/http** ✅ | Zero dependencies, fully controllable, small code | Must handle CONNECT manually |
| elazarl/goproxy | Feature-rich, MITM support | Extra dependency, over-engineered |

**Rationale**: agentbox targets "single binary, zero external runtime dependencies". The HTTP proxy core logic (CONNECT tunnel + request forwarding) is ~400 lines with the standard library. No MITM capability needed — we only do domain-level filtering, not TLS decryption.

### 3.2 HTTPConfig

```go
// HTTPConfig configures the HTTP proxy server.
type HTTPConfig struct {
    // Filter is the domain filtering function. If nil, all requests are allowed.
    Filter FilterFunc

    // DialTimeout is the timeout for establishing outbound connections.
    // Defaults to 10s if zero.
    DialTimeout time.Duration

    // IdleTimeout is the idle timeout for the proxy HTTP server.
    // Defaults to 60s if zero.
    IdleTimeout time.Duration

    // MaxRequestBodySize is the maximum allowed size in bytes for incoming
    // request bodies. Defaults to 10 MB if zero.
    MaxRequestBodySize int64

    // Logger is the structured logger. If nil, a no-op logger is used.
    Logger *slog.Logger
}
```

**Default values** (constants in http.go):
- `defaultDialTimeout = 10 * time.Second`
- `defaultIdleTimeout = 60 * time.Second`
- `maxRequestBodySize = 10 << 20` (10 MB)

### 3.3 HTTPProxy Struct

```go
type HTTPProxy struct {
    config    *HTTPConfig
    server    *http.Server
    dialer    *net.Dialer
    transport *http.Transport
    addr      net.Addr
    mu        sync.Mutex

    // dialFunc defaults to dialContextWithIPCheck. Used by both
    // the HTTP transport and the CONNECT handler.
    dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

    // resolver is the DNS resolver used by dialContextWithIPCheck.
    // Defaults to net.DefaultResolver. Can be overridden for testing.
    resolver *net.Resolver
}
```

### 3.4 NewHTTPProxy

```go
func NewHTTPProxy(cfg *HTTPConfig) *HTTPProxy
```

- Accepts nil `cfg` (uses empty defaults)
- Resolves dial timeout, idle timeout, max body size, logger to defaults if zero/nil
- Creates a `net.Dialer` with the resolved dial timeout
- Sets `dialFunc = p.dialContextWithIPCheck`
- Creates `http.Transport` with `DialContext: p.dialFunc` and `DisableKeepAlives: true`
- Does **not** create the `http.Server` yet (deferred to `ListenAndServe`)

### 3.5 ListenAndServe

```go
func (p *HTTPProxy) ListenAndServe(addr string) (net.Addr, error)
```

- Calls `net.Listen("tcp", addr)` — use `:0` for random port
- Creates `http.Server` with `Handler: p`, `IdleTimeout`, `ReadHeaderTimeout: 10s`
- Starts `p.server.Serve(ln)` in a goroutine
- Returns the actual listening address

### 3.6 ServeHTTP Dispatch

```go
func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

Routes to `handleConnect` for CONNECT method, `handleHTTP` for all others.

### 3.7 handleHTTP (Regular HTTP Forwarding)

1. Limits request body size via `http.MaxBytesReader(w, r.Body, p.config.MaxRequestBodySize)`
2. Validates `r.URL.Host` is non-empty
3. Parses host/port with `parseHostPort(r.URL.Host, "80")`
4. Applies domain filter if configured (denies with 403)
5. Clones request, clears `RequestURI`, removes hop-by-hop headers
6. Forwards via `p.transport.RoundTrip(outReq)`
7. Copies response headers (removing hop-by-hop) and body

### 3.8 handleConnect (HTTPS Tunneling)

1. Parses host/port with `parseHostPort(r.Host, "443")`
2. Applies domain filter if configured (denies with 403)
3. Dials target via `p.dialFunc(r.Context(), "tcp", targetAddr)`
4. Hijacks client connection
5. Sends `200 OK` + Flush before hijack
6. Bidirectional copy with `io.Copy` in two goroutines, joined by `sync.WaitGroup`
7. Both goroutines close both connections on completion

### 3.9 Shutdown

```go
func (p *HTTPProxy) Shutdown(ctx context.Context) error
```

- Thread-safe (uses mutex to read `p.server`)
- Returns nil if server not started
- Closes idle transport connections, then calls `srv.Shutdown(ctx)`

---

## 4. IP-Level Security (proxy/filter.go)

### 4.1 isBlockedIP

```go
func isBlockedIP(ip net.IP) bool
```

Uses a pre-computed `blockedIPNets` slice (initialized in `init()`) of CIDR ranges:

| Range | Description |
|-------|-------------|
| `0.0.0.0/8` | "This host on this network" |
| `127.0.0.0/8` | IPv4 loopback |
| `169.254.0.0/16` | IPv4 link-local |
| `224.0.0.0/4` | IPv4 multicast |
| `10.0.0.0/8` | RFC1918 private (Class A) |
| `172.16.0.0/12` | RFC1918 private (Class B) |
| `192.168.0.0/16` | RFC1918 private (Class C) |
| `100.64.0.0/10` | Shared address space (RFC 6598 / CGNAT) |
| `::1/128` | IPv6 loopback |
| `fe80::/10` | IPv6 link-local |
| `ff00::/8` | IPv6 multicast |
| `fc00::/7` | IPv6 unique local address (ULA) |

Additionally checks `169.254.169.254` (cloud metadata IP) explicitly.

**Note**: Returns `false` for nil IP (not `true` as in the original design doc).

### 4.2 dialContextWithIPCheck

```go
func (p *HTTPProxy) dialContextWithIPCheck(ctx context.Context, network, addr string) (net.Conn, error)
```

This is a method on `HTTPProxy` (not a standalone function):

1. Parses host/port via `parseHostPort(addr, "")`
2. If host is already an IP: checks `isBlockedIP`, dials directly if safe
3. Otherwise: resolves DNS via `p.resolver.LookupIPAddr(ctx, host)`
4. Returns error if no IPs found
5. Checks **all** resolved IPs against blocked list
6. Dials using the **first** resolved IP to prevent DNS rebinding (TOCTOU)

### 4.3 parseHostPort

```go
func parseHostPort(hostport, defaultPort string) (host, port string, err error)
```

- Returns error for empty input
- Tries `net.SplitHostPort` first
- If split fails and `defaultPort` is empty, returns error ("missing port")
- Handles IPv6 bracket notation without port
- Returns error for empty host
- Falls back to `defaultPort` if port is empty

---

## 5. Helper Functions

### 5.1 Hop-by-Hop Headers

```go
var hopByHopHeaders = []string{
    "Connection", "Keep-Alive", "Proxy-Authenticate",
    "Proxy-Authorization", "Te", "Trailers",
    "Transfer-Encoding", "Upgrade",
}

func removeHopByHopHeaders(h http.Header)
```

### 5.2 portFromAddr

```go
func portFromAddr(addr net.Addr) int
```

Extracts port from `net.Addr`. Returns 0 if nil or not a `*net.TCPAddr`.
