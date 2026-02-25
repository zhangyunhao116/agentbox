# agentbox: SOCKS5 Proxy, Domain Filtering & Environment Variable Injection

> **Status**: Implemented  
> **Author**: Agent  
> **Date**: 2026-02-16  
> **Scope**: SOCKS5 proxy implementation, domain filtering engine, environment variable injection

> Series: [03a](03a-network-architecture.md) | [03b](03b-socks-domain-env.md) | [03c](03c-bridge-fs.md) | [03d](03d-symlink-monitoring.md)

> **This file is part 2 of the 03-network-and-fs series**
> - 📄 [03a-network-architecture.md](03a-network-architecture.md) — Network Isolation Architecture & HTTP Proxy Implementation
> - 📄 Current: 03b — SOCKS5 Proxy, Domain Filtering & Environment Variable Injection
> - 📄 [03c-bridge-fs.md](03c-bridge-fs.md) — Linux Network Bridge & Filesystem Strategy
> - 📄 [03d-symlink-monitoring.md](03d-symlink-monitoring.md) — Symlink Protection & Violation Monitoring

---

## 3. SOCKS5 Proxy Implementation (proxy/socks5.go)

### 3.1 Internal SOCKS5 Implementation

The SOCKS5 proxy uses a **self-implemented** minimal SOCKS5 server located at `proxy/internal/socks5/`.

The internal implementation (`proxy/internal/socks5/socks5.go`) supports only the subset of SOCKS5 that agentbox requires:
- **CONNECT command only** (no BIND, no UDP ASSOCIATE)
- **No-auth only** (no username/password authentication)
- Exposes `RuleSet`, `NameResolver`, `Config`, `Server`, `Request`, `AddrSpec` types

Key internal types:

```go
package socks5

// AddrSpec holds the destination address from a SOCKS5 request.
type AddrSpec struct {
    FQDN string
    IP   net.IP
    Port int
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

// New creates a new SOCKS5 server with the given configuration.
func New(conf *Config) (*Server, error)

// Serve accepts connections on the listener.
func (s *Server) Serve(l net.Listener) error
```

### 3.2 SOCKS5Config

```go
// SOCKS5Config configures the SOCKS5 proxy server.
type SOCKS5Config struct {
    // Filter is the domain filtering function used to allow or deny connections.
    // If nil, all connections are denied by default.
    Filter FilterFunc

    // Logger is the structured logger for proxy events.
    // If nil, a default logger is used.
    Logger *slog.Logger

    // Dial is an optional custom dial function for outbound connections.
    // If nil, a default dialer with IP blocking is used.
    Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}
```

### 3.3 SOCKS5Proxy Struct

```go
type SOCKS5Proxy struct {
    config *SOCKS5Config
    server *socks5.Server
    mu     sync.Mutex
    ln     net.Listener
    addr   net.Addr
    closed bool // set to true on Shutdown, used for shutdown detection
}
```

### 3.4 NewSOCKS5Proxy

```go
func NewSOCKS5Proxy(cfg *SOCKS5Config) (*SOCKS5Proxy, error)
```

1. Accepts nil `cfg` (uses empty defaults)
2. Falls back to `slog.Default()` if Logger is nil
3. Creates a **silent** `log.Logger` (writes to `io.Discard`) for the internal socks5 library to avoid duplicate logging
4. Uses `cfg.Dial` if provided, otherwise creates `dialWithIPCheck(logger, nil)` as the default dialer
5. Constructs internal `socks5.Config` with:
   - `Rules: &domainRuleSet{filter: cfg.Filter, logger: logger}`
   - `Resolver: &proxyNameResolver{logger: logger}`
   - `Dial: dialFn`
   - `Logger: silentLogger`
6. Calls `socks5.New(conf)` to create the internal server

### 3.5 domainRuleSet (implements socks5.RuleSet)

```go
type domainRuleSet struct {
    filter FilterFunc
    logger *slog.Logger
}

func (r *domainRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool)
```

Behavior:
1. Returns `false` if `req.DestAddr` is nil
2. Determines host: prefers `dest.FQDN`, falls back to `dest.IP.String()`
3. Returns `false` if host is empty
4. Returns `false` if filter is nil (deny by default)
5. Calls `r.filter(ctx, host, port)` — denies on error
6. Logs allowed/denied decisions

### 3.6 proxyNameResolver (implements socks5.NameResolver)

```go
type proxyNameResolver struct {
    logger   *slog.Logger
    resolver *net.Resolver
}

func (r *proxyNameResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
```

Behavior:
1. Uses `r.resolver` (falls back to `net.DefaultResolver` if nil)
2. Calls `resolver.LookupIPAddr(ctx, name)`
3. Returns error if no addresses found
4. Checks **all** resolved IPs against `isBlockedIP()` — logs and returns error if any is blocked
5. Returns the **first** resolved IP (no IPv4 preference — differs from original design)

### 3.7 dialWithIPCheck

```go
func dialWithIPCheck(logger *slog.Logger, resolver *net.Resolver) func(ctx context.Context, network, addr string) (net.Conn, error)
```

Returns a closure that:
1. Parses host/port via `net.SplitHostPort`
2. If host is an IP: checks `isBlockedIP`, dials directly if safe
3. Otherwise: resolves DNS, **tries each resolved IP** (skipping blocked ones)
4. Returns the first successful connection
5. If all IPs are blocked or fail, returns the last error

**Key difference from HTTP proxy**: The SOCKS5 dialer tries multiple IPs (fallback behavior), while the HTTP proxy's `dialContextWithIPCheck` uses only the first resolved IP.

### 3.8 ListenAndServe / Shutdown

```go
func (p *SOCKS5Proxy) ListenAndServe(addr string) (net.Addr, error)
func (p *SOCKS5Proxy) Shutdown(ctx context.Context) error
func (p *SOCKS5Proxy) Addr() net.Addr
```

- `ListenAndServe`: Listens on TCP, stores listener/addr, starts `p.server.Serve(ln)` in goroutine. Uses `p.closed` flag to suppress expected shutdown errors.
- `Shutdown`: Sets `closed = true`, nils out `ln`, closes the listener. Thread-safe via mutex.
- `Addr`: Returns the listening address (thread-safe).

### 3.9 SSH/Database/Non-HTTP Traffic

SOCKS5 natively supports arbitrary TCP traffic:

| Traffic Type | Client Config | SOCKS5 Handling |
|-------------|---------------|-----------------|
| SSH (git clone ssh://) | `GIT_SSH_COMMAND` + ProxyCommand | CONNECT to target:22 |
| PostgreSQL | `ALL_PROXY` or proxychains | CONNECT to target:5432 |
| MySQL | `ALL_PROXY` or proxychains | CONNECT to target:3306 |
| gRPC | `GRPC_PROXY` env var | CONNECT to target:port |
| Redis | proxychains | CONNECT to target:6379 |

### 3.10 DNS Resolution Strategy

Uses `socks5h://` protocol prefix (note the `h` suffix), forcing the client to send the domain name to the proxy for resolution:

```
socks5://  → Client resolves DNS locally, sends IP to proxy (may leak DNS queries)
socks5h:// → Client sends domain to proxy, proxy resolves DNS (secure, no DNS leak)
```

---

## 4. Domain Filtering Engine (proxy/filter.go)

### 4.1 Filter Priority

```
Request arrives → IP check → denied list → allowed list → OnRequest callback → default deny
                    │            │              │              │                    │
                    ▼            ▼              ▼              ▼                    ▼
              blocked IP     deny (immediate)  allow       user decides          deny
```

**Priority order**: `blocked IP > denied > allowed > OnRequest callback > default deny`

### 4.2 Core Types

```go
// FilterFunc determines whether a connection to the given host:port is allowed.
type FilterFunc func(ctx context.Context, host string, port int) (bool, error)

// OnRequest is a callback for dynamic domain filtering decisions.
type OnRequest func(ctx context.Context, host string, port int) (bool, error)

// FilterConfig configures the domain filter.
type FilterConfig struct {
    DeniedDomains  []string
    AllowedDomains []string
    OnRequest      OnRequest
}
```

### 4.3 DomainFilter

```go
type DomainFilter struct {
    mu      sync.RWMutex
    denied  []string
    allowed []string
    onReq   OnRequest
}
```

Thread-safe, supports dynamic rule updates.

### 4.4 NewDomainFilter

```go
func NewDomainFilter(cfg *FilterConfig) (*DomainFilter, error)
```

- Returns empty filter if `cfg` is nil
- Validates all domain patterns via `ValidateDomainPattern()`
- Deep-copies denied and allowed slices

### 4.5 Filter Method

```go
func (f *DomainFilter) Filter(ctx context.Context, host string, port int) (bool, error)
```

1. **IP check**: If host is a raw IP, checks `isBlockedIP()` — denies if blocked
2. **Denied list**: Checks against denied patterns (highest priority)
3. **Allowed list**: Checks against allowed patterns
4. **OnRequest callback**: Delegates to callback if set
5. **Default deny**: Returns `false, nil`

### 4.6 UpdateRules

```go
func (f *DomainFilter) UpdateRules(denied, allowed []string) error
```

- Validates all patterns before applying
- Deep-copies slices
- Atomic update under write lock

### 4.7 matchesDomain

```go
func matchesDomain(hostname, pattern string) bool
```

- Case-insensitive (both lowered)
- Strips trailing dots
- Exact match for non-wildcard patterns
- Wildcard `*.example.com` matches `sub.example.com` but **NOT** `example.com` itself
- Wildcard matching: strips `*` to get `.example.com`, checks suffix + length

### 4.8 ValidateDomainPattern

```go
func ValidateDomainPattern(pattern string) error
```

Exported function. Validates:
- Not empty
- No protocol prefix (`://`)
- No port (`:`)
- No path (`/`)
- Wildcard only at beginning as `*.domain.tld` (must have at least one dot after `*.`)
- No other wildcard positions
- Bare domain must contain at least one dot

---

## 5. IP-Level Security Policy

### 5.1 Blocked Ranges

See 03a Section 4.1 for the complete `isBlockedIP` implementation. The function uses CIDR-based matching via `blockedIPNets` (initialized in `init()`), plus explicit check for cloud metadata IP `169.254.169.254`.

### 5.2 Verification Points

| Proxy Type | Verification Location | Description |
|-----------|----------------------|-------------|
| HTTP proxy | `dialContextWithIPCheck` (method on `HTTPProxy`) | Wraps `net.Dialer.DialContext`, resolves DNS then checks IP, dials resolved IP directly |
| SOCKS5 proxy | `proxyNameResolver.Resolve` | Checks all resolved IPs in the NameResolver, blocks before connection |
| SOCKS5 proxy | `dialWithIPCheck` (returned closure) | Additional IP check at dial time, tries multiple IPs |

### 5.3 Defense Model

```
Domain Filter (allowlist)  →  DNS Resolution  →  IP Security Check  →  Establish Connection
       ↓                                              ↓
   Non-allowlisted denied                      Internal IP denied
```

Key principles:
1. **Domain filter first, then IP check** — two layers of defense
2. **Dial resolved IP directly** — prevents TOCTOU from DNS rebinding
3. **Check all resolved IPs** — even one internal IP causes rejection (in HTTP proxy; SOCKS5 skips blocked IPs and tries others)

---

## 6. Environment Variable Injection (proxy/env.go)

### 6.1 EnvConfig

```go
// EnvConfig configures proxy environment variable generation.
type EnvConfig struct {
    HTTPProxyPort  int    // Port for the HTTP/CONNECT proxy
    SOCKSProxyPort int    // Port for the SOCKS5 proxy
    TmpDir         string // Overrides TMPDIR if set
}
```

### 6.2 GenerateProxyEnv

```go
func GenerateProxyEnv(cfg *EnvConfig) []string
```

Returns nil if `cfg` is nil. Otherwise generates:

| Variable | Condition | Value |
|----------|-----------|-------|
| `SANDBOX_RUNTIME` | Always | `1` |
| `TMPDIR` | If `cfg.TmpDir != ""` | `cfg.TmpDir` |
| `NO_PROXY` / `no_proxy` | Always | `localhost,127.0.0.1,::1,*.local,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` |
| `HTTP_PROXY` / `http_proxy` | If `HTTPProxyPort > 0` | `http://127.0.0.1:<port>` |
| `HTTPS_PROXY` / `https_proxy` | If `HTTPProxyPort > 0` | `http://127.0.0.1:<port>` |
| `FTP_PROXY` / `ftp_proxy` | If `HTTPProxyPort > 0` | `http://127.0.0.1:<port>` |
| `ALL_PROXY` / `all_proxy` | If `SOCKSProxyPort > 0` | `socks5h://127.0.0.1:<port>` |
| `GIT_SSH_COMMAND` | If `SOCKSProxyPort > 0` | Platform-specific (see below) |

**Note**: Compared to the original design, the actual implementation is simpler:
- No `GRPC_PROXY`, `RSYNC_PROXY`, `DOCKER_*_PROXY`, or `CLOUDSDK_PROXY_*` variables
- `FTP_PROXY` is set from `HTTPProxyPort` (not SOCKS)
- Uses `127.0.0.1` (not `localhost`)

### 6.3 NO_PROXY Value

Defined as a constant:
```go
const noProxyValue = "localhost,127.0.0.1,::1,*.local,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
```

**Note**: Compared to the original design, `169.254.0.0/16` and `.local` are not included.

### 6.4 Platform-Specific GIT_SSH_COMMAND

| Platform | Command |
|----------|---------|
| macOS (`darwin`) | `ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:<port> %h %p'` |
| Linux/others | `ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:<port> %h %p'` |

---
