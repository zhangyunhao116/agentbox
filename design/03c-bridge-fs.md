# agentbox: Linux Network Bridge & Filesystem Strategy

> **Status**: Implemented  
> **Author**: Agent  
> **Date**: 2026-02-16  
> **Scope**: Linux network bridge (replaces socat), filesystem read/write strategy, dangerous file protection

> Series: [03a](03a-network-architecture.md) | [03b](03b-socks-domain-env.md) | [03c](03c-bridge-fs.md) | [03d](03d-symlink-monitoring.md)

> **This file is part 3 of the 03-network-and-fs series**
> - 📄 [03a-network-architecture.md](03a-network-architecture.md) — Network Isolation Architecture & HTTP Proxy Implementation
> - 📄 [03b-socks-domain-env.md](03b-socks-domain-env.md) — SOCKS5 Proxy, Domain Filtering & Environment Variable Injection
> - 📄 Current: 03c — Linux Network Bridge & Filesystem Strategy
> - 📄 [03d-symlink-monitoring.md](03d-symlink-monitoring.md) — Symlink Protection & Violation Monitoring

---

## 6. Linux Network Bridge (proxy/bridge.go)

### 6.1 Design Motivation

sandbox-runtime uses external `socat` processes for Unix Socket ↔ TCP bridging. agentbox replaces this with a native Go implementation, eliminating the external dependency.

### 6.2 BridgeConfig

```go
// BridgeConfig configures a Unix socket to TCP bridge.
type BridgeConfig struct {
    // SocketDir is the directory where the Unix socket file will be created.
    SocketDir string

    // TargetAddr is the TCP target address to forward connections to
    // (e.g., "127.0.0.1:8080").
    TargetAddr string

    // Label is a descriptive label used in log messages.
    Label string

    // MaxConns is the maximum number of concurrent connections.
    // Defaults to 100 if zero.
    MaxConns int

    // DialTimeout is the timeout for dialing the TCP target.
    // Defaults to 5s if zero.
    DialTimeout time.Duration

    // Logger is the structured logger. If nil, a no-op logger is used.
    Logger *slog.Logger
}
```

**Default constants**:
- `defaultBridgeMaxConns = 100`
- `defaultBridgeDialTimeout = 5 * time.Second`
- `bridgeCopyBufSize = 32 * 1024` (32 KB buffer for io.CopyBuffer)

### 6.3 Bridge Struct

```go
type Bridge struct {
    config      *BridgeConfig
    socketPath  string
    listener    net.Listener
    dialer      net.Dialer
    ctx         context.Context
    cancel      context.CancelFunc
    wg          sync.WaitGroup
    sem         chan struct{}        // semaphore for connection limiting
    connMu      sync.Mutex
    activeConns map[net.Conn]struct{}
}
```

### 6.4 NewBridge

```go
func NewBridge(cfg *BridgeConfig) (*Bridge, error)
```

- Returns error if `cfg` is nil, `SocketDir` is empty, or `TargetAddr` is empty
- Resolves defaults: MaxConns → 100, DialTimeout → 5s, Logger → no-op, Label → "bridge"
- Socket path: `filepath.Join(cfg.SocketDir, label+".sock")` (deterministic, not random)
- Creates context with cancel, semaphore channel, active connections map

### 6.5 Start

```go
func (b *Bridge) Start() error
```

1. **Removes stale socket file** — returns error if removal fails (and not "not exist")
2. Calls `net.Listen("unix", b.socketPath)`
3. **`chmod 0600`** on the socket file for restrictive permissions
4. **On chmod failure**: closes listener, removes socket file, returns error
5. Starts `acceptLoop()` in a goroutine

### 6.6 acceptLoop

```go
func (b *Bridge) acceptLoop()
```

1. Accepts connections in a loop
2. On accept error: checks `b.ctx.Done()` for shutdown, otherwise returns (stops accepting)
3. **Semaphore acquisition**: blocks until a slot is available or context is cancelled
4. On context cancel during semaphore wait: closes the connection, returns
5. Dispatches `handleConn(conn)` in a goroutine

### 6.7 handleConn

```go
func (b *Bridge) handleConn(conn net.Conn)
```

1. Releases semaphore slot on return
2. Tracks connection in `activeConns` map
3. Dials TCP target via `b.dialer.DialContext(b.ctx, "tcp", b.config.TargetAddr)`
4. On dial failure: closes connection, returns
5. **Bidirectional copy** using `io.CopyBuffer` with 32KB buffers
6. Half-close: `TCPConn.CloseWrite()` for target, `UnixConn.CloseWrite()` for client
7. Closes both connections after copy completes

### 6.8 Shutdown

```go
func (b *Bridge) Shutdown(timeout time.Duration) error
```

1. Cancels context
2. Closes listener (stops accepting)
3. Waits for `wg.Wait()` with timeout
4. On timeout: **force-closes all tracked connections** via `conn.Close()` (not `SetDeadline`)
5. **Secondary 2-second wait** after force-close to ensure WaitGroup goroutine completes
6. Removes socket file (returns error if removal fails)

### 6.9 Connection Tracking

```go
func (b *Bridge) trackConn(conn net.Conn, add bool)
```

Single method with `add` boolean parameter (not separate `trackConn`/`untrackConn` methods). Thread-safe via `connMu` mutex.

---

## 7. BridgePair

### 7.1 Type

```go
type BridgePair struct {
    HTTP  *Bridge
    SOCKS *Bridge
}
```

### 7.2 NewBridgePair

```go
func NewBridgePair(socketDir string, httpAddr, socksAddr string, logger *slog.Logger) (*BridgePair, error)
```

- Creates HTTP bridge with label `"http-proxy"` (not `"http"`)
- Creates SOCKS bridge with label `"socks-proxy"` (not `"socks"`)
- Does **not** set `MaxConns` explicitly (uses default 100)
- Falls back to no-op logger if nil

### 7.3 Start

```go
func (bp *BridgePair) Start() error
```

- Starts HTTP bridge first
- If SOCKS bridge fails: shuts down HTTP bridge with 5s timeout before returning error

### 7.4 Shutdown

```go
func (bp *BridgePair) Shutdown(timeout time.Duration)
```

- Shuts down **both bridges concurrently** using goroutines + WaitGroup
- Best-effort shutdown (errors ignored)

---

## 8. Filesystem Strategy

### 8.1 Read Strategy: deny-only Mode

**Semantics**: Allow all reads by default, explicitly deny specific paths.

```
Read request → Check denyRead list → Match → Deny → Otherwise → Allow
```

**Design rationale**: Agents need broad read access for code analysis. Data exfiltration is controlled via network policy, not read restrictions.

#### Default DenyRead Paths (from DefaultConfig)

```go
DenyRead: []string{
    filepath.Join(home, ".ssh"),
    filepath.Join(home, ".aws"),
    filepath.Join(home, ".gnupg"),
    filepath.Join(home, ".git-credentials"),
    filepath.Join(home, ".npmrc"),
    filepath.Join(home, ".netrc"),
    filepath.Join(home, ".docker"),
    filepath.Join(home, ".pypirc"),
    filepath.Join(home, ".kube"),
    filepath.Join(home, ".config", "gcloud"),
    "/proc/*/mem",
    "/sys",
}
```

#### macOS SBPL Implementation (darwin/profile.go)

```scheme
; File read: allow all by default, deny specific paths
(allow file-read*)
(deny file-read* (subpath "/Users/user/.ssh"))
(deny file-read* (subpath "/Users/user/.aws"))
; ... etc
```

Generated by `profileBuilder.writeFileRead(cfg)`.

### 8.2 Write Strategy: allow-only Mode

**Semantics**: Deny all writes by default, explicitly allow specific paths.

```
Write request → Check denyWrite list → Match → Deny
                                        ↓ No match
             → Check writableRoots → Match → Allow → Otherwise → Deny
```

#### Default DenyWrite Paths (from DefaultConfig)

```go
DenyWrite: []string{
    home,
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
}
```

#### macOS SBPL Implementation (darwin/profile.go)

```scheme
; File write: deny all by default, allow specific paths
(deny file-write*)

; Always allow temp directories
(allow file-write* (subpath "/private/tmp"))
(allow file-write* (subpath "/private/var/folders"))

; Allow configured writable roots
(allow file-write* (subpath "/path/to/project"))

; Deny writes to explicitly denied paths (overrides writable roots)
(deny file-write* (subpath "/Users/user"))
```

Generated by `profileBuilder.writeFileWrite(cfg)`.

---

## 9. Dangerous File Protection (darwin/profile.go)

### 9.1 Dangerous File Lists

The actual dangerous file lists are defined in `darwin/profile.go` within the `writeDangerousFileProtection` method:

**Dangerous files** (protected with `literal` match):
```go
dangerousFiles := []string{
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".gitconfig",
    ".ssh",
}
```

**Dangerous directories** (protected with `subpath` match):
```go
dangerousDirs := []string{
    ".git/hooks",
}
```

**Note**: The actual implementation is simpler than the original design doc. There are no separate `DangerousMultiLevelFiles` or `DiscoverDangerousPaths` functions. The protection is applied relative to `$HOME` only.

### 9.2 SBPL Generation

```scheme
; Dangerous file protection: deny writes to sensitive paths
(deny file-write* (literal "/Users/user/.bashrc"))
(deny file-write* (literal "/Users/user/.bash_profile"))
(deny file-write* (literal "/Users/user/.zshrc"))
(deny file-write* (literal "/Users/user/.zprofile"))
(deny file-write* (literal "/Users/user/.profile"))
(deny file-write* (literal "/Users/user/.gitconfig"))
(deny file-write* (literal "/Users/user/.ssh"))
(deny file-write* (subpath "/Users/user/.git/hooks"))
```

### 9.3 AllowGitConfig

If `cfg.AllowGitConfig` is true, an explicit allow rule is added:
```scheme
(allow file-read* (literal "/Users/user/.gitconfig"))
```

### 9.4 PTY Access

The profile also allows PTY access for interactive commands:
```scheme
; Allow PTY access for interactive commands
(allow file-read* (regex #"^/dev/(ttys|pty|null|zero|random|urandom|fd)"))
(allow file-write* (regex #"^/dev/ttys[0-9]+$"))
(allow file-write* (regex #"^/dev/pty[a-z][0-9a-f]$"))
(allow file-write* (literal "/dev/null"))
(allow file-write* (literal "/dev/zero"))
(allow file-write* (literal "/dev/random"))
(allow file-write* (literal "/dev/urandom"))
(allow file-ioctl (regex #"^/dev/(ttys|pty)"))
```

---

## 10. Path Canonicalization (darwin/profile.go)

### 10.1 canonicalizePath

```go
func canonicalizePath(p string) string
```

1. Tries `filepath.EvalSymlinks(p)` — returns cleaned result on success
2. **Fallback**: Manual mapping for well-known macOS symlinks:
   - `/tmp` or `/tmp/...` → `/private/tmp` or `/private/tmp/...`
   - `/var` or `/var/...` → `/private/var` or `/private/var/...`
3. Returns `filepath.Clean(result)`

### 10.2 getTmpdirParents

```go
func getTmpdirParents() []string
```

Returns sorted list of temp directories that should be writable:
- Always includes `/private/tmp` and `/private/var/folders`
- Includes canonicalized `$TMPDIR` if set

### 10.3 sanitizeEnv

```go
func sanitizeEnv(env []string) []string
```

Removes `DYLD_*` and `LD_*` environment variables using `envutil.RemoveEnvPrefix()` to prevent dynamic library injection.

---
