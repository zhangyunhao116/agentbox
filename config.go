package agentbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/zhangyunhao116/agentbox/internal/pathutil"
	"github.com/zhangyunhao116/agentbox/platform"
)

// FallbackPolicy determines behavior when the sandbox platform is unavailable.
type FallbackPolicy int

const (
	// FallbackStrict refuses to execute commands if sandboxing is unavailable.
	FallbackStrict FallbackPolicy = iota

	// FallbackWarn executes commands without sandboxing but logs a warning.
	FallbackWarn
)

// String returns the string representation of a FallbackPolicy.
func (f FallbackPolicy) String() string {
	switch f {
	case FallbackStrict:
		return "strict"
	case FallbackWarn:
		return "warn"
	default:
		return unknownStr
	}
}

// MarshalText implements encoding.TextMarshaler.
// It encodes the FallbackPolicy as its string representation (e.g., "strict", "warn").
func (f FallbackPolicy) MarshalText() ([]byte, error) {
	s := f.String()
	if s == unknownStr {
		return nil, fmt.Errorf("agentbox: cannot marshal unknown FallbackPolicy value %d", int(f))
	}
	return []byte(s), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
// It accepts the lowercase string representations: "strict", "warn".
func (f *FallbackPolicy) UnmarshalText(text []byte) error {
	switch string(text) {
	case "strict":
		*f = FallbackStrict
	case "warn":
		*f = FallbackWarn
	default:
		return fmt.Errorf("unknown fallback policy: %q", text)
	}
	return nil
}

// NetworkMode determines how network access is handled inside the sandbox.
type NetworkMode int

const (
	// NetworkFiltered allows network access only to explicitly allowed domains.
	NetworkFiltered NetworkMode = iota

	// NetworkBlocked denies all network access from within the sandbox.
	NetworkBlocked

	// NetworkAllowed permits unrestricted network access.
	NetworkAllowed
)

// String returns the string representation of a NetworkMode.
func (n NetworkMode) String() string {
	switch n {
	case NetworkFiltered:
		return "filtered"
	case NetworkBlocked:
		return "blocked" //nolint:goconst // duplicated in UnmarshalText switch by design
	case NetworkAllowed:
		return "allowed"
	default:
		return unknownStr
	}
}

// MarshalText implements encoding.TextMarshaler.
// It encodes the NetworkMode as its string representation (e.g., "filtered", "blocked", "allowed").
func (n NetworkMode) MarshalText() ([]byte, error) {
	s := n.String()
	if s == unknownStr {
		return nil, fmt.Errorf("agentbox: cannot marshal unknown NetworkMode value %d", int(n))
	}
	return []byte(s), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
// It accepts the lowercase string representations: "filtered", "blocked", "allowed".
func (n *NetworkMode) UnmarshalText(text []byte) error {
	switch string(text) {
	case "filtered":
		*n = NetworkFiltered
	case "blocked":
		*n = NetworkBlocked
	case "allowed":
		*n = NetworkAllowed
	default:
		return fmt.Errorf("unknown network mode: %q", text)
	}
	return nil
}

// ResourceLimits specifies resource constraints for sandboxed processes.
// It is an alias for platform.ResourceLimits.
type ResourceLimits = platform.ResourceLimits

// DependencyCheck holds the result of a dependency check.
// It is an alias for platform.DependencyCheck.
type DependencyCheck = platform.DependencyCheck

// DefaultResourceLimits returns sensible default resource limits.
func DefaultResourceLimits() *ResourceLimits {
	return platform.DefaultResourceLimits()
}

// FilesystemConfig defines filesystem access restrictions for the sandbox.
type FilesystemConfig struct {
	// WritableRoots lists directories where write access is permitted.
	WritableRoots []string `json:"writableRoots,omitempty"`

	// DenyWrite lists path patterns that must never be writable.
	DenyWrite []string `json:"denyWrite,omitempty"`

	// DenyRead lists path patterns that must never be readable.
	DenyRead []string `json:"denyRead,omitempty"`

	// AllowGitConfig permits read access to ~/.gitconfig and related files.
	AllowGitConfig bool `json:"allowGitConfig,omitempty"`

	// AutoProtectDangerousFiles enables automatic scanning of WritableRoots
	// for dangerous files (.bashrc, .gitconfig, etc.) and adds them to DenyWrite.
	AutoProtectDangerousFiles bool `json:"autoProtectDangerousFiles,omitempty"`

	// DangerousFileScanDepth limits directory traversal depth when scanning
	// for dangerous files. 0 means use default (5).
	DangerousFileScanDepth int `json:"dangerousFileScanDepth,omitempty"`
}

// NetworkConfig defines network access restrictions for the sandbox.
type NetworkConfig struct {
	// Mode determines the overall network access policy.
	Mode NetworkMode `json:"mode"`

	// AllowedDomains lists domain patterns that are permitted when Mode is NetworkFiltered.
	AllowedDomains []string `json:"allowedDomains,omitempty"`

	// DeniedDomains lists domain patterns that are always blocked.
	DeniedDomains []string `json:"deniedDomains,omitempty"`

	// AllowLocalBinding permits sandboxed processes to bind to local ports
	// (e.g., for development servers). Only effective on macOS.
	AllowLocalBinding bool `json:"allowLocalBinding,omitempty"`

	// AllowAllUnixSockets permits all Unix domain socket connections.
	// Only effective on macOS.
	AllowAllUnixSockets bool `json:"allowAllUnixSockets,omitempty"`

	// AllowUnixSockets lists specific Unix socket paths that are permitted.
	// Only effective on macOS.
	AllowUnixSockets []string `json:"allowUnixSockets,omitempty"`

	// MITMProxy configures routing of specific domains through an upstream
	// MITM proxy via Unix socket, for enterprise TLS inspection.
	MITMProxy *MITMProxyConfig `json:"mitmProxy,omitempty"`

	// OnRequest is an optional callback invoked for each outgoing connection attempt.
	// It receives the target host and port and returns whether the connection is allowed.
	// Only called when Mode is NetworkFiltered and the domain is not in AllowedDomains or DeniedDomains.
	//
	// OnRequest is shared by reference across the manager and any config snapshots.
	// Implementations must be safe for concurrent use by multiple goroutines.
	OnRequest func(ctx context.Context, host string, port int) (bool, error) `json:"-"`
}

// MITMProxyConfig configures MITM proxy routing.
type MITMProxyConfig struct {
	// SocketPath is the Unix socket path to the MITM proxy.
	SocketPath string `json:"socketPath"`

	// Domains lists domain patterns to route through the MITM proxy.
	// Supports exact match and wildcard prefix (e.g., "*.example.com").
	Domains []string `json:"domains,omitempty"`
}

// Config holds the complete configuration for a sandbox Manager.
// Config should be created using DefaultConfig, DevelopmentConfig, or CIConfig
// rather than as a zero-value literal, since several fields require non-zero
// defaults for correct operation.
//
// Copying a Config value is safe; however, fields holding reference types
// (Logger, OnRequest, ApprovalCallback, ApprovalCache, Classifier) are
// shared between copies.
type Config struct {
	// Filesystem defines filesystem access restrictions.
	Filesystem FilesystemConfig `json:"filesystem"`

	// Network defines network access restrictions.
	Network NetworkConfig `json:"network"`

	// Classifier determines how commands are classified.
	Classifier Classifier `json:"-"`

	// Shell is the path to the shell used for command execution.
	// If empty, the system default shell is used.
	Shell string `json:"shell,omitempty"`

	// MaxOutputBytes limits the size of captured stdout/stderr.
	// 0 means no limit. Defaults to defaultMaxOutputBytes (10 MB) when
	// created via DefaultConfig(). Set explicitly to 0 to disable the limit.
	MaxOutputBytes int `json:"maxOutputBytes,omitempty"`

	// ResourceLimits defines resource constraints for sandboxed processes.
	// If nil, DefaultResourceLimits() is used.
	ResourceLimits *ResourceLimits `json:"resourceLimits,omitempty"`

	// FallbackPolicy determines behavior when sandboxing is unavailable.
	FallbackPolicy FallbackPolicy `json:"fallbackPolicy"`

	// Logger is the structured logger for operational messages such as
	// sandbox fallback warnings, wrapping errors, and cleanup diagnostics.
	// If nil, slog.Default() is used.
	Logger *slog.Logger `json:"-"`

	// ApprovalCallback is invoked when a command is classified as Escalated.
	// The callback must be safe for concurrent use, as it may be invoked
	// from multiple goroutines simultaneously.
	// If nil, escalated commands return ErrEscalatedCommand.
	ApprovalCallback ApprovalCallback `json:"-"`

	// ApprovalCache caches user approval decisions for escalated commands,
	// avoiding repeated prompts for the same command. When set, the cache
	// is consulted before invoking ApprovalCallback, and the callback's
	// result is stored after invocation. Only Escalated command decisions
	// are cached; Forbidden commands are never cached.
	// If nil, no caching is performed (every escalated command triggers
	// the callback).
	ApprovalCache ApprovalCache `json:"-"`
}

// DefaultConfig returns a Config with secure defaults suitable for most use cases.
// If the user's home directory cannot be determined, os.TempDir() is used as a
// fallback for home-relative deny paths.
//
// The default paths are platform-aware:
// - On Unix (Linux/macOS): protects system directories like /etc, /usr, /bin
// - On Windows: protects system directories like C:\Windows, C:\Program Files
func DefaultConfig() *Config {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir() // fallback
	}

	return &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: []string{},
			DenyWrite:     defaultDenyWritePaths(home),
			DenyRead:      defaultDenyReadPaths(home),
			AllowGitConfig: false,
		},
		Network: NetworkConfig{
			Mode: NetworkFiltered,
		},
		Shell:          "",
		MaxOutputBytes: defaultMaxOutputBytes,
		ResourceLimits: DefaultResourceLimits(),
		FallbackPolicy: FallbackStrict,
	}
}

// DevelopmentConfig returns a Config suitable for local development.
// It uses FallbackWarn so commands still run when the sandbox platform
// is unavailable, and allows unrestricted network access.
func DevelopmentConfig() *Config {
	cfg := DefaultConfig()
	cfg.FallbackPolicy = FallbackWarn
	cfg.Network.Mode = NetworkAllowed
	return cfg
}

// CIConfig returns a Config optimized for CI/CD environments.
// It blocks all network access and uses strict fallback policy to
// ensure commands always run inside a sandbox.
func CIConfig() *Config {
	cfg := DefaultConfig()
	cfg.FallbackPolicy = FallbackStrict
	cfg.Network.Mode = NetworkBlocked
	return cfg
}

// Validate checks the configuration for errors and returns a descriptive error
// if any field is invalid. The returned error wraps ErrConfigInvalid.
func (c *Config) Validate() error {
	var errs []string

	errs = c.validateFilesystem(errs)
	errs = c.validateNetwork(errs)

	// Validate shell path format.
	if c.Shell != "" {
		if !filepath.IsAbs(c.Shell) {
			errs = append(errs, fmt.Sprintf("Shell: %q must be an absolute path", c.Shell))
		}
	}

	errs = c.validateResourceLimits(errs)

	// Validate MaxOutputBytes.
	if c.MaxOutputBytes < 0 {
		errs = append(errs, "MaxOutputBytes: must be >= 0")
	}

	// Validate enum ranges.
	if c.FallbackPolicy < FallbackStrict || c.FallbackPolicy > FallbackWarn {
		errs = append(errs, "FallbackPolicy: invalid value")
	}
	if c.Network.Mode < NetworkFiltered || c.Network.Mode > NetworkAllowed {
		errs = append(errs, "Network.Mode: invalid value")
	}

	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrConfigInvalid, strings.Join(errs, "; "))
	}

	return nil
}

// validateFilesystem checks filesystem configuration fields and appends any
// validation errors to errs.
func (c *Config) validateFilesystem(errs []string) []string {
	for i, root := range c.Filesystem.WritableRoots {
		if root == "" {
			errs = append(errs, fmt.Sprintf("Filesystem.WritableRoots[%d]: must not be empty", i))
			continue
		}
		if pathutil.ContainsNullByte(root) {
			errs = append(errs, fmt.Sprintf("Filesystem.WritableRoots[%d]: must not contain null bytes", i))
			continue
		}
		if !filepath.IsAbs(root) {
			if _, err := filepath.Abs(root); err != nil {
				errs = append(errs, fmt.Sprintf("Filesystem.WritableRoots[%d]: cannot resolve to absolute path: %v", i, err))
			}
		}
	}

	for i, p := range c.Filesystem.DenyWrite {
		if p == "" {
			errs = append(errs, fmt.Sprintf("Filesystem.DenyWrite[%d]: must not be empty", i))
			continue
		}
		if pathutil.ContainsNullByte(p) {
			errs = append(errs, fmt.Sprintf("Filesystem.DenyWrite[%d]: must not contain null bytes", i))
		}
	}

	for i, p := range c.Filesystem.DenyRead {
		if p == "" {
			errs = append(errs, fmt.Sprintf("Filesystem.DenyRead[%d]: must not be empty", i))
			continue
		}
		if pathutil.ContainsNullByte(p) {
			errs = append(errs, fmt.Sprintf("Filesystem.DenyRead[%d]: must not contain null bytes", i))
		}
	}

	// Cross-check WritableRoots against DenyWrite for conflicts.
	for _, root := range c.Filesystem.WritableRoots {
		absRoot := root
		if !filepath.IsAbs(absRoot) {
			absRoot, _ = filepath.Abs(absRoot)
		}
		for _, deny := range c.Filesystem.DenyWrite {
			absDeny := deny
			if !filepath.IsAbs(absDeny) {
				absDeny, _ = filepath.Abs(absDeny)
			}
			if strings.HasPrefix(absRoot, absDeny+string(filepath.Separator)) || absRoot == absDeny {
				errs = append(errs, fmt.Sprintf("Filesystem: WritableRoots %q conflicts with DenyWrite %q", root, deny))
			}
		}
	}

	if c.Filesystem.DangerousFileScanDepth < 0 {
		errs = append(errs, "Filesystem.DangerousFileScanDepth: must be >= 0")
	}

	return errs
}

// validateNetwork checks network configuration fields and appends any
// validation errors to errs.
func (c *Config) validateNetwork(errs []string) []string {
	for i, d := range c.Network.AllowedDomains {
		if err := validateDomainPattern(d); err != nil {
			errs = append(errs, fmt.Sprintf("Network.AllowedDomains[%d]: %v", i, err))
		}
	}

	for i, d := range c.Network.DeniedDomains {
		if err := validateDomainPattern(d); err != nil {
			errs = append(errs, fmt.Sprintf("Network.DeniedDomains[%d]: %v", i, err))
		}
	}

	// Validate MITMProxy config.
	if c.Network.MITMProxy != nil {
		if c.Network.MITMProxy.SocketPath == "" {
			errs = append(errs, "Network.MITMProxy.SocketPath: must not be empty")
		} else if !filepath.IsAbs(c.Network.MITMProxy.SocketPath) {
			errs = append(errs, fmt.Sprintf("Network.MITMProxy.SocketPath: %q must be an absolute path", c.Network.MITMProxy.SocketPath))
		}
		for i, d := range c.Network.MITMProxy.Domains {
			if err := validateDomainPattern(d); err != nil {
				errs = append(errs, fmt.Sprintf("Network.MITMProxy.Domains[%d]: %v", i, err))
			}
		}
	}

	// Validate AllowUnixSockets paths.
	for i, p := range c.Network.AllowUnixSockets {
		if p == "" {
			errs = append(errs, fmt.Sprintf("Network.AllowUnixSockets[%d]: must not be empty", i))
		} else if !filepath.IsAbs(p) {
			errs = append(errs, fmt.Sprintf("Network.AllowUnixSockets[%d]: %q must be an absolute path", i, p))
		}
	}

	return errs
}

// validateResourceLimits checks resource limit fields and appends any
// validation errors to errs.
func (c *Config) validateResourceLimits(errs []string) []string {
	if c.ResourceLimits != nil {
		if c.ResourceLimits.MaxProcesses < 0 {
			errs = append(errs, "ResourceLimits.MaxProcesses: must be >= 0")
		}
		if c.ResourceLimits.MaxMemoryBytes < 0 {
			errs = append(errs, "ResourceLimits.MaxMemoryBytes: must be >= 0")
		}
		if c.ResourceLimits.MaxFileDescriptors < 0 {
			errs = append(errs, "ResourceLimits.MaxFileDescriptors: must be >= 0")
		}
		if c.ResourceLimits.MaxCPUSeconds < 0 {
			errs = append(errs, "ResourceLimits.MaxCPUSeconds: must be >= 0")
		}
	}

	return errs
}

// validateDomainPattern checks that a domain pattern is well-formed.
// Valid patterns: "example.com", "*.example.com".
// Invalid: empty, no dot, protocol prefix, malformed wildcards.
func validateDomainPattern(pattern string) error {
	if pattern == "" {
		return errors.New("domain pattern must not be empty")
	}

	// Reject protocol prefixes.
	if strings.Contains(pattern, "://") {
		return fmt.Errorf("domain pattern %q must not contain protocol prefix", pattern)
	}

	// Must contain at least one dot.
	if !strings.Contains(pattern, ".") {
		return fmt.Errorf("domain pattern %q must contain at least one dot", pattern)
	}

	// Validate wildcard format: only *.xxx.yyy is allowed.
	if strings.Contains(pattern, "*") {
		if !strings.HasPrefix(pattern, "*.") {
			return fmt.Errorf("domain pattern %q: wildcard must be in *.domain.tld format", pattern)
		}
		// Ensure no additional wildcards after the prefix.
		rest := pattern[2:]
		if strings.Contains(rest, "*") {
			return fmt.Errorf("domain pattern %q: only one leading wildcard is allowed", pattern)
		}
		// The rest must still contain a dot (i.e., *.com is not valid, need *.example.com).
		if !strings.Contains(rest, ".") {
			return fmt.Errorf("domain pattern %q: wildcard domain must have at least two labels (e.g., *.example.com)", pattern)
		}
	}

	return nil
}

// deepCopyConfig returns a copy of cfg with all slice fields deep-copied
// to prevent aliasing. Reference-type fields (OnRequest, ApprovalCallback,
// ApprovalCache, Classifier, Logger) are shared by reference intentionally.
func deepCopyConfig(cfg *Config) Config {
	cfgCopy := *cfg
	cfgCopy.Filesystem.WritableRoots = append([]string{}, cfg.Filesystem.WritableRoots...)
	cfgCopy.Filesystem.DenyWrite = append([]string{}, cfg.Filesystem.DenyWrite...)
	cfgCopy.Filesystem.DenyRead = append([]string{}, cfg.Filesystem.DenyRead...)
	cfgCopy.Network.AllowedDomains = append([]string{}, cfg.Network.AllowedDomains...)
	cfgCopy.Network.DeniedDomains = append([]string{}, cfg.Network.DeniedDomains...)
	cfgCopy.Network.AllowUnixSockets = append([]string{}, cfg.Network.AllowUnixSockets...)
	if cfg.Network.MITMProxy != nil {
		mitmCopy := *cfg.Network.MITMProxy
		mitmCopy.Domains = append([]string{}, cfg.Network.MITMProxy.Domains...)
		cfgCopy.Network.MITMProxy = &mitmCopy
	}
	if cfg.ResourceLimits != nil {
		rl := *cfg.ResourceLimits
		cfgCopy.ResourceLimits = &rl
	}
	return cfgCopy
}
