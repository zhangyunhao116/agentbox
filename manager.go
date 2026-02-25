package agentbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/zhangyunhao116/agentbox/internal/pathutil"
	"github.com/zhangyunhao116/agentbox/platform"
	"github.com/zhangyunhao116/agentbox/proxy"
)

const (
	// defaultMaxOutputBytes is the default limit for captured stdout/stderr (10 MB).
	defaultMaxOutputBytes = 10 * 1024 * 1024

	// defaultShell is the default shell used for command execution.
	defaultShell = "/bin/sh"
)

// detectPlatformFn is the function used to detect the sandbox platform.
// It defaults to platform.Detect and can be overridden in tests.
var detectPlatformFn = platform.Detect

// manager is the core Manager implementation that orchestrates
// platform-specific sandboxing, command classification, and option merging.
type manager struct {
	mu               sync.RWMutex
	closed           bool
	cfg              *Config
	platform         platform.Platform
	approvalCallback ApprovalCallback
	logger           *slog.Logger
	proxy            *proxy.Server
	proxyFilter      *proxy.DomainFilter
	httpProxyPort    int
	socksProxyPort   int
	sessionApprovals map[string]struct{} // commands approved for the session
}

// newManager creates a new sandbox Manager with the given configuration.
// It validates the config, fills in defaults, detects the platform, and
// checks availability according to the FallbackPolicy.
func newManager(cfg *Config) (Manager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: config must not be nil", ErrConfigInvalid)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Work on a shallow copy so Validate() + newManager() do not mutate the caller's Config.
	cfgCopy := deepCopyConfig(cfg)

	// Normalize relative writable roots to absolute paths.
	for i, root := range cfgCopy.Filesystem.WritableRoots {
		if !filepath.IsAbs(root) {
			abs, err := filepath.Abs(root)
			if err != nil {
				return nil, fmt.Errorf("%w: cannot resolve WritableRoots[%d] to absolute path: %w", ErrConfigInvalid, i, err)
			}
			cfgCopy.Filesystem.WritableRoots[i] = abs
		}
	}

	// Fill in defaults.
	if cfgCopy.Classifier == nil {
		cfgCopy.Classifier = DefaultClassifier()
	}
	if cfgCopy.Shell == "" {
		cfgCopy.Shell = defaultShell
	}
	if cfgCopy.ResourceLimits == nil {
		cfgCopy.ResourceLimits = DefaultResourceLimits()
	}

	// Check that the configured shell exists on the filesystem.
	if cfgCopy.Shell != "" {
		if _, err := os.Stat(cfgCopy.Shell); err != nil {
			return nil, fmt.Errorf("%w: shell %q does not exist: %w", ErrConfigInvalid, cfgCopy.Shell, err)
		}
	}

	// Resolve the logger early so it is available for fallback warnings.
	logger := cfgCopy.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Detect platform.
	plat := detectPlatformFn()

	if !plat.Available() {
		switch cfgCopy.FallbackPolicy {
		case FallbackStrict:
			return nil, ErrUnsupportedPlatform
		case FallbackWarn:
			logger.Warn("sandbox platform unavailable, running without sandboxing")
			return newNopManagerWithConfig(&cfgCopy), nil
		default:
			return nil, ErrUnsupportedPlatform
		}
	}

	m := &manager{
		cfg:              &cfgCopy,
		platform:         plat,
		approvalCallback: cfgCopy.ApprovalCallback,
		logger:           logger,
		sessionApprovals: make(map[string]struct{}),
	}

	// Start proxy server if network mode is filtered.
	if cfgCopy.Network.Mode == NetworkFiltered {
		filter, err := proxy.NewDomainFilter(&proxy.FilterConfig{
			AllowedDomains: cfgCopy.Network.AllowedDomains,
			DeniedDomains:  cfgCopy.Network.DeniedDomains,
			OnRequest:      proxy.OnRequest(cfgCopy.Network.OnRequest),
		})
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrProxyStartFailed, err)
		}

		proxyCfg := &proxy.Config{
			Filter: filter,
			Logger: logger,
		}
		// Wire MITM proxy config from the top-level config to the proxy layer.
		if cfgCopy.Network.MITMProxy != nil {
			proxyCfg.MITM = &proxy.MITMConfig{
				SocketPath: cfgCopy.Network.MITMProxy.SocketPath,
				Domains:    cfgCopy.Network.MITMProxy.Domains,
			}
		}

		ps, err := proxy.NewServer(proxyCfg)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrProxyStartFailed, err)
		}

		httpPort, socksPort, err := ps.Start(context.Background())
		if err != nil {
			_ = ps.Close()
			return nil, fmt.Errorf("%w: %w", ErrProxyStartFailed, err)
		}

		m.proxy = ps
		m.proxyFilter = filter
		m.httpProxyPort = httpPort
		m.socksProxyPort = socksPort
	}

	return m, nil
}

// mergeCallOptions applies per-call Option functions and returns the result.
func mergeCallOptions(opts ...Option) *callOptions {
	co := &callOptions{}
	for _, opt := range opts {
		opt(co)
	}
	return co
}

// configSnapshot holds a shallow copy of Config taken under the read lock.
// Fields that are pointers/slices are safe because UpdateConfig deep-copies
// them before storing, so the snapshot references the old (immutable) data.
type configSnapshot struct {
	cfg Config
}

// snapshotConfig returns a shallow copy of the current config under the read lock.
// The caller must NOT hold the lock when calling this method.
func (m *manager) snapshotConfig() (configSnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return configSnapshot{}, ErrManagerClosed
	}
	return configSnapshot{cfg: *m.cfg}, nil
}

// classify runs the classifier on a shell command string and returns the result.
// If a per-call classifier is provided via options, it takes precedence.
func classify(snap *configSnapshot, command string, co *callOptions) ClassifyResult {
	cl := snap.cfg.Classifier
	if co.classifier != nil {
		cl = co.classifier
	}
	return cl.Classify(command)
}

// classifyArgs runs the classifier on a program name and argument list.
func classifyArgs(snap *configSnapshot, name string, args []string, co *callOptions) ClassifyResult {
	cl := snap.cfg.Classifier
	if co.classifier != nil {
		cl = co.classifier
	}
	return cl.ClassifyArgs(name, args)
}

// handleDecision checks the classification result and returns an error for
// Forbidden or Escalated (without approval callback) commands.
func (m *manager) handleDecision(ctx context.Context, result ClassifyResult, command string) error {
	switch result.Decision {
	case Forbidden:
		return &ForbiddenCommandError{Command: command, Reason: result.Reason}
	case Escalated:
		// Check session-level approval cache first.
		normalizedCmd := normalizeCommand(command)
		m.mu.RLock()
		_, cached := m.sessionApprovals[normalizedCmd]
		cb := m.approvalCallback
		m.mu.RUnlock()
		if cached {
			return nil
		}

		// approvalCallback may be updated via UpdateConfig; read under lock above.
		if cb == nil {
			return &EscalatedCommandError{Command: command, Reason: result.Reason}
		}
		decision, err := cb(ctx, ApprovalRequest{
			Command:  command,
			Reason:   result.Reason,
			Decision: result.Decision,
		})
		if err != nil {
			return fmt.Errorf("%w: %w", &EscalatedCommandError{Command: command, Reason: result.Reason}, err)
		}
		switch decision {
		case Approve:
			// fall through to return nil
		case ApproveSession:
			m.mu.Lock()
			m.sessionApprovals[normalizedCmd] = struct{}{}
			m.mu.Unlock()
		default:
			// Treat unknown/unset decisions as deny for safety.
			return &EscalatedCommandError{Command: command, Reason: "denied by user"}
		}
		return nil
	default:
		return nil
	}
}

// buildWrapConfig constructs a platform.WrapConfig from the config snapshot
// and per-call options.
//
//nolint:gocyclo // sequential config building; splitting would obscure the data flow
func (m *manager) buildWrapConfig(snap *configSnapshot, co *callOptions) *platform.WrapConfig {
	wcfg := &platform.WrapConfig{
		WritableRoots:  append([]string{}, snap.cfg.Filesystem.WritableRoots...),
		DenyWrite:      append([]string{}, snap.cfg.Filesystem.DenyWrite...),
		DenyRead:       append([]string{}, snap.cfg.Filesystem.DenyRead...),
		AllowGitConfig: snap.cfg.Filesystem.AllowGitConfig,
		Shell:          snap.cfg.Shell,
	}

	// Merge per-call writable roots.
	if len(co.writableRoots) > 0 {
		wcfg.WritableRoots = append(wcfg.WritableRoots, co.writableRoots...)
	}

	// Merge per-call deny read paths.
	if len(co.denyRead) > 0 {
		wcfg.DenyRead = append(wcfg.DenyRead, co.denyRead...)
	}

	// Merge per-call deny write paths.
	if len(co.denyWrite) > 0 {
		wcfg.DenyWrite = append(wcfg.DenyWrite, co.denyWrite...)
	}

	// Per-call shell override.
	if co.shell != "" {
		wcfg.Shell = co.shell
	}

	// Resolve symlinks and check boundaries for writable roots.
	// NOTE: There is a TOCTOU window between symlink resolution and
	// platform enforcement. Landlock/seatbelt provide kernel-level
	// protection that mitigates this for the actual enforcement.
	for i, root := range wcfg.WritableRoots {
		resolved, err := pathutil.ResolveWithBoundaryCheck(root)
		if err == nil {
			wcfg.WritableRoots[i] = resolved
		}
		// If resolution fails (broken symlink, etc.), keep original path.
	}

	// Auto-protect dangerous files if enabled.
	if snap.cfg.Filesystem.AutoProtectDangerousFiles {
		depth := snap.cfg.Filesystem.DangerousFileScanDepth
		if depth == 0 {
			depth = 5 // default
		}
		for _, root := range wcfg.WritableRoots {
			dangerous, err := pathutil.ScanDangerousFiles(root, depth)
			if err != nil {
				m.logger.Warn("dangerous file scan failed", "root", root, "error", err)
				continue
			}
			wcfg.DenyWrite = append(wcfg.DenyWrite, dangerous...)
		}
	}

	// Expand glob patterns in DenyRead.
	var expandedDenyRead []string
	for _, p := range wcfg.DenyRead {
		if pathutil.IsGlobPattern(p) {
			expanded, err := pathutil.ExpandGlob(p, 0)
			if err != nil {
				m.logger.Warn("glob expansion failed", "pattern", p, "error", err)
				continue
			}
			expandedDenyRead = append(expandedDenyRead, expanded...)
		} else {
			expandedDenyRead = append(expandedDenyRead, p)
		}
	}
	wcfg.DenyRead = expandedDenyRead

	// Expand glob patterns in DenyWrite.
	var expandedDenyWrite []string
	for _, p := range wcfg.DenyWrite {
		if pathutil.IsGlobPattern(p) {
			expanded, err := pathutil.ExpandGlob(p, 0)
			if err != nil {
				m.logger.Warn("glob expansion failed", "pattern", p, "error", err)
				continue
			}
			expandedDenyWrite = append(expandedDenyWrite, expanded...)
		} else {
			expandedDenyWrite = append(expandedDenyWrite, p)
		}
	}
	wcfg.DenyWrite = expandedDenyWrite

	// Check for git worktree - if .git is a file (worktree), skip hooks/config denies
	// since worktrees use a different .git layout.
	for _, root := range wcfg.WritableRoots {
		if pathutil.IsGitWorktree(root) {
			wcfg.DenyWrite = filterOutPrefix(wcfg.DenyWrite, filepath.Join(root, ".git", "hooks"))
		}
	}

	// Check non-existent paths in DenyWrite/DenyRead — protection may be
	// incomplete if the path does not fully exist on disk. We still record
	// the warning in wcfg.Warnings for programmatic access, but log at Debug
	// level because DefaultConfig includes many home-relative credential
	// paths (e.g. ~/.gnupg, ~/.kube) that commonly don't exist, and logging
	// them at Warn produces excessive noise on every command execution.
	for _, p := range wcfg.DenyWrite {
		if first := pathutil.FindFirstNonExistent(p); first != "" {
			w := fmt.Sprintf("DenyWrite path %q: component %q does not exist, protection may be incomplete", p, first)
			wcfg.Warnings = append(wcfg.Warnings, w)
			m.logger.Debug("non-existent deny path", "kind", "DenyWrite", "path", p, "missing", first)
		}
	}
	for _, p := range wcfg.DenyRead {
		if first := pathutil.FindFirstNonExistent(p); first != "" {
			w := fmt.Sprintf("DenyRead path %q: component %q does not exist, protection may be incomplete", p, first)
			wcfg.Warnings = append(wcfg.Warnings, w)
			m.logger.Debug("non-existent deny path", "kind", "DenyRead", "path", p, "missing", first)
		}
	}

	// Network restriction.
	netCfg := snap.cfg.Network
	if co.network != nil {
		netCfg = *co.network
	}
	if netCfg.Mode == NetworkBlocked || netCfg.Mode == NetworkFiltered {
		wcfg.NeedsNetworkRestriction = true
	}

	// Pass proxy ports to the platform wrapper when filtering is active.
	// httpProxyPort and socksProxyPort are immutable after creation, safe to read.
	if m.httpProxyPort > 0 {
		wcfg.HTTPProxyPort = m.httpProxyPort
	}
	if m.socksProxyPort > 0 {
		wcfg.SOCKSProxyPort = m.socksProxyPort
	}

	// Resource limits.
	if snap.cfg.ResourceLimits != nil {
		rl := *snap.cfg.ResourceLimits // copy the struct
		wcfg.ResourceLimits = &rl
	}

	// Pass through network feature flags.
	wcfg.AllowLocalBinding = netCfg.AllowLocalBinding
	wcfg.AllowAllUnixSockets = netCfg.AllowAllUnixSockets
	wcfg.AllowUnixSockets = append([]string{}, netCfg.AllowUnixSockets...)

	return wcfg
}

func (m *manager) Wrap(ctx context.Context, cmd *exec.Cmd, opts ...Option) error {
	if cmd == nil {
		return ErrNilCommand
	}

	snap, err := m.snapshotConfig()
	if err != nil {
		return err
	}

	co := mergeCallOptions(opts...)

	// Reject commands with empty Args to prevent unclassified execution.
	if len(cmd.Args) == 0 {
		return fmt.Errorf("%w: cmd.Args must not be empty", ErrNilCommand)
	}

	// Classify the command from cmd.Args.
	var result ClassifyResult
	// cmd.Args[0] is the program name, rest are arguments.
	if len(cmd.Args) > 1 {
		result = classifyArgs(&snap, cmd.Args[0], cmd.Args[1:], co)
	} else {
		result = classifyArgs(&snap, cmd.Args[0], nil, co)
	}

	// Build the command string for the approval request.
	command := buildCommandKey(cmd.Args[0], cmd.Args[1:])

	if err := m.handleDecision(ctx, result, command); err != nil {
		return err
	}

	wcfg := m.buildWrapConfig(&snap, co)

	// Apply per-call env.
	if len(co.env) > 0 {
		cmd.Env = append(cmd.Environ(), co.env...)
	}

	// Inject proxy environment variables when proxy is active.
	m.injectProxyEnv(cmd)

	return m.platform.WrapCommand(ctx, cmd, wcfg)
}

func (m *manager) Exec(ctx context.Context, command string, opts ...Option) (*ExecResult, error) {
	snap, err := m.snapshotConfig()
	if err != nil {
		return nil, err
	}

	co := mergeCallOptions(opts...)

	// Apply per-call timeout.
	if co.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, co.timeout)
		defer cancel()
	}

	// Classify the command string.
	result := classify(&snap, command, co)
	if err := m.handleDecision(ctx, result, command); err != nil {
		return nil, err
	}

	shell := snap.cfg.Shell
	if co.shell != "" {
		shell = co.shell
	}

	cmd := exec.CommandContext(ctx, shell, "-c", command)
	if co.workingDir != "" {
		cmd.Dir = co.workingDir
	}
	return m.runCommand(ctx, cmd, co, &snap)
}

func (m *manager) ExecArgs(ctx context.Context, name string, args []string, opts ...Option) (*ExecResult, error) {
	snap, err := m.snapshotConfig()
	if err != nil {
		return nil, err
	}

	co := mergeCallOptions(opts...)

	// Apply per-call timeout.
	if co.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, co.timeout)
		defer cancel()
	}

	// Classify the command.
	result := classifyArgs(&snap, name, args, co)
	if err := m.handleDecision(ctx, result, buildCommandKey(name, args)); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, name, args...)
	if co.workingDir != "" {
		cmd.Dir = co.workingDir
	}
	return m.runCommand(ctx, cmd, co, &snap)
}

// runCommand wraps, executes, and captures output from a command.
func (m *manager) runCommand(ctx context.Context, cmd *exec.Cmd, co *callOptions, snap *configSnapshot) (*ExecResult, error) {
	wcfg := m.buildWrapConfig(snap, co)

	// Apply per-call env.
	if len(co.env) > 0 {
		cmd.Env = append(cmd.Environ(), co.env...)
	}

	// Inject proxy environment variables when proxy is active.
	m.injectProxyEnv(cmd)

	// Wrap with platform sandbox (fail-closed by default).
	sandboxed := true
	if err := m.platform.WrapCommand(ctx, cmd, wcfg); err != nil {
		if snap.cfg.FallbackPolicy == FallbackWarn {
			m.logger.Warn("sandbox wrapping failed, running without sandbox", "error", err)
			sandboxed = false
		} else {
			return nil, fmt.Errorf("sandbox wrapping failed: %w", err)
		}
	}

	return execHelper(cmd, snap.cfg.MaxOutputBytes, sandboxed)
}

func (m *manager) Check(ctx context.Context, command string) (ClassifyResult, error) {
	snap, err := m.snapshotConfig()
	if err != nil {
		return ClassifyResult{}, err
	}
	co := &callOptions{}
	return classify(&snap, command, co), nil
}

func (m *manager) Cleanup(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true

	// Stop the proxy server if running.
	var proxyErr error
	if m.proxy != nil {
		proxyErr = m.proxy.Close()
	}

	platErr := m.platform.Cleanup(ctx)
	return errors.Join(proxyErr, platErr)
}

func (m *manager) Available() bool {
	return m.platform.Available()
}

func (m *manager) CheckDependencies() *DependencyCheck {
	return m.platform.CheckDependencies()
}

// injectProxyEnv appends proxy environment variables to cmd.Env when the
// proxy server is active (i.e., httpProxyPort or socksProxyPort > 0).
// Reads proxy ports under RLock to avoid races with UpdateConfig.
func (m *manager) injectProxyEnv(cmd *exec.Cmd) {
	m.mu.RLock()
	httpPort, socksPort := m.httpProxyPort, m.socksProxyPort
	m.mu.RUnlock()

	if httpPort == 0 && socksPort == 0 {
		return
	}
	proxyEnv := proxy.GenerateProxyEnv(&proxy.EnvConfig{
		HTTPProxyPort:  httpPort,
		SOCKSProxyPort: socksPort,
	})
	if len(proxyEnv) > 0 {
		if cmd.Env == nil {
			cmd.Env = cmd.Environ()
		}
		cmd.Env = append(cmd.Env, proxyEnv...)
	}
}

// limitedWriter wraps a bytes.Buffer and stops writing after limit bytes.
type limitedWriter struct {
	buf   *bytes.Buffer
	limit int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.buf.Len()
	if remaining <= 0 {
		return len(p), nil // discard but report success
	}
	if len(p) <= remaining {
		return w.buf.Write(p)
	}
	// Write only what fits, but report full length to avoid io.ErrShortWrite.
	_, err := w.buf.Write(p[:remaining])
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// UpdateConfig dynamically updates the manager's configuration.
// The new config is validated before being applied. Network filter rules
// and the classifier are hot-reloaded; filesystem changes take effect on
// the next Wrap/Exec call. When Network.Mode transitions between filtered
// and non-filtered, the proxy server is started or stopped accordingly.
func (m *manager) UpdateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("%w: config must not be nil", ErrConfigInvalid)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrManagerClosed
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	// Deep-copy slices to avoid aliasing the caller's data.
	cfgCopy := deepCopyConfig(cfg)

	// Normalize relative writable roots to absolute paths.
	for i, root := range cfgCopy.Filesystem.WritableRoots {
		if !filepath.IsAbs(root) {
			abs, err := filepath.Abs(root)
			if err != nil {
				return fmt.Errorf("%w: cannot resolve WritableRoots[%d] to absolute path: %w", ErrConfigInvalid, i, err)
			}
			cfgCopy.Filesystem.WritableRoots[i] = abs
		}
	}

	// Validate shell existence before applying any side effects (proxy lifecycle, etc.)
	// so that a validation failure does not leave the manager in a partially-updated state.
	if cfgCopy.Shell != "" {
		if _, err := os.Stat(cfgCopy.Shell); err != nil {
			return fmt.Errorf("%w: shell %q does not exist: %w", ErrConfigInvalid, cfgCopy.Shell, err)
		}
	}

	// Detect network mode transitions and manage proxy lifecycle.
	oldMode := m.cfg.Network.Mode
	newMode := cfgCopy.Network.Mode

	if oldMode != newMode {
		if err := m.handleModeTransition(oldMode, newMode, &cfgCopy); err != nil {
			return err
		}
	}

	// Hot-reload proxy filter rules if network domains changed (only when staying in filtered mode).
	if m.proxyFilter != nil && oldMode == NetworkFiltered && newMode == NetworkFiltered {
		oldNet := m.cfg.Network
		newNet := cfgCopy.Network
		if !stringSlicesEqual(oldNet.AllowedDomains, newNet.AllowedDomains) ||
			!stringSlicesEqual(oldNet.DeniedDomains, newNet.DeniedDomains) {
			if err := m.proxyFilter.UpdateRules(newNet.DeniedDomains, newNet.AllowedDomains); err != nil {
				return fmt.Errorf("%w: failed to update proxy filter rules: %w", ErrConfigInvalid, err)
			}
		}
	}

	// Update classifier if changed (non-nil override).
	if cfgCopy.Classifier != nil {
		m.cfg.Classifier = cfgCopy.Classifier
	}

	// Apply the rest of the config fields.
	m.cfg.Filesystem = cfgCopy.Filesystem
	m.cfg.Network = cfgCopy.Network
	if cfgCopy.Shell != "" {
		m.cfg.Shell = cfgCopy.Shell
	}
	m.cfg.MaxOutputBytes = cfgCopy.MaxOutputBytes
	m.cfg.ResourceLimits = cfgCopy.ResourceLimits
	m.cfg.FallbackPolicy = cfgCopy.FallbackPolicy

	// Update the approval callback.
	m.approvalCallback = cfgCopy.ApprovalCallback
	m.cfg.ApprovalCallback = cfgCopy.ApprovalCallback

	return nil
}

// handleModeTransition manages the proxy lifecycle when the network mode
// changes. It starts the proxy when entering filtered mode and stops it
// when leaving filtered mode. Must be called with m.mu held.
func (m *manager) handleModeTransition(oldMode, newMode NetworkMode, cfgCopy *Config) error {
	switch {
	case newMode == NetworkFiltered && oldMode != NetworkFiltered:
		// Starting filtered mode: create and start proxy.
		filter, err := proxy.NewDomainFilter(&proxy.FilterConfig{
			AllowedDomains: cfgCopy.Network.AllowedDomains,
			DeniedDomains:  cfgCopy.Network.DeniedDomains,
			OnRequest:      proxy.OnRequest(cfgCopy.Network.OnRequest),
		})
		if err != nil {
			return fmt.Errorf("%w: %w", ErrProxyStartFailed, err)
		}
		proxyCfg := &proxy.Config{
			Filter: filter,
			Logger: m.logger,
		}
		if cfgCopy.Network.MITMProxy != nil {
			proxyCfg.MITM = &proxy.MITMConfig{
				SocketPath: cfgCopy.Network.MITMProxy.SocketPath,
				Domains:    cfgCopy.Network.MITMProxy.Domains,
			}
		}
		ps, err := proxy.NewServer(proxyCfg)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrProxyStartFailed, err)
		}
		httpPort, socksPort, err := ps.Start(context.Background())
		if err != nil {
			_ = ps.Close()
			return fmt.Errorf("%w: %w", ErrProxyStartFailed, err)
		}
		// Stop old proxy if any (shouldn't happen but be safe).
		if m.proxy != nil {
			_ = m.proxy.Close()
		}
		m.proxy = ps
		m.proxyFilter = filter
		m.httpProxyPort = httpPort
		m.socksProxyPort = socksPort

	case newMode != NetworkFiltered && oldMode == NetworkFiltered:
		// Leaving filtered mode: stop proxy and clear ports.
		if m.proxy != nil {
			_ = m.proxy.Close()
		}
		m.proxy = nil
		m.proxyFilter = nil
		m.httpProxyPort = 0
		m.socksProxyPort = 0
	}
	return nil
}

// stringSlicesEqual reports whether two string slices have identical contents.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// filterOutPrefix returns a new slice with all entries that have the given
// prefix removed. This is used to strip git worktree-specific deny paths.
func filterOutPrefix(paths []string, prefix string) []string {
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		if !strings.HasPrefix(p, prefix) {
			result = append(result, p)
		}
	}
	return result
}

// normalizeCommand collapses whitespace in a command string so that
// "pip  install  requests" and "pip install requests" map to the same
// session-approval cache key.
func normalizeCommand(cmd string) string {
	return strings.Join(strings.Fields(cmd), " ")
}

// buildCommandKey constructs a normalized command string from a program name
// and argument list, preserving argument boundaries by quoting args that
// contain spaces. This is used for approval cache keys and approval prompts.
func buildCommandKey(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, name)
	for _, a := range args {
		if strings.ContainsAny(a, " \t\n\"\\") {
			parts = append(parts, strconv.Quote(a))
		} else {
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, " ")
}
