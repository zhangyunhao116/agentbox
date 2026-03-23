// manager_update.go provides dynamic configuration update methods for the
// manager, including UpdateConfig and network mode transition handling.
package agentbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zhangyunhao116/agentbox/proxy"
)

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

	// Update the approval cache.
	m.approvalCache = cfgCopy.ApprovalCache
	m.cfg.ApprovalCache = cfgCopy.ApprovalCache

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
