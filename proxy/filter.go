package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

// FilterFunc determines whether a connection to the given host:port is allowed.
// It returns true to allow the connection, false to deny it.
// If an error is returned, the connection is denied and the error is logged.
type FilterFunc func(ctx context.Context, host string, port int) (bool, error)

// OnRequest is a callback for dynamic domain filtering decisions.
// It is invoked when a host does not match any static denied or allowed rule.
// Return true to allow the connection, false to deny.
type OnRequest func(ctx context.Context, host string, port int) (bool, error)

// AskCallback is called when a network request doesn't match any allow/deny rule.
// It returns true to allow the request, false to deny it.
// This is functionally equivalent to OnRequest and provides an alternative
// callback mechanism for network request approval.
type AskCallback func(ctx context.Context, host string, port int) (allow bool, err error)

// FilterConfig configures the domain filter.
type FilterConfig struct {
	// DeniedDomains is a list of domain patterns that are always blocked.
	// Supports exact match (e.g. "example.com") and wildcard (e.g. "*.example.com").
	DeniedDomains []string

	// AllowedDomains is a list of domain patterns that are always permitted.
	// Supports exact match and wildcard patterns.
	AllowedDomains []string

	// OnRequest is an optional callback invoked when no static rule matches.
	// If nil, unmatched domains are denied by default.
	OnRequest OnRequest

	// AskCallback is an optional callback invoked when no static rule matches
	// and OnRequest is nil. It provides an alternative mechanism for dynamic
	// network request approval. If both OnRequest and AskCallback are set,
	// OnRequest takes precedence. If neither is set, unmatched domains are
	// denied by default.
	AskCallback AskCallback
}

// DomainFilter implements domain-based filtering with priority:
// denied > allowed > OnRequest > default deny.
//
// It is safe for concurrent use.
type DomainFilter struct {
	mu      sync.RWMutex
	denied  []string
	allowed []string
	onReq   OnRequest
	askCb   AskCallback
}

// NewDomainFilter creates a new DomainFilter from the given configuration.
// It validates all domain patterns during construction and returns an error
// if any pattern is invalid.
func NewDomainFilter(cfg *FilterConfig) (*DomainFilter, error) {
	if cfg == nil {
		return &DomainFilter{}, nil
	}

	for _, p := range cfg.DeniedDomains {
		if err := ValidateDomainPattern(p); err != nil {
			return nil, fmt.Errorf("invalid denied domain pattern %q: %w", p, err)
		}
	}
	for _, p := range cfg.AllowedDomains {
		if err := ValidateDomainPattern(p); err != nil {
			return nil, fmt.Errorf("invalid allowed domain pattern %q: %w", p, err)
		}
	}

	denied := make([]string, len(cfg.DeniedDomains))
	copy(denied, cfg.DeniedDomains)
	allowed := make([]string, len(cfg.AllowedDomains))
	copy(allowed, cfg.AllowedDomains)

	return &DomainFilter{
		denied:  denied,
		allowed: allowed,
		onReq:   cfg.OnRequest,
		askCb:   cfg.AskCallback,
	}, nil
}

// Filter checks whether a connection to the given host and port should be allowed.
//
// Priority order:
//  1. If the host resolves to a blocked IP, deny.
//  2. If the host matches a denied domain pattern, deny.
//  3. If the host matches an allowed domain pattern, allow.
//  4. If an OnRequest callback is set, delegate to it.
//  5. Default: deny.
func (f *DomainFilter) Filter(ctx context.Context, host string, port int) (bool, error) {
	// Check if host is a raw IP address.
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return false, nil
		}
	}

	f.mu.RLock()
	denied := f.denied
	allowed := f.allowed
	onReq := f.onReq
	askCb := f.askCb
	f.mu.RUnlock()

	// Check denied list first (highest priority).
	for _, pattern := range denied {
		if matchesDomain(host, pattern) {
			return false, nil
		}
	}

	// Check allowed list.
	for _, pattern := range allowed {
		if matchesDomain(host, pattern) {
			return true, nil
		}
	}

	// Delegate to OnRequest callback if available.
	if onReq != nil {
		return onReq(ctx, host, port)
	}

	// Fall back to AskCallback if available.
	if askCb != nil {
		return askCb(ctx, host, port)
	}

	// Default deny.
	return false, nil
}

// UpdateRules dynamically updates the denied and allowed domain lists.
// It validates all patterns before applying the update. This method is thread-safe.
func (f *DomainFilter) UpdateRules(denied, allowed []string) error {
	for _, p := range denied {
		if err := ValidateDomainPattern(p); err != nil {
			return fmt.Errorf("invalid denied domain pattern %q: %w", p, err)
		}
	}
	for _, p := range allowed {
		if err := ValidateDomainPattern(p); err != nil {
			return fmt.Errorf("invalid allowed domain pattern %q: %w", p, err)
		}
	}

	newDenied := make([]string, len(denied))
	copy(newDenied, denied)
	newAllowed := make([]string, len(allowed))
	copy(newAllowed, allowed)

	f.mu.Lock()
	f.denied = newDenied
	f.allowed = newAllowed
	f.mu.Unlock()

	return nil
}

// matchesDomain checks if hostname matches a domain pattern.
// Supports exact match and wildcard patterns (*.example.com).
// *.example.com matches sub.example.com but NOT example.com itself.
// Matching is case-insensitive.
func matchesDomain(hostname, pattern string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))

	if !strings.HasPrefix(pattern, "*.") {
		// Exact match.
		return hostname == pattern
	}

	// Wildcard match: *.example.com
	// Strip the "*" prefix to get ".example.com".
	suffix := pattern[1:] // ".example.com"

	// The hostname must end with the suffix and must be longer than the suffix
	// (i.e., there must be a subdomain part). This ensures *.example.com does
	// NOT match example.com itself.
	return len(hostname) > len(suffix) && strings.HasSuffix(hostname, suffix)
}

// ValidateDomainPattern validates a domain pattern string.
// Valid patterns are either a bare domain (e.g. "example.com") or a wildcard
// pattern (e.g. "*.example.com"). The pattern must contain at least one dot,
// must not include a protocol prefix, and wildcard patterns must start with "*.".
func ValidateDomainPattern(pattern string) error {
	if pattern == "" {
		return errors.New("empty domain pattern")
	}

	// Reject protocol prefixes.
	if strings.Contains(pattern, "://") {
		return errors.New("domain pattern must not contain protocol prefix")
	}

	// Reject patterns with port numbers.
	if strings.Contains(pattern, ":") {
		return errors.New("domain pattern must not contain port")
	}

	// Reject patterns with path components.
	if strings.Contains(pattern, "/") {
		return errors.New("domain pattern must not contain path")
	}

	// Strip optional trailing dot for validation.
	p := strings.TrimSuffix(pattern, ".")

	// Handle wildcard patterns.
	if strings.HasPrefix(p, "*.") {
		// Validate the domain part after "*.".
		domain := p[2:]
		if !strings.Contains(domain, ".") {
			return errors.New("domain pattern must contain at least one dot in the domain part")
		}
		return nil
	}

	// Reject other wildcard positions.
	if strings.Contains(p, "*") {
		return errors.New("wildcard (*) is only allowed at the beginning as *.<domain>")
	}

	// Bare domain must contain at least one dot.
	if !strings.Contains(p, ".") {
		return errors.New("domain pattern must contain at least one dot")
	}

	return nil
}

// blockedIPNets contains the CIDR ranges that are blocked by default.
// These include loopback, link-local, multicast, RFC1918 private ranges,
// and IPv6 unique local addresses (ULA).
var blockedIPNets []*net.IPNet

// cloudMetadataIP is the well-known cloud metadata service IP (169.254.169.254).
var cloudMetadataIP = net.ParseIP("169.254.169.254")

func init() {
	cidrs := []string{
		// IPv4 "this host on this network" (0.0.0.0/8).
		"0.0.0.0/8",
		// IPv4 loopback.
		"127.0.0.0/8",
		// IPv4 link-local.
		"169.254.0.0/16",
		// IPv4 multicast.
		"224.0.0.0/4",
		// RFC1918 private ranges.
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		// Shared address space (RFC 6598 / CGNAT).
		"100.64.0.0/10",
		// IPv6 loopback.
		"::1/128",
		// IPv6 link-local.
		"fe80::/10",
		// IPv6 multicast.
		"ff00::/8",
		// IPv6 unique local address (ULA).
		"fc00::/7",
	}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse CIDR %q: %v", cidr, err))
		}
		blockedIPNets = append(blockedIPNets, ipNet)
	}
}

// isBlockedIP checks if an IP is in a blocked range.
// Blocks: loopback, link-local, multicast, RFC1918 private, IPv6 ULA,
// and the cloud metadata service IP (169.254.169.254).
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check cloud metadata IP explicitly.
	if ip.Equal(cloudMetadataIP) {
		return true
	}

	for _, ipNet := range blockedIPNets {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}
