package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// matchesDomain tests
// ---------------------------------------------------------------------------

func TestMatchesDomain_ExactMatch(t *testing.T) {
	tests := []struct {
		hostname string
		pattern  string
		want     bool
	}{
		{"example.com", "example.com", true},
		{"api.github.com", "api.github.com", true},
		{"example.com", "other.com", false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.hostname, tt.pattern), func(t *testing.T) {
			if got := matchesDomain(tt.hostname, tt.pattern); got != tt.want {
				t.Errorf("matchesDomain(%q, %q) = %v, want %v", tt.hostname, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestMatchesDomain_WildcardMatch(t *testing.T) {
	tests := []struct {
		hostname string
		pattern  string
		want     bool
	}{
		{"sub.example.com", "*.example.com", true},
		{"deep.sub.example.com", "*.example.com", true},
		{"api.github.com", "*.github.com", true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.hostname, tt.pattern), func(t *testing.T) {
			if got := matchesDomain(tt.hostname, tt.pattern); got != tt.want {
				t.Errorf("matchesDomain(%q, %q) = %v, want %v", tt.hostname, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestMatchesDomain_WildcardDoesNotMatchBareDomain(t *testing.T) {
	// *.example.com should NOT match example.com itself.
	if matchesDomain("example.com", "*.example.com") {
		t.Error("matchesDomain(\"example.com\", \"*.example.com\") = true, want false")
	}
}

func TestMatchesDomain_CaseInsensitive(t *testing.T) {
	tests := []struct {
		hostname string
		pattern  string
		want     bool
	}{
		{"Example.COM", "example.com", true},
		{"SUB.Example.COM", "*.example.com", true},
		{"example.com", "EXAMPLE.COM", true},
		{"sub.example.com", "*.EXAMPLE.COM", true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.hostname, tt.pattern), func(t *testing.T) {
			if got := matchesDomain(tt.hostname, tt.pattern); got != tt.want {
				t.Errorf("matchesDomain(%q, %q) = %v, want %v", tt.hostname, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestMatchesDomain_TrailingDot(t *testing.T) {
	// FQDN trailing dots should be handled.
	tests := []struct {
		hostname string
		pattern  string
		want     bool
	}{
		{"example.com.", "example.com", true},
		{"example.com", "example.com.", true},
		{"sub.example.com.", "*.example.com.", true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.hostname, tt.pattern), func(t *testing.T) {
			if got := matchesDomain(tt.hostname, tt.pattern); got != tt.want {
				t.Errorf("matchesDomain(%q, %q) = %v, want %v", tt.hostname, tt.pattern, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidateDomainPattern tests
// ---------------------------------------------------------------------------

func TestValidateDomainPattern_Valid(t *testing.T) {
	valid := []string{
		"example.com",
		"*.example.com",
		"sub.example.com",
		"*.sub.example.com",
		"a.b.c.d.example.com",
	}
	for _, p := range valid {
		t.Run(p, func(t *testing.T) {
			if err := ValidateDomainPattern(p); err != nil {
				t.Errorf("ValidateDomainPattern(%q) returned error: %v", p, err)
			}
		})
	}
}

func TestValidateDomainPattern_Invalid(t *testing.T) {
	invalid := []struct {
		pattern string
		desc    string
	}{
		{"", "empty"},
		{"localhost", "no dot"},
		{"http://example.com", "protocol prefix"},
		{"https://example.com", "protocol prefix https"},
		{"example.com:443", "port number"},
		{"example.com/path", "path component"},
		{"*example.com", "bad wildcard no dot"},
		{"**.example.com", "bad wildcard double star"},
		{"exam*ple.com", "wildcard in middle"},
		{"*.com", "wildcard with single-level domain"},
		{"*.", "wildcard missing domain"},
	}
	for _, tt := range invalid {
		t.Run(tt.desc, func(t *testing.T) {
			if err := ValidateDomainPattern(tt.pattern); err == nil {
				t.Errorf("ValidateDomainPattern(%q) expected error for %s, got nil", tt.pattern, tt.desc)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isBlockedIP tests
// ---------------------------------------------------------------------------

func TestIsBlockedIP_Loopback(t *testing.T) {
	tests := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("127.0.0.2"),
		net.ParseIP("127.255.255.255"),
		net.ParseIP("::1"),
	}
	for _, ip := range tests {
		t.Run(ip.String(), func(t *testing.T) {
			if !isBlockedIP(ip) {
				t.Errorf("isBlockedIP(%s) = false, want true (loopback)", ip)
			}
		})
	}
}

func TestIsBlockedIP_Private(t *testing.T) {
	tests := []net.IP{
		net.ParseIP("10.0.0.1"),
		net.ParseIP("10.255.255.255"),
		net.ParseIP("172.16.0.1"),
		net.ParseIP("172.31.255.255"),
		net.ParseIP("192.168.0.1"),
		net.ParseIP("192.168.255.255"),
	}
	for _, ip := range tests {
		t.Run(ip.String(), func(t *testing.T) {
			if !isBlockedIP(ip) {
				t.Errorf("isBlockedIP(%s) = false, want true (private)", ip)
			}
		})
	}
}

func TestIsBlockedIP_LinkLocal(t *testing.T) {
	tests := []net.IP{
		net.ParseIP("169.254.1.1"),
		net.ParseIP("169.254.0.0"),
		net.ParseIP("fe80::1"),
	}
	for _, ip := range tests {
		t.Run(ip.String(), func(t *testing.T) {
			if !isBlockedIP(ip) {
				t.Errorf("isBlockedIP(%s) = false, want true (link-local)", ip)
			}
		})
	}
}

func TestIsBlockedIP_Multicast(t *testing.T) {
	tests := []net.IP{
		net.ParseIP("224.0.0.1"),
		net.ParseIP("239.255.255.255"),
		net.ParseIP("ff02::1"),
	}
	for _, ip := range tests {
		t.Run(ip.String(), func(t *testing.T) {
			if !isBlockedIP(ip) {
				t.Errorf("isBlockedIP(%s) = false, want true (multicast)", ip)
			}
		})
	}
}

func TestIsBlockedIP_CloudMetadata(t *testing.T) {
	ip := net.ParseIP("169.254.169.254")
	if !isBlockedIP(ip) {
		t.Error("isBlockedIP(169.254.169.254) = false, want true (cloud metadata)")
	}
}

func TestIsBlockedIP_IPv6ULA(t *testing.T) {
	ip := net.ParseIP("fd00::1")
	if !isBlockedIP(ip) {
		t.Error("isBlockedIP(fd00::1) = false, want true (IPv6 ULA)")
	}
}

func TestIsBlockedIP_PublicIPs(t *testing.T) {
	public := []net.IP{
		net.ParseIP("8.8.8.8"),
		net.ParseIP("1.1.1.1"),
		net.ParseIP("93.184.216.34"),
		net.ParseIP("2606:4700::1111"),
	}
	for _, ip := range public {
		t.Run(ip.String(), func(t *testing.T) {
			if isBlockedIP(ip) {
				t.Errorf("isBlockedIP(%s) = true, want false (public IP)", ip)
			}
		})
	}
}

func TestIsBlockedIP_NilIP(t *testing.T) {
	if isBlockedIP(nil) {
		t.Error("isBlockedIP(nil) = true, want false")
	}
}

func TestIsBlockedIP_ZeroNetwork(t *testing.T) {
	// 0.0.0.0/8 should be blocked.
	blockedIPs := []net.IP{
		net.ParseIP("0.0.0.0"),
		net.ParseIP("0.0.0.1"),
		net.ParseIP("0.255.255.255"),
	}
	for _, ip := range blockedIPs {
		t.Run(ip.String(), func(t *testing.T) {
			if !isBlockedIP(ip) {
				t.Errorf("isBlockedIP(%s) = false, want true", ip)
			}
		})
	}
}

func TestIsBlockedIP_CGNAT(t *testing.T) {
	// 100.64.0.0/10 (Shared Address Space / CGNAT) should be blocked.
	blockedIPs := []net.IP{
		net.ParseIP("100.64.0.0"),
		net.ParseIP("100.64.0.1"),
		net.ParseIP("100.127.255.255"),
	}
	for _, ip := range blockedIPs {
		t.Run(ip.String(), func(t *testing.T) {
			if !isBlockedIP(ip) {
				t.Errorf("isBlockedIP(%s) = false, want true", ip)
			}
		})
	}

	// 100.128.0.0 should NOT be blocked (outside CGNAT range).
	notBlocked := net.ParseIP("100.128.0.0")
	if isBlockedIP(notBlocked) {
		t.Errorf("isBlockedIP(%s) = true, want false (outside CGNAT range)", notBlocked)
	}
}

// ---------------------------------------------------------------------------
// DomainFilter.Filter tests
// ---------------------------------------------------------------------------

func TestDomainFilter_DeniedOverAllowed(t *testing.T) {
	f, err := NewDomainFilter(&FilterConfig{
		DeniedDomains:  []string{"evil.example.com"},
		AllowedDomains: []string{"*.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// evil.example.com is denied even though *.example.com is allowed.
	allowed, err := f.Filter(context.Background(), "evil.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected evil.example.com to be denied (denied > allowed)")
	}

	// good.example.com should be allowed.
	allowed, err = f.Filter(context.Background(), "good.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected good.example.com to be allowed")
	}
}

func TestDomainFilter_AllowedOverDefault(t *testing.T) {
	f, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"api.github.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := f.Filter(context.Background(), "api.github.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected api.github.com to be allowed")
	}

	// Unmatched domain should be denied by default.
	allowed, err = f.Filter(context.Background(), "other.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected other.com to be denied (default deny)")
	}
}

func TestDomainFilter_OnRequestCallback(t *testing.T) {
	callbackCalled := false
	f, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"known.example.com"},
		OnRequest: func(ctx context.Context, host string, port int) (bool, error) {
			callbackCalled = true
			if host == "dynamic.example.com" {
				return true, nil
			}
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Known domain should not trigger callback.
	allowed, err := f.Filter(context.Background(), "known.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected known.example.com to be allowed")
	}
	if callbackCalled {
		t.Error("OnRequest should not be called for statically allowed domains")
	}

	// Unknown domain should trigger callback.
	allowed, err = f.Filter(context.Background(), "dynamic.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected dynamic.example.com to be allowed via OnRequest")
	}
	if !callbackCalled {
		t.Error("OnRequest should have been called")
	}

	// Another unknown domain denied by callback.
	allowed, err = f.Filter(context.Background(), "unknown.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected unknown.example.com to be denied by OnRequest")
	}
}

func TestDomainFilter_OnRequestError(t *testing.T) {
	expectedErr := errors.New("callback error")
	f, err := NewDomainFilter(&FilterConfig{
		OnRequest: func(ctx context.Context, host string, port int) (bool, error) {
			return false, expectedErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Filter(context.Background(), "example.com", 443)
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

func TestDomainFilter_NilOnRequest(t *testing.T) {
	f, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"allowed.example.com"},
		OnRequest:      nil,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Unmatched domain should be denied (default deny, no callback).
	allowed, err := f.Filter(context.Background(), "other.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected other.example.com to be denied (nil OnRequest, default deny)")
	}
}

func TestDomainFilter_DefaultDeny(t *testing.T) {
	f, err := NewDomainFilter(&FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := f.Filter(context.Background(), "anything.com", 80)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected default deny for empty filter")
	}
}

func TestDomainFilter_NilConfig(t *testing.T) {
	f, err := NewDomainFilter(nil)
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := f.Filter(context.Background(), "anything.com", 80)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected default deny for nil config")
	}
}

func TestDomainFilter_BlockedIP(t *testing.T) {
	f, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"*.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Raw IP addresses that are blocked should be denied.
	tests := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"169.254.169.254", false},
		{"::1", false},
		{"8.8.8.8", false}, // Public IP, but not in allowed list -> default deny.
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			allowed, err := f.Filter(context.Background(), tt.host, 80)
			if err != nil {
				t.Fatal(err)
			}
			if allowed != tt.want {
				t.Errorf("Filter(%q) = %v, want %v", tt.host, allowed, tt.want)
			}
		})
	}
}

func TestDomainFilter_EmptyLists(t *testing.T) {
	f, err := NewDomainFilter(&FilterConfig{
		DeniedDomains:  []string{},
		AllowedDomains: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := f.Filter(context.Background(), "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected default deny with empty lists")
	}
}

// ---------------------------------------------------------------------------
// DomainFilter.UpdateRules tests
// ---------------------------------------------------------------------------

func TestDomainFilter_UpdateRules(t *testing.T) {
	f, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"old.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Before update: old.example.com is allowed.
	allowed, err := f.Filter(context.Background(), "old.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected old.example.com to be allowed before update")
	}

	// Update rules.
	err = f.UpdateRules(
		[]string{"old.example.com"},
		[]string{"new.example.com"},
	)
	if err != nil {
		t.Fatal(err)
	}

	// After update: old.example.com is now denied.
	allowed, err = f.Filter(context.Background(), "old.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected old.example.com to be denied after update")
	}

	// After update: new.example.com is allowed.
	allowed, err = f.Filter(context.Background(), "new.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected new.example.com to be allowed after update")
	}
}

func TestDomainFilter_UpdateRulesInvalidPattern(t *testing.T) {
	f, err := NewDomainFilter(&FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}

	// Invalid denied pattern.
	err = f.UpdateRules([]string{"invalid"}, nil)
	if err == nil {
		t.Error("expected error for invalid denied pattern")
	}

	// Invalid allowed pattern.
	err = f.UpdateRules(nil, []string{"http://bad.com"})
	if err == nil {
		t.Error("expected error for invalid allowed pattern")
	}
}

func TestDomainFilter_UpdateRulesConcurrent(t *testing.T) {
	f, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"initial.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	ctx := context.Background()

	// Concurrent readers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = f.Filter(ctx, "initial.example.com", 443)
				_, _ = f.Filter(ctx, "other.example.com", 443)
			}
		}()
	}

	// Concurrent writers.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				domain := fmt.Sprintf("domain%d-%d.example.com", i, j)
				_ = f.UpdateRules(nil, []string{domain})
			}
		}(i)
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// NewDomainFilter validation tests
// ---------------------------------------------------------------------------

func TestNewDomainFilter_InvalidDeniedPattern(t *testing.T) {
	_, err := NewDomainFilter(&FilterConfig{
		DeniedDomains: []string{"invalid"},
	})
	if err == nil {
		t.Error("expected error for invalid denied domain pattern")
	}
}

func TestNewDomainFilter_InvalidAllowedPattern(t *testing.T) {
	_, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"http://bad.com"},
	})
	if err == nil {
		t.Error("expected error for invalid allowed domain pattern")
	}
}

// ---------------------------------------------------------------------------
// AskCallback tests
// ---------------------------------------------------------------------------

// TestFilterAskCallbackAllow verifies that AskCallback returning true allows the request.
func TestFilterAskCallbackAllow(t *testing.T) {
	f, err := NewDomainFilter(&FilterConfig{
		AskCallback: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := f.Filter(context.Background(), "unknown.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected request to be allowed via AskCallback")
	}
}

// TestFilterAskCallbackDeny verifies that AskCallback returning false denies the request.
func TestFilterAskCallbackDeny(t *testing.T) {
	f, err := NewDomainFilter(&FilterConfig{
		AskCallback: func(ctx context.Context, host string, port int) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := f.Filter(context.Background(), "unknown.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected request to be denied via AskCallback")
	}
}

// TestFilterAskCallbackError verifies that AskCallback returning an error denies the request.
func TestFilterAskCallbackError(t *testing.T) {
	expectedErr := errors.New("ask callback error")
	f, err := NewDomainFilter(&FilterConfig{
		AskCallback: func(ctx context.Context, host string, port int) (bool, error) {
			return false, expectedErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Filter(context.Background(), "unknown.example.com", 443)
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

// TestFilterAskCallbackNil verifies that with no callback set, requests are denied by default.
func TestFilterAskCallbackNil(t *testing.T) {
	f, err := NewDomainFilter(&FilterConfig{
		AskCallback: nil,
		OnRequest:   nil,
	})
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := f.Filter(context.Background(), "unknown.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected request to be denied (nil AskCallback, nil OnRequest, default deny)")
	}
}

// TestFilterAskCallbackNotCalled verifies that AskCallback is not called when
// the request matches the allow list.
func TestFilterAskCallbackNotCalled(t *testing.T) {
	called := false
	f, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"allowed.example.com"},
		AskCallback: func(ctx context.Context, host string, port int) (bool, error) {
			called = true
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := f.Filter(context.Background(), "allowed.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected allowed.example.com to be allowed via allow list")
	}
	if called {
		t.Error("AskCallback should not be called when request matches allow list")
	}
}

// TestFilterAskCallbackOnRequestTakesPrecedence verifies that OnRequest takes
// precedence over AskCallback when both are set.
func TestFilterAskCallbackOnRequestTakesPrecedence(t *testing.T) {
	askCalled := false
	f, err := NewDomainFilter(&FilterConfig{
		OnRequest: func(ctx context.Context, host string, port int) (bool, error) {
			return true, nil // OnRequest allows
		},
		AskCallback: func(ctx context.Context, host string, port int) (bool, error) {
			askCalled = true
			return false, nil // AskCallback would deny
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := f.Filter(context.Background(), "unknown.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected request to be allowed via OnRequest (takes precedence)")
	}
	if askCalled {
		t.Error("AskCallback should not be called when OnRequest is set")
	}
}
