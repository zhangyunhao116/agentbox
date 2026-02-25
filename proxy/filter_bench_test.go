package proxy

import (
	"context"
	"net"
	"testing"
)

// ---------------------------------------------------------------------------
// DomainFilter.Filter benchmarks
// ---------------------------------------------------------------------------

func BenchmarkDomainFilter_AllowedDomain(b *testing.B) {
	f, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"*.example.com", "api.github.com"},
		DeniedDomains:  []string{"*.evil.com"},
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		f.Filter(ctx, "sub.example.com", 443)
	}
}

func BenchmarkDomainFilter_DeniedDomain(b *testing.B) {
	f, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"*.example.com"},
		DeniedDomains:  []string{"*.evil.com"},
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		f.Filter(ctx, "sub.evil.com", 443)
	}
}

func BenchmarkDomainFilter_DefaultDeny(b *testing.B) {
	f, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"*.example.com"},
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		f.Filter(ctx, "unknown.org", 443)
	}
}

func BenchmarkDomainFilter_ExactAllowed(b *testing.B) {
	f, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"api.github.com"},
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		f.Filter(ctx, "api.github.com", 443)
	}
}

func BenchmarkDomainFilter_IPHost_Blocked(b *testing.B) {
	f, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"*.example.com"},
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		f.Filter(ctx, "127.0.0.1", 80)
	}
}

func BenchmarkDomainFilter_IPHost_Public(b *testing.B) {
	f, err := NewDomainFilter(&FilterConfig{
		AllowedDomains: []string{"*.example.com"},
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		f.Filter(ctx, "8.8.8.8", 443)
	}
}

// ---------------------------------------------------------------------------
// isBlockedIP benchmarks
// ---------------------------------------------------------------------------

func BenchmarkIsBlockedIP_Public(b *testing.B) {
	ip := net.ParseIP("8.8.8.8")
	b.ResetTimer()
	for b.Loop() {
		isBlockedIP(ip)
	}
}

func BenchmarkIsBlockedIP_Loopback(b *testing.B) {
	ip := net.ParseIP("127.0.0.1")
	b.ResetTimer()
	for b.Loop() {
		isBlockedIP(ip)
	}
}

func BenchmarkIsBlockedIP_CloudMetadata(b *testing.B) {
	ip := net.ParseIP("169.254.169.254")
	b.ResetTimer()
	for b.Loop() {
		isBlockedIP(ip)
	}
}

func BenchmarkIsBlockedIP_RFC1918(b *testing.B) {
	ip := net.ParseIP("192.168.1.1")
	b.ResetTimer()
	for b.Loop() {
		isBlockedIP(ip)
	}
}

func BenchmarkIsBlockedIP_IPv6Loopback(b *testing.B) {
	ip := net.ParseIP("::1")
	b.ResetTimer()
	for b.Loop() {
		isBlockedIP(ip)
	}
}

// ---------------------------------------------------------------------------
// ValidateDomainPattern benchmarks
// ---------------------------------------------------------------------------

func BenchmarkValidateDomainPattern_Wildcard(b *testing.B) {
	for b.Loop() {
		ValidateDomainPattern("*.example.com")
	}
}

func BenchmarkValidateDomainPattern_Exact(b *testing.B) {
	for b.Loop() {
		ValidateDomainPattern("example.com")
	}
}

// ---------------------------------------------------------------------------
// matchesDomain benchmarks
// ---------------------------------------------------------------------------

func BenchmarkMatchesDomain_Wildcard(b *testing.B) {
	for b.Loop() {
		matchesDomain("sub.example.com", "*.example.com")
	}
}

func BenchmarkMatchesDomain_Exact(b *testing.B) {
	for b.Loop() {
		matchesDomain("example.com", "example.com")
	}
}

func BenchmarkMatchesDomain_NoMatch(b *testing.B) {
	for b.Loop() {
		matchesDomain("other.org", "*.example.com")
	}
}
