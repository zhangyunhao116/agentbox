//go:build darwin

package darwin

import (
	"context"
	"os/exec"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
)

// BenchmarkProfileBuild_Minimal benchmarks profile generation with a minimal
// configuration (single writable root, shell only).
func BenchmarkProfileBuild_Minimal(b *testing.B) {
	pb := newProfileBuilder()
	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/tmp/test"},
		Shell:         "/bin/sh",
	}
	b.ResetTimer()
	for b.Loop() {
		pb.Build(cfg)
	}
}

// BenchmarkProfileBuild_Full benchmarks profile generation with a fully
// populated configuration including network restrictions and proxy ports.
func BenchmarkProfileBuild_Full(b *testing.B) {
	pb := newProfileBuilder()
	cfg := &platform.WrapConfig{
		WritableRoots:           []string{"/tmp/test", "/home/user/project", "/var/data"},
		DenyRead:                []string{"/etc/shadow", "/root"},
		DenyWrite:               []string{"/usr", "/bin"},
		Shell:                   "/bin/bash",
		AllowGitConfig:          true,
		NeedsNetworkRestriction: true,
		HTTPProxyPort:           8080,
		SOCKSProxyPort:          1080,
	}
	b.ResetTimer()
	for b.Loop() {
		pb.Build(cfg)
	}
}

// BenchmarkProfileBuild_NetworkUnrestricted benchmarks profile generation
// when network access is unrestricted (the common non-proxy path).
func BenchmarkProfileBuild_NetworkUnrestricted(b *testing.B) {
	pb := newProfileBuilder()
	cfg := &platform.WrapConfig{
		WritableRoots:           []string{"/tmp/test"},
		NeedsNetworkRestriction: false,
		Shell:                   "/bin/sh",
	}
	b.ResetTimer()
	for b.Loop() {
		pb.Build(cfg)
	}
}

// BenchmarkEscapeForSBPL benchmarks SBPL string escaping with special characters.
func BenchmarkEscapeForSBPL(b *testing.B) {
	for b.Loop() {
		escapeForSBPL("/path/with spaces/and\"quotes")
	}
}

// BenchmarkCanonicalizePath benchmarks path canonicalization for a /tmp path
// (which triggers the macOS /private/tmp symlink resolution).
func BenchmarkCanonicalizePath(b *testing.B) {
	for b.Loop() {
		canonicalizePath("/tmp/test")
	}
}

// BenchmarkCanonicalizePath_Cached benchmarks path canonicalization
// with a warm cache (sync.Map hit path).
func BenchmarkCanonicalizePath_Cached(b *testing.B) {
	// Warm up cache
	canonicalizePath("/tmp/test")
	b.ResetTimer()
	for b.Loop() {
		canonicalizePath("/tmp/test")
	}
}


// BenchmarkWrapCommand_Cached benchmarks WrapCommand with repeated calls using
// the same configuration to measure cache hit performance.
func BenchmarkWrapCommand_Cached(b *testing.B) {
	p := New()
	ctx := context.Background()
	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/tmp/test"},
		DenyWrite:     []string{"/usr"},
	}

	// Warm up the cache.
	cmd := exec.CommandContext(ctx, "/bin/echo", "warmup")
	if err := p.WrapCommand(ctx, cmd, cfg); err != nil {
		b.Fatalf("Warmup error: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		cmd := exec.CommandContext(ctx, "/bin/echo", "hello")
		if err := p.WrapCommand(ctx, cmd, cfg); err != nil {
			b.Fatalf("WrapCommand error: %v", err)
		}
	}
}

// BenchmarkWrapCommand_CacheMiss benchmarks WrapCommand with varying configs
// that produce cache misses on each call.
func BenchmarkWrapCommand_CacheMiss(b *testing.B) {
	p := New()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use loop index to vary the configuration on each iteration.
		cfg := &platform.WrapConfig{
			WritableRoots: []string{"/tmp/test"},
			HTTPProxyPort: i % 10000, // Vary port to force cache miss
		}
		cmd := exec.CommandContext(ctx, "/bin/echo", "hello")
		if err := p.WrapCommand(ctx, cmd, cfg); err != nil {
			b.Fatalf("WrapCommand error: %v", err)
		}
	}
}

