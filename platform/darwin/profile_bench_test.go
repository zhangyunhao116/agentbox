//go:build darwin

package darwin

import (
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
