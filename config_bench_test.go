package agentbox

import "testing"

func BenchmarkDefaultConfig(b *testing.B) {
	for b.Loop() {
		DefaultConfig()
	}
}

func BenchmarkConfigValidate(b *testing.B) {
	cfg := DefaultConfig()
	b.ResetTimer()
	for b.Loop() {
		_ = cfg.Validate()
	}
}

func BenchmarkConfigValidate_WithDomains(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Network.AllowedDomains = []string{"*.example.com", "api.github.com", "registry.npmjs.org"}
	cfg.Network.DeniedDomains = []string{"*.evil.com", "malware.example.org"}
	b.ResetTimer()
	for b.Loop() {
		_ = cfg.Validate()
	}
}
