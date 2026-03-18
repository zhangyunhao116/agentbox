//go:build linux

package main

import (
	"encoding/json"
	"testing"
)

func TestHelperConfigParsing(t *testing.T) {
	input := `{"writable_roots":["/tmp","/workspace"],"deny_write":["/etc"],"command":["sh","-c","echo hello"]}`
	var cfg HelperConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cfg.WritableRoots) != 2 {
		t.Errorf("WritableRoots = %v, want 2 items", cfg.WritableRoots)
	}
	if cfg.WritableRoots[0] != "/tmp" {
		t.Errorf("WritableRoots[0] = %q, want /tmp", cfg.WritableRoots[0])
	}
	if cfg.WritableRoots[1] != "/workspace" {
		t.Errorf("WritableRoots[1] = %q, want /workspace", cfg.WritableRoots[1])
	}
	if len(cfg.DenyWrite) != 1 || cfg.DenyWrite[0] != "/etc" {
		t.Errorf("DenyWrite = %v, want [/etc]", cfg.DenyWrite)
	}
	if len(cfg.Command) != 3 {
		t.Errorf("Command = %v, want 3 items", cfg.Command)
	}
	if cfg.NeedsNetworkRestriction {
		t.Errorf("NeedsNetworkRestriction should be false by default")
	}
}

func TestHelperConfigEmpty(t *testing.T) {
	input := `{"command":["echo","hello"]}`
	var cfg HelperConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cfg.WritableRoots) != 0 {
		t.Errorf("WritableRoots should be empty, got %v", cfg.WritableRoots)
	}
	if len(cfg.DenyWrite) != 0 {
		t.Errorf("DenyWrite should be empty, got %v", cfg.DenyWrite)
	}
	if len(cfg.DenyRead) != 0 {
		t.Errorf("DenyRead should be empty, got %v", cfg.DenyRead)
	}
	if len(cfg.Command) != 2 {
		t.Errorf("Command = %v, want 2 items", cfg.Command)
	}
}

func TestHelperConfigNetworkRestriction(t *testing.T) {
	input := `{"needs_network_restriction":true,"command":["curl","http://example.com"]}`
	var cfg HelperConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !cfg.NeedsNetworkRestriction {
		t.Errorf("NeedsNetworkRestriction should be true")
	}
}

func TestHelperConfigRoundTrip(t *testing.T) {
	original := HelperConfig{
		WritableRoots:           []string{"/tmp"},
		DenyWrite:               []string{"/etc", "/usr"},
		DenyRead:                []string{"/root"},
		NeedsNetworkRestriction: true,
		ResourceLimits: &struct {
			MaxProcesses       int   `json:"MaxProcesses,omitempty"`
			MaxMemoryBytes     int64 `json:"MaxMemoryBytes,omitempty"`
			MaxFileDescriptors int   `json:"MaxFileDescriptors,omitempty"`
			MaxCPUSeconds      int   `json:"MaxCPUSeconds,omitempty"`
		}{
			MaxProcesses:       512,
			MaxMemoryBytes:     1024 * 1024 * 1024,
			MaxFileDescriptors: 256,
			MaxCPUSeconds:      60,
		},
		Command: []string{"bash", "-c", "ls -la"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded HelperConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.WritableRoots) != len(original.WritableRoots) {
		t.Errorf("WritableRoots length mismatch: got %d, want %d",
			len(decoded.WritableRoots), len(original.WritableRoots))
	}
	if decoded.NeedsNetworkRestriction != original.NeedsNetworkRestriction {
		t.Errorf("NeedsNetworkRestriction = %v, want %v",
			decoded.NeedsNetworkRestriction, original.NeedsNetworkRestriction)
	}
	if decoded.ResourceLimits == nil {
		t.Fatal("ResourceLimits should not be nil")
	}
	if decoded.ResourceLimits.MaxProcesses != 512 {
		t.Errorf("MaxProcesses = %d, want 512", decoded.ResourceLimits.MaxProcesses)
	}
	if decoded.ResourceLimits.MaxMemoryBytes != 1024*1024*1024 {
		t.Errorf("MaxMemoryBytes = %d, want %d", decoded.ResourceLimits.MaxMemoryBytes, 1024*1024*1024)
	}
	if decoded.ResourceLimits.MaxFileDescriptors != 256 {
		t.Errorf("MaxFileDescriptors = %d, want 256", decoded.ResourceLimits.MaxFileDescriptors)
	}
	if decoded.ResourceLimits.MaxCPUSeconds != 60 {
		t.Errorf("MaxCPUSeconds = %d, want 60", decoded.ResourceLimits.MaxCPUSeconds)
	}
}

func TestHelperConfigResourceLimitsNil(t *testing.T) {
	input := `{"command":["echo","hello"]}`
	var cfg HelperConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.ResourceLimits != nil {
		t.Error("ResourceLimits should be nil when not provided")
	}
}

func TestHelperConfigResourceLimitsFromJSON(t *testing.T) {
	// Simulate the JSON that would come from the Windows host, matching
	// the serialization of platform.ResourceLimits (no json tags).
	input := `{
		"resource_limits": {
			"MaxProcesses": 100,
			"MaxMemoryBytes": 2147483648,
			"MaxFileDescriptors": 512,
			"MaxCPUSeconds": 30
		},
		"command": ["sh", "-c", "echo test"]
	}`
	var cfg HelperConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.ResourceLimits == nil {
		t.Fatal("ResourceLimits should not be nil")
	}
	if cfg.ResourceLimits.MaxProcesses != 100 {
		t.Errorf("MaxProcesses = %d, want 100", cfg.ResourceLimits.MaxProcesses)
	}
	if cfg.ResourceLimits.MaxMemoryBytes != 2147483648 {
		t.Errorf("MaxMemoryBytes = %d, want 2147483648", cfg.ResourceLimits.MaxMemoryBytes)
	}
	if cfg.ResourceLimits.MaxFileDescriptors != 512 {
		t.Errorf("MaxFileDescriptors = %d, want 512", cfg.ResourceLimits.MaxFileDescriptors)
	}
	if cfg.ResourceLimits.MaxCPUSeconds != 30 {
		t.Errorf("MaxCPUSeconds = %d, want 30", cfg.ResourceLimits.MaxCPUSeconds)
	}
}
