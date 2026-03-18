package windows

import (
	"encoding/json"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
)

func TestTranslatePaths(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		want    []string
		wantErr bool
	}{
		{
			name:  "nil input",
			input: nil,
			want:  nil,
		},
		{
			name:  "empty input",
			input: []string{},
			want:  nil,
		},
		{
			name:  "unix paths pass through",
			input: []string{"/tmp", "/home/user", "/var/log"},
			want:  []string{"/tmp", "/home/user", "/var/log"},
		},
		{
			name:  "windows paths translated",
			input: []string{`C:\Users\foo`, `D:\data`},
			want:  []string{"/mnt/c/Users/foo", "/mnt/d/data"},
		},
		{
			name:  "mixed windows and unix paths",
			input: []string{`C:\temp`, "/opt/work", `D:\projects\go`},
			want:  []string{"/mnt/c/temp", "/opt/work", "/mnt/d/projects/go"},
		},
		{
			name:    "UNC path fails",
			input:   []string{`\\server\share`},
			wantErr: true,
		},
		{
			name:  "single unix path",
			input: []string{"/"},
			want:  []string{"/"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := translatePaths(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("translatePaths(%v) expected error, got %v", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("translatePaths(%v) unexpected error: %v", tt.input, err)
			}
			if !slicesEqual(got, tt.want) {
				t.Errorf("translatePaths(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildHelperConfig(t *testing.T) {
	origArgs := []string{"echo", "hello", "world"}
	cfg := &platform.WrapConfig{
		WritableRoots:           []string{`C:\Users\foo\project`, "/tmp"},
		DenyWrite:               []string{`D:\secrets`},
		DenyRead:                []string{"/etc/shadow"},
		NeedsNetworkRestriction: true,
		ResourceLimits: &platform.ResourceLimits{
			MaxProcesses:       512,
			MaxMemoryBytes:     1024 * 1024 * 1024,
			MaxFileDescriptors: 256,
			MaxCPUSeconds:      60,
		},
	}

	hCfg, err := buildHelperConfig(origArgs, cfg)
	if err != nil {
		t.Fatalf("buildHelperConfig() error: %v", err)
	}

	// Verify path translation.
	wantWritable := []string{"/mnt/c/Users/foo/project", "/tmp"}
	if !slicesEqual(hCfg.WritableRoots, wantWritable) {
		t.Errorf("WritableRoots = %v, want %v", hCfg.WritableRoots, wantWritable)
	}

	wantDenyWrite := []string{"/mnt/d/secrets"}
	if !slicesEqual(hCfg.DenyWrite, wantDenyWrite) {
		t.Errorf("DenyWrite = %v, want %v", hCfg.DenyWrite, wantDenyWrite)
	}

	wantDenyRead := []string{"/etc/shadow"}
	if !slicesEqual(hCfg.DenyRead, wantDenyRead) {
		t.Errorf("DenyRead = %v, want %v", hCfg.DenyRead, wantDenyRead)
	}

	if !hCfg.NeedsNetworkRestriction {
		t.Error("NeedsNetworkRestriction should be true")
	}
	if !slicesEqual(hCfg.Command, origArgs) {
		t.Errorf("Command = %v, want %v", hCfg.Command, origArgs)
	}

	// Verify resource limits.
	if hCfg.ResourceLimits == nil {
		t.Fatal("ResourceLimits should not be nil")
	}
	if hCfg.ResourceLimits.MaxProcesses != 512 {
		t.Errorf("MaxProcesses = %d, want 512", hCfg.ResourceLimits.MaxProcesses)
	}
	if hCfg.ResourceLimits.MaxMemoryBytes != 1024*1024*1024 {
		t.Errorf("MaxMemoryBytes = %d, want 1073741824", hCfg.ResourceLimits.MaxMemoryBytes)
	}
	if hCfg.ResourceLimits.MaxFileDescriptors != 256 {
		t.Errorf("MaxFileDescriptors = %d, want 256", hCfg.ResourceLimits.MaxFileDescriptors)
	}
	if hCfg.ResourceLimits.MaxCPUSeconds != 60 {
		t.Errorf("MaxCPUSeconds = %d, want 60", hCfg.ResourceLimits.MaxCPUSeconds)
	}
}

func TestBuildHelperConfigNilResourceLimits(t *testing.T) {
	hCfg, err := buildHelperConfig([]string{"ls"}, &platform.WrapConfig{})
	if err != nil {
		t.Fatalf("buildHelperConfig() error: %v", err)
	}
	if hCfg.ResourceLimits != nil {
		t.Errorf("ResourceLimits should be nil when not configured, got %+v",
			hCfg.ResourceLimits)
	}
}

func TestBuildHelperConfigUNCPathError(t *testing.T) {
	cfg := &platform.WrapConfig{
		WritableRoots: []string{`\\server\share`},
	}
	_, err := buildHelperConfig([]string{"ls"}, cfg)
	if err == nil {
		t.Fatal("expected error for UNC path in WritableRoots")
	}
}

func TestHelperConfigJSONFormat(t *testing.T) {
	// Verify that helperConfig serializes to JSON matching what
	// cmd/sandbox-helper/main.go:HelperConfig expects.
	hCfg := &helperConfig{
		WritableRoots:           []string{"/tmp", "/home/sandbox"},
		DenyWrite:               []string{"/etc"},
		DenyRead:                []string{"/root"},
		NeedsNetworkRestriction: true,
		ResourceLimits: &helperResourceLimits{
			MaxProcesses:       100,
			MaxMemoryBytes:     2147483648,
			MaxFileDescriptors: 512,
			MaxCPUSeconds:      30,
		},
		Command: []string{"echo", "hello"},
	}

	data, err := json.Marshal(hCfg)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	// Unmarshal into a map to verify field names match the helper's expectations.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}

	// Check expected top-level keys (matches cmd/sandbox-helper/main.go:22-38).
	wantKeys := []string{
		"writable_roots", "deny_write", "deny_read",
		"needs_network_restriction", "resource_limits",
		"command",
	}
	for _, key := range wantKeys {
		if _, ok := m[key]; !ok {
			t.Errorf("missing expected JSON key %q in serialized config", key)
		}
	}

	// Verify resource_limits sub-keys (matches cmd/sandbox-helper/main.go:31-35).
	var rl map[string]json.RawMessage
	if err := json.Unmarshal(m["resource_limits"], &rl); err != nil {
		t.Fatalf("unmarshal resource_limits: %v", err)
	}
	rlKeys := []string{"MaxProcesses", "MaxMemoryBytes", "MaxFileDescriptors", "MaxCPUSeconds"}
	for _, key := range rlKeys {
		if _, ok := rl[key]; !ok {
			t.Errorf("missing expected resource_limits key %q", key)
		}
	}
}

func TestBuildHelperConfigEmptyPaths(t *testing.T) {
	hCfg, err := buildHelperConfig([]string{"cmd"}, &platform.WrapConfig{})
	if err != nil {
		t.Fatalf("buildHelperConfig() error: %v", err)
	}
	if hCfg.WritableRoots != nil {
		t.Errorf("WritableRoots should be nil for empty input, got %v", hCfg.WritableRoots)
	}
	if hCfg.DenyWrite != nil {
		t.Errorf("DenyWrite should be nil for empty input, got %v", hCfg.DenyWrite)
	}
	if hCfg.DenyRead != nil {
		t.Errorf("DenyRead should be nil for empty input, got %v", hCfg.DenyRead)
	}
}

// slicesEqual returns true if a and b are equal (both nil or same elements).
func slicesEqual(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		// Treat nil and empty as equal for nil case, but also
		// check both-nil vs both-empty.
		if a == nil && b == nil {
			return true
		}
		if a == nil || b == nil {
			// One nil, one empty — only matters for specific tests.
			return len(a) == len(b)
		}
		return true
	}
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
