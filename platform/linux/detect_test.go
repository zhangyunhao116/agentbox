//go:build linux

package linux

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    KernelVersion
		wantErr bool
	}{
		{
			name:  "standard version",
			input: "5.15.0",
			want:  KernelVersion{Major: 5, Minor: 15, Patch: 0},
		},
		{
			name:  "version with suffix",
			input: "5.15.0-generic",
			want:  KernelVersion{Major: 5, Minor: 15, Patch: 0},
		},
		{
			name:  "version with complex suffix",
			input: "6.1.52-1-lts",
			want:  KernelVersion{Major: 6, Minor: 1, Patch: 52},
		},
		{
			name:  "major.minor only",
			input: "5.15",
			want:  KernelVersion{Major: 5, Minor: 15, Patch: 0},
		},
		{
			name:  "high version numbers",
			input: "6.8.12",
			want:  KernelVersion{Major: 6, Minor: 8, Patch: 12},
		},
		{
			name:  "kernel 4.x",
			input: "4.19.0-25-amd64",
			want:  KernelVersion{Major: 4, Minor: 19, Patch: 0},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "single number",
			input:   "5",
			wantErr: true,
		},
		{
			name:    "non-numeric major",
			input:   "abc.1.2",
			wantErr: true,
		},
		{
			name:    "non-numeric minor",
			input:   "5.abc.2",
			wantErr: true,
		},
		{
			name:    "non-numeric patch",
			input:   "5.15.abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKernelVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseKernelVersion(%q) expected error, got %v", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseKernelVersion(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ParseKernelVersion(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestKernelVersionAtLeast(t *testing.T) {
	tests := []struct {
		version      KernelVersion
		major, minor int
		want         bool
	}{
		{KernelVersion{5, 15, 0}, 5, 13, true},  // 5.15 >= 5.13
		{KernelVersion{5, 13, 0}, 5, 13, true},  // 5.13 >= 5.13 (equal)
		{KernelVersion{5, 12, 0}, 5, 13, false}, // 5.12 < 5.13
		{KernelVersion{6, 0, 0}, 5, 13, true},   // 6.0 >= 5.13 (major higher)
		{KernelVersion{4, 19, 0}, 5, 13, false}, // 4.19 < 5.13 (major lower)
		{KernelVersion{5, 0, 0}, 5, 0, true},    // 5.0 >= 5.0
		{KernelVersion{6, 1, 0}, 6, 1, true},    // exact match
		{KernelVersion{6, 1, 52}, 6, 1, true},   // patch doesn't matter
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%s_atleast_%d.%d", tt.version, tt.major, tt.minor)
		t.Run(name, func(t *testing.T) {
			got := tt.version.AtLeast(tt.major, tt.minor)
			if got != tt.want {
				t.Errorf("%s.AtLeast(%d, %d) = %v, want %v",
					tt.version, tt.major, tt.minor, got, tt.want)
			}
		})
	}
}

func TestKernelVersionString(t *testing.T) {
	tests := []struct {
		version KernelVersion
		want    string
	}{
		{KernelVersion{5, 15, 0}, "5.15.0"},
		{KernelVersion{6, 1, 52}, "6.1.52"},
		{KernelVersion{4, 19, 0}, "4.19.0"},
		{KernelVersion{0, 0, 0}, "0.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.version.String()
			if got != tt.want {
				t.Errorf("KernelVersion%v.String() = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestDetectKernelVersion(t *testing.T) {
	// This test only runs on Linux where /proc/version exists.
	kv, err := DetectKernelVersion()
	if err != nil {
		t.Fatalf("DetectKernelVersion() error: %v", err)
	}
	if kv.Major == 0 && kv.Minor == 0 {
		t.Error("DetectKernelVersion() returned zero version")
	}
	// Sanity check: kernel should be at least 3.0.
	if !kv.AtLeast(3, 0) {
		t.Errorf("DetectKernelVersion() = %s, expected at least 3.0", kv)
	}
}

func TestDetectKernelVersion_Format(t *testing.T) {
	// Verify the returned version has reasonable values for a modern Linux system.
	kv, err := DetectKernelVersion()
	if err != nil {
		t.Fatalf("DetectKernelVersion() error: %v", err)
	}
	if kv.Major < 3 {
		t.Errorf("DetectKernelVersion().Major = %d, expected >= 3", kv.Major)
	}
	// Minor version should be non-negative (always true for int, but verify it's reasonable).
	if kv.Minor < 0 {
		t.Errorf("DetectKernelVersion().Minor = %d, expected >= 0", kv.Minor)
	}
	// Patch should be non-negative.
	if kv.Patch < 0 {
		t.Errorf("DetectKernelVersion().Patch = %d, expected >= 0", kv.Patch)
	}
	// String representation should be parseable back.
	s := kv.String()
	reparsed, err := ParseKernelVersion(s)
	if err != nil {
		t.Fatalf("ParseKernelVersion(%q) error: %v", s, err)
	}
	if reparsed != kv {
		t.Errorf("Round-trip failed: %v -> %q -> %v", kv, s, reparsed)
	}
}

// TestDetectKernelVersion_ReadError verifies that DetectKernelVersion returns
// an error when reading /proc/version fails.
func TestDetectKernelVersion_ReadError(t *testing.T) {
	orig := readProcVersion
	t.Cleanup(func() { readProcVersion = orig })

	readProcVersion = func() ([]byte, error) {
		return nil, errors.New("simulated read error")
	}

	_, err := DetectKernelVersion()
	if err == nil {
		t.Fatal("DetectKernelVersion() expected error when read fails, got nil")
	}
	if !strings.Contains(err.Error(), "read /proc/version") {
		t.Errorf("error should mention 'read /proc/version', got: %v", err)
	}
}

// TestDetectKernelVersion_BadFormat verifies that DetectKernelVersion returns
// an error when /proc/version has an unexpected format (fewer than 3 fields).
func TestDetectKernelVersion_BadFormat(t *testing.T) {
	orig := readProcVersion
	t.Cleanup(func() { readProcVersion = orig })

	readProcVersion = func() ([]byte, error) {
		return []byte("bad format"), nil
	}

	_, err := DetectKernelVersion()
	if err == nil {
		t.Fatal("DetectKernelVersion() expected error for bad format, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected /proc/version format") {
		t.Errorf("error should mention 'unexpected /proc/version format', got: %v", err)
	}
}
