package windows

import (
	"fmt"
	"testing"
)

func TestParseSemver(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    semver
		wantErr bool
	}{
		{
			name:  "standard version",
			input: "2.5.10",
			want:  semver{Major: 2, Minor: 5, Patch: 10},
		},
		{
			name:  "four-part version",
			input: "2.5.10.0",
			want:  semver{Major: 2, Minor: 5, Patch: 10},
		},
		{
			name:  "zero version",
			input: "0.0.0",
			want:  semver{Major: 0, Minor: 0, Patch: 0},
		},
		{
			name:  "large numbers",
			input: "100.200.300",
			want:  semver{Major: 100, Minor: 200, Patch: 300},
		},
		{
			name:  "version 1.0.0",
			input: "1.0.0",
			want:  semver{Major: 1, Minor: 0, Patch: 0},
		},
		{
			name:  "four parts with trailing zero",
			input: "2.4.4.0",
			want:  semver{Major: 2, Minor: 4, Patch: 4},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "single number",
			input:   "2",
			wantErr: true,
		},
		{
			name:    "two parts only",
			input:   "2.5",
			wantErr: true,
		},
		{
			name:    "non-numeric major",
			input:   "abc.5.10",
			wantErr: true,
		},
		{
			name:    "non-numeric minor",
			input:   "2.abc.10",
			wantErr: true,
		},
		{
			name:    "non-numeric patch",
			input:   "2.5.abc",
			wantErr: true,
		},
		{
			name:    "garbage input",
			input:   "not-a-version",
			wantErr: true,
		},
		{
			name:    "dots only",
			input:   "...",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSemver(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseSemver(%q) expected error, got %v", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSemver(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("parseSemver(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSemverLess(t *testing.T) {
	tests := []struct {
		a, b semver
		want bool
	}{
		{semver{1, 0, 0}, semver{2, 0, 0}, true},    // major less
		{semver{2, 0, 0}, semver{1, 0, 0}, false},   // major greater
		{semver{2, 4, 0}, semver{2, 5, 0}, true},    // minor less
		{semver{2, 5, 0}, semver{2, 4, 0}, false},   // minor greater
		{semver{2, 5, 9}, semver{2, 5, 10}, true},   // patch less
		{semver{2, 5, 10}, semver{2, 5, 9}, false},  // patch greater
		{semver{2, 5, 10}, semver{2, 5, 10}, false}, // equal
		{semver{0, 0, 0}, semver{0, 0, 1}, true},    // zero vs one
		{semver{0, 0, 0}, semver{0, 0, 0}, false},   // both zero
		{semver{1, 9, 9}, semver{2, 0, 0}, true},    // major boundary
		{semver{2, 0, 0}, semver{1, 9, 9}, false},   // major boundary reverse
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%s_less_%s", tt.a, tt.b)
		t.Run(name, func(t *testing.T) {
			got := tt.a.Less(tt.b)
			if got != tt.want {
				t.Errorf("%s.Less(%s) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSemverString(t *testing.T) {
	tests := []struct {
		version semver
		want    string
	}{
		{semver{2, 5, 10}, "2.5.10"},
		{semver{0, 0, 0}, "0.0.0"},
		{semver{1, 0, 0}, "1.0.0"},
		{semver{100, 200, 300}, "100.200.300"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.version.String()
			if got != tt.want {
				t.Errorf("semver%v.String() = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestSemverRoundTrip(t *testing.T) {
	// Parse a version string and verify String() returns an equivalent
	// that re-parses to the same value.
	original := "2.5.10"
	v, err := parseSemver(original)
	if err != nil {
		t.Fatalf("parseSemver(%q) error: %v", original, err)
	}
	s := v.String()
	reparsed, err := parseSemver(s)
	if err != nil {
		t.Fatalf("parseSemver(%q) error on round-trip: %v", s, err)
	}
	if reparsed != v {
		t.Errorf("round-trip failed: %v -> %q -> %v", v, s, reparsed)
	}
}

func TestParseWSLVersionOutput(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantMajor int
		wantVer   semver
		wantErr   bool
	}{
		{
			name: "standard wsl --version output",
			output: `WSL version: 2.5.10.0
Kernel version: 6.6.87.2-1
WSLg version: 1.0.66
MSRDC version: 1.2.5716
Direct3D version: 1.611.1-81528511
DXCore version: 10.0.26100.1-240331-1435.ge-release
Windows version: 10.0.26100.3476`,
			wantMajor: 2,
			wantVer:   semver{Major: 2, Minor: 5, Patch: 10},
		},
		{
			name:      "bare version string",
			output:    "2.5.10.0",
			wantMajor: 2,
			wantVer:   semver{Major: 2, Minor: 5, Patch: 10},
		},
		{
			name:      "version without trailing zero",
			output:    "WSL version: 2.4.4",
			wantMajor: 2,
			wantVer:   semver{Major: 2, Minor: 4, Patch: 4},
		},
		{
			name:      "version 1.x",
			output:    "WSL version: 1.0.0",
			wantMajor: 1,
			wantVer:   semver{Major: 1, Minor: 0, Patch: 0},
		},
		{
			name: "mixed case spacing",
			output: `WSL  version:  2.5.10.0
Kernel version: 6.6.87.2`,
			wantMajor: 2,
			wantVer:   semver{Major: 2, Minor: 5, Patch: 10},
		},
		{
			name:    "empty output",
			output:  "",
			wantErr: true,
		},
		{
			name:    "garbage output",
			output:  "this is not version output at all",
			wantErr: true,
		},
		{
			name:    "no version numbers",
			output:  "WSL version: unknown",
			wantErr: true,
		},
		{
			name:      "output with UTF-8 BOM residue",
			output:    "\xef\xbb\xbfWSL version: 2.5.10.0",
			wantMajor: 2,
			wantVer:   semver{Major: 2, Minor: 5, Patch: 10},
		},
		{
			name:      "output with leading whitespace",
			output:    "   WSL version: 2.5.10.0   ",
			wantMajor: 2,
			wantVer:   semver{Major: 2, Minor: 5, Patch: 10},
		},
		{
			name:      "CRLF line endings",
			output:    "WSL version: 2.5.10.0\r\nKernel version: 6.6.87.2\r\n",
			wantMajor: 2,
			wantVer:   semver{Major: 2, Minor: 5, Patch: 10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMajor, gotVer, err := parseWSLVersionOutput(tt.output)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseWSLVersionOutput() expected error, got major=%d, ver=%s",
						gotMajor, gotVer)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseWSLVersionOutput() unexpected error: %v", err)
			}
			if gotMajor != tt.wantMajor {
				t.Errorf("parseWSLVersionOutput() major = %d, want %d", gotMajor, tt.wantMajor)
			}
			if gotVer != tt.wantVer {
				t.Errorf("parseWSLVersionOutput() ver = %s, want %s", gotVer, tt.wantVer)
			}
		})
	}
}

func TestParseWSLListVerbose(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    int
		wantErr bool
	}{
		{
			name: "single WSL2 distro",
			output: `  NAME            STATE           VERSION
* Ubuntu          Running         2`,
			want: 2,
		},
		{
			name: "mixed WSL1 and WSL2",
			output: `  NAME            STATE           VERSION
* Ubuntu          Running         2
  Alpine          Stopped         1`,
			want: 2,
		},
		{
			name: "only WSL1 distros",
			output: `  NAME            STATE           VERSION
  Debian          Stopped         1
  Alpine          Stopped         1`,
			want: 1,
		},
		{
			name: "multiple WSL2 distros",
			output: `  NAME            STATE           VERSION
* Ubuntu-22.04   Running         2
  Ubuntu-20.04   Stopped         2
  Alpine          Stopped         2`,
			want: 2,
		},
		{
			name:   "CRLF line endings",
			output: "  NAME            STATE           VERSION\r\n* Ubuntu          Running         2\r\n",
			want:   2,
		},
		{
			name: "extra whitespace in fields",
			output: `  NAME            STATE           VERSION
*  Ubuntu          Running          2`,
			want: 2,
		},
		{
			name:    "empty output",
			output:  "",
			wantErr: true,
		},
		{
			name:    "header only",
			output:  "  NAME            STATE           VERSION",
			wantErr: true,
		},
		{
			name:    "garbage output",
			output:  "error: some wsl error occurred",
			wantErr: true,
		},
		{
			name: "no version column parseable",
			output: `  NAME            STATE           VERSION
* Ubuntu          Running         two`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWSLListVerbose(tt.output)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseWSLListVerbose() expected error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseWSLListVerbose() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseWSLListVerbose() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseWSLStatusOutput(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    int
		wantErr bool
	}{
		{
			name:   "standard WSL2 default",
			output: "Default Version: 2",
			want:   2,
		},
		{
			name:   "WSL1 default",
			output: "Default Version: 1",
			want:   1,
		},
		{
			name: "multi-line status output",
			output: `Default Distribution: Ubuntu
Default Version: 2`,
			want: 2,
		},
		{
			name:   "extra spacing",
			output: "Default  Version:  2",
			want:   2,
		},
		{
			name:   "CRLF line endings",
			output: "Default Version: 2\r\n",
			want:   2,
		},
		{
			name:    "empty output",
			output:  "",
			wantErr: true,
		},
		{
			name:    "no default version line",
			output:  "Default Distribution: Ubuntu",
			wantErr: true,
		},
		{
			name:    "garbage output",
			output:  "some random error text",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWSLStatusOutput(tt.output)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseWSLStatusOutput() expected error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseWSLStatusOutput() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseWSLStatusOutput() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestMinWSLVersionComparison(t *testing.T) {
	// Verify that known-vulnerable versions are detected as less than the minimum.
	tests := []struct {
		name      string
		version   semver
		wantBelow bool // true if version is below minWSLVersion
	}{
		{
			name:      "vulnerable 2.4.4",
			version:   semver{Major: 2, Minor: 4, Patch: 4},
			wantBelow: true,
		},
		{
			name:      "vulnerable 2.5.9",
			version:   semver{Major: 2, Minor: 5, Patch: 9},
			wantBelow: true,
		},
		{
			name:      "exact minimum 2.5.10",
			version:   semver{Major: 2, Minor: 5, Patch: 10},
			wantBelow: false,
		},
		{
			name:      "above minimum 2.5.11",
			version:   semver{Major: 2, Minor: 5, Patch: 11},
			wantBelow: false,
		},
		{
			name:      "above minimum 2.6.0",
			version:   semver{Major: 2, Minor: 6, Patch: 0},
			wantBelow: false,
		},
		{
			name:      "above minimum 3.0.0",
			version:   semver{Major: 3, Minor: 0, Patch: 0},
			wantBelow: false,
		},
		{
			name:      "old 1.x version",
			version:   semver{Major: 1, Minor: 0, Patch: 0},
			wantBelow: true,
		},
		{
			name:      "zero version",
			version:   semver{Major: 0, Minor: 0, Patch: 0},
			wantBelow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBelow := tt.version.Less(minWSLVersion)
			if gotBelow != tt.wantBelow {
				t.Errorf("%s.Less(%s) = %v, want %v",
					tt.version, minWSLVersion, gotBelow, tt.wantBelow)
			}
		})
	}
}
