package pathutil

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// FindFirstNonExistent
// ---------------------------------------------------------------------------

func TestFindFirstNonExistent(t *testing.T) {
	tmp := t.TempDir()
	mkDir(t, tmp, "a/b")

	tests := []struct {
		name string
		path string
		want string // "" means entire path exists
	}{
		{
			name: "entire path exists",
			path: filepath.Join(tmp, "a", "b"),
			want: "",
		},
		{
			name: "last component missing",
			path: filepath.Join(tmp, "a", "b", "c"),
			want: filepath.Join(tmp, "a", "b", "c"),
		},
		{
			name: "middle component missing",
			path: filepath.Join(tmp, "a", "x", "y"),
			want: filepath.Join(tmp, "a", "x"),
		},
		{
			name: "root exists",
			path: "/",
			want: "",
		},
		{
			name: "relative existing",
			path: ".",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindFirstNonExistent(tt.path)
			if got != tt.want {
				t.Errorf("FindFirstNonExistent(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestFindFirstNonExistent_RelativePath(t *testing.T) {
	// Test with a relative path where all components exist.
	got := FindFirstNonExistent(".")
	if got != "" {
		t.Errorf("expected empty for '.', got %q", got)
	}

	// Test with a relative path that doesn't exist.
	got = FindFirstNonExistent("nonexistent_dir_xyz/sub/file")
	if got == "" {
		t.Error("expected non-empty for nonexistent relative path")
	}
}

func TestFindFirstNonExistent_SingleRelativeComponent(t *testing.T) {
	// A single relative component that doesn't exist.
	got := FindFirstNonExistent("nonexistent_xyz_12345")
	if got != "nonexistent_xyz_12345" {
		t.Errorf("expected 'nonexistent_xyz_12345', got %q", got)
	}
}

// ---------------------------------------------------------------------------
// ContainsNullByte / StripNullBytes
// ---------------------------------------------------------------------------

func TestContainsNullByte(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello", false},
		{"", false},
		{"hel\x00lo", true},
		{"\x00", true},
		{"abc\x00\x00def", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ContainsNullByte(tt.input); got != tt.want {
				t.Errorf("ContainsNullByte(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestStripNullBytes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"", ""},
		{"hel\x00lo", "hello"},
		{"\x00", ""},
		{"\x00a\x00b\x00", "ab"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := StripNullBytes(tt.input); got != tt.want {
				t.Errorf("StripNullBytes(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers — shared by all test files in this package.
// ---------------------------------------------------------------------------

func mkFile(t *testing.T, base, rel string) {
	t.Helper()
	p := filepath.Join(base, rel)
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
}

func mkDir(t *testing.T, base, rel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(base, rel), 0755); err != nil {
		t.Fatal(err)
	}
}
