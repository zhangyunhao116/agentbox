package testutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTempDir(t *testing.T) {
	got := TempDir()
	if got == "" {
		t.Fatal("TempDir() returned empty string")
	}
	// Must match the standard library.
	if got != os.TempDir() {
		t.Errorf("TempDir() = %q, want %q", got, os.TempDir())
	}
}

func TestTempDirExists(t *testing.T) {
	info, err := os.Stat(TempDir())
	if err != nil {
		t.Fatalf("TempDir() %q does not exist: %v", TempDir(), err)
	}
	if !info.IsDir() {
		t.Errorf("TempDir() %q is not a directory", TempDir())
	}
}

func TestTempPath(t *testing.T) {
	tests := []struct {
		name     string
		filename string
	}{
		{name: "simple", filename: "test.txt"},
		{name: "nested", filename: "subdir/test.txt"},
		{name: "dotfile", filename: ".hidden"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TempPath(tt.filename)
			want := filepath.Join(os.TempDir(), tt.filename)
			if got != want {
				t.Errorf("TempPath(%q) = %q, want %q", tt.filename, got, want)
			}
		})
	}
}

func TestTempPathPrefix(t *testing.T) {
	got := TempPath("foo")
	if !strings.HasPrefix(got, TempDir()) {
		t.Errorf("TempPath(\"foo\") = %q does not start with TempDir() %q", got, TempDir())
	}
}

func TestHomeDir(t *testing.T) {
	got := HomeDir()
	if got == "" {
		t.Fatal("HomeDir() returned empty string")
	}
	// Should return a valid directory.
	info, err := os.Stat(got)
	if err != nil {
		t.Fatalf("HomeDir() %q does not exist: %v", got, err)
	}
	if !info.IsDir() {
		t.Errorf("HomeDir() %q is not a directory", got)
	}
}

func TestHomeDirMatchesOS(t *testing.T) {
	want, err := os.UserHomeDir()
	if err != nil {
		t.Skip("os.UserHomeDir() unavailable")
	}
	got := HomeDir()
	if got != want {
		t.Errorf("HomeDir() = %q, want %q", got, want)
	}
}
