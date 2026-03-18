package windows

import (
	"errors"
	"runtime"
	"testing"
)

func TestToWSL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{"drive C", `C:\Users\foo`, "/mnt/c/Users/foo", nil},
		{"drive D", `D:\data`, "/mnt/d/data", nil},
		{"lowercase drive", `c:\temp`, "/mnt/c/temp", nil},
		{"forward slashes", "C:/Users/foo", "/mnt/c/Users/foo", nil},
		{"extended path", `\\?\C:\long\path`, "/mnt/c/long/path", nil},
		{"UNC path", `\\server\share`, "", ErrUNCPathNotSupported},
		{"unix passthrough", "/tmp", "/tmp", nil},
		{"drive root", `C:\`, "/mnt/c/", nil},
		{"drive letter only", "C:", "/mnt/c", nil},
		{"nested path", `C:\a\b\c\d`, "/mnt/c/a/b/c/d", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToWSL(tt.input)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ToWSL(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ToWSL(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ToWSL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestWSLToWindows(t *testing.T) {
	// Expected separator depends on runtime platform.
	sep := "/"
	if runtime.GOOS == "windows" {
		sep = `\`
	}

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"mnt c", "/mnt/c/Users/foo", "C:" + sep + "Users" + sep + "foo", false},
		{"mnt d", "/mnt/d/data", "D:" + sep + "data", false},
		{"mnt root", "/mnt/c/", "C:" + sep, false},
		{"mnt bare", "/mnt/c", "C:", false},
		{"no equiv", "/tmp", "", true},
		{"no equiv root", "/", "", true},
		{"no equiv home", "/home/user", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WSLToWindows(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("WSLToWindows(%q) expected error, got %q", tt.input, got)
				}
				if !errors.Is(err, ErrPathTranslationFailed) {
					t.Errorf("WSLToWindows(%q) error should wrap ErrPathTranslationFailed, got: %v", tt.input, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("WSLToWindows(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("WSLToWindows(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
