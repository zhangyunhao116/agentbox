package pathutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhangyunhao116/agentbox/testutil"
)

// ---------------------------------------------------------------------------
// IsSymlinkOutsideBoundary
// ---------------------------------------------------------------------------

func TestIsSymlinkOutsideBoundary(t *testing.T) {
	tests := []struct {
		name     string
		original string
		resolved string
		want     bool
	}{
		{
			name:     "resolves to root escapes",
			original: "/tmp/link",
			resolved: "/",
			want:     true,
		},
		{
			name:     "stays within boundary",
			original: "/tmp/link",
			resolved: "/tmp/real",
			want:     false,
		},
		{
			name:     "escapes workspace",
			original: "/workspace/link",
			resolved: "/etc",
			want:     true,
		},
		{
			name:     "resolves to parent dir exactly",
			original: "/tmp/sub/link",
			resolved: "/tmp/sub",
			want:     false,
		},
		{
			name:     "resolves to sibling",
			original: "/tmp/sub/link",
			resolved: "/tmp/sub/other",
			want:     false,
		},
		{
			name:     "resolves to grandparent",
			original: "/a/b/c/link",
			resolved: "/a",
			want:     true,
		},
		{
			name:     "same path",
			original: "/tmp/file",
			resolved: "/tmp/file",
			want:     false,
		},
		{
			name:     "root original",
			original: "/link",
			resolved: "/somewhere",
			want:     false,
		},
		{
			name:     "double slashes cleaned",
			original: "/tmp//link",
			resolved: "/tmp//real",
			want:     false,
		},
		{
			name:     "trailing slash original",
			original: "/tmp/link/",
			resolved: "/etc/passwd",
			want:     true,
		},
		{
			name:     "boundary prefix trick",
			original: "/tmp/link",
			resolved: "/tmpevil/data",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "root original" {
				testutil.SkipIfWindows(t, "Unix-specific path boundary semantics")
			}
			got := IsSymlinkOutsideBoundary(tt.original, tt.resolved)
			if got != tt.want {
				t.Errorf("IsSymlinkOutsideBoundary(%q, %q) = %v, want %v",
					tt.original, tt.resolved, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ResolveWithBoundaryCheck
// ---------------------------------------------------------------------------

func TestResolveWithBoundaryCheck(t *testing.T) {
	// Test with a real file (no symlink) — should succeed.
	tmp := t.TempDir()
	// On macOS /var is a symlink to /private/var; resolve the temp dir so
	// that both the boundary and the resolved path use the canonical form.
	tmp, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(tmp, "real.txt")
	if err := os.WriteFile(realFile, []byte("hi"), 0644); err != nil {
		t.Fatal(err)
	}

	resolved, err := ResolveWithBoundaryCheck(realFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(resolved, "real.txt") {
		t.Errorf("expected resolved to end with real.txt, got %q", resolved)
	}

	// Test with a symlink that stays within boundary.
	linkInside := filepath.Join(tmp, "link_inside")
	if err := os.Symlink(realFile, linkInside); err != nil {
		t.Fatal(err)
	}
	resolved, err = ResolveWithBoundaryCheck(linkInside)
	if err != nil {
		t.Fatalf("unexpected error for inside link: %v", err)
	}
	if !strings.HasSuffix(resolved, "real.txt") {
		t.Errorf("expected resolved to end with real.txt, got %q", resolved)
	}

	// Test with a symlink that escapes boundary.
	linkOutside := filepath.Join(tmp, "link_outside")
	if err := os.Symlink("/", linkOutside); err != nil {
		t.Fatal(err)
	}
	_, err = ResolveWithBoundaryCheck(linkOutside)
	if err == nil {
		t.Error("expected error for escaping symlink, got nil")
	}

	// Test with a non-existent path (EvalSymlinks should fail).
	_, err = ResolveWithBoundaryCheck(filepath.Join(tmp, "nonexistent"))
	if err == nil {
		t.Error("expected error for non-existent path, got nil")
	}
}

// ---------------------------------------------------------------------------
// Edge cases for symlinks with real filesystem
// ---------------------------------------------------------------------------

func TestSymlinkBoundaryWithRealFS(t *testing.T) {
	testutil.SkipIfWindows(t, "symlink tests not reliable on Windows")

	tmp := t.TempDir()
	sub := filepath.Join(tmp, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(sub, "real.txt")
	if err := os.WriteFile(realFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Run("link to parent", func(t *testing.T) {
		link := filepath.Join(sub, "link_parent")
		if err := os.Symlink(tmp, link); err != nil {
			t.Fatal(err)
		}
		if !IsSymlinkOutsideBoundary(link, tmp) {
			t.Error("link to parent should be outside boundary")
		}
	})

	t.Run("link within same dir", func(t *testing.T) {
		link := filepath.Join(sub, "link_sibling")
		if err := os.Symlink(realFile, link); err != nil {
			t.Fatal(err)
		}
		if IsSymlinkOutsideBoundary(link, realFile) {
			t.Error("link within same dir should NOT be outside boundary")
		}
	})

	t.Run("broken symlink resolve fails", func(t *testing.T) {
		link := filepath.Join(sub, "broken_link")
		if err := os.Symlink(filepath.Join(sub, "nonexistent"), link); err != nil {
			t.Fatal(err)
		}
		_, err := ResolveWithBoundaryCheck(link)
		if err == nil {
			t.Error("expected error for broken symlink")
		}
	})
}
