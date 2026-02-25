package pathutil

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
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
// GlobToRegex
// ---------------------------------------------------------------------------

func TestGlobToRegex(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		match   []string
		noMatch []string
	}{
		{
			name:    "single star",
			pattern: "/tmp/*.txt",
			match:   []string{"/tmp/file.txt", "/tmp/a.txt"},
			noMatch: []string{"/tmp/sub/file.txt", "/tmp/file.log"},
		},
		{
			name:    "double star",
			pattern: "**/.git/hooks",
			match:   []string{".git/hooks", "a/b/.git/hooks", "/workspace/.git/hooks"},
			noMatch: []string{".git/config"},
		},
		{
			name:    "question mark",
			pattern: "/tmp/?.txt",
			match:   []string{"/tmp/a.txt", "/tmp/1.txt"},
			noMatch: []string{"/tmp/ab.txt", "/tmp/.txt"},
		},
		{
			name:    "double star with trailing slash",
			pattern: "**/src/",
			match:   []string{"src/", "a/b/src/"},
			noMatch: []string{},
		},
		{
			name:    "literal dots and special chars",
			pattern: "file.name+extra",
			match:   []string{"file.name+extra"},
			noMatch: []string{"filexname+extra", "file.name_extra"},
		},
		{
			name:    "character class",
			pattern: "test[0]",
			match:   []string{"test0"},
			noMatch: []string{"test1", "testx"},
		},
		{
			name:    "star at end",
			pattern: "/tmp/prefix*",
			match:   []string{"/tmp/prefix", "/tmp/prefixABC"},
			noMatch: []string{"/tmp/other"},
		},
		{
			name:    "double star mid path",
			pattern: "/a/**/z",
			match:   []string{"/a/z", "/a/b/z", "/a/b/c/z"},
			noMatch: []string{"/b/z"},
		},
		{
			name:    "special regex chars",
			pattern: "file(1).txt",
			match:   []string{"file(1).txt"},
			noMatch: []string{"file1.txt"},
		},
		{
			name:    "caret and dollar",
			pattern: "^start$end",
			match:   []string{"^start$end"},
			noMatch: []string{"startend"},
		},
		{
			name:    "pipe char",
			pattern: "a|b",
			match:   []string{"a|b"},
			noMatch: []string{"a", "b"},
		},
		{
			name:    "curly braces",
			pattern: "a{b}c",
			match:   []string{"a{b}c"},
			noMatch: []string{"abc"},
		},
		{
			name:    "backslash",
			pattern: "a\\b",
			match:   []string{"a\\b"},
			noMatch: []string{"ab"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reStr := GlobToRegex(tt.pattern)
			re := mustCompileRegex(t, reStr)
			for _, s := range tt.match {
				if !re.MatchString(s) {
					t.Errorf("GlobToRegex(%q) => %q should match %q", tt.pattern, reStr, s)
				}
			}
			for _, s := range tt.noMatch {
				if re.MatchString(s) {
					t.Errorf("GlobToRegex(%q) => %q should NOT match %q", tt.pattern, reStr, s)
				}
			}
		})
	}
}

func mustCompileRegex(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	return regexp.MustCompile(pattern)
}

// ---------------------------------------------------------------------------
// IsGlobPattern
// ---------------------------------------------------------------------------

func TestIsGlobPattern(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"*.txt", true},
		{"file?.go", true},
		{"[abc]", true},
		{"normal.txt", false},
		{"", false},
		{"**/*.go", true},
		{"/plain/path", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsGlobPattern(tt.input); got != tt.want {
				t.Errorf("IsGlobPattern(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ExpandGlob
// ---------------------------------------------------------------------------

func TestExpandGlob(t *testing.T) {
	// Build a temp tree:
	// root/
	//   a.txt
	//   b.log
	//   sub/
	//     c.txt
	//     deep/
	//       d.txt
	tmp := t.TempDir()
	mkFile(t, tmp, "a.txt")
	mkFile(t, tmp, "b.log")
	mkDir(t, tmp, "sub")
	mkFile(t, tmp, "sub/c.txt")
	mkDir(t, tmp, "sub/deep")
	mkFile(t, tmp, "sub/deep/d.txt")

	t.Run("star pattern", func(t *testing.T) {
		matches, err := ExpandGlob(filepath.Join(tmp, "*.txt"), 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 {
			t.Errorf("expected 1 match, got %d: %v", len(matches), matches)
		}
	})

	t.Run("double star pattern", func(t *testing.T) {
		matches, err := ExpandGlob(filepath.Join(tmp, "**", "*.txt"), 0)
		if err != nil {
			t.Fatal(err)
		}
		// Should match a.txt, sub/c.txt, sub/deep/d.txt
		if len(matches) < 3 {
			t.Errorf("expected at least 3 matches, got %d: %v", len(matches), matches)
		}
	})

	t.Run("maxDepth limits traversal", func(t *testing.T) {
		matches, err := ExpandGlob(filepath.Join(tmp, "**", "*.txt"), 1)
		if err != nil {
			t.Fatal(err)
		}
		// Only root level: a.txt
		for _, m := range matches {
			rel, _ := filepath.Rel(tmp, m)
			if strings.Count(rel, string(filepath.Separator)) > 1 {
				t.Errorf("maxDepth=1 should not reach %q", rel)
			}
		}
	})

	t.Run("no glob chars returns existing path", func(t *testing.T) {
		existing := filepath.Join(tmp, "a.txt")
		matches, err := ExpandGlob(existing, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 || matches[0] != existing {
			t.Errorf("expected [%s], got %v", existing, matches)
		}
	})

	t.Run("no glob chars non-existent returns nil", func(t *testing.T) {
		matches, err := ExpandGlob(filepath.Join(tmp, "nope.txt"), 0)
		if err != nil {
			t.Fatal(err)
		}
		if matches != nil {
			t.Errorf("expected nil, got %v", matches)
		}
	})

	t.Run("question mark pattern", func(t *testing.T) {
		matches, err := ExpandGlob(filepath.Join(tmp, "?.txt"), 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 {
			t.Errorf("expected 1 match for ?.txt, got %d: %v", len(matches), matches)
		}
	})
}

// ---------------------------------------------------------------------------
// DangerousFiles / ScanDangerousFiles
// ---------------------------------------------------------------------------

func TestScanDangerousFiles(t *testing.T) {
	tmp := t.TempDir()

	// Create some dangerous files.
	mkFile(t, tmp, ".gitconfig")
	mkFile(t, tmp, ".bashrc")
	mkFile(t, tmp, "safe.txt")
	mkDir(t, tmp, ".git/hooks")
	mkDir(t, tmp, ".vscode")
	mkDir(t, tmp, "sub")
	mkFile(t, tmp, "sub/.npmrc")
	mkDir(t, tmp, "sub/.idea")

	found, err := ScanDangerousFiles(tmp, 0)
	if err != nil {
		t.Fatal(err)
	}

	// We expect: .gitconfig, .bashrc, .git/hooks, .vscode, sub/.npmrc, sub/.idea
	if len(found) < 6 {
		t.Errorf("expected at least 6 dangerous entries, got %d: %v", len(found), found)
	}

	// safe.txt should NOT be in the list.
	for _, f := range found {
		if strings.HasSuffix(f, "safe.txt") {
			t.Errorf("safe.txt should not be flagged as dangerous")
		}
	}

	t.Run("maxDepth limits scan", func(t *testing.T) {
		found2, err := ScanDangerousFiles(tmp, 1)
		if err != nil {
			t.Fatal(err)
		}
		// At depth 1 we should find root-level items but not sub/.idea or sub/.npmrc
		for _, f := range found2 {
			rel, _ := filepath.Rel(tmp, f)
			depth := strings.Count(rel, string(filepath.Separator))
			if depth > 1 {
				t.Errorf("maxDepth=1 should not reach %q (depth %d)", rel, depth)
			}
		}
	})

	t.Run("non-existent root", func(t *testing.T) {
		_, err := ScanDangerousFiles(filepath.Join(tmp, "nonexistent"), 0)
		// filepath.Walk returns an error for non-existent root, but we skip walk errors.
		// The function should not panic.
		if err != nil {
			// It's acceptable to return an error here.
			_ = err
		}
	})
}

// ---------------------------------------------------------------------------
// IsGitWorktree
// ---------------------------------------------------------------------------

func TestIsGitWorktree(t *testing.T) {
	tmp := t.TempDir()

	t.Run("no .git entry", func(t *testing.T) {
		if IsGitWorktree(tmp) {
			t.Error("expected false when no .git exists")
		}
	})

	t.Run(".git is directory (normal repo)", func(t *testing.T) {
		dir := filepath.Join(tmp, "normalrepo")
		mkDir(t, dir, ".git")
		if IsGitWorktree(dir) {
			t.Error("expected false when .git is a directory")
		}
	})

	t.Run(".git is file (worktree)", func(t *testing.T) {
		dir := filepath.Join(tmp, "worktree")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		gitFile := filepath.Join(dir, ".git")
		if err := os.WriteFile(gitFile, []byte("gitdir: /some/path"), 0644); err != nil {
			t.Fatal(err)
		}
		if !IsGitWorktree(dir) {
			t.Error("expected true when .git is a file")
		}
	})
}

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
// Edge cases for symlinks with real filesystem
// ---------------------------------------------------------------------------

func TestSymlinkBoundaryWithRealFS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests not reliable on Windows")
	}

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

// ---------------------------------------------------------------------------
// DangerousFiles variable checks
// ---------------------------------------------------------------------------

func TestDangerousFilesNotEmpty(t *testing.T) {
	if len(GetDangerousFiles()) == 0 {
		t.Error("GetDangerousFiles() should not be empty")
	}
	if len(GetDangerousDirectories()) == 0 {
		t.Error("GetDangerousDirectories() should not be empty")
	}
}

// ---------------------------------------------------------------------------
// Additional edge-case tests for 100% coverage
// ---------------------------------------------------------------------------

func TestGlobToRegex_UnclosedBracket(t *testing.T) {
	// An unclosed [ should be escaped literally.
	reStr := GlobToRegex("test[abc")
	re := regexp.MustCompile(reStr)
	if !re.MatchString("test[abc") {
		t.Errorf("unclosed bracket should match literal: %q", reStr)
	}
	if re.MatchString("testa") {
		t.Errorf("unclosed bracket should not act as character class: %q", reStr)
	}
}

func TestGlobToRegex_BracketWithClosingFirst(t *testing.T) {
	// []] should be a character class containing ]
	reStr := GlobToRegex("[]]")
	re := regexp.MustCompile(reStr)
	if !re.MatchString("]") {
		t.Errorf("expected []] to match ']', regex: %q", reStr)
	}
}

func TestExpandGlob_RootGlob(t *testing.T) {
	// A pattern like "*" where root walks up to "." (current dir).
	// This tests the parent == root break condition.
	matches, err := ExpandGlob("*", 1)
	if err != nil {
		t.Fatal(err)
	}
	// Should return some files in current directory.
	_ = matches
}

func TestExpandGlob_InaccessibleDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}
	tmp := t.TempDir()
	mkDir(t, tmp, "noperm/child")
	mkFile(t, tmp, "noperm/child/file.txt")

	// Remove read permission on the directory.
	noPermDir := filepath.Join(tmp, "noperm")
	if err := os.Chmod(noPermDir, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(noPermDir, 0755) //nolint: errcheck

	// ExpandGlob should not fail, just skip inaccessible entries.
	matches, err := ExpandGlob(filepath.Join(tmp, "**", "*.txt"), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should not find the file inside noperm.
	for _, m := range matches {
		if strings.Contains(m, "noperm") {
			t.Errorf("should not find files in inaccessible dir: %s", m)
		}
	}
}

func TestScanDangerousFiles_InaccessibleDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}
	tmp := t.TempDir()
	mkDir(t, tmp, "noperm/child")
	mkFile(t, tmp, "noperm/child/.bashrc")

	noPermDir := filepath.Join(tmp, "noperm")
	if err := os.Chmod(noPermDir, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(noPermDir, 0755) //nolint: errcheck

	// Should not fail, just skip inaccessible entries.
	found, err := ScanDangerousFiles(tmp, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range found {
		if strings.Contains(f, "noperm") {
			t.Errorf("should not find files in inaccessible dir: %s", f)
		}
	}
}

func TestScanDangerousFiles_DeepMaxDepth(t *testing.T) {
	// Test that maxDepth properly skips deep directories and files.
	tmp := t.TempDir()
	// Create a structure deeper than maxDepth=1:
	// root/sub/deep/.bashrc  (depth 3 from root)
	// root/sub/deep/deepdir/ (depth 3 from root, directory)
	mkDir(t, tmp, "sub/deep/deepdir")
	mkFile(t, tmp, "sub/deep/.bashrc")

	found, err := ScanDangerousFiles(tmp, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		if strings.Contains(f, "deep") {
			t.Errorf("maxDepth=1 should not reach deep entries: %s", f)
		}
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

func TestExpandGlob_MaxDepthSkipDirBranch(t *testing.T) {
	// Ensure the SkipDir branch is hit: create a deep tree and use maxDepth.
	tmp := t.TempDir()
	mkDir(t, tmp, "a/b/c/d")
	mkFile(t, tmp, "a/b/c/d/file.txt")
	mkFile(t, tmp, "a/top.txt")

	matches, err := ExpandGlob(filepath.Join(tmp, "**", "*.txt"), 1)
	if err != nil {
		t.Fatal(err)
	}
	// Should find top.txt but not deep file.txt
	for _, m := range matches {
		if strings.Contains(m, "d/file.txt") {
			t.Errorf("maxDepth=1 should not reach deep file: %s", m)
		}
	}
}

func TestExpandGlob_NonExistentRoot(t *testing.T) {
	// When the glob root doesn't exist, Walk calls the callback with walkErr.
	// The function should return nil matches without error.
	matches, err := ExpandGlob("/nonexistent_root_xyz_12345/*.txt", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected no matches for non-existent root, got %v", matches)
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
// Helpers
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

// TestScanDangerousFiles_AbsError triggers the filepath.Abs error path
// by removing the current working directory so that os.Getwd (called
// internally by filepath.Abs for relative paths) fails.
func TestScanDangerousFiles_AbsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cannot remove CWD on Windows")
	}
	if runtime.GOOS == "darwin" {
		t.Skip("filepath.Abs does not fail on macOS when CWD is deleted")
	}

	// Save original working directory so we can restore it.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	// Create a temporary directory, chdir into it, then remove it.
	tmp := t.TempDir()
	doomed := filepath.Join(tmp, "doomed")
	if err := os.Mkdir(doomed, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(doomed); err != nil {
		t.Fatal(err)
	}
	// Ensure we restore CWD even on failure.
	defer func() {
		_ = os.Chdir(origDir)
	}()

	if err := os.Remove(doomed); err != nil {
		t.Fatal(err)
	}

	// Now filepath.Abs("relative") will fail because Getwd fails.
	_, err = ScanDangerousFiles("relative", 0)
	if err == nil {
		t.Fatal("expected error from ScanDangerousFiles with invalid CWD, got nil")
	}
	if !strings.Contains(err.Error(), "cannot resolve root") {
		t.Fatalf("unexpected error message: %v", err)
	}
}
