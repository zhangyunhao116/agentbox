package pathutil

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/zhangyunhao116/agentbox/testutil"
)

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
		testutil.SkipIfWindows(t, "glob regex uses Unix path separators")
		matches, err := ExpandGlob(filepath.Join(tmp, "*.txt"), 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 {
			t.Errorf("expected 1 match, got %d: %v", len(matches), matches)
		}
	})

	t.Run("double star pattern", func(t *testing.T) {
		testutil.SkipIfWindows(t, "glob regex uses Unix path separators")
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
// Additional edge-case tests
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
