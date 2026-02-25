package pathutil

import (
	"testing"
)

// FuzzGlobToRegex exercises GlobToRegex with arbitrary glob patterns.
// The function performs character-by-character parsing with index arithmetic
// and bracket-class handling, making it a prime target for fuzz testing.
// It must never panic regardless of input.
func FuzzGlobToRegex(f *testing.F) {
	seeds := []string{
		"*.go",
		"**/*.txt",
		"[abc]",
		"[!a-z]",
		"",
		"{",
		"}",
		"[",
		"]",
		"\\*",
		"path/to/*.{go,js}",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, pattern string) {
		// Must not panic; any output string is acceptable.
		_ = GlobToRegex(pattern)
	})
}
