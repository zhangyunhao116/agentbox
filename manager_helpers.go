// manager_helpers.go contains small utility types and functions used by the
// manager implementation, including output limiting, command normalization,
// and slice comparison helpers.
package agentbox

import (
	"bytes"
	"strconv"
	"strings"
)

// limitedWriter wraps a bytes.Buffer and silently discards writes beyond a byte limit.
type limitedWriter struct {
	buf   *bytes.Buffer
	limit int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.buf.Len()
	if remaining <= 0 {
		return len(p), nil // discard but report success
	}
	if len(p) <= remaining {
		return w.buf.Write(p)
	}
	// Write only what fits, but report full length to avoid io.ErrShortWrite.
	_, err := w.buf.Write(p[:remaining])
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// stringSlicesEqual reports whether two string slices have identical contents.
func stringSlicesEqual(a, b []string) bool {
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

// filterOutPrefix returns a new slice with all entries that have the given
// prefix removed. This is used to strip git worktree-specific deny paths.
func filterOutPrefix(paths []string, prefix string) []string {
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		if !strings.HasPrefix(p, prefix) {
			result = append(result, p)
		}
	}
	return result
}

// normalizeCommand collapses whitespace in a command string so that
// "pip  install  requests" and "pip install requests" map to the same
// session-approval cache key.
func normalizeCommand(cmd string) string {
	return strings.Join(strings.Fields(cmd), " ")
}

// buildCommandKey constructs a normalized command string from a program name
// and argument list, preserving argument boundaries by quoting args that
// contain spaces. This is used for approval cache keys and approval prompts.
func buildCommandKey(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, name)
	for _, a := range args {
		if strings.ContainsAny(a, " \t\n\"\\") {
			parts = append(parts, strconv.Quote(a))
		} else {
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, " ")
}
