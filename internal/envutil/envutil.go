package envutil

import (
	"strings"
)

// SetEnv sets or replaces an environment variable in an env slice.
// Returns the modified slice. If the key already exists, its value is updated
// in place. Otherwise, the new entry is appended.
func SetEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

// GetEnv gets a value from an env slice.
// Returns the value and true if found, or empty string and false if not.
func GetEnv(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return e[len(prefix):], true
		}
	}
	return "", false
}

// RemoveEnv removes a variable from an env slice.
// Returns a new slice with the variable removed.
func RemoveEnv(env []string, key string) []string {
	prefix := key + "="
	result := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, prefix) {
			result = append(result, e)
		}
	}
	return result
}

// RemoveEnvPrefix removes all variables with a given prefix from an env slice.
// Useful for removing DYLD_* variables on macOS.
// The prefix is matched against the key portion (before '=').
func RemoveEnvPrefix(env []string, prefix string) []string {
	result := make([]string, 0, len(env))
	for _, e := range env {
		key := e
		if idx := strings.IndexByte(e, '='); idx >= 0 {
			key = e[:idx]
		}
		if !strings.HasPrefix(key, prefix) {
			result = append(result, e)
		}
	}
	return result
}

// MergeEnv merges additional env vars into base, with additional taking precedence.
// Returns a new slice. Variables in additional override those in base with the same key.
func MergeEnv(base, additional []string) []string {
	// Build a map of additional keys for quick lookup.
	overrides := make(map[string]string, len(additional))
	overrideOrder := make([]string, 0, len(additional))
	for _, e := range additional {
		key := e
		if idx := strings.IndexByte(e, '='); idx >= 0 {
			key = e[:idx]
		}
		if _, exists := overrides[key]; !exists {
			overrideOrder = append(overrideOrder, key)
		}
		overrides[key] = e
	}

	// Copy base, replacing any overridden keys.
	replaced := make(map[string]bool, len(overrides))
	result := make([]string, 0, len(base)+len(additional))
	for _, e := range base {
		key := e
		if idx := strings.IndexByte(e, '='); idx >= 0 {
			key = e[:idx]
		}
		if override, ok := overrides[key]; ok {
			result = append(result, override)
			replaced[key] = true
		} else {
			result = append(result, e)
		}
	}

	// Append any additional vars that weren't in base, preserving order.
	for _, key := range overrideOrder {
		if !replaced[key] {
			result = append(result, overrides[key])
		}
	}

	return result
}
