// Package envutil provides utilities for sanitizing and filtering environment
// variables in sandboxed command execution.
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

// sensitiveExactKeys is the set of environment variable names that are
// unconditionally removed by SanitizeEnv.
var sensitiveExactKeys = map[string]bool{
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"AWS_SECRET_ACCESS_KEY": true,
	"AWS_SESSION_TOKEN":     true,
	"GITHUB_TOKEN":          true,
	"GH_TOKEN":              true,
	"GITHUB_PAT":            true,
	"DOCKER_AUTH_CONFIG":    true,
	"NPM_TOKEN":             true,
}

// sensitiveSuffixes lists the upper-case suffixes that cause a variable to be
// removed by SanitizeEnv. Matching is case-insensitive on the key.
var sensitiveSuffixes = []string{
	"_SECRET",
	"_PASSWORD",
	"_API_KEY",
	"_PRIVATE_KEY",
	"_TOKEN",
}

// SanitizeConfig configures environment variable sanitization.
type SanitizeConfig struct {
	// ExactKeys are exact env var names to remove (case-sensitive match).
	ExactKeys []string
	// Suffixes are case-insensitive suffixes to match against env var keys.
	Suffixes []string
	// Preserve is a set of keys that should never be removed, even if they
	// match an exact key or suffix pattern.
	Preserve []string
}

// DefaultSanitizeConfig returns the default sanitization configuration.
func DefaultSanitizeConfig() SanitizeConfig {
	exact := make([]string, 0, len(sensitiveExactKeys))
	for k := range sensitiveExactKeys {
		exact = append(exact, k)
	}
	return SanitizeConfig{
		ExactKeys: exact,
		Suffixes:  append([]string(nil), sensitiveSuffixes...),
	}
}

// SanitizeEnv removes sensitive and dangerous environment variables from env.
// It strips exact-match keys (e.g. LD_PRELOAD, AWS_SECRET_ACCESS_KEY) and keys
// ending with known sensitive suffixes (e.g. _SECRET, _PASSWORD). The internal
// _AGENTBOX_CONFIG variable is always preserved.
func SanitizeEnv(env []string) []string {
	return SanitizeEnvWith(env, DefaultSanitizeConfig())
}

// SanitizeEnvWith filters env using the provided config. The internal
// _AGENTBOX_CONFIG variable is always preserved regardless of config.
func SanitizeEnvWith(env []string, cfg SanitizeConfig) []string {
	// Build lookup structures for efficient matching.
	exactSet := make(map[string]bool, len(cfg.ExactKeys))
	for _, k := range cfg.ExactKeys {
		exactSet[k] = true
	}
	preserveSet := make(map[string]bool, len(cfg.Preserve))
	for _, k := range cfg.Preserve {
		preserveSet[k] = true
	}

	result := make([]string, 0, len(env))
	for _, e := range env {
		key := e
		if idx := strings.IndexByte(e, '='); idx >= 0 {
			key = e[:idx]
		}

		// Always preserve the internal config variable.
		if key == "_AGENTBOX_CONFIG" {
			result = append(result, e)
			continue
		}

		// Honor explicit preserve list.
		if preserveSet[key] {
			result = append(result, e)
			continue
		}

		if exactSet[key] {
			continue
		}

		upper := strings.ToUpper(key)
		blocked := false
		for _, suffix := range cfg.Suffixes {
			if strings.HasSuffix(upper, suffix) {
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}

		result = append(result, e)
	}
	return result
}
