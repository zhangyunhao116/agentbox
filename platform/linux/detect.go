//go:build linux

package linux

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// KernelVersion represents a parsed Linux kernel version.
type KernelVersion struct {
	Major, Minor, Patch int
}

// readProcVersion is a function variable for reading /proc/version.
// It is overridden in tests to simulate errors.
var readProcVersion = func() ([]byte, error) {
	return os.ReadFile("/proc/version")
}

// DetectKernelVersion reads and parses the running kernel version from /proc/version.
func DetectKernelVersion() (KernelVersion, error) {
	data, err := readProcVersion()
	if err != nil {
		return KernelVersion{}, fmt.Errorf("read /proc/version: %w", err)
	}
	// /proc/version format: "Linux version X.Y.Z-... (...)"
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return KernelVersion{}, errors.New("unexpected /proc/version format")
	}
	return ParseKernelVersion(fields[2])
}

// ParseKernelVersion parses a kernel version string like "5.15.0-generic" into
// a KernelVersion. Only the major.minor.patch components are extracted; any
// trailing suffix (e.g., "-generic") is ignored.
func ParseKernelVersion(s string) (KernelVersion, error) {
	// Strip everything after the first hyphen or space.
	if idx := strings.IndexAny(s, "- "); idx != -1 {
		s = s[:idx]
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return KernelVersion{}, fmt.Errorf("invalid kernel version: %q", s)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return KernelVersion{}, fmt.Errorf("invalid major version in %q: %w", s, err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return KernelVersion{}, fmt.Errorf("invalid minor version in %q: %w", s, err)
	}

	var patch int
	if len(parts) == 3 && parts[2] != "" {
		patch, err = strconv.Atoi(parts[2])
		if err != nil {
			return KernelVersion{}, fmt.Errorf("invalid patch version in %q: %w", s, err)
		}
	}

	return KernelVersion{Major: major, Minor: minor, Patch: patch}, nil
}

// AtLeast reports whether v is at least major.minor.
func (v KernelVersion) AtLeast(major, minor int) bool {
	if v.Major != major {
		return v.Major > major
	}
	return v.Minor >= minor
}

// String returns the version in "major.minor.patch" format.
func (v KernelVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}
