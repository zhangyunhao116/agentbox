package windows

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// semver represents a semantic version with three components.
type semver struct {
	Major int
	Minor int
	Patch int
}

// String returns the version in "major.minor.patch" format.
func (v semver) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Less returns true if v is strictly less than other.
func (v semver) Less(other semver) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor < other.Minor
	}
	return v.Patch < other.Patch
}

// parseSemver parses a "major.minor.patch" string. Trailing components
// (e.g., "2.5.10.0") are ignored.
func parseSemver(s string) (semver, error) {
	parts := strings.SplitN(s, ".", 4)
	if len(parts) < 3 {
		return semver{}, fmt.Errorf("invalid semver %q: need at least 3 components", s)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return semver{}, fmt.Errorf("invalid major version in %q: %w", s, err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return semver{}, fmt.Errorf("invalid minor version in %q: %w", s, err)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return semver{}, fmt.Errorf("invalid patch version in %q: %w", s, err)
	}
	return semver{Major: major, Minor: minor, Patch: patch}, nil
}

// minWSLVersion is the minimum WSL version required to mitigate CVE-2025-53788.
var minWSLVersion = semver{Major: 2, Minor: 5, Patch: 10}

// wslVersionRegexp extracts the WSL version from "wsl.exe --version" output.
// Matches lines like "WSL version: 2.5.10.0" or bare "2.5.10.0".
var wslVersionRegexp = regexp.MustCompile(`(?:WSL\s+version:\s+)?(\d+\.\d+\.\d+)`)

// wslStatusRegexp extracts the default WSL version from "wsl.exe --status" output.
// Matches lines like "Default Version: 2".
var wslStatusRegexp = regexp.MustCompile(`Default\s+Version:\s+(\d+)`)

// parseWSLVersionOutput extracts the WSL major version (1 or 2) and the
// full semver from "wsl.exe --version" output text.
func parseWSLVersionOutput(output string) (int, semver, error) {
	m := wslVersionRegexp.FindStringSubmatch(output)
	if m == nil {
		return 0, semver{}, errors.New("cannot parse WSL version from output")
	}
	ver, err := parseSemver(m[1])
	if err != nil {
		return 0, semver{}, err
	}
	return ver.Major, ver, nil
}

// parseWSLListVerbose parses "wsl.exe -l -v" output and returns the highest
// WSL version number found among listed distros (1 or 2).
//
// Sample output:
//
//	  NAME            STATE           VERSION
//	* Ubuntu          Running         2
//	  Alpine          Stopped         1
func parseWSLListVerbose(output string) (int, error) {
	maxVer := 0
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// Skip header and empty lines.
		if line == "" || strings.HasPrefix(line, "NAME") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// Version is the last field.
		v, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil {
			continue
		}
		if v > maxVer {
			maxVer = v
		}
	}
	if maxVer == 0 {
		return 0, errors.New("no WSL distros found in list output")
	}
	return maxVer, nil
}

// parseWSLStatusOutput parses "wsl.exe --status" output and returns the
// default WSL version number (1 or 2).
//
// Sample output:
//
//	Default Version: 2
func parseWSLStatusOutput(output string) (int, error) {
	m := wslStatusRegexp.FindStringSubmatch(output)
	if m == nil {
		return 0, errors.New("cannot parse default version from status output")
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("invalid default version: %w", err)
	}
	return v, nil
}
