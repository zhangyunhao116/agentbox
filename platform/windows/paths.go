package windows

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Sentinel errors for path translation.
var (
	// ErrPathTranslationFailed indicates a Windows path could not be
	// translated to a WSL path.
	ErrPathTranslationFailed = errors.New("path translation failed")

	// ErrUNCPathNotSupported indicates a UNC path (\\server\share) was
	// provided; these cannot be mapped into WSL2.
	ErrUNCPathNotSupported = errors.New("UNC paths are not supported in WSL2")
)

// ToWSL translates a Windows path to a WSL path.
//
//	C:\Users\foo\project  → /mnt/c/Users/foo/project
//	D:\data               → /mnt/d/data
//	\\?\C:\long\path      → /mnt/c/long/path
//
// UNC paths (\\server\share) are not supported and return an error.
func ToWSL(winPath string) (string, error) {
	// Normalize path separators. We use ReplaceAll instead of
	// filepath.ToSlash so that backslashes are converted to forward
	// slashes on every OS, not just Windows.
	p := strings.ReplaceAll(winPath, `\`, "/")

	// Strip \\?\ prefix (extended-length path).
	p = strings.TrimPrefix(p, "//?/")

	// Check for UNC paths.
	if strings.HasPrefix(p, "//") {
		return "", ErrUNCPathNotSupported
	}

	// Extract drive letter.
	if len(p) >= 2 && p[1] == ':' {
		drive := strings.ToLower(string(p[0]))
		rest := p[2:]
		return "/mnt/" + drive + rest, nil
	}

	// Already a Unix-style path (e.g., /tmp) — pass through.
	return p, nil
}

// WSLToWindows translates a WSL path to a Windows path.
//
//	/mnt/c/Users/foo  → C:\Users\foo
//	/tmp              → (error: no Windows equivalent)
func WSLToWindows(wslPath string) (string, error) {
	if strings.HasPrefix(wslPath, "/mnt/") && len(wslPath) >= 6 {
		drive := strings.ToUpper(string(wslPath[5]))
		rest := wslPath[6:]
		return drive + ":" + filepath.FromSlash(rest), nil
	}
	return "", fmt.Errorf("%w: path %q has no Windows equivalent", ErrPathTranslationFailed, wslPath)
}
