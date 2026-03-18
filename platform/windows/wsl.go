//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zhangyunhao116/agentbox/platform"
)

// errHelperBinaryNotFound is returned when SetHelperBinary is called with a
// non-existent file path.
var errHelperBinaryNotFound = errors.New("helper binary not found at specified path")

// defaultDistroName is the WSL2 distro name used for sandboxed execution.
const defaultDistroName = "agentbox-sb"

// Platform implements the platform.Platform interface for Windows using WSL2.
type Platform struct {
	wslPath          string
	wslVersion       int
	wslBuildVersion  semver // full build version (e.g., 2.5.10)
	distroName       string
	installDir       string
	helperBinaryPath string // Windows path to pre-built Linux helper binary
	wslNetworkMode   string // "nat" or "mirrored"

	helperMu        sync.Mutex
	helperAvailable bool

	distroOnce sync.Once
	distroErr  error
}

// New returns a Windows WSL2 Platform. Detection is performed internally;
// errors are stored for Available()/CheckDependencies() rather than returned.
func New() *Platform {
	wslPath := findWSLExe()
	var wslVer int
	var buildVer semver
	if wslPath != "" {
		wslVer, buildVer = detectWSL(wslPath)
	}
	installDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "agentbox", "wsl", defaultDistroName)
	networkMode := detectWSLNetworkMode()

	return &Platform{
		wslPath:         wslPath,
		wslVersion:      wslVer,
		wslBuildVersion: buildVer,
		distroName:      defaultDistroName,
		installDir:      installDir,
		wslNetworkMode:  networkMode,
	}
}

// Name returns the platform identifier.
func (p *Platform) Name() string { return "windows-wsl2" }

// Available reports whether WSL2 is usable on this system.
func (p *Platform) Available() bool {
	return p.wslPath != "" && p.wslVersion >= 2
}

// CheckDependencies inspects the system for WSL2 requirements.
func (p *Platform) CheckDependencies() *platform.DependencyCheck {
	check := &platform.DependencyCheck{}
	if p.wslPath == "" {
		check.Errors = append(check.Errors, "wsl.exe not found in PATH: WSL2 is required")
		return check
	}
	if p.wslVersion < 2 {
		check.Errors = append(check.Errors,
			"WSL1 detected; WSL2 is required (run: wsl --set-default-version 2)")
	}
	// CVE-2025-53788 check: TOCTOU privilege escalation in WSL2 < 2.5.10.
	if p.wslBuildVersion != (semver{}) && p.wslBuildVersion.Less(minWSLVersion) {
		check.Errors = append(check.Errors,
			fmt.Sprintf("WSL version %s is below %s — vulnerable to CVE-2025-53788 "+
				"(TOCTOU privilege escalation, CVSS 7.0). Update with: wsl --update",
				p.wslBuildVersion, minWSLVersion))
	}
	if !p.distroExists() {
		check.Warnings = append(check.Warnings,
			"sandbox distro not yet provisioned (will be created on first use)")
	}
	p.helperMu.Lock()
	helperReady := p.helperAvailable
	helperPath := p.helperBinaryPath
	p.helperMu.Unlock()
	if helperReady {
		// Full Mode active — sandbox-helper installed in distro.
	} else if helperPath != "" {
		check.Warnings = append(check.Warnings,
			"sandbox-helper binary provided but not yet installed (will install on first WrapCommand)")
	} else {
		check.Warnings = append(check.Warnings,
			"sandbox-helper not configured: using Simple Mode (Tier 1 only). "+
				"Call SetHelperBinary() for Full Mode with Linux-level isolation")
	}
	return check
}

// SetHelperBinary tells the platform where the pre-built Linux sandbox-helper
// binary is located on the Windows filesystem. During provisioning or the
// first Full Mode WrapCommand call, the binary is installed into the WSL2
// distro. If the binary does not exist at the given path, an error is returned.
func (p *Platform) SetHelperBinary(windowsPath string) error {
	if _, err := os.Stat(windowsPath); err != nil {
		return fmt.Errorf("%w: %s", errHelperBinaryNotFound, windowsPath)
	}
	p.helperMu.Lock()
	p.helperBinaryPath = windowsPath
	p.helperMu.Unlock()
	return nil
}

// WrapCommand modifies cmd to execute within the WSL2 sandbox.
// If the sandbox helper is installed in the distro (Full Mode / Tier 2),
// the command runs with Linux-level isolation (namespaces, Landlock, seccomp).
// Otherwise, it falls back to Simple Mode (Tier 1) with WSL2 VM isolation only.
func (p *Platform) WrapCommand(ctx context.Context, cmd *exec.Cmd, cfg *platform.WrapConfig) error {
	if cfg == nil {
		cfg = &platform.WrapConfig{}
	}
	if !p.Available() {
		return errors.New("windows-wsl2: platform is not available")
	}

	// Ensure distro is provisioned.
	if err := p.ensureDistro(ctx); err != nil {
		return fmt.Errorf("provisioning sandbox distro: %w", err)
	}

	// Try to install the helper if a binary path was provided but helper
	// is not yet installed. If installation fails, fall back to Simple Mode
	// gracefully — this is intentional so that WrapCommand never hard-fails
	// due to optional helper features. Users can detect the fallback via
	// CheckDependencies() which reports whether Full Mode is active.
	p.helperMu.Lock()
	if p.helperBinaryPath != "" && !p.helperAvailable {
		if p.helperInstalled() {
			p.helperAvailable = true
		} else if err := p.installHelper(ctx, p.helperBinaryPath); err == nil {
			p.helperAvailable = true
		}
		// else: installation failed, remain in Simple Mode
	} else if p.helperAvailable || (p.helperBinaryPath != "" && p.helperInstalled()) {
		p.helperAvailable = true
	}
	useFullMode := p.helperAvailable
	p.helperMu.Unlock()

	if useFullMode {
		return p.wrapCommandFullMode(ctx, cmd, cfg)
	}
	return p.wrapCommandSimpleMode(cmd, cfg)
}

// wrapCommandSimpleMode wraps cmd for Tier 1 (WSL2 VM boundary only):
//
//	wsl.exe -d <distro> -e /bin/sh -c "<command>"
func (p *Platform) wrapCommandSimpleMode(cmd *exec.Cmd, cfg *platform.WrapConfig) error {
	// Save original command.
	origArgs := cmd.Args

	// Build wsl.exe arguments for Simple Mode:
	//   wsl.exe -d <distro> -e /bin/sh -c "<command>"
	wslArgs := []string{p.wslPath, "-d", p.distroName, "-e", "/bin/sh", "-c"}

	// Reconstruct command string.
	// NOTE: cfg.Shell is intentionally ignored in Simple Mode. The outer
	// wrapper already uses /bin/sh (see wslArgs above), and cfg.Shell
	// typically contains a Windows path (e.g. cmd.exe) that does not
	// exist inside the Linux distro.
	quoted := make([]string, len(origArgs))
	for i, a := range origArgs {
		quoted[i] = shellQuote(a)
	}
	cmdStr := strings.Join(quoted, " ")

	// Translate the working directory from Windows to WSL path.
	// cmd.Dir is cleared because wsl.exe itself runs on Windows; the
	// directory change is applied inside the Linux distro via cd.
	if cmd.Dir != "" {
		wslDir, err := ToWSL(cmd.Dir)
		if err != nil {
			return fmt.Errorf("translate working dir: %w", err)
		}
		cmdStr = "cd " + shellQuote(wslDir) + " && " + cmdStr
		cmd.Dir = ""
	}

	// In NAT mode, proxy env vars must be resolved at shell time, so we
	// prepend a shell snippet that discovers the host IP from resolv.conf.
	if p.wslNetworkMode != "mirrored" {
		cmdStr = p.prependNATProxyExports(cmdStr, cfg)
	}

	wslArgs = append(wslArgs, cmdStr)

	cmd.Path = p.wslPath
	cmd.Args = wslArgs

	// Sanitize environment, translating Windows paths to WSL paths.
	cmd.Env = p.sanitizeEnv(cmd.Env, cfg)

	return nil
}

// Cleanup releases platform resources by terminating the sandbox distro.
func (p *Platform) Cleanup(ctx context.Context) error {
	if p.wslPath == "" {
		return nil
	}
	if err := wslCommandContext(ctx, p.wslPath, "--terminate", p.distroName).Run(); err != nil {
		return fmt.Errorf("terminate distro: %w", err)
	}
	return nil
}

// Capabilities returns the isolation features this platform supports.
func (p *Platform) Capabilities() platform.Capabilities {
	return platform.Capabilities{
		FileReadDeny:   true,
		FileWriteAllow: true,
		NetworkDeny:    true,
		NetworkProxy:   true,
		PIDIsolation:   true,
		SyscallFilter:  true,
		ProcessHarden:  true,
	}
}

// findWSLExe locates wsl.exe on the system.
func findWSLExe() string {
	// Look for wsl.exe in System32.
	sys32 := filepath.Join(os.Getenv("SYSTEMROOT"), "System32", "wsl.exe")
	if _, err := os.Stat(sys32); err == nil {
		return sys32
	}
	// Fallback to PATH.
	path, err := exec.LookPath("wsl.exe")
	if err == nil {
		return path
	}
	return ""
}

// detectWSL runs wsl.exe subcommands to determine the WSL version and build.
// It uses parseWSLVersionOutput, parseWSLStatusOutput, and parseWSLListVerbose
// from detect.go. Output is decoded from UTF-16LE when necessary via
// cleanWSLOutput (see encoding.go). Each command has a timeout to prevent
// hangs when the WSL service is unresponsive.
func detectWSL(wslPath string) (int, semver) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Try "wsl.exe --version" first (most informative).
	out, err := wslCommandContext(ctx, wslPath, "--version").CombinedOutput()
	if err == nil {
		ver, sv, parseErr := parseWSLVersionOutput(cleanWSLOutput(out))
		if parseErr == nil {
			return ver, sv
		}
	}
	// Fallback to "wsl.exe --status".
	out, err = wslCommandContext(ctx, wslPath, "--status").CombinedOutput()
	if err == nil {
		ver, parseErr := parseWSLStatusOutput(cleanWSLOutput(out))
		if parseErr == nil {
			return ver, semver{}
		}
	}
	// Fallback to "wsl.exe -l -v".
	out, err = wslCommandContext(ctx, wslPath, "-l", "-v").CombinedOutput()
	if err == nil {
		ver, parseErr := parseWSLListVerbose(cleanWSLOutput(out))
		if parseErr == nil {
			return ver, semver{}
		}
	}
	return 0, semver{}
}

// ensureDistro provisions the sandbox distro exactly once.
func (p *Platform) ensureDistro(ctx context.Context) error {
	p.distroOnce.Do(func() {
		p.distroErr = p.provisionIfNeeded(ctx)
	})
	return p.distroErr
}

func (p *Platform) provisionIfNeeded(ctx context.Context) error {
	if p.distroExists() {
		return nil
	}
	return p.provisionDistro(ctx)
}

// distroExists checks whether the sandbox distro is already registered.
// Output is decoded from UTF-16LE when necessary (see encoding.go).
// A short timeout prevents hangs when the WSL service is not responsive.
func (p *Platform) distroExists() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := wslCommandContext(ctx, p.wslPath, "-l", "-q").CombinedOutput()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(cleanWSLOutput(out), "\n") {
		if strings.TrimSpace(line) == p.distroName {
			return true
		}
	}
	return false
}

// sanitizeEnv filters Windows-specific environment variables, translates
// Windows paths in values to WSL paths, and injects WSL-specific settings.
// In mirrored mode, proxy env vars use "localhost" directly. In NAT mode,
// proxy env vars are injected via shell exports in the command string (see
// prependNATProxyExports) so they are NOT added here.
func (p *Platform) sanitizeEnv(env []string, cfg *platform.WrapConfig) []string {
	if len(env) == 0 {
		env = os.Environ()
	}
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		key, val, _ := strings.Cut(e, "=")
		upper := strings.ToUpper(key)
		switch upper {
		case "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
			"OS", "PROGRAMFILES", "APPDATA", "LOCALAPPDATA", "PATH":
			continue
		default:
			// Translate Windows paths in values to WSL paths so that
			// env vars like GOCACHE=C:\Users\... become
			// GOCACHE=/mnt/c/Users/... inside the Linux distro.
			if looksLikeWindowsPath(val) {
				if wslVal, err := ToWSL(val); err == nil {
					val = wslVal
				}
				e = key + "=" + val
			}
			filtered = append(filtered, e)
		}
	}
	// Inject WSL_UTF8 for consistent output encoding.
	filtered = append(filtered, "WSL_UTF8=1")

	// In mirrored mode, localhost works directly — set proxy env vars.
	// In NAT mode, proxy is handled via shell exports in the command string.
	if p.wslNetworkMode == "mirrored" {
		if cfg.HTTPProxyPort > 0 {
			filtered = append(filtered,
				fmt.Sprintf("HTTP_PROXY=http://localhost:%d", cfg.HTTPProxyPort),
				fmt.Sprintf("HTTPS_PROXY=http://localhost:%d", cfg.HTTPProxyPort),
			)
		}
		if cfg.SOCKSProxyPort > 0 {
			filtered = append(filtered,
				fmt.Sprintf("ALL_PROXY=socks5://localhost:%d", cfg.SOCKSProxyPort),
			)
		}
	}
	return filtered
}

// hostIPShellExpr is the shell expression to resolve the Windows host IP
// from WSL2's NAT network. The host IP appears as the nameserver in
// /etc/resolv.conf.
const hostIPShellExpr = `$(cat /etc/resolv.conf | grep nameserver | head -1 | awk '{print $2}')`

// prependNATProxyExports returns cmdStr prefixed with shell variable
// assignments that resolve the host IP and export HTTP_PROXY / HTTPS_PROXY /
// ALL_PROXY when the platform is in NAT mode and proxy ports are configured.
// If no proxy is configured, cmdStr is returned unchanged.
func (p *Platform) prependNATProxyExports(cmdStr string, cfg *platform.WrapConfig) string {
	if cfg.HTTPProxyPort <= 0 && cfg.SOCKSProxyPort <= 0 {
		return cmdStr
	}

	var parts []string
	parts = append(parts, fmt.Sprintf("_AGENTBOX_HOST=%s", hostIPShellExpr))
	if cfg.HTTPProxyPort > 0 {
		parts = append(parts,
			fmt.Sprintf("export HTTP_PROXY=http://$_AGENTBOX_HOST:%d", cfg.HTTPProxyPort),
			fmt.Sprintf("export HTTPS_PROXY=http://$_AGENTBOX_HOST:%d", cfg.HTTPProxyPort),
		)
	}
	if cfg.SOCKSProxyPort > 0 {
		parts = append(parts,
			fmt.Sprintf("export ALL_PROXY=socks5://$_AGENTBOX_HOST:%d", cfg.SOCKSProxyPort),
		)
	}
	parts = append(parts, cmdStr)
	return strings.Join(parts, " && ")
}

// proxyHostAddr returns the address that WSL2 should use to reach the
// Windows host for proxy connections in mirrored mode.
func (p *Platform) proxyHostAddr() string {
	if p.wslNetworkMode == "mirrored" {
		return "localhost"
	}
	// In NAT mode, the host IP is resolved at shell time via
	// prependNATProxyExports, not through this function.
	return "localhost"
}

// detectWSLNetworkMode reads ~/.wslconfig to determine the WSL2 networking mode.
// Returns "mirrored" if explicitly configured, "nat" otherwise.
func detectWSLNetworkMode() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "nat"
	}
	cfg, err := os.ReadFile(filepath.Join(home, ".wslconfig"))
	if err != nil {
		return "nat"
	}
	inWSL2Section := false
	for _, line := range strings.Split(string(cfg), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inWSL2Section = strings.EqualFold(line, "[wsl2]")
			continue
		}
		if inWSL2Section && strings.HasPrefix(strings.ToLower(line), "networkingmode") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 && strings.TrimSpace(strings.ToLower(parts[1])) == "mirrored" {
				return "mirrored"
			}
		}
	}
	return "nat"
}

// shellQuote wraps s in single quotes, escaping any embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// looksLikeWindowsPath returns true if s appears to be a Windows absolute path
// (e.g. "C:\Users\..." or "D:/temp"). It checks for a drive letter followed
// by a colon and a path separator.
func looksLikeWindowsPath(s string) bool {
	if len(s) < 3 {
		return false
	}
	drive := s[0]
	if !((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) {
		return false
	}
	return s[1] == ':' && (s[2] == '\\' || s[2] == '/')
}
