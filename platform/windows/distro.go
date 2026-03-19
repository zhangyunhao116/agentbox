//go:build windows

package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const (
	alpineVersion = "3.21.3"
	alpineArch    = "x86_64"
	alpineURL     = "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/" +
		"alpine-minirootfs-" + alpineVersion + "-" + alpineArch + ".tar.gz"
	// alpineSHA256 is the SHA256 of the Alpine minirootfs tarball.
	// Update when alpineVersion changes.
	alpineSHA256 = "1a694899e406ce55d32334c47ac0b2efb6c06d7e878102d1840892ad44cd5239"
)

// wslConfContent returns the /etc/wsl.conf content written into the sandbox distro.
// Security-critical: interop disabled, non-root user.
// Note: automount uses metadata mode (not read-only) because Simple Mode
// relies on the unprivileged sandbox user for write control rather than
// filesystem mount options. Full Mode adds Landlock for fine-grained access.
func wslConfContent() string {
	return `[interop]
enabled=false
appendWindowsPath=false

[automount]
enabled=true
options="metadata"
mountFsTab=false

[user]
default=sandbox

[network]
hostname=` + defaultDistroName + `
generateHosts=false
generateResolvConf=true

[boot]
systemd=false
`
}

// provisionDistro imports a fresh Alpine rootfs as a WSL2 distro and
// configures it for sandboxed execution.
func (p *Platform) provisionDistro(ctx context.Context) error {
	// Create install directory.
	if err := os.MkdirAll(p.installDir, 0o700); err != nil {
		return fmt.Errorf("creating install directory: %w", err)
	}

	// Download rootfs if not cached.
	tarball := filepath.Join(p.installDir, "rootfs.tar.gz")
	if _, err := os.Stat(tarball); err != nil {
		if err := downloadRootfs(ctx, tarball); err != nil {
			return fmt.Errorf("downloading rootfs: %w", err)
		}
	}

	// Import distro via "wsl.exe --import <name> <dir> <tarball>".
	importCmd := wslCommandContext(ctx, p.wslPath,
		"--import", p.distroName, p.installDir, tarball)
	if out, err := importCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("importing distro: %s: %w", string(out), err)
	}

	// Write /etc/wsl.conf for sandbox hardening.
	writeConf := wslCommandContext(ctx, p.wslPath,
		"-d", p.distroName, "-e", "sh", "-c",
		fmt.Sprintf("cat > /etc/wsl.conf << 'EOF'\n%sEOF", wslConfContent()))
	if out, err := writeConf.CombinedOutput(); err != nil {
		return fmt.Errorf("writing wsl.conf: %s: %w", string(out), err)
	}

	// Create unprivileged sandbox user.
	addUser := wslCommandContext(ctx, p.wslPath,
		"-d", p.distroName, "-e", "sh", "-c",
		"adduser -D -s /bin/sh sandbox")
	if out, err := addUser.CombinedOutput(); err != nil {
		return fmt.Errorf("creating sandbox user: %s: %w", string(out), err)
	}

	// Create helper directory.
	mkHelper := wslCommandContext(ctx, p.wslPath,
		"-d", p.distroName, "-e", "sh", "-c",
		"mkdir -p /opt/agentbox")
	if out, err := mkHelper.CombinedOutput(); err != nil {
		return fmt.Errorf("creating helper dir: %s: %w", string(out), err)
	}

	// Terminate the distro to apply wsl.conf on next start.
	termCmd := wslCommandContext(ctx, p.wslPath, "--terminate", p.distroName)
	_ = termCmd.Run()

	return nil
}

// downloadRootfs fetches the Alpine minirootfs tarball to dest, optionally
// verifying its SHA256 checksum.
func downloadRootfs(ctx context.Context, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, alpineURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", alpineURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	tmpFile := dest + ".tmp"
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		os.Remove(tmpFile) // clean up on error; no-op if renamed
	}()

	h := sha256.New()
	if _, err := io.Copy(f, io.TeeReader(resp.Body, h)); err != nil {
		return fmt.Errorf("writing rootfs: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}

	// Verify SHA256 if configured.
	if alpineSHA256 != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if got != alpineSHA256 {
			return fmt.Errorf("SHA256 mismatch: got %s, want %s", got, alpineSHA256)
		}
	}

	return os.Rename(tmpFile, dest)
}

// Unregister removes the sandbox distro entirely.
func (p *Platform) Unregister(ctx context.Context) error {
	if err := wslCommandContext(ctx, p.wslPath, "--unregister", p.distroName).Run(); err != nil {
		return fmt.Errorf("unregister distro %s: %w", p.distroName, err)
	}
	return nil
}
