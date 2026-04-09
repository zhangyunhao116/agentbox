//go:build linux

package linux

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/zhangyunhao116/agentbox/platform"
)

// Function variables for dependency injection in tests.
var mountFn = syscall.Mount
var evalSymlinksFn = filepath.EvalSymlinks

// applyReadOnlyBindMounts enforces DenyWrite paths that are subpaths of
// writable roots by bind-mounting them as read-only. This MUST be called
// inside a mount namespace (CLONE_NEWNS) to avoid affecting the host.
//
// Landlock cannot restrict subpaths below a parent with broader access
// (access rights are unioned along the path hierarchy within a layer).
// Read-only bind mounts provide kernel-enforced write protection.
func applyReadOnlyBindMounts(cfg *platform.WrapConfig) error {
	subpaths := denyWriteSubpaths(cfg.DenyWrite, cfg.WritableRoots)
	if len(subpaths) == 0 {
		return nil
	}

	// Make the root mount private to prevent bind mount propagation back to
	// the host namespace. On systems where "/" is shared, bind/remount
	// operations would otherwise propagate despite CLONE_NEWNS.
	if err := mountFn("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make root mount private: %w", err)
	}

	for _, p := range subpaths {
		// Resolve symlinks for the mount target.
		target := p
		if resolved, err := evalSymlinksFn(p); err == nil {
			target = resolved
		}
		// Check that the resolved path exists before attempting to bind-mount.
		if _, err := statPathFn(target); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // Non-fatal: path does not exist.
			}
			return fmt.Errorf("stat deny-write path %q: %w", target, err)
		}
		// Bind mount the path onto itself.
		if err := mountFn(target, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
			return fmt.Errorf("bind mount %q: %w", target, err)
		}
		// Remount as read-only. MS_REMOUNT|MS_BIND|MS_REC|MS_RDONLY makes
		// the bind mount (and any nested submounts) read-only without
		// affecting the underlying filesystem.
		if err := mountFn("", target, "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_REC|syscall.MS_RDONLY, ""); err != nil {
			return fmt.Errorf("remount read-only %q: %w", target, err)
		}
	}
	return nil
}

// denyWriteSubpaths returns DenyWrite paths that are strict subpaths
// (not exact matches) of any writable root. Exact matches are handled
// by the Landlock DenyWrite set logic directly.
func denyWriteSubpaths(denyWrite, writableRoots []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, dw := range denyWrite {
		cdw := filepath.Clean(dw)
		if resolved, err := evalSymlinksFn(cdw); err == nil {
			cdw = resolved
		}
		for _, wr := range writableRoots {
			cwr := filepath.Clean(wr)
			if resolved, err := evalSymlinksFn(cwr); err == nil {
				cwr = resolved
			}
			isSubpath := false
			if cwr == "/" {
				isSubpath = cdw != cwr
			} else {
				isSubpath = cdw != cwr && strings.HasPrefix(cdw, cwr+string(filepath.Separator))
			}
			if isSubpath {
				if _, ok := seen[cdw]; !ok {
					seen[cdw] = struct{}{}
					result = append(result, cdw)
				}
				break
			}
		}
	}
	return result
}
