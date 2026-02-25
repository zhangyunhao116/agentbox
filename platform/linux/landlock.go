//go:build linux

package linux

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/zhangyunhao116/agentbox/platform"
)

// Landlock ABI constants.
const (
	// landlockCreateRulesetFlags is the syscall number for landlock_create_ruleset.
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446
)

// Function variables for Landlock syscalls, overridden in tests.
var landlockCreateRulesetFn = func(attr, size, flags uintptr) (uintptr, uintptr, syscall.Errno) {
	return syscall.Syscall(uintptr(sysLandlockCreateRuleset), attr, size, flags)
}

var landlockAddRuleFn = func(rulesetFd, ruleType, ruleAttr, flags, _, _ uintptr) (uintptr, uintptr, syscall.Errno) {
	return syscall.Syscall6(uintptr(sysLandlockAddRule), rulesetFd, ruleType, ruleAttr, flags, 0, 0)
}

var landlockRestrictSelfFn = func(rulesetFd, flags, _ uintptr) (uintptr, uintptr, syscall.Errno) {
	return syscall.Syscall(uintptr(sysLandlockRestrictSelf), rulesetFd, flags, 0)
}

var openPathFn = syscall.Open

var closePathFn = syscall.Close

var statPathFn = os.Stat

// Landlock access flags for filesystem operations.
const (
	accessFSExecute    = 1 << 0
	accessFSWriteFile  = 1 << 1
	accessFSReadFile   = 1 << 2
	accessFSReadDir    = 1 << 3
	accessFSRemoveDir  = 1 << 4
	accessFSRemoveFile = 1 << 5
	accessFSMakeChar   = 1 << 6
	accessFSMakeDir    = 1 << 7
	accessFSMakeReg    = 1 << 8
	accessFSMakeSock   = 1 << 9
	accessFSMakeFifo   = 1 << 10
	accessFSMakeBlock  = 1 << 11
	accessFSMakeSym    = 1 << 12
	accessFSRefer      = 1 << 13 // ABI v2
	accessFSTruncate   = 1 << 14 // ABI v3
)

// landlockRulesetAttr is the attribute structure for landlock_create_ruleset.
type landlockRulesetAttr struct {
	handledAccessFS uint64
}

// landlockPathBeneathAttr is the attribute structure for LANDLOCK_RULE_PATH_BENEATH.
type landlockPathBeneathAttr struct {
	allowedAccess uint64
	parentFd      int32
	_             [4]byte // padding
}

// LandlockInfo describes Landlock support on the current kernel.
type LandlockInfo struct {
	// Supported indicates whether Landlock is available.
	Supported bool

	// ABIVersion is the Landlock ABI version supported by the kernel.
	ABIVersion int

	// Features is a human-readable description of supported features.
	Features string
}

// DetectLandlock checks Landlock support on the running kernel.
func DetectLandlock() LandlockInfo {
	// Use landlock_create_ruleset with flag 1 (LANDLOCK_CREATE_RULESET_VERSION)
	// to query the ABI version without creating a ruleset.
	version, _, errno := landlockCreateRulesetFn(0, 0, 1)
	if errno != 0 {
		return LandlockInfo{
			Supported: false,
			Features:  "landlock not available: " + errno.Error(),
		}
	}

	abi := int(version)
	features := fmt.Sprintf("ABI v%d", abi)
	switch {
	case abi >= 3:
		features += " (fs access, refer, truncate)"
	case abi >= 2:
		features += " (fs access, refer)"
	case abi >= 1:
		features += " (fs access)"
	}

	return LandlockInfo{
		Supported:  true,
		ABIVersion: abi,
		Features:   features,
	}
}

// applyLandlock applies Landlock filesystem restrictions based on the given
// WrapConfig. It creates a Landlock ruleset, adds rules for writable paths,
// and restricts the current process.
func applyLandlock(cfg *platform.WrapConfig) error {
	info := DetectLandlock()
	if !info.Supported {
		return fmt.Errorf("landlock not available: filesystem restrictions cannot be enforced (requires kernel >= 5.13)")
	}

	// Determine the set of handled access rights based on ABI version.
	var handledAccess uint64
	handledAccess = accessFSExecute | accessFSWriteFile | accessFSReadFile |
		accessFSReadDir | accessFSRemoveDir | accessFSRemoveFile |
		accessFSMakeChar | accessFSMakeDir | accessFSMakeReg |
		accessFSMakeSock | accessFSMakeFifo | accessFSMakeBlock |
		accessFSMakeSym
	if info.ABIVersion >= 2 {
		handledAccess |= accessFSRefer
	}
	if info.ABIVersion >= 3 {
		handledAccess |= accessFSTruncate
	}

	// Create the ruleset.
	attr := landlockRulesetAttr{handledAccessFS: handledAccess}
	rulesetFd, _, errno := landlockCreateRulesetFn(
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	defer func() { _ = closePathFn(int(rulesetFd)) }()

	// writeAccess is the set of access rights granted to writable paths.
	writeAccess := uint64(accessFSWriteFile | accessFSReadFile | accessFSReadDir |
		accessFSRemoveDir | accessFSRemoveFile | accessFSMakeDir |
		accessFSMakeReg | accessFSMakeSym | accessFSExecute)
	if info.ABIVersion >= 2 {
		writeAccess |= accessFSRefer
	}
	if info.ABIVersion >= 3 {
		writeAccess |= accessFSTruncate
	}

	// readAccess is the set of access rights granted to read-only paths.
	readAccess := uint64(accessFSExecute | accessFSReadFile | accessFSReadDir)

	// Add rules for writable roots (skip paths in DenyWrite).
	denyWriteSet := make(map[string]bool, len(cfg.DenyWrite))
	for _, p := range cfg.DenyWrite {
		denyWriteSet[p] = true
	}
	for _, path := range cfg.WritableRoots {
		if denyWriteSet[path] {
			// Add as read-only instead of writable.
			if err := landlockAddPathRule(int(rulesetFd), path, readAccess); err != nil {
				return fmt.Errorf("landlock add read-only rule for denied-write %q: %w", path, err)
			}
			continue
		}
		if err := landlockAddPathRule(int(rulesetFd), path, writeAccess); err != nil {
			return fmt.Errorf("landlock add writable rule for %q: %w", path, err)
		}
	}

	// Build a set of DenyRead paths to exclude from readable ruleset.
	denyReadSet := make(map[string]bool, len(cfg.DenyRead))
	for _, p := range cfg.DenyRead {
		denyReadSet[p] = true
	}

	// Allow read access to common system paths (skip DenyRead paths).
	systemReadPaths := []string{"/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin", "/proc", "/dev"}
	for _, path := range systemReadPaths {
		if denyReadSet[path] {
			continue
		}
		if _, err := statPathFn(path); err == nil {
			if err := landlockAddPathRule(int(rulesetFd), path, readAccess); err != nil {
				// Non-fatal: some paths may not exist.
				continue
			}
		}
	}

	// Restrict self.
	_, _, errno = landlockRestrictSelfFn(
		rulesetFd,
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}

	return nil
}

// landlockAddPathRule adds a path-beneath rule to the given Landlock ruleset.
func landlockAddPathRule(rulesetFd int, path string, allowedAccess uint64) error {
	// O_PATH (0x200000) is not defined in Go's syscall package for all platforms.
	const oPath = 0x200000
	fd, err := openPathFn(path, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %q: %w", path, err)
	}
	defer func() { _ = closePathFn(fd) }()

	pathAttr := landlockPathBeneathAttr{
		allowedAccess: allowedAccess,
		parentFd:      int32(fd), //nolint:gosec // fd is a small file descriptor, no overflow risk
	}

	_, _, errno := landlockAddRuleFn(
		uintptr(rulesetFd),
		1, // LANDLOCK_RULE_PATH_BENEATH
		uintptr(unsafe.Pointer(&pathAttr)),
		0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_add_rule: %w", errno)
	}

	return nil
}
