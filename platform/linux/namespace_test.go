//go:build linux

package linux

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
)

// saveRlimit saves the current rlimit for the given resource and restores it
// after the test completes. This prevents tests that call applyResourceLimits
// from permanently altering the process rlimits.
func saveRlimit(t *testing.T, resource int) {
	t.Helper()
	var orig syscall.Rlimit
	if err := syscall.Getrlimit(resource, &orig); err != nil {
		t.Fatalf("getrlimit(%d): %v", resource, err)
	}
	t.Cleanup(func() {
		syscall.Setrlimit(resource, &orig)
	})
}

// safeLimit returns the smaller of defaultLimit and the current hard limit for
// resource. This avoids EPERM when the test runs in a container whose hard
// limits are lower than the desired value.
func safeLimit(t *testing.T, resource int) uint64 {
	t.Helper()
	const defaultLimit = 65536
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(resource, &rl); err != nil {
		t.Fatalf("getrlimit(%d): %v", resource, err)
	}
	if defaultLimit > rl.Max {
		return rl.Max
	}
	return defaultLimit
}

func TestConfigureNamespaces_DefaultFlags(t *testing.T) {
	cmd := exec.Command("/bin/echo")
	cfg := &platform.WrapConfig{}
	configureNamespaces(cmd, cfg)

	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr is nil")
	}
	flags := cmd.SysProcAttr.Cloneflags
	if flags&syscall.CLONE_NEWUSER == 0 {
		t.Error("CLONE_NEWUSER not set")
	}
	if flags&syscall.CLONE_NEWNS == 0 {
		t.Error("CLONE_NEWNS not set")
	}
	if flags&syscall.CLONE_NEWPID == 0 {
		t.Error("CLONE_NEWPID not set")
	}
	// IPC namespace should be set by default.
	const cloneNewIPC = 0x08000000
	if flags&cloneNewIPC == 0 {
		t.Error("CLONE_NEWIPC not set")
	}
	// UTS namespace should be set by default.
	const cloneNewUTS = 0x04000000
	if flags&cloneNewUTS == 0 {
		t.Error("CLONE_NEWUTS not set")
	}
	// Network namespace should NOT be set by default.
	if flags&syscall.CLONE_NEWNET != 0 {
		t.Error("CLONE_NEWNET should not be set by default")
	}
}

func TestConfigureNamespaces_WithNetworkRestriction(t *testing.T) {
	cmd := exec.Command("/bin/echo")
	cfg := &platform.WrapConfig{NeedsNetworkRestriction: true}
	configureNamespaces(cmd, cfg)

	flags := cmd.SysProcAttr.Cloneflags
	if flags&syscall.CLONE_NEWNET == 0 {
		t.Error("CLONE_NEWNET should be set when NeedsNetworkRestriction=true")
	}
	// Other default flags should still be present.
	if flags&syscall.CLONE_NEWUSER == 0 {
		t.Error("CLONE_NEWUSER not set")
	}
	if flags&syscall.CLONE_NEWNS == 0 {
		t.Error("CLONE_NEWNS not set")
	}
	if flags&syscall.CLONE_NEWPID == 0 {
		t.Error("CLONE_NEWPID not set")
	}
	const cloneNewIPC = 0x08000000
	if flags&cloneNewIPC == 0 {
		t.Error("CLONE_NEWIPC not set")
	}
	const cloneNewUTS = 0x04000000
	if flags&cloneNewUTS == 0 {
		t.Error("CLONE_NEWUTS not set")
	}
}

func TestConfigureNamespaces_UidGidMappings(t *testing.T) {
	cmd := exec.Command("/bin/echo")
	cfg := &platform.WrapConfig{}
	configureNamespaces(cmd, cfg)

	uid := os.Getuid()
	gid := os.Getgid()

	if len(cmd.SysProcAttr.UidMappings) != 1 {
		t.Fatalf("UidMappings: got %d entries, want 1", len(cmd.SysProcAttr.UidMappings))
	}
	uidMap := cmd.SysProcAttr.UidMappings[0]
	if uidMap.ContainerID != 0 {
		t.Errorf("UidMappings[0].ContainerID = %d, want 0", uidMap.ContainerID)
	}
	if uidMap.HostID != uid {
		t.Errorf("UidMappings[0].HostID = %d, want %d", uidMap.HostID, uid)
	}
	if uidMap.Size != 1 {
		t.Errorf("UidMappings[0].Size = %d, want 1", uidMap.Size)
	}

	if len(cmd.SysProcAttr.GidMappings) != 1 {
		t.Fatalf("GidMappings: got %d entries, want 1", len(cmd.SysProcAttr.GidMappings))
	}
	gidMap := cmd.SysProcAttr.GidMappings[0]
	if gidMap.ContainerID != 0 {
		t.Errorf("GidMappings[0].ContainerID = %d, want 0", gidMap.ContainerID)
	}
	if gidMap.HostID != gid {
		t.Errorf("GidMappings[0].HostID = %d, want %d", gidMap.HostID, gid)
	}
	if gidMap.Size != 1 {
		t.Errorf("GidMappings[0].Size = %d, want 1", gidMap.Size)
	}
}

func TestConfigureNamespaces_PreservesExistingSysProcAttr(t *testing.T) {
	cmd := exec.Command("/bin/echo")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	cfg := &platform.WrapConfig{}
	configureNamespaces(cmd, cfg)

	// Cloneflags should be set.
	if cmd.SysProcAttr.Cloneflags == 0 {
		t.Error("Cloneflags not set on existing SysProcAttr")
	}
	// The pre-existing Setsid field should be preserved.
	if !cmd.SysProcAttr.Setsid {
		t.Error("Setsid was overwritten; existing SysProcAttr fields should be preserved")
	}
}

func TestConfigureNamespaces_NilSysProcAttr(t *testing.T) {
	cmd := exec.Command("/bin/echo")
	cmd.SysProcAttr = nil // explicitly nil
	cfg := &platform.WrapConfig{}
	configureNamespaces(cmd, cfg)

	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr should be created when nil")
	}
	if cmd.SysProcAttr.Cloneflags == 0 {
		t.Error("Cloneflags not set on newly created SysProcAttr")
	}
}

func TestApplyResourceLimits_NilLimits(t *testing.T) {
	err := applyResourceLimits(nil)
	if err != nil {
		t.Fatalf("applyResourceLimits(nil) error: %v", err)
	}
}

func TestApplyResourceLimits_ZeroValues(t *testing.T) {
	err := applyResourceLimits(&platform.ResourceLimits{})
	if err != nil {
		t.Fatalf("applyResourceLimits(zero values) error: %v", err)
	}
}

func TestApplyResourceLimits_AllFields(t *testing.T) {
	saveRlimit(t, rlimitNPROC)
	saveRlimit(t, rlimitNOFILE)
	saveRlimit(t, rlimitAS)
	saveRlimit(t, rlimitCPU)

	// Query current hard limits so we don't exceed them (CI containers may
	// have low hard limits that unprivileged processes cannot raise).
	maxProc := safeLimit(t, rlimitNPROC)
	maxFD := safeLimit(t, rlimitNOFILE)

	limits := &platform.ResourceLimits{
		MaxProcesses:       int(maxProc),
		MaxFileDescriptors: int(maxFD),
		MaxMemoryBytes:     1 << 40, // 1 TB virtual memory (safe, just a limit)
		MaxCPUSeconds:      3600,
	}
	err := applyResourceLimits(limits)
	if err != nil {
		t.Fatalf("applyResourceLimits(all fields) error: %v", err)
	}
}

func TestApplyResourceLimits_PartialFields(t *testing.T) {
	saveRlimit(t, rlimitNOFILE)
	saveRlimit(t, rlimitCPU)

	maxFD := safeLimit(t, rlimitNOFILE)

	// Only MaxFileDescriptors and MaxCPUSeconds set.
	limits := &platform.ResourceLimits{
		MaxFileDescriptors: int(maxFD),
		MaxCPUSeconds:      3600,
	}
	err := applyResourceLimits(limits)
	if err != nil {
		t.Fatalf("applyResourceLimits(partial fields) error: %v", err)
	}
}

func TestApplyResourceLimits_NoCmd(t *testing.T) {
	saveRlimit(t, rlimitNOFILE)

	maxFD := safeLimit(t, rlimitNOFILE)

	// Verify that applyResourceLimits works without cmd parameter.
	limits := &platform.ResourceLimits{
		MaxFileDescriptors: int(maxFD),
	}
	err := applyResourceLimits(limits)
	if err != nil {
		t.Fatalf("applyResourceLimits error: %v", err)
	}
}

// TestApplyResourceLimits_SetrlimitError verifies that applyResourceLimits returns
// an error when setrlimit fails.
func TestApplyResourceLimits_SetrlimitError(t *testing.T) {
	origSetrlimit := setrlimitFunc
	t.Cleanup(func() { setrlimitFunc = origSetrlimit })

	setrlimitFunc = func(resource int, rlim *syscall.Rlimit) error {
		return errors.New("simulated setrlimit failure")
	}

	limits := &platform.ResourceLimits{
		MaxProcesses: 100,
	}
	err := applyResourceLimits(limits)
	if err == nil {
		t.Fatal("applyResourceLimits() expected error when setrlimit fails, got nil")
	}
	if !strings.Contains(err.Error(), "setrlimit resource") {
		t.Errorf("error should mention 'setrlimit resource', got: %v", err)
	}
}
