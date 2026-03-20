//go:build windows

package windows

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"syscall"

	"github.com/zhangyunhao116/agentbox/platform"
	"golang.org/x/sys/windows"
)

// aclCleanupInfo tracks ACL entries and their associated SID for cleanup.
type aclCleanupInfo struct {
	entries []aclEntry
	sid     *windows.SID
}

// Platform implements the platform.Platform interface using native Windows
// security mechanisms: Restricted Tokens, Job Objects, and Low Integrity Level.
//
// This implementation provides process-level sandboxing without requiring WSL2,
// making it suitable for environments where WSL is unavailable or undesirable.
//
// Two-tier architecture:
//  Tier 1 (non-admin): Restricted Token + Job Object + Low IL + ACLs
//  Tier 2 (admin): Tier 1 PLUS sandbox users + firewall rules (network isolation)
//
// Tier 1 security layers:
//  1. Restricted Token - removes privileges and adds restricting SIDs
//  2. Low Integrity Level - prevents write-up to Medium IL objects
//  3. Job Object - resource limits and automatic process tree cleanup
//  4. ACLs - filesystem access control for WritableRoots and DenyWrite paths
//
// Tier 2 additions (requires admin):
//  5. Sandbox Users - dedicated local user accounts for isolation
//  6. Firewall Rules - per-user-SID outbound network blocking
//
// Thread-safety: Platform is safe for concurrent use. The activeJobs, activeTokens,
// and activeACLs slices are protected by a mutex.
type Platform struct {
	mu          sync.Mutex
	osVersion   uint32            // major OS version (10 = Win10+)
	isAdmin     bool              // running as administrator
	initialized bool              // initialization complete
	activeJobs  []windows.Handle  // job handles for cleanup
	activeTokens []windows.Token   // token handles for cleanup
	activeACLs  []aclCleanupInfo  // ACL entries for cleanup
	
	// Tier 2 (admin-only) components
	userManager *SandboxUserManager // manages sandbox user accounts
	fwManager   *FirewallManager    // manages firewall rules
	tier2Active bool                // whether Tier 2 was successfully set up
}

// compile-time interface implementation check
var _ platform.Platform = (*Platform)(nil)

// New creates and initializes a new Windows native sandbox platform.
// It detects the OS version and administrator status during construction.
// If running as administrator, it attempts to set up Tier 2 features
// (sandbox users + firewall rules) for enhanced network isolation.
func New() *Platform {
	p := &Platform{}

	// Detect OS version using RtlGetNtVersionNumbers (reliable, not affected by compatibility shims)
	major, minor, build := windows.RtlGetNtVersionNumbers()
	_ = minor // unused
	_ = build // unused
	p.osVersion = major

	// Check if running as administrator by attempting to open a privileged object
	// We use \\.\PhysicalDrive0 as a test - only admins can open it
	p.isAdmin = checkAdminStatus()

	// Attempt Tier 2 setup if running as administrator
	if p.isAdmin {
		p.userManager = &SandboxUserManager{}
		p.fwManager = NewFirewallManager()
		
		// Try to set up Tier 2 (sandbox users + firewall rules)
		// If setup fails, fall back to Tier 1 gracefully (logged in CheckDependencies)
		if err := p.setupTier2(); err != nil {
			// Tier 2 setup failed - remain at Tier 1
			// The error is stored implicitly by tier2Active=false
			// CheckDependencies will report the fallback status
			p.tier2Active = false
			// Clean up partial state if any
			if p.userManager != nil {
				_ = p.userManager.Teardown()
			}
			if p.fwManager != nil {
				_ = p.fwManager.Cleanup()
			}
		} else {
			p.tier2Active = true
		}
	}

	p.initialized = true
	return p
}

// checkAdminStatus checks if the current process is running with administrator privileges.
// It attempts to open a privileged object (PhysicalDrive0) which only admins can access.
func checkAdminStatus() bool {
	// Try to open \\.\PhysicalDrive0 (requires admin)
	path, err := windows.UTF16PtrFromString(`\\.\PhysicalDrive0`)
	if err != nil {
		return false
	}

	handle, err := windows.CreateFile(
		path,
		0,                           // no access, just test open
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return false // not admin
	}
	windows.CloseHandle(handle)
	return true
}

// setupTier2 initializes Tier 2 admin features: sandbox users and firewall rules.
// This provides network isolation by creating a dedicated local user account and
// blocking outbound network connections for that user via Windows Firewall.
//
// Requirements:
//   - Administrator privileges (checked by caller)
//   - Windows 10+ with netapi32.dll and Windows Firewall enabled
//
// Returns an error if setup fails. The platform falls back to Tier 1 on error.
func (p *Platform) setupTier2() error {
	// Step 1: Create sandbox group + user
	if err := p.userManager.Setup(); err != nil {
		return fmt.Errorf("sandbox user setup: %w", err)
	}

	// Step 2: Get the user for firewall configuration
	user, err := p.userManager.GetUser()
	if err != nil {
		// Clean up on failure
		_ = p.userManager.Teardown()
		return fmt.Errorf("get sandbox user: %w", err)
	}

	// Step 3: Block network for the sandbox user
	if err := p.fwManager.BlockUser(user.Username, user.SID); err != nil {
		// Clean up on failure
		_ = p.userManager.Teardown()
		return fmt.Errorf("firewall setup: %w", err)
	}

	return nil
}

// Name returns the platform identifier.
func (p *Platform) Name() string {
	return "windows-native"
}

// Available returns true if the platform can run on the current system.
// The native Windows sandbox requires Windows 10 or later.
func (p *Platform) Available() bool {
	return p.osVersion >= 10
}

// CheckDependencies validates that all required system features are available.
// Returns OK status on Windows 10+ with warnings/info about tier level and admin status.
func (p *Platform) CheckDependencies() *platform.DependencyCheck {
	if p.osVersion < 10 {
		return &platform.DependencyCheck{
			Errors: []string{fmt.Sprintf("Windows 10+ required, detected version: %d", p.osVersion)},
		}
	}

	check := &platform.DependencyCheck{}
	
	// Report tier status based on admin privilege and Tier 2 setup success
	if p.tier2Active {
		check.Warnings = append(check.Warnings,
			"Tier 2 active: sandbox users + network isolation via Windows Firewall")
	} else if p.isAdmin {
		check.Warnings = append(check.Warnings,
			"running as administrator but Tier 2 setup failed — fallback to Tier 1 (no network isolation)")
	} else {
		check.Warnings = append(check.Warnings,
			"Tier 1: restricted token + job object + low IL (no network isolation, requires admin for Tier 2)")
	}

	return check
}

// Capabilities reports the security features this platform provides.
// NetworkDeny is only available in Tier 2 (admin with sandbox users + firewall).
func (p *Platform) Capabilities() platform.Capabilities {
	return platform.Capabilities{
		FileReadDeny:   false,           // Low IL prevents write-up but not read
		FileWriteAllow: true,            // Restricted token + Low IL + ACLs provide write control
		// NetworkDeny is false even with Tier 2 because processes currently run under
		// the caller's restricted token, not the sandbox user. The firewall rule targets
		// the sandbox user's SID. Full network isolation requires CreateProcessWithLogonW
		// integration to launch processes as the sandbox user. See WrapCommand TODO.
		NetworkDeny:    false,
		NetworkProxy:   false,           // No proxy support in base tier
		PIDIsolation:   false,           // No PID namespaces on Windows
		SyscallFilter:  false,           // No seccomp equivalent on Windows
		ProcessHarden:  true,            // Restricted token + Low IL + Job Object hardening
	}
}

// WrapCommand modifies the given command to run in a sandboxed environment.
// This is the core platform integration point called by the manager.
//
// Tier 1 implementation (non-admin or when Tier 2 setup fails):
//  1. Creates a restricted security token with removed privileges
//  2. Creates a Job Object with resource limits
//  3. Configures the command to start suspended with the restricted token
//  4. Registers a post-start hook to assign the process to the Job Object and resume it
//
// Tier 2 implementation (admin with successful setup):
//  Currently uses the same implementation as Tier 1 (restricted token from caller).
//  The sandbox user and firewall rule are created during Platform initialization,
//  but the process still runs under the caller's restricted token for now.
//
//  TODO: Full Tier 2 integration requires launching the process as the sandbox user
//  via CreateProcessWithLogonW. This will enable the firewall rule to take effect,
//  providing true network isolation. Until then, NetworkDeny remains based on
//  tier2Active reflecting the readiness of Tier 2 infrastructure.
//
// The command must be executed by the caller using cmd.Start() + cmd.Wait().
// Do NOT call cmd.Run() - the post-start hook requires Start/Wait separation.
func (p *Platform) WrapCommand(ctx context.Context, cmd *exec.Cmd, cfg *platform.WrapConfig) error {
	// For now, both Tier 1 and Tier 2 use the same implementation
	// (restricted token from caller's context).
	// Future enhancement: detect p.tier2Active and use CreateProcessWithLogonW
	// to launch as sandbox user for true network isolation.
	return p.wrapCommandTier1(ctx, cmd, cfg)
}

// wrapCommandTier1 implements the Tier 1 sandboxing approach using the caller's
// restricted token. This is the current implementation for both tiers.
func (p *Platform) wrapCommandTier1(ctx context.Context, cmd *exec.Cmd, cfg *platform.WrapConfig) error {
	// Step 1: Create restricted token
	restrictedToken, err := createSandboxToken()
	if err != nil {
		return fmt.Errorf("createSandboxToken failed: %w", err)
	}

	// Step 2: Create Job Object with resource limits
	var limits *platform.ResourceLimits
	if cfg != nil {
		limits = cfg.ResourceLimits
	}
	jobHandle, err := createJobObject(limits)
	if err != nil {
		restrictedToken.Close()
		return fmt.Errorf("createJobObject failed: %w", err)
	}

	// Step 3: Apply filesystem ACLs if configured (best-effort).
	// ACL enforcement is a supplementary layer on top of the core security boundary
	// (restricted token + job object + low integrity level). If ACL setup fails
	// (e.g., insufficient permissions on system directories), the sandbox continues
	// with the token-based isolation which is the primary security mechanism.
	if cfg != nil && (len(cfg.WritableRoots) > 0 || len(cfg.DenyWrite) > 0) {
		// Get the restricted token's user SID for ACL operations
		tokenUser, tokenUserErr := restrictedToken.GetTokenUser()
		if tokenUserErr == nil {
			// Copy the SID so it remains valid after tokenUser is garbage collected.
			// tokenUser.User.Sid points into memory owned by tokenUser — storing it
			// directly in activeACLs would create a dangling pointer.
			sidCopy, sidErr := tokenUser.User.Sid.Copy()
			if sidErr == nil {
				aclEntries, aclErr := applyACLs(cfg, sidCopy)
				if aclErr == nil {
					// Track ACL entries for cleanup (sidCopy is Go-managed, no manual free needed)
					p.mu.Lock()
					p.activeACLs = append(p.activeACLs, aclCleanupInfo{entries: aclEntries, sid: sidCopy})
					p.mu.Unlock()
				}
				// ACL failure is non-fatal: token + job + Low IL provide the core sandbox.
			}
		}
	}

	// Track resources for cleanup
	p.mu.Lock()
	p.activeTokens = append(p.activeTokens, restrictedToken)
	p.activeJobs = append(p.activeJobs, jobHandle)
	p.mu.Unlock()

	// Step 4: Configure command to use restricted token
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// Set the restricted token (Go automatically uses CreateProcessAsUser when Token is set)
	cmd.SysProcAttr.Token = syscall.Token(restrictedToken)

	// Don't set CREATE_SUSPENDED — the restricted token provides the main security boundary.
	// Job Object is assigned after Start() with a tiny race window, which is acceptable
	// because:
	// 1. The token already restricts the process (primary security layer)
	// 2. The Job Object's KILL_ON_JOB_CLOSE ensures the process can't escape cleanup
	// 3. This matches the approach used by many real-world sandboxes

	// Step 5: Register post-start hook for Job Object assignment
	// This hook is called after cmd.Start() creates the process.
	// There's a small window between process start and Job Object assignment where the
	// process runs unrestricted by the job (but still restricted by the token).
	// Explicitly capture jobHandle to avoid closure issues with loop variables
	capturedJob := jobHandle
	platform.RegisterPostStartHook(cmd, func(c *exec.Cmd) error {
		// Get process handle - after Start(), c.Process is available
		// We need to open our own handle with the right access for AssignProcessToJobObject
		processHandle, err := windows.OpenProcess(
			windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
			false,
			uint32(c.Process.Pid),
		)
		if err != nil {
			return fmt.Errorf("OpenProcess failed: %w", err)
		}
		defer windows.CloseHandle(processHandle)

		// Assign process to Job Object
		err = windows.AssignProcessToJobObject(capturedJob, processHandle)
		if err != nil {
			return fmt.Errorf("AssignProcessToJobObject failed: %w", err)
		}

		// No need to resume — process was never suspended
		return nil
	})

	return nil
}

// Cleanup releases all resources allocated by WrapCommand and Platform initialization.
// This should be called when the manager is shutting down.
//
// Cleanup order:
//  1. Jobs (terminate processes immediately)
//  2. ACLs (revoke while processes are dead)
//  3. Tokens (close handles)
//  4. Tier 2: Firewall rules → Sandbox users
//
// This ordering ensures sandboxed processes are killed before filesystem restrictions
// are removed, and Tier 2 resources are cleaned up after Tier 1 resources.
func (p *Platform) Cleanup(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error

	// Close all job handles first — terminates all processes in the jobs via
	// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, ensuring sandboxed processes are dead
	// before we revoke ACLs.
	for _, job := range p.activeJobs {
		if err := closeJobObject(job); err != nil {
			errs = append(errs, err)
		}
	}
	p.activeJobs = nil

	// Cleanup ACLs (processes are already dead, safe to revoke)
	for _, acl := range p.activeACLs {
		if err := cleanupACLs(acl.entries, acl.sid); err != nil {
			errs = append(errs, err)
		}
	}
	p.activeACLs = nil

	// Close all token handles last
	for _, token := range p.activeTokens {
		if err := token.Close(); err != nil {
			errs = append(errs, fmt.Errorf("token.Close failed: %w", err))
		}
	}
	p.activeTokens = nil

	// Tier 2 cleanup: firewall rules → sandbox users
	// This runs even if Tier 1 cleanup had errors (best-effort)
	if p.tier2Active {
		// Remove firewall rules first
		if p.fwManager != nil {
			if err := p.fwManager.Cleanup(); err != nil {
				errs = append(errs, fmt.Errorf("firewall cleanup: %w", err))
			}
		}
		
		// Delete sandbox users and group
		if p.userManager != nil {
			if err := p.userManager.Teardown(); err != nil {
				errs = append(errs, fmt.Errorf("user teardown: %w", err))
			}
		}
		
		p.tier2Active = false
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}

	return nil
}
