//go:build darwin

package darwin

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zhangyunhao116/agentbox/internal/envutil"
	"github.com/zhangyunhao116/agentbox/platform"
)

// profileBuilder constructs an SBPL (Sandbox Profile Language) profile
// from a WrapConfig. SBPL uses Scheme-like S-expression syntax.
type profileBuilder struct {
	buf strings.Builder
}

// newProfileBuilder returns a new profileBuilder.
func newProfileBuilder() *profileBuilder {
	return &profileBuilder{}
}

// Build generates an SBPL profile string from the given WrapConfig.
func (b *profileBuilder) Build(cfg *platform.WrapConfig) (string, error) {
	b.buf.Reset()

	b.writeBase()
	b.writeFileRead(cfg)
	b.writeFileWrite(cfg)
	b.writeDangerousFileProtection(cfg)
	b.writeMoveBlocking(cfg)
	b.writeNetwork(cfg)
	b.writePTY()

	return b.buf.String(), nil
}

// writeBase emits the SBPL version header and base process permissions.
func (b *profileBuilder) writeBase() {
	b.line("(version 1)")
	b.line("(deny default)")
	b.blank()
	b.comment("Allow basic process operations")
	b.line("(allow process-fork)")
	b.line("(allow process-exec)")
	b.line("(allow signal (target self))")
	b.comment("Allow process info queries within same sandbox")
	b.line("(allow process-info* (target same-sandbox))")
	b.writeSysctl()
	b.writeIOKit()
	b.writePOSIXIPC()
	b.comment("Allow Mach IPC for essential system services only")
	b.line("(allow mach-lookup")
	b.line(`  (global-name "com.apple.audio.systemsoundserver")`)
	b.line(`  (global-name "com.apple.distributed_notifications@Uv3")`)
	b.line(`  (global-name "com.apple.FontObjectsServer")`)
	b.line(`  (global-name "com.apple.fonts")`)
	b.line(`  (global-name "com.apple.logd")`)
	b.line(`  (global-name "com.apple.lsd.mapdb")`)
	b.line(`  (global-name "com.apple.PowerManagement.control")`)
	b.line(`  (global-name "com.apple.system.logger")`)
	b.line(`  (global-name "com.apple.system.notification_center")`)
	b.line(`  (global-name "com.apple.system.opendirectoryd.libinfo")`)
	b.line(`  (global-name "com.apple.system.opendirectoryd.membership")`)
	b.line(`  (global-name "com.apple.bsd.dirhelper")`)
	b.line(`  (global-name "com.apple.securityd.xpc")`)
	b.line(`  (global-name "com.apple.coreservices.launchservicesd")`)
	b.line(`  (global-name "com.apple.SecurityServer")`)
	b.line(")")
	b.line("(allow mach-per-user-lookup)")
	b.blank()
}

// writeSysctl emits precise sysctl read/write rules instead of a blanket allow.
func (b *profileBuilder) writeSysctl() {
	b.comment("Allow reading specific sysctl values")
	b.line("(allow sysctl-read")
	// hw.* (26 names)
	b.line(`  (sysctl-name "hw.activecpu")`)
	b.line(`  (sysctl-name "hw.busfrequency_compat")`)
	b.line(`  (sysctl-name "hw.byteorder")`)
	b.line(`  (sysctl-name "hw.cacheconfig")`)
	b.line(`  (sysctl-name "hw.cachelinesize_compat")`)
	b.line(`  (sysctl-name "hw.cpufamily")`)
	b.line(`  (sysctl-name "hw.cpufrequency")`)
	b.line(`  (sysctl-name "hw.cpufrequency_compat")`)
	b.line(`  (sysctl-name "hw.cputype")`)
	b.line(`  (sysctl-name "hw.l1dcachesize_compat")`)
	b.line(`  (sysctl-name "hw.l1icachesize_compat")`)
	b.line(`  (sysctl-name "hw.l2cachesize_compat")`)
	b.line(`  (sysctl-name "hw.l3cachesize_compat")`)
	b.line(`  (sysctl-name "hw.logicalcpu")`)
	b.line(`  (sysctl-name "hw.logicalcpu_max")`)
	b.line(`  (sysctl-name "hw.machine")`)
	b.line(`  (sysctl-name "hw.memsize")`)
	b.line(`  (sysctl-name "hw.ncpu")`)
	b.line(`  (sysctl-name "hw.nperflevels")`)
	b.line(`  (sysctl-name "hw.packages")`)
	b.line(`  (sysctl-name "hw.pagesize_compat")`)
	b.line(`  (sysctl-name "hw.pagesize")`)
	b.line(`  (sysctl-name "hw.physicalcpu")`)
	b.line(`  (sysctl-name "hw.physicalcpu_max")`)
	b.line(`  (sysctl-name "hw.tbfrequency_compat")`)
	b.line(`  (sysctl-name "hw.vectorunit")`)
	// kern.* (18 names)
	b.line(`  (sysctl-name "kern.argmax")`)
	b.line(`  (sysctl-name "kern.bootargs")`)
	b.line(`  (sysctl-name "kern.hostname")`)
	b.line(`  (sysctl-name "kern.maxfiles")`)
	b.line(`  (sysctl-name "kern.maxfilesperproc")`)
	b.line(`  (sysctl-name "kern.maxproc")`)
	b.line(`  (sysctl-name "kern.ngroups")`)
	b.line(`  (sysctl-name "kern.osproductversion")`)
	b.line(`  (sysctl-name "kern.osrelease")`)
	b.line(`  (sysctl-name "kern.ostype")`)
	b.line(`  (sysctl-name "kern.osvariant_status")`)
	b.line(`  (sysctl-name "kern.osversion")`)
	b.line(`  (sysctl-name "kern.secure_kernel")`)
	b.line(`  (sysctl-name "kern.tcsm_available")`)
	b.line(`  (sysctl-name "kern.tcsm_enable")`)
	b.line(`  (sysctl-name "kern.usrstack64")`)
	b.line(`  (sysctl-name "kern.version")`)
	b.line(`  (sysctl-name "kern.willshutdown")`)
	// other (5 names)
	b.line(`  (sysctl-name "machdep.cpu.brand_string")`)
	b.line(`  (sysctl-name "machdep.ptrauth_enabled")`)
	b.line(`  (sysctl-name "security.mac.lockdown_mode_state")`)
	b.line(`  (sysctl-name "sysctl.proc_cputype")`)
	b.line(`  (sysctl-name "vm.loadavg")`)
	// prefix patterns (9)
	b.line(`  (sysctl-name-prefix "hw.optional.arm")`)
	b.line(`  (sysctl-name-prefix "hw.optional.arm.")`)
	b.line(`  (sysctl-name-prefix "hw.optional.armv8_")`)
	b.line(`  (sysctl-name-prefix "hw.perflevel")`)
	b.line(`  (sysctl-name-prefix "kern.proc.all")`)
	b.line(`  (sysctl-name-prefix "kern.proc.pgrp.")`)
	b.line(`  (sysctl-name-prefix "kern.proc.pid.")`)
	b.line(`  (sysctl-name-prefix "machdep.cpu.")`)
	b.line(`  (sysctl-name-prefix "net.routetable.")`)
	b.line(")")
	b.comment("Allow writing kern.tcsm_enable for thread-specific CPU scheduling")
	b.line(`(allow sysctl-write (sysctl-name "kern.tcsm_enable"))`)
}

// writeIOKit emits IOKit rules for graphics and power management.
func (b *profileBuilder) writeIOKit() {
	b.comment("Allow IOKit for graphics and power management")
	b.line("(allow iokit-open")
	b.line(`  (iokit-registry-entry-class "IOSurfaceRootUserClient")`)
	b.line(`  (iokit-registry-entry-class "RootDomainUserClient")`)
	b.line(`  (iokit-user-client-class "IOSurfaceSendRight")`)
	b.line(")")
}

// writePOSIXIPC emits POSIX IPC rules for shared memory and semaphores.
func (b *profileBuilder) writePOSIXIPC() {
	b.comment("Allow POSIX IPC for shared memory and semaphores")
	b.line("(allow ipc-posix-shm)")
	b.line("(allow ipc-posix-sem)")
}

// writeFileRead emits file-read rules. By default all reads are allowed,
// then specific paths from DenyRead are denied.
func (b *profileBuilder) writeFileRead(cfg *platform.WrapConfig) {
	b.comment("File read: allow all by default, deny specific paths")
	b.line("(allow file-read*)")
	for _, p := range cfg.DenyRead {
		cp := canonicalizePath(p)
		b.linef("(deny file-read* (subpath \"%s\"))", escapeForSBPL(cp))
	}
	b.blank()
}

// writeFileWrite emits file-write rules. By default all writes are denied,
// then specific writable roots and temp directories are allowed.
func (b *profileBuilder) writeFileWrite(cfg *platform.WrapConfig) {
	b.comment("File write: deny all by default, allow specific paths")
	b.line("(deny file-write*)")
	b.blank()

	// Always allow writing to temp directories.
	tmpDirs := getTmpdirParents()
	for _, d := range tmpDirs {
		b.linef("(allow file-write* (subpath \"%s\"))", escapeForSBPL(d))
	}

	// Allow configured writable roots.
	for _, root := range cfg.WritableRoots {
		cp := canonicalizePath(root)
		b.linef("(allow file-write* (subpath \"%s\"))", escapeForSBPL(cp))
	}

	// Deny writes to explicitly denied paths (overrides writable roots).
	for _, p := range cfg.DenyWrite {
		cp := canonicalizePath(p)
		b.linef("(deny file-write* (subpath \"%s\"))", escapeForSBPL(cp))
	}
	b.blank()
}

// writeDangerousFileProtection denies writes to sensitive dotfiles and
// directories even if they fall within a writable root.
func (b *profileBuilder) writeDangerousFileProtection(cfg *platform.WrapConfig) {
	b.comment("Dangerous file protection: deny writes to sensitive paths")

	home, err := os.UserHomeDir()
	if err != nil {
		// If we cannot determine home, skip home-relative protections.
		return
	}
	home = canonicalizePath(home)

	dangerousFiles := []string{
		".bashrc",
		".bash_profile",
		".zshrc",
		".zprofile",
		".profile",
		".gitconfig",
		".ssh",
	}

	dangerousDirs := []string{
		".git/hooks",
	}

	for _, f := range dangerousFiles {
		fp := filepath.Join(home, f)
		b.linef("(deny file-write* (literal \"%s\"))", escapeForSBPL(fp))
	}

	for _, d := range dangerousDirs {
		dp := filepath.Join(home, d)
		b.linef("(deny file-write* (subpath \"%s\"))", escapeForSBPL(dp))
	}

	// Allow git config read if explicitly permitted.
	if cfg.AllowGitConfig {
		gitCfg := filepath.Join(home, ".gitconfig")
		b.linef("(allow file-read* (literal \"%s\"))", escapeForSBPL(gitCfg))
	}

	b.blank()
}

// writeMoveBlocking prevents bypass via mv/rename of protected paths by
// denying file-write-unlink on DenyWrite and DenyRead paths, and also
// protects all ancestor directories to prevent moving a parent directory.
func (b *profileBuilder) writeMoveBlocking(cfg *platform.WrapConfig) {
	b.comment("Prevent bypass via mv/rename of protected paths")
	// Use a set to deduplicate ancestor rules.
	seen := make(map[string]bool)

	writePathRules := func(paths []string) {
		for _, p := range paths {
			cp := canonicalizePath(p)
			escaped := escapeForSBPL(cp)
			b.linef(`(deny file-write-unlink (subpath "%s"))`, escaped)
			// Protect all ancestor directories to prevent bypass via moving parent.
			for _, ancestor := range ancestorDirectories(cp) {
				if !seen[ancestor] {
					seen[ancestor] = true
					b.linef(`(deny file-write-unlink (literal "%s"))`, escapeForSBPL(ancestor))
				}
			}
		}
	}

	writePathRules(cfg.DenyWrite)
	writePathRules(cfg.DenyRead)
	b.blank()
}

// ancestorDirectories returns all parent directories of path, excluding root "/".
func ancestorDirectories(p string) []string {
	var ancestors []string
	current := filepath.Dir(p)
	for current != "/" && current != "." {
		ancestors = append(ancestors, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return ancestors
}

// writeNetwork emits network rules. If NeedsNetworkRestriction is set,
// all network access is denied except localhost connections for the proxy.
func (b *profileBuilder) writeNetwork(cfg *platform.WrapConfig) {
	if !cfg.NeedsNetworkRestriction {
		b.comment("Network: no restrictions")
		b.line("(allow network*)")
		b.blank()
		return
	}

	b.comment("Network: deny all, allow proxy ports on localhost")
	b.line("(deny network*)")
	b.line(`(allow network* (local udp "*:*"))`)
	if cfg.HTTPProxyPort > 0 {
		b.linef(`(allow network* (remote tcp "localhost:%d"))`, cfg.HTTPProxyPort)
	}
	if cfg.SOCKSProxyPort > 0 {
		b.linef(`(allow network* (remote tcp "localhost:%d"))`, cfg.SOCKSProxyPort)
	}

	if cfg.AllowLocalBinding {
		b.comment("Allow binding to local ports (IPv6 dual-stack safe)")
		b.line(`(allow network-bind (local ip "*:*"))`)
		b.line(`(allow network-inbound (local ip "*:*"))`)
	}

	if cfg.AllowAllUnixSockets {
		b.comment("Allow all Unix domain socket connections")
		b.line(`(allow network-outbound (remote unix-socket (subpath "/")))`)
		b.line(`(allow network-inbound (local unix-socket (subpath "/")))`)
	} else if len(cfg.AllowUnixSockets) > 0 {
		b.comment("Allow specific Unix domain socket paths")
		for _, socketPath := range cfg.AllowUnixSockets {
			escaped := escapeForSBPL(socketPath)
			b.linef(`(allow network* (subpath "%s"))`, escaped)
		}
	}

	b.blank()
}

// writePTY allows PTY access for interactive commands.
// Instead of a blanket (allow file-read* (subpath "/dev")) which would
// override DenyRead rules for /dev subpaths, we use a regex that matches
// only the specific device nodes needed.
func (b *profileBuilder) writePTY() {
	b.comment("Allow PTY access for interactive commands")
	b.line("(allow file-read* (regex #\"^/dev/(ttys|pty|null|zero|random|urandom|fd)\"))")
	b.line("(allow file-write* (regex #\"^/dev/ttys[0-9]+$\"))")
	b.line("(allow file-write* (regex #\"^/dev/pty[a-z][0-9a-f]$\"))")
	b.line("(allow file-write* (literal \"/dev/null\"))")
	b.line("(allow file-write* (literal \"/dev/zero\"))")
	b.line("(allow file-write* (literal \"/dev/random\"))")
	b.line("(allow file-write* (literal \"/dev/urandom\"))")
	b.line("(allow file-ioctl (regex #\"^/dev/(ttys|pty)\"))")
	b.blank()
}

// line writes a single SBPL line.
func (b *profileBuilder) line(s string) {
	b.buf.WriteString(s)
	b.buf.WriteByte('\n')
}

// linef writes a formatted SBPL line.
func (b *profileBuilder) linef(format string, args ...any) {
	b.buf.WriteString(fmt.Sprintf(format, args...))
	b.buf.WriteByte('\n')
}

// comment writes an SBPL comment line.
func (b *profileBuilder) comment(s string) {
	b.buf.WriteString("; ")
	b.buf.WriteString(s)
	b.buf.WriteByte('\n')
}

// blank writes an empty line.
func (b *profileBuilder) blank() {
	b.buf.WriteByte('\n')
}

// escapeForSBPL escapes special characters in a string for use in SBPL
// string literals. SBPL uses double-quoted strings with backslash escaping.
func escapeForSBPL(s string) string {
	s = strings.ReplaceAll(s, "\x00", "") // Strip null bytes to prevent SBPL injection
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

// canonicalizePath resolves symlinks and normalizes the path.
// On macOS, /tmp -> /private/tmp and /var -> /private/var.
func canonicalizePath(p string) string {
	// Try to resolve symlinks via EvalSymlinks.
	resolved, err := filepath.EvalSymlinks(p)
	if err == nil {
		return filepath.Clean(resolved)
	}
	// Fallback: manual mapping for well-known macOS symlinks.
	cleaned := filepath.Clean(p)
	if cleaned == "/tmp" || strings.HasPrefix(cleaned, "/tmp/") {
		cleaned = "/private" + cleaned
	}
	if cleaned == "/var" || strings.HasPrefix(cleaned, "/var/") {
		cleaned = "/private" + cleaned
	}
	return cleaned
}

// getTmpdirParents returns the set of temp directory paths that should be
// writable. This includes /private/tmp, /private/var/folders, and the
// user-specific TMPDIR if set.
func getTmpdirParents() []string {
	dirs := make(map[string]struct{})

	// Always include the canonical macOS temp locations.
	dirs["/private/tmp"] = struct{}{}
	dirs["/private/var/folders"] = struct{}{}

	// Include TMPDIR if set (e.g., /var/folders/xx/.../T/).
	if tmpdir := os.Getenv("TMPDIR"); tmpdir != "" {
		cp := canonicalizePath(tmpdir)
		dirs[cp] = struct{}{}
	}

	result := make([]string, 0, len(dirs))
	for d := range dirs {
		result = append(result, d)
	}
	sort.Strings(result)
	return result
}

// sanitizeEnv removes DYLD_* and LD_* environment variables from the given
// environment slice. Both prefixes can be used to inject dynamic libraries
// into sandboxed processes and must be stripped to prevent code injection.
func sanitizeEnv(env []string) []string {
	env = envutil.RemoveEnvPrefix(env, "DYLD_")
	env = envutil.RemoveEnvPrefix(env, "LD_")
	return env
}

// proxyEnvVars generates environment variables that configure the sandboxed
// process to use the given HTTP and SOCKS5 proxy ports on localhost.
func proxyEnvVars(httpPort, socksPort int) []string {
	var vars []string
	if httpPort > 0 {
		proxy := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
		vars = append(vars,
			"HTTP_PROXY="+proxy,
			"http_proxy="+proxy,
			"HTTPS_PROXY="+proxy,
			"https_proxy="+proxy,
		)
	}
	if socksPort > 0 {
		socks := fmt.Sprintf("socks5h://127.0.0.1:%d", socksPort)
		vars = append(vars,
			"ALL_PROXY="+socks,
			"all_proxy="+socks,
		)
	}
	return vars
}
