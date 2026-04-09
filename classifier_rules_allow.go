// classifier_rules_allow.go contains all Allow-category rule functions and
// their supporting data. Allow rules auto-approve commands that are known to
// be safe read-only operations.

package agentbox

import "strings"

// subRemote is the git remote subcommand name.
const subRemote = "remote"

// commonSafeCommands is the set of commands considered safe for Allow.
var commonSafeCommands = map[string]struct{}{
	"ls": {}, "cat": {}, "echo": {}, "pwd": {},
	"whoami": {}, "date": {}, "head": {}, "tail": {},
	"wc": {}, "sort": {}, "uniq": {}, "grep": {},
	"which": {}, "file": {}, "basename": {},
	"dirname": {}, "realpath": {}, "stat": {}, "du": {},
	"df": {}, "printenv": {}, "id": {},
	"uname": {}, "hostname": {}, "true": {}, "false": {},
	"test": {}, "[": {},
	"find": {},
}

// gitReadSubcommands lists git subcommands that are read-only.
// "tag" is handled specially in gitReadCommandsRule to allow only listing
// and verification, so it is NOT included here.
// "branch" is handled specially by isGitBranchReadOnly to allow only
// listing operations, so it is NOT included here (BUG-ALLOW-3).
var gitReadSubcommands = map[string]struct{}{
	"status": {}, "log": {}, "diff": {}, "show": {},
}

// gitTagReadOnlyFlags lists flags for "git tag" that are read-only.
var gitTagReadOnlyFlags = map[string]struct{}{
	"-l": {}, "--list": {},
	"-v": {}, "--verify": {},
}

// gitTagWriteFlags lists flags for "git tag" that indicate a write operation.
// Their presence means the command is NOT read-only, even if a read-only flag
// is also present (e.g. "git tag -l -d v1.0" is a delete, not a list).
var gitTagWriteFlags = map[string]struct{}{
	"-a": {}, "--annotate": {},
	"-d": {}, "--delete": {},
	"-s": {}, "--sign": {},
	"-f": {}, "--force": {},
}

// isGitTagReadOnly reports whether the remaining args after "git tag"
// represent a read-only operation. Allowed: bare "git tag" (lists all),
// "git tag -l [pattern]", "git tag --list", "git tag -v", "git tag --verify".
// Rejected: "git tag -a" (annotated), "git tag -d" (delete), "git tag -s"
// (signed), "git tag -f" (force), "git tag tagname" (lightweight create).
// Contradictory combinations (e.g. "git tag -l -d v1.0") are rejected because
// write flags take precedence.
func isGitTagReadOnly(argsAfterTag []string) bool {
	if len(argsAfterTag) == 0 {
		// Bare "git tag" — lists all tags.
		return true
	}
	// Reject immediately if any write flag is present — write flags take
	// precedence even when mixed with read-only flags.
	for _, a := range argsAfterTag {
		if _, ok := gitTagWriteFlags[a]; ok {
			return false
		}
	}
	// If the first non-flag-like arg is present without a read-only flag,
	// it's a lightweight tag creation (e.g. "git tag v1.0").
	hasReadOnlyFlag := false
	for _, a := range argsAfterTag {
		if _, ok := gitTagReadOnlyFlags[a]; ok {
			hasReadOnlyFlag = true
		}
	}
	return hasReadOnlyFlag
}

// gitBranchReadOnlyFlags lists flags for "git branch" that indicate a
// read-only (listing/query) operation.
var gitBranchReadOnlyFlags = map[string]struct{}{
	"-a": {}, "--all": {},
	"-r": {}, "--remotes": {},
	"-v": {}, "-vv": {}, "--verbose": {},
	"-l": {}, "--list": {},
	"--show-current": {},
	"--contains": {}, "--no-contains": {},
	"--merged": {}, "--no-merged": {},
	"--sort": {}, "--format": {},
	"--points-at": {}, "--column": {}, "--no-column": {},
	"--color": {}, "--no-color": {},
	"--abbrev": {}, "--no-abbrev": {},
}

// gitBranchWriteFlags lists flags for "git branch" that indicate a write
// (delete/rename/copy) operation.
var gitBranchWriteFlags = map[string]struct{}{
	"-d": {}, "-D": {}, "--delete": {},
	"-m": {}, "-M": {}, "--move": {},
	"-c": {}, "-C": {}, "--copy": {},
	"--edit-description": {},
	"--set-upstream-to": {}, "-u": {},
	"--unset-upstream": {},
}

// isGitBranchReadOnly reports whether the remaining args after "git branch"
// represent a read-only (listing) operation (BUG-ALLOW-3).
// Allowed: bare "git branch", "git branch -a", "git branch -r",
// "git branch --list", "git branch --show-current", etc.
// Rejected: "git branch <name>" (create), "git branch -d <name>" (delete),
// "git branch -m old new" (rename), or any non-flag positional arg.
func isGitBranchReadOnly(argsAfterBranch []string) bool {
	if len(argsAfterBranch) == 0 {
		// Bare "git branch" — lists local branches.
		return true
	}
	// Reject immediately if any write flag is present.
	for _, a := range argsAfterBranch {
		if _, ok := gitBranchWriteFlags[a]; ok {
			return false
		}
	}
	// Check each argument: all must be recognized read-only flags or
	// flag values. Any non-flag argument is treated as a branch name
	// (create operation).
	for i, a := range argsAfterBranch {
		if strings.HasPrefix(a, "-") {
			// Accept known read-only flags; for flags with = values
			// (e.g. --sort=refname), check the prefix.
			bare := a
			if idx := strings.IndexByte(a, '='); idx >= 0 {
				bare = a[:idx]
			}
			if _, ok := gitBranchReadOnlyFlags[bare]; ok {
				continue
			}
			// Unknown flag: let it fall through to sandboxed to be safe.
			return false
		}
		// Non-flag argument. It's only safe if it follows a flag that
		// takes a value (e.g. "--sort refname", "--contains commit").
		if i > 0 {
			prev := argsAfterBranch[i-1]
			if prev == "--sort" || prev == "--format" || prev == "--contains" ||
				prev == "--no-contains" || prev == "--merged" || prev == "--no-merged" ||
				prev == "--points-at" || prev == "--abbrev" || prev == "--color" {
				continue
			}
		}
		// Bare positional arg without a qualifying flag — branch create.
		return false
	}
	return true
}

func commonSafeCommandsRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "command is in the safe-commands list",
		Rule:     RuleCommonSafeCommands,
	}
	return rule{
		Name: RuleCommonSafeCommands,
		Match: func(command string) (ClassifyResult, bool) {
			// Reject compound commands so that "which python && rm -rf /"
			// is not allowed just because the first segment is safe.
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(fields[0])
			if _, ok := commonSafeCommands[cmd]; ok {
				return result, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if _, ok := commonSafeCommands[cmd]; !ok {
				return ClassifyResult{}, false
			}
			// find with action flags (-exec, -delete, etc.) needs
			// deeper analysis — skip the blanket allow so the
			// destructive-find rule (or sandbox) handles it.
			if cmd == cmdFind && findHasActionFlag(args) {
				return ClassifyResult{}, false
			}
			return result, true
		},
	}
}

func gitReadCommandsRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "git read-only command",
		Rule:     RuleGitReadCommands,
	}
	return rule{
		Name: RuleGitReadCommands,
		Match: func(command string) (ClassifyResult, bool) {
			// Reject compound commands to prevent "git status && rm -rf /"
			// from being allowed.
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			if baseCommand(fields[0]) != cmdGit {
				return ClassifyResult{}, false
			}
			sub := findGitSubcommand(fields[1:])
			if _, ok := gitReadSubcommands[sub]; ok {
				return result, true
			}
			// git tag: only allow read-only operations (list, verify).
			if sub == "tag" {
				argsAfterTag := argsAfterSubcommand(fields[1:], "tag")
				if isGitTagReadOnly(argsAfterTag) {
					return result, true
				}
				return ClassifyResult{}, false
			}
			// git branch: only allow read-only operations (list, query).
			// Creating/deleting/renaming branches is rejected (BUG-ALLOW-3).
			if sub == "branch" {
				argsAfterBranch := argsAfterSubcommand(fields[1:], "branch")
				if isGitBranchReadOnly(argsAfterBranch) {
					return result, true
				}
				return ClassifyResult{}, false
			}
			// git remote -v (read-only variant of git remote).
			// Reject if a write subcommand (add, remove, rename, set-url) is present.
			if sub == subRemote && containsFlag(fields[1:], "-v") && !gitRemoteHasWriteSubcmd(fields[1:]) {
				return result, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if baseCommand(name) != cmdGit {
				return ClassifyResult{}, false
			}
			if len(args) == 0 {
				return ClassifyResult{}, false
			}
			sub := findGitSubcommand(args)
			if _, ok := gitReadSubcommands[sub]; ok {
				return result, true
			}
			// git tag: only allow read-only operations (list, verify).
			if sub == "tag" {
				argsAfterTag := argsAfterSubcommand(args, "tag")
				if isGitTagReadOnly(argsAfterTag) {
					return result, true
				}
				return ClassifyResult{}, false
			}
			// git branch: only allow read-only operations (BUG-ALLOW-3).
			if sub == "branch" {
				argsAfterBranch := argsAfterSubcommand(args, "branch")
				if isGitBranchReadOnly(argsAfterBranch) {
					return result, true
				}
				return ClassifyResult{}, false
			}
			if sub == subRemote && containsFlag(args, "-v") && !gitRemoteHasWriteSubcmd(args) {
				return result, true
			}
			return ClassifyResult{}, false
		},
	}
}

// argsAfterSubcommand returns the arguments after the first occurrence of
// subcmd in fields. It is used to extract the remaining arguments after a
// git subcommand like "tag" for further inspection.
func argsAfterSubcommand(fields []string, subcmd string) []string {
	for i, f := range fields {
		if f == subcmd {
			return fields[i+1:]
		}
	}
	return nil
}

// gitRemoteWriteSubcmds lists git remote subcommands that modify state.
var gitRemoteWriteSubcmds = map[string]struct{}{
	"add": {}, "remove": {}, "rm": {},
	"rename": {}, "set-url": {}, "set-head": {},
	"set-branches": {}, "prune": {},
}

// gitRemoteHasWriteSubcmd reports whether args contain a git remote write
// subcommand. This prevents "git remote add origin -v ..." from being
// auto-allowed by the "-v" check. It inspects only tokens after "remote"
// to correctly handle git global flags (e.g. "git -C /path remote add").
func gitRemoteHasWriteSubcmd(args []string) bool {
	afterRemote := argsAfterSubcommand(args, subRemote)
	for _, a := range afterRemote {
		if strings.HasPrefix(a, "-") {
			continue
		}
		_, ok := gitRemoteWriteSubcmds[a]
		return ok
	}
	return false
}

// versionHelpFlags is the set of flags that indicate a version/help check.
var versionHelpFlags = map[string]struct{}{
	flagVersion: {}, "-v": {}, "-V": {},
	flagHelp: {}, "-h": {},
}

// versionCheckRule matches simple "X --version", "X -v", "X --help" etc.
func versionCheckRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "version/help check command",
		Rule:     RuleVersionCheck,
	}
	return rule{
		Name: RuleVersionCheck,
		Match: func(command string) (ClassifyResult, bool) {
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			// Strip trailing 2>&1 redirect before checking fields.
			trimmed := strings.TrimSpace(command)
			trimmed = strings.TrimSuffix(trimmed, "2>&1")
			trimmed = strings.TrimSpace(trimmed)
			fields := strings.Fields(trimmed)
			if len(fields) != 2 {
				return ClassifyResult{}, false
			}
			if _, ok := versionHelpFlags[fields[1]]; ok {
				return result, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if len(args) != 1 {
				return ClassifyResult{}, false
			}
			if _, ok := versionHelpFlags[args[0]]; ok {
				return result, true
			}
			return ClassifyResult{}, false
		},
	}
}

// windowsSafeCmds is the set of Windows/cmd.exe safe read-only commands.
var windowsSafeCmds = map[string]struct{}{
	"where": {}, "dir": {}, "type": {}, "findstr": {},
	"ipconfig": {}, "systeminfo": {}, "tasklist": {},
	"where.exe": {}, "chcp": {}, "ver": {}, "set": {},
	"hostname": {}, "whoami": {},
}

// psCmdletsSafe is the set of PowerShell cmdlets considered safe (lowercase).
var psCmdletsSafe = map[string]struct{}{
	// Existing
	"get-command": {}, "get-process": {}, "get-childitem": {},
	"get-content": {}, "get-location": {},
	"select-object": {}, "format-list": {}, "format-table": {},
	"write-output": {}, "write-host": {}, "test-path": {},
	// Read-only Get-* cmdlets
	"get-service": {}, "get-item": {}, "get-itemproperty": {},
	"get-wmiobject": {}, "get-ciminstance": {},
	"get-netadapter": {}, "get-nettcpconnection": {},
	"get-date": {}, "get-help": {}, "get-member": {},
	"get-psdrive": {}, "get-volume": {}, "get-computerinfo": {},
	"get-pnpdevice": {}, "get-winevent": {},
	"get-acl": {}, "get-clipboard": {}, "get-culture": {},
	"get-disk": {}, "get-eventlog": {}, "get-executionpolicy": {},
	"get-filehash": {}, "get-host": {}, "get-hotfix": {},
	"get-netipaddress": {}, "get-netipinterface": {}, "get-netroute": {},
	"get-partition": {}, "get-physicaldisk": {},
	"get-timezone": {}, "get-variable": {},
	// Read-only pipeline/formatting cmdlets
	"measure-object": {}, "sort-object": {}, "group-object": {},
	"convertto-json": {}, "convertfrom-json": {},
	"out-string": {}, "out-null": {},
	"where-object": {}, "foreach-object": {},
	"format-wide": {}, "tee-object": {},
	"select-string": {}, "compare-object": {},
	"convertto-csv": {}, "convertfrom-csv": {},
	"convertto-xml": {}, "convertto-html": {},
	"confirm-securebootefi": {},
	"resolve-dnsname": {},
	"test-netconnection": {},
}

// psCmdletsDangerous lists PowerShell cmdlets that mutate state and must not
// be allowed even when they appear as arguments or downstream of a pipe from
// a safe cmdlet (e.g. "Get-Process | Stop-Process -Force").  Checked in
// lowercase for case-insensitive matching.
var psCmdletsDangerous = map[string]struct{}{
	"stop-process":        {},
	"remove-item":         {},
	"stop-service":        {},
	"restart-service":     {},
	"clear-content":       {},
	"set-executionpolicy": {},
	"new-item":            {},
	"new-service":         {},
	"new-object":          {},
	"start-process":       {},
	"start-service":       {},
	"invoke-expression":   {},
	"invoke-command":      {},
	"invoke-webrequest":   {},
	"invoke-restmethod":   {},
	"set-content":         {},
	"set-itemproperty":    {},
	"add-content":         {},
	"add-type":            {},
}

// hasDangerousPSCmdlet reports whether any token in fields matches a
// dangerous PowerShell cmdlet (case-insensitive).
func hasDangerousPSCmdlet(fields []string) bool {
	for _, f := range fields {
		if _, ok := psCmdletsDangerous[strings.ToLower(f)]; ok {
			return true
		}
	}
	return false
}

// windowsSafeCommandsRule matches Windows/PowerShell safe read-only commands.
// Commands that pipe to dangerous cmdlets (e.g. Stop-Process) are rejected.
func windowsSafeCommandsRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "Windows/PowerShell safe read-only command",
		Rule:     RuleWindowsSafeCommands,
	}
	return rule{
		Name: RuleWindowsSafeCommands,
		Match: func(command string) (ClassifyResult, bool) {
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			// Reject if any token is a dangerous PowerShell cmdlet
			// (catches piped commands like "Get-Process | Stop-Process").
			if hasDangerousPSCmdlet(fields) {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(fields[0])
			if _, ok := windowsSafeCmds[cmd]; ok {
				return result, true
			}
			// PowerShell cmdlets (case-insensitive).
			if _, ok := psCmdletsSafe[strings.ToLower(cmd)]; ok {
				return result, true
			}
			// $env: variable reads (e.g. "$env:PATH").
			if strings.HasPrefix(cmd, "$env:") {
				return result, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			// Reject if any arg contains a dangerous PowerShell cmdlet.
			if hasDangerousPSCmdlet(args) {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(name)
			if _, ok := windowsSafeCmds[cmd]; ok {
				return result, true
			}
			if _, ok := psCmdletsSafe[strings.ToLower(cmd)]; ok {
				return result, true
			}
			if strings.HasPrefix(cmd, "$env:") {
				return result, true
			}
			return ClassifyResult{}, false
		},
	}
}

// cdSleepCmds is the set of directory navigation and sleep commands.
var cdSleepCmds = map[string]struct{}{
	"cd": {}, "pushd": {}, "popd": {},
	"sleep": {},
}

// cdSleepRule matches directory navigation (cd/pushd/popd) and sleep.
func cdSleepRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "directory navigation/sleep command",
		Rule:     RuleCDSleep,
	}
	return rule{
		Name: RuleCDSleep,
		Match: func(command string) (ClassifyResult, bool) {
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(fields[0])
			if _, ok := cdSleepCmds[cmd]; !ok {
				return ClassifyResult{}, false
			}
			return result, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if _, ok := cdSleepCmds[cmd]; !ok {
				return ClassifyResult{}, false
			}
			return result, true
		},
	}
}

// processListCmds is the set of read-only process inspection commands.
var processListCmds = map[string]struct{}{
	"ps": {}, "top": {}, "htop": {}, "pgrep": {},
}

// processListRule matches read-only process inspection commands.
func processListRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "read-only process inspection command",
		Rule:     RuleProcessList,
	}
	return rule{
		Name: RuleProcessList,
		Match: func(command string) (ClassifyResult, bool) {
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(fields[0])
			if _, ok := processListCmds[cmd]; ok {
				return result, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if _, ok := processListCmds[cmd]; ok {
				return result, true
			}
			return ClassifyResult{}, false
		},
	}
}

// ---------------------------------------------------------------------------
// New Allow rules — scripting, build, Go, file management, text processing,
// network diagnostics, archive, shell builtins, and open commands.
// ---------------------------------------------------------------------------

// devToolCmds is the set of scripting runtime commands.
var devToolCmds = map[string]struct{}{
	"python": {}, "python3": {}, "python3.11": {}, "python3.12": {}, "python3.13": {},
	"python.exe": {}, "node": {}, "ruby": {}, "perl": {}, "php": {},
	"java": {}, "lua": {}, "Rscript": {}, "swift": {}, "julia": {},
	"deno": {}, "bun": {}, "ts-node": {}, "npx": {}, "uvx": {}, "py": {},
	"pytest": {}, "py.test": {},
}

// pythonCmds is the subset of devToolCmds that are Python interpreters.
var pythonCmds = map[string]struct{}{
	"python": {}, "python3": {}, "python3.11": {}, "python3.12": {}, "python3.13": {},
	"python.exe": {}, "py": {},
}

// devToolRunRule matches scripting runtime execution commands.
// Commands that wrap package-install operations (e.g. "py -m pip install")
// or runner-install operations (e.g. "npx clawhub install") are excluded
// so they fall through to escalated rules.
func devToolRunRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "scripting runtime execution",
		Rule:     RuleDevToolRun,
	}
	return rule{
		Name: RuleDevToolRun,
		Match: func(command string) (ClassifyResult, bool) {
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if _, ok := devToolCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			if devToolRunHasInstallPattern(base, fields[1:]) {
				return ClassifyResult{}, false
			}
			return result, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if _, ok := devToolCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			if devToolRunHasInstallPattern(base, args) {
				return ClassifyResult{}, false
			}
			return result, true
		},
	}
}

// devToolRunHasInstallPattern reports whether args contain a package-install
// pattern for the given base command.
//
//   - Python interpreters: reject "-m pip install" / "-m pip3 install"
//   - npx/uvx: reject "install" as a direct subcommand (e.g. "npx X install")
//   - npx: reject if -y or --yes flag is present (auto-installs packages
//     without confirmation — BUG-ALLOW-1)
func devToolRunHasInstallPattern(base string, args []string) bool {
	const installVerb = "install"
	if _, ok := pythonCmds[base]; ok {
		// Scan for "-m" followed by "pip"/"pip3" followed by "install".
		for i := 0; i < len(args)-2; i++ {
			if args[i] == "-m" && (args[i+1] == "pip" || args[i+1] == "pip3") && args[i+2] == installVerb {
				return true
			}
		}
	}
	if base == "npx" || base == "uvx" {
		// Reject if any non-flag argument after the runner is "install".
		for _, a := range args {
			if a == installVerb {
				return true
			}
		}
	}
	// npx -y / npx --yes auto-installs packages without confirmation.
	// Reject from allow so command falls through to sandboxed.
	if base == "npx" {
		for _, a := range args {
			if a == "-y" || a == "--yes" {
				return true
			}
		}
	}
	return false
}

// buildToolCmds is the set of build system and compiler commands.
var buildToolCmds = map[string]struct{}{
	"make": {}, "cmake": {}, "ninja": {}, "meson": {},
	"cargo": {}, "rustc": {},
	"mvn": {}, "gradle": {}, "gradlew": {}, "ant": {},
	"dotnet": {}, "msbuild": {},
	"xcodebuild": {},
	"gcc": {}, "g++": {}, "clang": {}, "clang++": {}, "cc": {},
	"ld": {}, "ar": {}, "nm": {}, "objdump": {},
	"bazel": {}, "buck": {}, "scons": {},
}

// buildToolRule matches build system and compiler commands.
// State-modifying subcommands are excluded for dotnet and cargo:
// "dotnet [tool|new|workload] install" and "cargo install" fall through
// to escalated rules or default Sandboxed.
func buildToolRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "build tool execution",
		Rule:     RuleBuildTool,
	}
	return rule{
		Name: RuleBuildTool,
		Match: func(command string) (ClassifyResult, bool) {
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if _, ok := buildToolCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			if buildToolHasInstall(base, fields[1:]) {
				return ClassifyResult{}, false
			}
			return result, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if _, ok := buildToolCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			if buildToolHasInstall(base, args) {
				return ClassifyResult{}, false
			}
			return result, true
		},
	}
}

// dotnetAllowedSubcmds is the set of dotnet subcommands that are safe
// build/test/format operations. Commands not in this set (new, add,
// install, nuget, etc.) fall through to sandboxed — BUG-ALLOW-2.
var dotnetAllowedSubcmds = map[string]struct{}{
	"build": {}, "run": {}, "test": {}, "clean": {},
	"restore": {}, "publish": {}, "format": {}, "watch": {},
}

// buildToolHasInstall reports whether the build tool command contains an
// install subcommand or a disallowed operation that should be escalated.
//
//   - dotnet: only allow build/run/test/clean/restore/publish/format/watch.
//     Reject new/add/install/nuget/--install-sdk (BUG-ALLOW-2).
//   - cargo: "cargo install"
//   - mvn: only allow compile/test/verify/package/validate/clean and
//     dependency:/help:/versions: prefixes. Reject install/deploy/
//     archetype:generate (BUG-ALLOW-7).
//   - make: reject clean/distclean/uninstall/install targets (BUG-ALLOW-8).
func buildToolHasInstall(base string, args []string) bool {
	const installVerb = "install"
	switch base {
	case "dotnet":
		// Reject if "install" appears anywhere in args (covers
		// "dotnet tool install X", "dotnet new install X", etc.).
		for _, a := range args {
			if a == installVerb {
				return true
			}
		}
		// Also reject if --install-sdk flag is present.
		for _, a := range args {
			if a == "--install-sdk" {
				return true
			}
		}
		// Whitelist approach: only allow known safe subcommands.
		// Bare "dotnet" (no args) is fine (prints help).
		if len(args) > 0 {
			if _, ok := dotnetAllowedSubcmds[args[0]]; !ok {
				return true
			}
		}
	case "cargo":
		// "cargo install" installs binaries globally.
		if len(args) > 0 && args[0] == installVerb {
			return true
		}
	case "mvn":
		for _, a := range args {
			if isMvnDisallowed(a) {
				return true
			}
		}
	case "make":
		if isMakeDisallowed(args) {
			return true
		}
	}
	return false
}

// mvnAllowedSubcmds lists Maven goals/phases that are safe read-only or
// build operations.
var mvnAllowedSubcmds = map[string]struct{}{
	"compile": {}, "test": {}, "verify": {}, "package": {},
	"validate": {}, "clean": {},
}

// mvnAllowedPrefixes lists Maven plugin prefixes whose goals are safe.
var mvnAllowedPrefixes = []string{"dependency:", "help:", "versions:"}

// isMvnDisallowed reports whether a Maven subcommand/phase should be
// rejected from the allow list (BUG-ALLOW-7).
func isMvnDisallowed(sub string) bool {
	if _, ok := mvnAllowedSubcmds[sub]; ok {
		return false
	}
	for _, p := range mvnAllowedPrefixes {
		if strings.HasPrefix(sub, p) {
			return false
		}
	}
	// Flags (e.g. -DskipTests, -P profile) are not subcommands; only
	// reject when the first non-flag arg is a disallowed goal/phase.
	if strings.HasPrefix(sub, "-") {
		return false
	}
	return true
}

// makeDisallowedTargets lists make targets that modify or delete build
// artifacts and should not be auto-allowed (BUG-ALLOW-8).
var makeDisallowedTargets = map[string]struct{}{
	"clean": {}, "distclean": {}, "uninstall": {}, "install": {},
}

// isMakeDisallowed reports whether the make args contain a disallowed
// target.
func isMakeDisallowed(args []string) bool {
	for _, a := range args {
		// Skip flags (e.g. -j8, -C dir).
		if strings.HasPrefix(a, "-") {
			continue
		}
		// Skip variable assignments (e.g. CC=gcc).
		if strings.Contains(a, "=") {
			continue
		}
		if _, ok := makeDisallowedTargets[a]; ok {
			return true
		}
	}
	return false
}

// goToolCmds is the set of Go ecosystem tool commands.
var goToolCmds = map[string]struct{}{
	"go": {}, "gofmt": {}, "gopls": {}, "dlv": {},
	"golangci-lint": {}, "staticcheck": {}, "govulncheck": {},
	"gotests": {}, "gomodifytags": {}, "impl": {},
}

// goStateModifySubcmds lists go subcommands that modify system state and
// should not be auto-allowed.  "install" and "get" download/build remote
// code; "env -w" writes persistent Go environment variables.  These fall
// through to the escalated package-install rule or default Sandboxed.
var goStateModifySubcmds = map[string]struct{}{
	"install": {},
	"get":     {},
}

// goToolRule matches Go ecosystem tool commands.
// State-modifying subcommands (install, get, env -w) are excluded.
func goToolRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "Go toolchain command",
		Rule:     RuleGoTool,
	}
	return rule{
		Name: RuleGoTool,
		Match: func(command string) (ClassifyResult, bool) {
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if _, ok := goToolCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			// For the "go" binary, reject state-modifying subcommands.
			if base == "go" && len(fields) > 1 {
				sub := fields[1]
				if _, ok := goStateModifySubcmds[sub]; ok {
					return ClassifyResult{}, false
				}
				// "go env -w" writes persistent env vars.
				if sub == cmdEnv && containsFlag(fields[2:], "-w") {
					return ClassifyResult{}, false
				}
			}
			return result, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if _, ok := goToolCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			if base == "go" && len(args) > 0 {
				sub := args[0]
				if _, ok := goStateModifySubcmds[sub]; ok {
					return ClassifyResult{}, false
				}
				if sub == cmdEnv && containsFlag(args[1:], "-w") {
					return ClassifyResult{}, false
				}
			}
			return result, true
		},
	}
}

// fileManagementCmds is the set of basic file management commands.
// rm and rmdir are intentionally excluded: rm can be destructive (rm -rf /etc)
// and rmdir /s on Windows can delete entire trees. Both fall through to Sandboxed
// where the sandbox provides the real security boundary. Forbidden rules catch
// the worst cases (rm -rf /, rmdir /s /q .).
var fileManagementCmds = map[string]struct{}{
	"mkdir": {}, "cp": {}, "mv": {}, "ln": {}, "touch": {},
	"install": {},
}

// fileManagementRule matches basic file management commands.
// Dangerous variants (e.g. rm -rf /) are caught by higher-priority
// forbidden rules before this rule is evaluated.
func fileManagementRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "file management command",
		Rule:     RuleFileManagement,
	}
	return rule{
		Name: RuleFileManagement,
		Match: func(command string) (ClassifyResult, bool) {
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if _, ok := fileManagementCmds[baseCommand(fields[0])]; ok {
				return result, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, _ []string) (ClassifyResult, bool) {
			if _, ok := fileManagementCmds[baseCommand(name)]; ok {
				return result, true
			}
			return ClassifyResult{}, false
		},
	}
}

// textProcessingCmds is the set of text manipulation commands.
var textProcessingCmds = map[string]struct{}{
	"awk": {}, "sed": {}, "jq": {}, "yq": {},
	"cut": {}, "tr": {}, "tee": {}, "diff": {}, "comm": {},
	"paste": {}, "column": {}, "expand": {}, "fold": {},
	"fmt": {}, "nl": {}, "rev": {}, "strings": {}, "od": {},
	"hexdump": {}, "xxd": {},
}

// textProcessingRule matches text manipulation commands. For sed, the rule
// does NOT match if the -i flag is present (in-place editing is caught by
// the escalated in-place-edit rule which runs at higher priority).
func textProcessingRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "text processing command",
		Rule:     RuleTextProcessing,
	}
	return rule{
		Name: RuleTextProcessing,
		Match: func(command string) (ClassifyResult, bool) {
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(fields[0])
			if _, ok := textProcessingCmds[cmd]; !ok {
				return ClassifyResult{}, false
			}
			// For sed, reject if -i flag is present (in-place edit).
			if cmd == cmdSed && hasSedInPlaceFlag(fields[1:]) {
				return ClassifyResult{}, false
			}
			return result, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if _, ok := textProcessingCmds[cmd]; !ok {
				return ClassifyResult{}, false
			}
			if cmd == cmdSed && hasSedInPlaceFlag(args) {
				return ClassifyResult{}, false
			}
			return result, true
		},
	}
}

// hasSedInPlaceFlag reports whether args contain a sed -i flag.
// Matches -i exactly and -i prefixed forms (e.g. -i.bak, -i'').
func hasSedInPlaceFlag(args []string) bool {
	for _, a := range args {
		if a == "-i" || (len(a) > 2 && a[:2] == "-i" && a[2] != '-') {
			return true
		}
	}
	return false
}

// networkDiagCmds is the set of network diagnostic commands.
var networkDiagCmds = map[string]struct{}{
	"ping": {}, "ping6": {}, "dig": {}, "nslookup": {},
	"traceroute": {}, "traceroute6": {}, "tracepath": {},
	"host": {}, "whois": {}, "ifconfig": {}, "route": {},
	"netstat": {}, "ss": {}, "lsof": {},
	"mtr": {}, "arp": {},
}

// routeWriteSubs lists route subcommands that modify the routing table.
// Plain "route", "route print", "route -n" remain allowed as diagnostics.
var routeWriteSubs = map[string]struct{}{
	"add": {}, "delete": {}, "del": {}, "change": {}, "flush": {},
}

// networkDiagnosticRule matches network diagnostic commands.
// nc/netcat are intentionally excluded (escalated as network-scan).
// "route" is excluded when followed by a write subcommand (add, delete, etc.).
func networkDiagnosticRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "network diagnostic command",
		Rule:     RuleNetworkDiagnostic,
	}
	return rule{
		Name: RuleNetworkDiagnostic,
		Match: func(command string) (ClassifyResult, bool) {
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if _, ok := networkDiagCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			// Reject route write subcommands (add, delete, change, flush).
			if base == "route" && len(fields) >= 2 {
				if _, ok := routeWriteSubs[fields[1]]; ok {
					return ClassifyResult{}, false
				}
			}
			return result, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if _, ok := networkDiagCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			// Reject route write subcommands.
			if base == "route" && len(args) >= 1 {
				if _, ok := routeWriteSubs[args[0]]; ok {
					return ClassifyResult{}, false
				}
			}
			return result, true
		},
	}
}

// archiveToolCmds is the set of archive and compression commands.
var archiveToolCmds = map[string]struct{}{
	"tar": {}, "zip": {}, "unzip": {}, "zipinfo": {},
	"gzip": {}, "gunzip": {}, "bzip2": {}, "bunzip2": {},
	"xz": {}, "unxz": {}, "zstd": {}, "unzstd": {},
	"7z": {}, "7za": {}, "rar": {}, "unrar": {},
}

// archiveToolRule matches archive and compression commands.
// For tar and unzip, only read-only operations are allowed (listing, testing,
// piping to stdout). Extraction and creation that write files to disk fall
// through to Sandboxed.
func archiveToolRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "archive/compression tool",
		Rule:     RuleArchiveTool,
	}
	return rule{
		Name: RuleArchiveTool,
		Match: func(command string) (ClassifyResult, bool) {
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if _, ok := archiveToolCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			if !isArchiveReadOnly(base, fields[1:]) {
				return ClassifyResult{}, false
			}
			return result, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if _, ok := archiveToolCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			if !isArchiveReadOnly(base, args) {
				return ClassifyResult{}, false
			}
			return result, true
		},
	}
}

// tarExtractFlags lists tar flags that extract or create files on disk.
// -x/--extract/--get extract; -c/--create create archives (writes files).
var tarExtractFlags = map[string]struct{}{
	"-x": {}, "--extract": {}, "--get": {},
	"-c": {}, "--create": {},
}

// unzipReadOnlyFlags lists unzip flags that are read-only operations.
var unzipReadOnlyFlags = map[string]struct{}{
	"-l": {}, // list
	"-p": {}, // pipe to stdout
	"-t": {}, // test archive
}

// isArchiveReadOnly reports whether the archive command with the given
// args is a read-only operation. For tar, it rejects extraction and
// creation flags. For unzip, it requires an explicit read-only flag
// (-l, -p, -t). For zip, 7z/7za, gzip, bzip2, xz, and other compression
// tools, only listing/testing flags are allowed (BUG-ALLOW-5).
// Unrecognized commands default to false (safer).
func isArchiveReadOnly(base string, args []string) bool {
	switch base {
	case "tar":
		return isTarReadOnly(args)
	case "unzip":
		return isUnzipReadOnly(args)
	case "zip":
		return isZipReadOnly(args)
	case "zipinfo":
		// zipinfo is always read-only (only lists archive contents).
		return true
	case "7z", "7za":
		return is7zReadOnly(args)
	case "gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz", "zstd", "unzstd":
		return isCompressionReadOnly(args)
	case "rar":
		return isRarReadOnly(args)
	case "unrar":
		return isUnrarReadOnly(args)
	default:
		// Unknown archive command — reject from allow to be safe.
		return false
	}
}

// isZipReadOnly reports whether zip args represent a read-only operation.
// Only listing with -l/-sf or displaying info is read-only.
func isZipReadOnly(args []string) bool {
	for _, a := range args {
		if a == "-l" || a == "-sf" {
			return true
		}
	}
	return false
}

// is7zReadOnly reports whether 7z/7za args represent a read-only operation.
// Only the "l" (list) and "t" (test) subcommands are read-only.
func is7zReadOnly(args []string) bool {
	if len(args) > 0 && (args[0] == "l" || args[0] == "t") {
		return true
	}
	return false
}

// isCompressionReadOnly reports whether compression tool args (gzip, bzip2,
// xz, zstd) represent a read-only operation. Only -l (list), -t (test),
// and --list/--test flags are read-only.
func isCompressionReadOnly(args []string) bool {
	for _, a := range args {
		if a == "-l" || a == "--list" || a == "-t" || a == "--test" {
			return true
		}
	}
	return false
}

// isRarReadOnly reports whether rar args represent a read-only operation.
// Only "l" (list), "lt" (list technical), "v" (verbose list), "vt" (verbose
// technical list), and "t" (test) subcommands are read-only.
func isRarReadOnly(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "l", "lt", "v", "vt", "t":
		return true
	}
	return false
}

// isUnrarReadOnly reports whether unrar args represent a read-only operation.
// Only "l" (list), "lt" (list technical), "v" (verbose list), "vt" (verbose
// technical list), and "t" (test) subcommands are read-only.
func isUnrarReadOnly(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "l", "lt", "v", "vt", "t":
		return true
	}
	return false
}

// isTarReadOnly reports whether tar args represent a read-only operation.
// Tar commands with extraction flags (-x, --extract, --get) or creation
// flags (-c, --create) are rejected. Combined short flags like -xzf are
// checked character by character. Tar also allows flags without a leading
// dash (e.g. "tar xzf archive.tar.gz"), so the first non-flag arg is also
// scanned for x/c characters.
func isTarReadOnly(args []string) bool {
	for i, a := range args {
		// Long flags.
		if _, ok := tarExtractFlags[a]; ok {
			return false
		}
		// Combined short flags with dash (e.g. -xzf, -czf, -tvf).
		if len(a) > 1 && a[0] == '-' && a[1] != '-' {
			for j := 1; j < len(a); j++ {
				if a[j] == 'x' || a[j] == 'c' {
					return false
				}
			}
			continue
		}
		// Tar allows the first argument to be flags without a leading dash
		// (e.g. "xzf", "czf", "tvf"). Only check the first positional arg.
		if i == 0 && len(a) > 0 && a[0] != '-' {
			for j := 0; j < len(a); j++ {
				if a[j] == 'x' || a[j] == 'c' {
					return false
				}
			}
		}
	}
	return true
}

// isUnzipReadOnly reports whether unzip args represent a read-only operation.
// Only -l (list), -p (pipe to stdout), and -t (test) are read-only.
// Any other unzip invocation (including bare "unzip file.zip") is rejected.
func isUnzipReadOnly(args []string) bool {
	for _, a := range args {
		if _, ok := unzipReadOnlyFlags[a]; ok {
			return true
		}
	}
	return false
}

// shellBuiltinCmds is the set of common shell builtins and utility commands.
// nohup is excluded (escalated as background-process). source, eval, exec
// are excluded (escalated as eval-exec). Command-runner utilities (env,
// command, timeout, xargs, time, strace, ltrace, nice) are excluded because
// they execute arbitrary commands as arguments.
var shellBuiltinCmds = map[string]struct{}{
	"export": {}, "set": {}, "unset": {},
	"printf": {}, "tput": {}, "alias": {}, "unalias": {},
	"type": {}, "hash": {}, "builtin": {},
	"read": {}, "declare": {}, "local": {}, "readonly": {},
	"trap": {}, "wait": {}, "jobs": {}, "fg": {}, "bg": {},
	"times": {}, "ulimit": {}, "umask": {}, "getopts": {},
}

// shellBuiltinRule matches common shell builtins and utility commands.
// Commands with output redirection (> / >>) or pipes to clipboard tools
// are rejected so they fall through to Sandboxed.
func shellBuiltinRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "shell builtin/utility command",
		Rule:     RuleShellBuiltin,
	}
	return rule{
		Name: RuleShellBuiltin,
		Match: func(command string) (ClassifyResult, bool) {
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if _, ok := shellBuiltinCmds[baseCommand(fields[0])]; !ok {
				return ClassifyResult{}, false
			}
			// Reject output redirection and clipboard pipes.
			if hasOutputRedirectOrClipboardPipe(command) {
				return ClassifyResult{}, false
			}
			return result, true
		},
		MatchArgs: func(name string, _ []string) (ClassifyResult, bool) {
			if _, ok := shellBuiltinCmds[baseCommand(name)]; ok {
				return result, true
			}
			return ClassifyResult{}, false
		},
	}
}

// openCmds is the set of commands that open URLs/files in default applications.
var openCmds = map[string]struct{}{
	"open": {}, "xdg-open": {}, "start": {},
	"wslview": {}, "sensible-browser": {}, "x-www-browser": {},
}

// openCommandRule matches commands that open URLs or files in the default
// application (macOS open, Linux xdg-open, Windows start).
//
// Windows "start" can launch arbitrary executables, so it is restricted:
// only arguments that look like URLs or known safe protocols are allowed.
func openCommandRule() rule {
	result := ClassifyResult{
		Decision: Allow,
		Reason:   "open URL/file in default application",
		Rule:     RuleOpenCommand,
	}
	return rule{
		Name: RuleOpenCommand,
		Match: func(command string) (ClassifyResult, bool) {
			if !isSimpleCommand(command) {
				return ClassifyResult{}, false
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if _, ok := openCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			// Windows "start" can launch executables; restrict to URLs.
			if base == "start" && !startArgsAreSafe(fields[1:]) {
				return ClassifyResult{}, false
			}
			return result, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if _, ok := openCmds[base]; !ok {
				return ClassifyResult{}, false
			}
			if base == "start" && !startArgsAreSafe(args) {
				return ClassifyResult{}, false
			}
			return result, true
		},
	}
}

// startSafeProtocols lists URL protocol prefixes that are safe for
// Windows "start" to open (they invoke default handlers, not executables).
var startSafeProtocols = [...]string{
	"http://", "https://", "ftp://", "ftps://",
	"ms-settings:", "ms-windows-store:", "mailto:",
}

// startArgsAreSafe reports whether the arguments to Windows "start" look
// like a URL or known safe protocol.  If no arguments are provided or the
// target doesn't look like a URL, return false.
func startArgsAreSafe(args []string) bool {
	// "start" may have flags like /min, /wait before the target.
	// Find the first non-flag argument.
	target := ""
	for _, a := range args {
		if strings.HasPrefix(a, "/") || strings.HasPrefix(a, "-") {
			continue
		}
		target = a
		break
	}
	if target == "" {
		// No target — bare "start" opens a new cmd window; allow it.
		return len(args) == 0
	}
	lower := strings.ToLower(target)
	for _, proto := range startSafeProtocols {
		if strings.HasPrefix(lower, proto) {
			return true
		}
	}
	// Only explicitly listed protocols are allowed; reject unknown schemes.
	return false
}
