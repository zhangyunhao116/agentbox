// classifier_rules_escalated.go contains all Escalated-category rule functions
// and their helpers. Escalated rules require user approval before execution —
// they are evaluated after forbidden rules but before allow rules.

package agentbox

import (
	"path"
	"strings"
)

// sudoRule matches commands that use sudo or doas for privilege escalation.
func sudoRule() rule {
	return rule{
		Name: ruleSudo,
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(fields[0])
			if cmd == ruleSudo || cmd == "doas" {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "privilege escalation via sudo/doas requires approval",
					Rule:     ruleSudo,
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if cmd == ruleSudo || cmd == "doas" {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "privilege escalation via sudo/doas requires approval",
					Rule:     ruleSudo,
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

// suPrivilegeRule matches the "su" command used for privilege escalation.
// All forms of su (including "su -c <cmd>") require approval because they
// perform privilege escalation regardless of flags.
func suPrivilegeRule() rule {
	return rule{
		Name: "su-privilege",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(fields[0])
			if cmd != "su" {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "privilege escalation via su requires approval",
				Rule:     "su-privilege",
			}, true
		},
		MatchArgs: func(name string, _ []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if cmd != "su" {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "privilege escalation via su requires approval",
				Rule:     "su-privilege",
			}, true
		},
	}
}

// credentialSensitivePaths lists path substrings that indicate credential or
// secret files. An argument is considered sensitive if it contains one of these
// patterns. The ".env" pattern requires special handling to avoid matching
// substrings like ".environment".
var credentialSensitivePaths = []string{
	".ssh/id_",
	".ssh/known_hosts",
	".aws/credentials",
	".aws/config",
	".npmrc",
	".pypirc",
	".netrc",
	".pgpass",
	".my.cnf",
}

// credentialSensitiveGlobs lists filename tokens (matched via path.Base)
// that indicate credential or secret files.  Matching uses word-boundary
// logic (containsWordToken) so that tokens like "secret" only trigger when
// delimited by '_', '-', '.' or string boundaries — avoiding false
// positives on words like "secretariat" or "secretary".
var credentialSensitiveGlobs = []string{
	"secret",
	"credential",
	"password",
}

// credentialSensitiveExtensions lists file extensions that indicate private
// keys or certificates.
var credentialSensitiveExtensions = []string{
	".pem",
	".key",
}

// credentialReaders lists commands that read file contents.
var credentialReaders = map[string]bool{
	"cat": true, "head": true, "tail": true,
	"less": true, "more": true, "type": true,
}

// isCredentialSensitivePath reports whether the argument looks like a
// sensitive credential/secret file path.
func isCredentialSensitivePath(arg string) bool {
	lower := strings.ToLower(arg)
	// Check known sensitive path substrings.
	for _, p := range credentialSensitivePaths {
		if strings.Contains(lower, p) {
			return true
		}
	}
	// Check ".env" as exact filename (base) to avoid matching ".environment".
	base := strings.ToLower(path.Base(arg))
	if base == ".env" {
		return true
	}
	// Check word-boundary name patterns (secret, credential, password).
	// Uses containsWordToken to avoid false positives like "secretariat".
	for _, g := range credentialSensitiveGlobs {
		if containsWordToken(base, g) {
			return true
		}
	}
	// Check private key / certificate extensions.
	for _, ext := range credentialSensitiveExtensions {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

// envEnumCmds lists commands that print environment variables.
var envEnumCmds = map[string]bool{"env": true, "printenv": true}

// credGrepPatterns are substrings that indicate credential enumeration
// when used as a grep argument after env/printenv.
var credGrepPatterns = []string{
	"secret", "password", "passwd", "token",
	"key", "credential", "api_key", "apikey",
}

// isEnvCredentialEnum reports whether the command is an env/printenv pipe to
// grep that filters for credential-related patterns (e.g. "env | grep -i secret").
func isEnvCredentialEnum(command string) bool {
	if !strings.Contains(command, "|") {
		return false
	}
	parts := splitTopLevelPipes(command)
	if len(parts) < 2 {
		return false
	}
	firstFields := strings.Fields(strings.TrimSpace(parts[0]))
	if len(firstFields) == 0 || !envEnumCmds[baseCommand(firstFields[0])] {
		return false
	}
	for _, p := range parts[1:] {
		pFields := strings.Fields(strings.TrimSpace(p))
		if len(pFields) < 2 || baseCommand(pFields[0]) != "grep" {
			continue
		}
		grepLower := strings.ToLower(strings.Join(pFields[1:], " "))
		for _, pat := range credGrepPatterns {
			if strings.Contains(grepLower, pat) {
				return true
			}
		}
	}
	return false
}

// credentialAccessRule matches commands that attempt to read sensitive
// credential or secret files (e.g. cat ~/.ssh/id_rsa, head .env), or
// enumerate credentials from environment variables (e.g. env | grep -i secret).
func credentialAccessRule() rule {
	return rule{
		Name: "credential-access",
		Match: func(command string) (ClassifyResult, bool) {
			// Check for env/printenv piped to grep for credential patterns.
			if isEnvCredentialEnum(command) {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "environment credential enumeration requires approval",
					Rule:     "credential-access",
				}, true
			}

			// Check for file-based credential access (cat ~/.ssh/id_rsa, etc.).
			fields := strings.Fields(command)
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(fields[0])
			if !credentialReaders[cmd] {
				return ClassifyResult{}, false
			}
			for _, f := range fields[1:] {
				if strings.HasPrefix(f, "-") {
					continue // skip flags
				}
				if isCredentialSensitivePath(f) {
					return ClassifyResult{
						Decision: Escalated,
						Reason:   "reading credential/secret files requires approval",
						Rule:     "credential-access",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if !credentialReaders[cmd] {
				return ClassifyResult{}, false
			}
			for _, a := range args {
				if strings.HasPrefix(a, "-") {
					continue
				}
				if isCredentialSensitivePath(a) {
					return ClassifyResult{
						Decision: Escalated,
						Reason:   "reading credential/secret files requires approval",
						Rule:     "credential-access",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
	}
}

// userManagementRule matches commands that manage system users and groups.
func userManagementRule() rule {
	userCmds := map[string]bool{
		"useradd": true, "userdel": true, "usermod": true,
		"groupadd": true, "groupdel": true, "groupmod": true,
		"passwd": true, "chpasswd": true,
		"adduser": true, "deluser": true,
		"addgroup": true, "delgroup": true,
	}
	return rule{
		Name: "user-management",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if userCmds[baseCommand(fields[0])] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "user/group management requires approval",
					Rule:     "user-management",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, _ []string) (ClassifyResult, bool) {
			if userCmds[baseCommand(name)] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "user/group management requires approval",
					Rule:     "user-management",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

func globalInstallRule() rule {
	return rule{
		Name: "global-install",
		Match: func(command string) (ClassifyResult, bool) {
			cmd := strings.Join(strings.Fields(command), " ")

			// npm install -g / npm i -g
			if (strings.Contains(cmd, "npm install") || strings.Contains(cmd, "npm i ")) &&
				strings.Contains(cmd, " -g") {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "global npm install requires approval",
					Rule:     "global-install",
				}, true
			}

			// yarn global add
			if strings.Contains(cmd, "yarn global add") {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "global yarn install requires approval",
					Rule:     "global-install",
				}, true
			}

			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)

			// npm install -g
			if base == "npm" && len(args) >= 2 {
				hasInstall := args[0] == "install" || args[0] == "i"
				hasGlobal := false
				for _, a := range args {
					if a == "-g" || a == "--global" {
						hasGlobal = true
					}
				}
				if hasInstall && hasGlobal {
					return ClassifyResult{
						Decision: Escalated,
						Reason:   "global npm install requires approval",
						Rule:     "global-install",
					}, true
				}
			}

			// yarn global add
			if base == "yarn" && len(args) >= 2 && args[0] == "global" && args[1] == "add" {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "global yarn install requires approval",
					Rule:     "global-install",
				}, true
			}

			return ClassifyResult{}, false
		},
	}
}

func dockerRuntimeRule() rule {
	// Subcommands for docker/podman that need escalation.
	dockerSubs := map[string]bool{
		"run": true, "exec": true, "stop": true, "rm": true,
		"restart": true, "kill": true, "pause": true, "unpause": true,
	}
	// docker <object> <destructive-action> patterns.
	dockerObjActions := map[string]map[string]bool{
		"system":    {"prune": true},
		"volume":    {"rm": true, "prune": true},
		"image":     {"rm": true, "prune": true},
		"container": {"rm": true, "prune": true},
	}
	// docker-compose / docker compose subcommands.
	composeSubs := map[string]bool{
		"up": true, "down": true, "restart": true,
		"rm": true, "stop": true, "kill": true,
	}
	// kubectl subcommands.
	kubectlSubs := map[string]bool{
		"exec": true, "run": true, "delete": true, "apply": true,
		"create": true, "edit": true, "patch": true, "scale": true,
		"rollout": true,
	}

	const runtimeReason = "container runtime operation requires approval"
	const k8sReason = "kubernetes operation requires approval"
	const ruleName = "docker-runtime"

	matchFields := func(fields []string) (ClassifyResult, bool) {
		if len(fields) == 0 {
			return ClassifyResult{}, false
		}
		base := baseCommand(fields[0])

		switch base {
		case "docker", "podman":
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			sub := fields[1]
			// docker compose <subcmd>
			if sub == "compose" && len(fields) >= 3 {
				if composeSubs[fields[2]] {
					return ClassifyResult{
						Decision: Escalated,
						Reason:   runtimeReason,
						Rule:     ruleName,
					}, true
				}
				return ClassifyResult{}, false
			}
			// docker <object> <action>
			if actions, ok := dockerObjActions[sub]; ok && len(fields) >= 3 {
				if actions[fields[2]] {
					return ClassifyResult{
						Decision: Escalated,
						Reason:   runtimeReason,
						Rule:     ruleName,
					}, true
				}
				return ClassifyResult{}, false
			}
			// docker <subcmd>
			if dockerSubs[sub] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   runtimeReason,
					Rule:     ruleName,
				}, true
			}

		case "docker-compose":
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			if composeSubs[fields[1]] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   runtimeReason,
					Rule:     ruleName,
				}, true
			}

		case "kubectl":
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			if kubectlSubs[fields[1]] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   k8sReason,
					Rule:     ruleName,
				}, true
			}
		}
		return ClassifyResult{}, false
	}

	return rule{
		Name: ruleName,
		Match: func(command string) (ClassifyResult, bool) {
			return matchFields(strings.Fields(command))
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			fields := make([]string, 0, 1+len(args))
			fields = append(fields, name)
			fields = append(fields, args...)
			return matchFields(fields)
		},
	}
}

func systemPackageInstallRule() rule {
	// Map of package manager base command to the subcommand(s) that trigger escalation.
	type pkgMgr struct {
		cmd  string
		subs []string
	}
	managers := []pkgMgr{
		{"brew", []string{"install"}},
		{"apt", []string{"install"}},
		{"apt-get", []string{"install"}},
		{"yum", []string{"install"}},
		{"dnf", []string{"install"}},
	}

	return rule{
		Name: "system-package-install",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			for _, m := range managers {
				if base == m.cmd {
					for _, sub := range m.subs {
						if fields[1] == sub {
							return ClassifyResult{
								Decision: Escalated,
								Reason:   base + " " + sub + " requires approval",
								Rule:     "system-package-install",
							}, true
						}
					}
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if len(args) == 0 {
				return ClassifyResult{}, false
			}
			for _, m := range managers {
				if base == m.cmd {
					for _, sub := range m.subs {
						if args[0] == sub {
							return ClassifyResult{
								Decision: Escalated,
								Reason:   base + " " + sub + " requires approval",
								Rule:     "system-package-install",
							}, true
						}
					}
				}
			}
			return ClassifyResult{}, false
		},
	}
}

// processKillRule escalates process termination commands.
// Matches kill, pkill, killall (Unix), taskkill (Windows), Stop-Process (PowerShell).
func processKillRule() rule {
	killCmds := map[string]bool{
		"kill":         true,
		"pkill":        true,
		"killall":      true,
		"taskkill":     true,
		"Stop-Process": true,
		"stop-process": true, // Windows/PowerShell commands are case-insensitive.
	}

	return rule{
		Name: "process-kill",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if killCmds[base] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "process termination requires approval",
					Rule:     "process-kill",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if killCmds[base] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "process termination requires approval",
					Rule:     "process-kill",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

// gitWriteRule escalates git remote and destructive operations.
// Local-only ops (add, commit, stash, checkout, etc.) are left to the sandbox.
// It scans past git flags (arguments starting with "-") to find the subcommand.
func gitWriteRule() rule {
	writeSubs := map[string]bool{
		"push":   true,
		"pull":   true,
		"clone":  true,
		"fetch":  true,
		"reset":  true,
		"rebase": true,
		"merge":  true,
	}

	return rule{
		Name: "git-write",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			if baseCommand(fields[0]) != cmdGit {
				return ClassifyResult{}, false
			}
			sub := findGitSubcommand(fields[1:])
			if writeSubs[sub] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "git remote/destructive operation requires approval",
					Rule:     "git-write",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if baseCommand(name) != cmdGit || len(args) == 0 {
				return ClassifyResult{}, false
			}
			sub := findGitSubcommand(args)
			if writeSubs[sub] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "git remote/destructive operation requires approval",
					Rule:     "git-write",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

// sshCommandRule escalates SSH remote access commands.
// Only the exact base command "ssh" is matched; related utilities like
// ssh-keygen, ssh-agent, ssh-add, and sshpass are not escalated.
func sshCommandRule() rule {
	return rule{
		Name: "ssh-command",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if baseCommand(fields[0]) == "ssh" {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "SSH remote access requires approval",
					Rule:     "ssh-command",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, _ []string) (ClassifyResult, bool) {
			if baseCommand(name) == "ssh" {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "SSH remote access requires approval",
					Rule:     "ssh-command",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

// fileTransferRule escalates file transfer commands: scp, rsync, sftp, ftp.
func fileTransferRule() rule {
	transferCmds := map[string]bool{
		"scp":   true,
		"rsync": true,
		"sftp":  true,
		"ftp":   true,
	}

	return rule{
		Name: "file-transfer",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if transferCmds[baseCommand(fields[0])] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "file transfer requires approval",
					Rule:     "file-transfer",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, _ []string) (ClassifyResult, bool) {
			if transferCmds[baseCommand(name)] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "file transfer requires approval",
					Rule:     "file-transfer",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

// downloadToFileRule escalates file downloads: wget (always), and curl with
// download flags (-o, -O, --output). Plain curl without download flags is
// allowed (used for API calls).
func downloadToFileRule() rule {
	curlDownloadFlags := map[string]bool{
		"-o":       true,
		"-O":       true,
		"--output": true,
	}

	return rule{
		Name: "download-to-file",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if base == cmdWget {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "file download requires approval",
					Rule:     "download-to-file",
				}, true
			}
			if base == cmdCurl {
				for _, f := range fields[1:] {
					// Handle combined short flags like -sOL or -Lo
					if curlDownloadFlags[f] {
						return ClassifyResult{
							Decision: Escalated,
							Reason:   "file download requires approval",
							Rule:     "download-to-file",
						}, true
					}
					// Check for -o/O combined with other short flags (e.g. -Lo, -sOL).
					if len(f) > 1 && f[0] == '-' && f[1] != '-' {
						for _, ch := range f[1:] {
							if ch == 'o' || ch == 'O' {
								return ClassifyResult{
									Decision: Escalated,
									Reason:   "file download requires approval",
									Rule:     "download-to-file",
								}, true
							}
						}
					}
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if base == cmdWget {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "file download requires approval",
					Rule:     "download-to-file",
				}, true
			}
			if base == cmdCurl {
				for _, a := range args {
					if curlDownloadFlags[a] {
						return ClassifyResult{
							Decision: Escalated,
							Reason:   "file download requires approval",
							Rule:     "download-to-file",
						}, true
					}
					// Check combined short flags (e.g. -Lo, -sOL).
					if len(a) > 1 && a[0] == '-' && a[1] != '-' {
						for _, ch := range a[1:] {
							if ch == 'o' || ch == 'O' {
								return ClassifyResult{
									Decision: Escalated,
									Reason:   "file download requires approval",
									Rule:     "download-to-file",
								}, true
							}
						}
					}
				}
			}
			return ClassifyResult{}, false
		},
	}
}

// serviceManagementRule escalates service management commands: systemctl,
// service, launchctl, and sc/sc.exe (Windows, only with recognized subcommands).
func serviceManagementRule() rule {
	// Direct service management commands that always escalate.
	directCmds := map[string]bool{
		"systemctl": true,
		"service":   true,
		"launchctl": true,
	}

	// Windows sc subcommands that indicate service management.
	scSubs := map[string]bool{
		"start":  true,
		"stop":   true,
		"create": true,
		"delete": true,
		"config": true,
		"query":  true,
	}

	return rule{
		Name: "service-management",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if directCmds[base] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "service management requires approval",
					Rule:     "service-management",
				}, true
			}
			// Windows sc.exe or sc with service subcommand.
			if (base == "sc" || base == "sc.exe") && len(fields) >= 2 {
				if scSubs[strings.ToLower(fields[1])] {
					return ClassifyResult{
						Decision: Escalated,
						Reason:   "service management requires approval",
						Rule:     "service-management",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if directCmds[base] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "service management requires approval",
					Rule:     "service-management",
				}, true
			}
			if (base == "sc" || base == "sc.exe") && len(args) >= 1 {
				if scSubs[strings.ToLower(args[0])] {
					return ClassifyResult{
						Decision: Escalated,
						Reason:   "service management requires approval",
						Rule:     "service-management",
					}, true
				}
			}
			return ClassifyResult{}, false
		},
	}
}

// crontabAtRule escalates scheduled task management commands: crontab, at, atq, atrm.
func crontabAtRule() rule {
	scheduleCmds := map[string]bool{
		"crontab": true,
		"at":      true,
		"atq":     true,
		"atrm":    true,
	}

	return rule{
		Name: "crontab-at",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if scheduleCmds[baseCommand(fields[0])] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "scheduled task management requires approval",
					Rule:     "crontab-at",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, _ []string) (ClassifyResult, bool) {
			if scheduleCmds[baseCommand(name)] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "scheduled task management requires approval",
					Rule:     "crontab-at",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

// filePermissionRule matches chmod, chown, and chgrp commands that are NOT
// already caught by the more specific forbidden rules (chmod-recursive-root,
// chown-recursive-root). Since forbidden rules run first and take priority,
// this escalated rule only fires for non-root-recursive usages.
func filePermissionRule() rule {
	permCmds := map[string]bool{
		"chmod": true, "chown": true, "chgrp": true,
	}
	return rule{
		Name: "file-permission",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if permCmds[baseCommand(fields[0])] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "file permission change requires approval",
					Rule:     "file-permission",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, _ []string) (ClassifyResult, bool) {
			if permCmds[baseCommand(name)] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "file permission change requires approval",
					Rule:     "file-permission",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

func firewallManagementRule() rule {
	fwCmds := map[string]bool{
		"iptables": true, "ip6tables": true, "ufw": true,
		"nft": true, "firewall-cmd": true,
	}
	return rule{
		Name: "firewall-management",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if fwCmds[baseCommand(fields[0])] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "firewall management requires approval",
					Rule:     "firewall-management",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, _ []string) (ClassifyResult, bool) {
			if fwCmds[baseCommand(name)] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "firewall management requires approval",
					Rule:     "firewall-management",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

func networkScanRule() rule {
	scanCmds := map[string]bool{
		"nmap": true, "tcpdump": true, "tshark": true,
		"wireshark": true, "ettercap": true, "masscan": true,
	}
	return rule{
		Name: "network-scan",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if scanCmds[baseCommand(fields[0])] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "network scanning/capture requires approval",
					Rule:     "network-scan",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, _ []string) (ClassifyResult, bool) {
			if scanCmds[baseCommand(name)] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "network scanning/capture requires approval",
					Rule:     "network-scan",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

func databaseClientRule() rule {
	dbCmds := map[string]bool{
		"mysql": true, "psql": true, "sqlite3": true,
		"redis-cli": true, "mongo": true, "mongosh": true,
		"mongodump": true, "mongoexport": true,
		"mongoimport": true, "mongorestore": true,
		"pg_dump": true, "pg_restore": true, "mysqldump": true,
	}
	return rule{
		Name: "database-client",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if dbCmds[baseCommand(fields[0])] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "database access requires approval",
					Rule:     "database-client",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, _ []string) (ClassifyResult, bool) {
			if dbCmds[baseCommand(name)] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "database access requires approval",
					Rule:     "database-client",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

// gitStashDropRule escalates git stash drop/clear which destroy stashed work.
func gitStashDropRule() rule {
	destructiveStashSubs := map[string]bool{
		"drop":  true,
		"clear": true,
	}

	return rule{
		Name: "git-stash-drop",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) < 3 {
				return ClassifyResult{}, false
			}
			if baseCommand(fields[0]) != cmdGit {
				return ClassifyResult{}, false
			}
			// Find the "stash" subcommand, skipping git global flags.
			sub := findGitSubcommand(fields[1:])
			if sub != subStash {
				return ClassifyResult{}, false
			}
			// Find the stash sub-subcommand after "stash".
			// Locate where "stash" appears and look at the next non-flag token.
			foundStash := false
			for _, f := range fields[1:] {
				if !foundStash {
					if strings.HasPrefix(f, "-") {
						continue
					}
					if f == subStash {
						foundStash = true
						continue
					}
					break
				}
				// After "stash", skip flags to find the stash sub-subcommand.
				if strings.HasPrefix(f, "-") {
					continue
				}
				if destructiveStashSubs[f] {
					return ClassifyResult{
						Decision: Escalated,
						Reason:   "git stash drop/clear destroys stashed work and requires approval",
						Rule:     "git-stash-drop",
					}, true
				}
				break
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if baseCommand(name) != cmdGit || len(args) < 2 {
				return ClassifyResult{}, false
			}
			sub := findGitSubcommand(args)
			if sub != subStash {
				return ClassifyResult{}, false
			}
			// Find the stash sub-subcommand after "stash".
			foundStash := false
			for _, a := range args {
				if !foundStash {
					if strings.HasPrefix(a, "-") {
						continue
					}
					if a == subStash {
						foundStash = true
						continue
					}
					break
				}
				if strings.HasPrefix(a, "-") {
					continue
				}
				if destructiveStashSubs[a] {
					return ClassifyResult{
						Decision: Escalated,
						Reason:   "git stash drop/clear destroys stashed work and requires approval",
						Rule:     "git-stash-drop",
					}, true
				}
				break
			}
			return ClassifyResult{}, false
		},
	}
}

// evalExecRule escalates shell builtins that execute arbitrary code:
// eval, source, and the dot (.) command.
func evalExecRule() rule {
	// evalCmds lists commands that execute code from arguments or files.
	evalCmds := map[string]bool{"eval": true, "source": true}

	return rule{
		Name: "eval-exec",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			cmd := baseCommand(fields[0])
			if evalCmds[cmd] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "eval/source executes arbitrary code and requires approval",
					Rule:     "eval-exec",
				}, true
			}
			// Match the dot command: ". script.sh"
			// Must be exactly "." as the command (not "./" which is a relative path).
			if cmd == "." {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "dot-source executes arbitrary code and requires approval",
					Rule:     "eval-exec",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if len(args) == 0 {
				return ClassifyResult{}, false
			}
			if evalCmds[cmd] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "eval/source executes arbitrary code and requires approval",
					Rule:     "eval-exec",
				}, true
			}
			// Match the dot command.
			if cmd == "." {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "dot-source executes arbitrary code and requires approval",
					Rule:     "eval-exec",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}

func dockerBuildRule() rule {
	const cmdDocker = "docker"
	return rule{
		Name: "docker-build",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if base != cmdDocker {
				return ClassifyResult{}, false
			}
			sub := fields[1]
			if sub == "build" || sub == "push" || sub == "pull" {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "docker " + sub + " requires approval",
					Rule:     "docker-build",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if baseCommand(name) != cmdDocker || len(args) == 0 {
				return ClassifyResult{}, false
			}
			sub := args[0]
			if sub == "build" || sub == "push" || sub == "pull" {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "docker " + sub + " requires approval",
					Rule:     "docker-build",
				}, true
			}
			return ClassifyResult{}, false
		},
	}
}
