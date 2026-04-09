// classifier_rules_escalated.go contains all Escalated-category rule functions
// and their helpers. Escalated rules require user approval before execution —
// they are evaluated after forbidden rules but before allow rules.

package agentbox

import (
	"path"
	"strings"
)

// isShellRedirect reports whether tok looks like a shell redirect token
// (e.g. "2>/dev/null", "2>&1", ">/dev/null", "&>/dev/null", "&>", "1>&2").
func isShellRedirect(tok string) bool {
	// Patterns: 2>/dev/null, 2>&1, >/dev/null, &>/dev/null, 1>&2, etc.
	for i, ch := range tok {
		if ch == '>' {
			return true
		}
		// Only digits (fd numbers) and '&' may precede '>'.
		if i == 0 && (ch == '&' || (ch >= '0' && ch <= '9')) {
			continue
		}
		if ch >= '0' && ch <= '9' {
			continue
		}
		return false
	}
	return false
}

// stripFieldsRedirectsAndPipes takes already-split fields (from strings.Fields)
// and returns only the fields belonging to the first pipe-segment with shell
// redirect tokens removed. This lets rule helpers examine the core command
// without being confused by trailing "2>/dev/null", "2>&1", "| head -20", etc.
//
// Design note: this intentionally analyzes only the first segment of compound
// commands. A command like "iptables -L && iptables -A INPUT -j DROP" would
// have only the first segment ("iptables -L") analyzed for read-only status.
// This is acceptable because the sandbox (not the classifier) is the primary
// security boundary — see defense-in-depth design.
//
// Examples:
//
//	["iptables", "-L", "-n", "|", "head", "-20"]  →  ["iptables", "-L", "-n"]
//	["redis-cli", "ping", "2>&1"]                  →  ["redis-cli", "ping"]
//	["crontab", "-l", "2>/dev/null"]                →  ["crontab", "-l"]
func stripFieldsRedirectsAndPipes(fields []string) []string {
	out := make([]string, 0, len(fields))
	skipNext := false
	for _, f := range fields {
		if skipNext {
			skipNext = false
			continue
		}
		if f == "|" || f == "||" || f == "&&" || f == ";" {
			break
		}
		if isShellRedirect(f) {
			// When the redirect target is separate (e.g. "2>" "/dev/null"),
			// skip the next token as well. A glued form like "2>/dev/null"
			// or "2>&1" is a single token — no extra skip needed.
			if strings.HasSuffix(f, ">") || strings.HasSuffix(f, ">>") {
				skipNext = true
			}
			continue
		}
		out = append(out, f)
	}
	return out
}

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
			if cmd == ruleSudo || cmd == cmdDoas {
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
			if cmd == ruleSudo || cmd == cmdDoas {
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
	".kube/config",
	".docker/config.json",
	".alibabacloud/",
	".config/gcloud/",
	".config/gh/hosts",
	"/etc/shadow",
	".bash_history",
	".zsh_history",
	".python_history",
	".node_repl_history",
	".mysql_history",
	".psql_history",
	".rediscli_history",
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
	"credentials",
	"password",
	"token",
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
	// SSH public key files (*.pub) are meant to be shared and are safe to
	// read. Exclude them before checking sensitive path patterns so that
	// e.g. "~/.ssh/id_ed25519.pub" is not flagged.
	if strings.HasSuffix(lower, ".pub") {
		return false
	}
	// Check known sensitive path substrings.
	for _, p := range credentialSensitivePaths {
		if strings.Contains(lower, p) {
			return true
		}
	}
	// Check ".env" and ".env.*" variants (e.g. .env.local, .env.production)
	// but exclude non-sensitive example/template files.
	base := strings.ToLower(path.Base(arg))
	if base == ".env" || (strings.HasPrefix(base, ".env.") && !isEnvExampleFile(base)) {
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

// envExampleSuffixes lists .env file suffixes that typically contain
// placeholder values rather than real secrets.
var envExampleSuffixes = []string{
	"example", "sample", "template", "defaults", "dist",
}

// isEnvExampleFile reports whether a lowercased .env.* basename is a
// non-sensitive example/template file (e.g. ".env.example", ".env.dist").
func isEnvExampleFile(base string) bool {
	// base is already lowercased and starts with ".env.".
	suffix := base[len(".env."):]
	for _, s := range envExampleSuffixes {
		if suffix == s {
			return true
		}
	}
	return false
}

// envEnumCmds lists commands that print environment variables.
var envEnumCmds = map[string]bool{cmdEnv: true, "printenv": true}

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
			base := baseCommand(fields[0])
			if !userCmds[base] {
				return ClassifyResult{}, false
			}
			cleaned := stripFieldsRedirectsAndPipes(fields[1:])
			// --help, -h, --version are informational only.
			if escalatedHasInfoFlag(cleaned) {
				return ClassifyResult{}, false
			}
			// passwd -S shows password status — read-only.
			if base == "passwd" && isPasswdStatusOnly(cleaned) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "user/group management requires approval",
				Rule:     "user-management",
			}, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if !userCmds[base] {
				return ClassifyResult{}, false
			}
			if escalatedHasInfoFlag(args) {
				return ClassifyResult{}, false
			}
			if base == "passwd" && isPasswdStatusOnly(args) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "user/group management requires approval",
				Rule:     "user-management",
			}, true
		},
	}
}

// isPasswdStatusOnly reports whether the passwd arguments represent a
// status-only invocation. "passwd -S [user]" only displays the password status
// and does not modify anything.
func isPasswdStatusOnly(args []string) bool {
	hasStatus := false
	for _, a := range args {
		switch a {
		case "-S", "--status":
			hasStatus = true
		default:
			// Unknown flags mean this is not a status-only invocation.
			if strings.HasPrefix(a, "-") {
				return false
			}
			// Non-flag args (usernames) are acceptable with -S.
		}
	}
	return hasStatus
}

// globalInstallRule escalates global package installations: npm -g, pip install
// without --user, gem install, and similar commands that modify system-wide paths.
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

// dockerContainerRule escalates Docker/Podman container lifecycle commands:
// run, exec, stop, rm, restart, kill, pause, unpause, and object-level
// destructive actions (system prune, volume rm, image rm, container rm, etc.).
func dockerContainerRule() rule {
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

	const reason = "container runtime operation requires approval"
	const ruleName = "docker-container"

	matchFields := func(fields []string) (ClassifyResult, bool) {
		if len(fields) == 0 {
			return ClassifyResult{}, false
		}
		base := baseCommand(fields[0])

		switch base {
		case cmdDocker, cmdPodman:
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			sub := fields[1]
			// Skip "docker compose" — handled by docker-compose rule.
			if sub == "compose" {
				return ClassifyResult{}, false
			}
			// docker <object> <action>
			if actions, ok := dockerObjActions[sub]; ok && len(fields) >= 3 {
				if actions[fields[2]] {
					return ClassifyResult{
						Decision: Escalated,
						Reason:   reason,
						Rule:     ruleName,
					}, true
				}
				return ClassifyResult{}, false
			}
			// docker <subcmd>
			if dockerSubs[sub] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   reason,
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

// dockerComposeRule escalates docker-compose / docker compose commands.
func dockerComposeRule() rule {
	composeSubs := map[string]bool{
		"up": true, "down": true, "restart": true,
		"rm": true, "stop": true, "kill": true,
	}

	const reason = "docker compose operation requires approval"
	const ruleName = "docker-compose"

	matchFields := func(fields []string) (ClassifyResult, bool) {
		if len(fields) == 0 {
			return ClassifyResult{}, false
		}
		base := baseCommand(fields[0])

		switch base {
		case cmdDocker, cmdPodman:
			// docker compose <subcmd>
			if len(fields) < 3 {
				return ClassifyResult{}, false
			}
			if fields[1] != "compose" {
				return ClassifyResult{}, false
			}
			if composeSubs[fields[2]] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   reason,
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
					Reason:   reason,
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

// kubernetesRule escalates kubectl operations that modify cluster state.
func kubernetesRule() rule {
	kubectlSubs := map[string]bool{
		"exec": true, "run": true, "delete": true, "apply": true,
		"create": true, "edit": true, "patch": true, "scale": true,
		"rollout": true,
	}

	const reason = "kubernetes operation requires approval"
	const ruleName = "kubernetes"

	matchFields := func(fields []string) (ClassifyResult, bool) {
		if len(fields) == 0 {
			return ClassifyResult{}, false
		}
		base := baseCommand(fields[0])

		if base == "kubectl" {
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			if kubectlSubs[fields[1]] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   reason,
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

// systemPackageInstallRule escalates system package manager install commands:
// brew, apt, apt-get, yum, dnf, pacman, apk, zypper, and similar.
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
		{"winget", []string{"install", "upgrade", "uninstall"}},
		{"choco", []string{"install", "upgrade", "uninstall"}},
		{"scoop", []string{"install", "update", "uninstall"}},
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
			if !killCmds[base] {
				return ClassifyResult{}, false
			}
			// "kill -l" / "kill --list" lists signal names — read-only.
			if base == "kill" && isKillListOnly(fields[1:]) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "process termination requires approval",
				Rule:     "process-kill",
			}, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if !killCmds[base] {
				return ClassifyResult{}, false
			}
			if base == "kill" && isKillListOnly(args) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "process termination requires approval",
				Rule:     "process-kill",
			}, true
		},
	}
}

// isKillListOnly reports whether args represent "kill -l" or "kill --list",
// optionally followed by a signal name. These invocations only print signal
// names and do not terminate any process.
func isKillListOnly(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if args[0] == "-l" || args[0] == flagList {
		// "kill -l" or "kill -l TERM" — both are read-only.
		return true
	}
	return false
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
// Only the exact base commands "ssh" and "sshpass" are matched; related
// utilities like ssh-keygen, ssh-agent, and ssh-add are not escalated.
func sshCommandRule() rule {
	return rule{
		Name: "ssh-command",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if base == "sshpass" {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "sshpass wraps SSH remote access; requires approval",
					Rule:     "ssh-command",
				}, true
			}
			if base == "ssh" {
				// ssh -V (uppercase) is a version check — safe, not a connection.
				if isSSHVersionOnly(stripFieldsRedirectsAndPipes(fields[1:])) {
					return ClassifyResult{}, false
				}
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "SSH remote access requires approval",
					Rule:     "ssh-command",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if base == "sshpass" {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "sshpass wraps SSH remote access; requires approval",
					Rule:     "ssh-command",
				}, true
			}
			if base == "ssh" {
				if isSSHVersionOnly(args) {
					return ClassifyResult{}, false
				}
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

// isSSHVersionOnly reports whether the SSH arguments represent a version check
// only. "ssh -V" (uppercase) prints the version; -v (lowercase) enables verbose
// mode for connections and should still be escalated.
func isSSHVersionOnly(args []string) bool {
	for _, a := range args {
		if a == "-V" {
			return true
		}
	}
	return false
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

	const reason = "file download requires approval"
	const ruleName = "download-to-file"

	// hasCurlDownloadFlag reports whether args contain a curl download flag
	// (-o, -O, --output), including combined short flags like -Lo or -sOL.
	// Only the curl segment is examined: scanning stops at the first pipe or
	// command separator so that flags from downstream commands (e.g. grep -o)
	// are not mistaken for curl download flags.
	hasCurlDownloadFlag := func(args []string) bool {
		for _, a := range args {
			// Stop at pipe / command separator — anything after belongs
			// to a different command.
			if isCommandSeparator(a) {
				return false
			}
			if curlDownloadFlags[a] {
				return true
			}
			// Check for -o/O combined with other short flags (e.g. -Lo, -sOL).
			if len(a) > 1 && a[0] == '-' && a[1] != '-' {
				for _, ch := range a[1:] {
					if ch == 'o' || ch == 'O' {
						return true
					}
				}
			}
		}
		return false
	}

	matchFields := func(fields []string) (ClassifyResult, bool) {
		if len(fields) == 0 {
			return ClassifyResult{}, false
		}
		base := baseCommand(fields[0])
		if base == cmdWget {
			return ClassifyResult{
				Decision: Escalated,
				Reason:   reason,
				Rule:     ruleName,
			}, true
		}
		if base == cmdCurl && hasCurlDownloadFlag(fields[1:]) {
			return ClassifyResult{
				Decision: Escalated,
				Reason:   reason,
				Rule:     ruleName,
			}, true
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

// serviceManagementRule escalates service management commands: systemctl,
// service, launchctl, and sc/sc.exe (Windows, only with recognized subcommands).
func serviceManagementRule() rule {
	// Direct service management commands.
	directCmds := map[string]bool{
		"systemctl": true,
		"service":   true,
		"launchctl": true,
	}

	// Read-only systemctl subcommands that should not be escalated.
	systemctlReadOnly := map[string]bool{
		"status":            true,
		"is-active":         true,
		"is-enabled":        true,
		"is-failed":         true,
		"show":              true,
		"list-units":        true,
		"list-unit-files":   true,
		"list-timers":       true,
		"list-sockets":      true,
		"list-dependencies": true,
		"cat":               true,
	}

	// Read-only launchctl subcommands.
	launchctlReadOnly := map[string]bool{
		"list":  true,
		"print": true,
	}

	// Windows sc subcommands that indicate service management (write ops).
	// "query" is excluded — it is read-only.
	scSubs := map[string]bool{
		"start":  true,
		"stop":   true,
		"create": true,
		"delete": true,
		"config": true,
	}

	const reason = "service management requires approval"
	const ruleName = "service-management"

	matchFields := func(fields []string) (ClassifyResult, bool) {
		if len(fields) == 0 {
			return ClassifyResult{}, false
		}
		base := baseCommand(fields[0])
		args := fields[1:]
		if directCmds[base] {
			sub := serviceFirstSubcommand(args)
			if base == "systemctl" && systemctlReadOnly[sub] {
				return ClassifyResult{}, false
			}
			if base == "launchctl" && launchctlReadOnly[sub] {
				return ClassifyResult{}, false
			}
			// "service <name> status" is read-only.
			if base == "service" && isServiceStatusCmd(args) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   reason,
				Rule:     ruleName,
			}, true
		}
		// Windows sc.exe or sc with service subcommand.
		if (base == "sc" || base == "sc.exe") && len(args) >= 1 {
			if scSubs[strings.ToLower(args[0])] {
				return ClassifyResult{
					Decision: Escalated,
					Reason:   reason,
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

// serviceFirstSubcommand returns the first non-flag token from args.
// It is used to find the subcommand for systemctl/launchctl.
func serviceFirstSubcommand(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

// isServiceStatusCmd reports whether args (after the base "service" command)
// represent "service <name> status", which is read-only.
func isServiceStatusCmd(args []string) bool {
	// "service <name> status" — args[0] is the service name, args[1] is "status".
	if len(args) >= 2 && args[1] == "status" {
		return true
	}
	return false
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
			base := baseCommand(fields[0])
			if !scheduleCmds[base] {
				return ClassifyResult{}, false
			}
			// crontab -l is read-only (list crontab); skip escalation.
			// Strip redirects/pipes so "crontab -l 2>/dev/null | head -20"
			// is correctly recognized as a list-only invocation.
			if base == "crontab" && isCrontabListOnly(stripFieldsRedirectsAndPipes(fields[1:])) {
				return ClassifyResult{}, false
			}
			// at -c displays the contents of a scheduled job (read-only);
			// skip escalation.
			if base == "at" && isAtCatOnly(stripFieldsRedirectsAndPipes(fields[1:])) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "scheduled task management requires approval",
				Rule:     "crontab-at",
			}, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if !scheduleCmds[base] {
				return ClassifyResult{}, false
			}
			if base == "crontab" && isCrontabListOnly(args) {
				return ClassifyResult{}, false
			}
			if base == "at" && isAtCatOnly(args) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "scheduled task management requires approval",
				Rule:     "crontab-at",
			}, true
		},
	}
}

// isCrontabListOnly reports whether args represent a read-only crontab
// invocation. "crontab -l" and "crontab -l -u <user>" only list the crontab
// and do not modify scheduled tasks.
func isCrontabListOnly(args []string) bool {
	hasList := false
	for _, a := range args {
		switch a {
		case "-l":
			hasList = true
		case "-u":
			// -u <user> is valid with -l; the next arg is the username
			// and will be consumed as a non-flag below.
			continue
		default:
			// Any other flag (e.g. -e, -r) or a file argument means
			// this is NOT a list-only invocation.
			if strings.HasPrefix(a, "-") {
				return false
			}
			// Non-flag argument — could be the username after -u; allow it.
		}
	}
	return hasList
}

// isAtCatOnly reports whether args represent a read-only "at -c" invocation.
// "at -c <jobid>" displays the contents of a scheduled job without modifying
// anything. The -c flag must be the only flag; an optional numeric job ID is
// allowed.
func isAtCatOnly(args []string) bool {
	hasCat := false
	for _, a := range args {
		switch {
		case a == "-c":
			hasCat = true
		case strings.HasPrefix(a, "-"):
			// Any other flag (e.g. -f, -m) means this is NOT read-only.
			return false
		default:
			// Non-flag argument (e.g. job ID) — allowed.
		}
	}
	return hasCat
}

// filePermissionRule matches chmod, chown, and chgrp commands that are NOT
// already caught by the more specific forbidden rule (recursive-perm-root).
// Since forbidden rules run first and take priority,
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

// firewallManagementRule escalates firewall management commands: iptables,
// ip6tables, ufw, nft, and firewall-cmd. Read-only flags (-L, --list, etc.)
// are exempted.
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
			base := baseCommand(fields[0])
			if !fwCmds[base] {
				return ClassifyResult{}, false
			}
			// Strip redirects and pipes so read-only detection is not
			// confused by trailing "2>/dev/null", "| head -20", etc.
			cleaned := stripFieldsRedirectsAndPipes(fields[1:])
			if escalatedHasInfoFlag(cleaned) {
				return ClassifyResult{}, false
			}
			if isFirewallReadOnly(base, cleaned) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "firewall management requires approval",
				Rule:     "firewall-management",
			}, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if !fwCmds[base] {
				return ClassifyResult{}, false
			}
			if escalatedHasInfoFlag(args) {
				return ClassifyResult{}, false
			}
			if isFirewallReadOnly(base, args) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "firewall management requires approval",
				Rule:     "firewall-management",
			}, true
		},
	}
}

// iptablesListOnlyFlags are the flags that constitute a read-only iptables
// invocation. A command is list-only if every flag is in this set.
var iptablesListOnlyFlags = map[string]bool{
	"-L": true, flagList: true,
	"-S": true, "--list-rules": true,
	"-n": true, "--numeric": true,
	"-v": true, "--verbose": true,
	"--line-numbers": true,
}

// isFirewallReadOnly reports whether the given firewall command arguments
// represent a read-only operation that does not modify firewall rules.
func isFirewallReadOnly(base string, args []string) bool {
	switch base {
	case "iptables", "ip6tables":
		return isIptablesListOnly(args)
	case "ufw":
		// "ufw status" (with optional "verbose"/"numbered") is read-only.
		if len(args) >= 1 && args[0] == "status" {
			return true
		}
	case "nft":
		// "nft list ..." is read-only.
		if len(args) >= 1 && args[0] == "list" {
			return true
		}
	case "firewall-cmd":
		return isFirewallCmdReadOnly(args)
	}
	return false
}

// isIptablesListOnly reports whether the iptables/ip6tables arguments only
// contain listing flags (and optional table selection via -t <table>).
func isIptablesListOnly(args []string) bool {
	hasListFlag := false
	skipNext := false
	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if a == "-t" || a == "--table" {
			skipNext = true // next arg is the table name
			continue
		}
		if strings.HasPrefix(a, "-t") && len(a) > 2 {
			// Short form: -tnat (table name glued to flag).
			continue
		}
		if strings.HasPrefix(a, "--table=") {
			continue
		}
		if iptablesListOnlyFlags[a] {
			if a == "-L" || a == flagList || a == "-S" || a == "--list-rules" {
				hasListFlag = true
			}
			continue
		}
		// A non-flag argument (chain name like "INPUT") is acceptable
		// as part of listing, but any other flag (like -A, -D, -I, -F)
		// means this is a write operation.
		if strings.HasPrefix(a, "-") {
			return false
		}
	}
	return hasListFlag
}

// firewallCmdReadOnlyFlags are firewall-cmd flags that indicate read-only queries.
var firewallCmdReadOnlyFlags = map[string]bool{
	"--list-all":         true,
	"--list-all-zones":   true,
	"--state":            true,
	"--get-active-zones": true,
}

// isFirewallCmdReadOnly reports whether the firewall-cmd arguments
// only contain read-only query flags. All --flags must be in the
// read-only set; any unknown --flag is treated as a potential write.
func isFirewallCmdReadOnly(args []string) bool {
	hasReadOnlyFlag := false
	for _, a := range args {
		if firewallCmdReadOnlyFlags[a] {
			hasReadOnlyFlag = true
			continue
		}
		// Any unknown --flag means this may be a write operation.
		if strings.HasPrefix(a, "--") {
			return false
		}
		// Non-flag args (like zone names) are acceptable with read-only flags.
	}
	return hasReadOnlyFlag
}

// networkScanRule escalates network scanning and packet capture tools:
// nmap, tcpdump, tshark, wireshark, ettercap, and masscan.
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
				// --help, -h, --version, -V are informational only.
				if escalatedHasInfoFlag(stripFieldsRedirectsAndPipes(fields[1:])) {
					return ClassifyResult{}, false
				}
				return ClassifyResult{
					Decision: Escalated,
					Reason:   "network scanning/capture requires approval",
					Rule:     "network-scan",
				}, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if scanCmds[baseCommand(name)] {
				if escalatedHasInfoFlag(args) {
					return ClassifyResult{}, false
				}
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

// databaseClientRule escalates interactive database client commands: mysql,
// psql, sqlite3, redis-cli, mongo, and mongosh. Commands with --help or
// --version are exempted. Note: -h is NOT exempted because psql uses -h for host.
func databaseClientRule() rule {
	// Interactive database client commands only.
	dbCmds := map[string]bool{
		"mysql": true, "psql": true, "sqlite3": true,
		cmdRedisCLI: true, "mongo": true, "mongosh": true,
	}
	return rule{
		Name: "database-client",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if !dbCmds[base] {
				return ClassifyResult{}, false
			}
			if isDBClientInfoOnly(base, fields[1:]) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "database access requires approval",
				Rule:     "database-client",
			}, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if !dbCmds[base] {
				return ClassifyResult{}, false
			}
			if isDBClientInfoOnly(base, args) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "database access requires approval",
				Rule:     "database-client",
			}, true
		},
	}
}

// databaseBackupRule escalates database backup and restore operations.
func databaseBackupRule() rule {
	backupCmds := map[string]bool{
		"pg_dump": true, "pg_restore": true, "mysqldump": true,
		"mongodump": true, "mongorestore": true,
		"mongoexport": true, "mongoimport": true,
	}
	return rule{
		Name: "database-backup",
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if !backupCmds[base] {
				// Also check redis-cli SAVE/BGSAVE.
				if base == cmdRedisCLI {
					return checkRedisBackup(fields[1:])
				}
				return ClassifyResult{}, false
			}
			if isDBClientInfoOnly(base, fields[1:]) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "database backup/restore operation requires approval",
				Rule:     "database-backup",
			}, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if !backupCmds[base] {
				if base == cmdRedisCLI {
					return checkRedisBackup(args)
				}
				return ClassifyResult{}, false
			}
			if isDBClientInfoOnly(base, args) {
				return ClassifyResult{}, false
			}
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "database backup/restore operation requires approval",
				Rule:     "database-backup",
			}, true
		},
	}
}

// checkRedisBackup checks if a redis-cli command is a SAVE/BGSAVE operation.
func checkRedisBackup(args []string) (ClassifyResult, bool) {
	for _, a := range args {
		upper := strings.ToUpper(a)
		if upper == "SAVE" || upper == "BGSAVE" {
			return ClassifyResult{
				Decision: Escalated,
				Reason:   "database backup/restore operation requires approval",
				Rule:     "database-backup",
			}, true
		}
	}
	return ClassifyResult{}, false
}

// isDBClientInfoOnly reports whether the database client arguments represent
// an informational-only invocation: version checks, help text, or a
// redis-cli ping health check.
// NOTE: unlike escalatedHasInfoFlag, this does NOT treat -h as help because
// database tools like psql use -h for --host.
func isDBClientInfoOnly(base string, args []string) bool {
	cleaned := stripFieldsRedirectsAndPipes(args)
	for _, a := range cleaned {
		switch a {
		case flagHelp, flagVersion, "-V":
			return true
		}
	}
	// redis-cli ping is a read-only health check.
	if base == cmdRedisCLI && len(cleaned) == 1 && strings.EqualFold(cleaned[0], "ping") {
		return true
	}
	return false
}

// gitStashDropRule escalates git stash drop/clear which destroy stashed work.
func gitStashDropRule() rule {
	destructiveStashSubs := map[string]bool{
		"drop":  true,
		"clear": true,
	}

	const reason = "git stash drop/clear destroys stashed work and requires approval"
	const ruleName = "git-stash-drop"

	// findDestructiveStashSub looks for "stash" in fields, then returns true
	// if the next non-flag token is a destructive stash sub-subcommand.
	findDestructiveStashSub := func(fields []string) bool {
		foundStash := false
		for _, f := range fields {
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
			return destructiveStashSubs[f]
		}
		return false
	}

	matchFields := func(fields []string) (ClassifyResult, bool) {
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
		if findDestructiveStashSub(fields[1:]) {
			return ClassifyResult{
				Decision: Escalated,
				Reason:   reason,
				Rule:     ruleName,
			}, true
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

// dockerBuildRule escalates Docker/Podman image lifecycle commands:
// build, push, and pull. These are separated from dockerContainerRule because
// they affect image registries rather than running containers.
func dockerBuildRule() rule {
	const ruleName = "docker-build"

	buildSubs := map[string]bool{
		"build": true,
		"push":  true,
		"pull":  true,
	}

	matchFields := func(fields []string) (ClassifyResult, bool) {
		if len(fields) < 2 {
			return ClassifyResult{}, false
		}
		base := baseCommand(fields[0])
		if base != cmdDocker && base != cmdPodman {
			return ClassifyResult{}, false
		}
		sub := fields[1]
		if buildSubs[sub] {
			return ClassifyResult{
				Decision: Escalated,
				Reason:   base + " " + sub + " requires approval",
				Rule:     ruleName,
			}, true
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

// packageInstallCmds maps base command names to their install subcommands for
// local package installation detection. Global installs are handled by the
// higher-priority global-install rule.
var packageInstallCmds = map[string]map[string]bool{
	"pip":      {"install": true, "uninstall": true},
	"pip3":     {"install": true, "uninstall": true},
	"npm":      {"install": true, "i": true, "add": true, "ci": true},
	"yarn":     {"install": true, "add": true},
	"pnpm":     {"install": true, "add": true, "i": true},
	"cargo":    {"install": true},
	"go":       {"install": true},
	"gem":      {"install": true},
	"composer": {"install": true, "require": true},
	"conda":    {"install": true},
}

// isPythonLauncher reports whether base is a Python interpreter name:
// python, python3, python3.X (any minor version), or py (Windows launcher).
func isPythonLauncher(base string) bool {
	if base == "python" || base == "python3" || base == "py" {
		return true
	}
	// Match python3.X where X is one or more digits (e.g. python3.11).
	if strings.HasPrefix(base, "python3.") {
		suffix := base[len("python3."):]
		if len(suffix) > 0 {
			for _, c := range suffix {
				if c < '0' || c > '9' {
					return false
				}
			}
			return true
		}
	}
	return false
}

// matchPythonMPip checks whether fields represent a "python -m pip install/uninstall"
// invocation. The py launcher may have version flags like -3.11 before -m.
func matchPythonMPip(fields []string, ruleName RuleName, reason string) (ClassifyResult, bool) {
	// Walk fields[1:] looking for -m; skip flags like -3.11, -u, etc.
	mIdx := -1
	for i := 1; i < len(fields); i++ {
		if fields[i] == "-m" {
			mIdx = i
			break
		}
	}
	if mIdx < 0 || mIdx+1 >= len(fields) {
		return ClassifyResult{}, false
	}
	pipCmd := fields[mIdx+1]
	if pipCmd != "pip" && pipCmd != "pip3" {
		return ClassifyResult{}, false
	}
	// The subcommand after pip/pip3 must be install or uninstall.
	if mIdx+2 >= len(fields) {
		return ClassifyResult{}, false
	}
	sub := fields[mIdx+2]
	if sub == "install" || sub == "uninstall" {
		return ClassifyResult{
			Decision: Escalated,
			Reason:   reason,
			Rule:     ruleName,
		}, true
	}
	return ClassifyResult{}, false
}

// packageInstallRule escalates local package installation commands that modify
// the project or user environment. System-level and global installs are caught
// by higher-priority rules (system-package-install, global-install).
func packageInstallRule() rule {
	const ruleName = "package-install"
	const reason = "package installation modifies the environment"

	matchFields := func(fields []string) (ClassifyResult, bool) {
		if len(fields) < 2 {
			return ClassifyResult{}, false
		}
		base := baseCommand(fields[0])

		// Special case: python -m pip install / uninstall.
		// Matches python, python3, python3.X, and py (Windows launcher).
		if isPythonLauncher(base) {
			if r, ok := matchPythonMPip(fields, ruleName, reason); ok {
				return r, true
			}
		}

		subs, ok := packageInstallCmds[base]
		if !ok {
			return ClassifyResult{}, false
		}
		if subs[fields[1]] {
			return ClassifyResult{
				Decision: Escalated,
				Reason:   reason,
				Rule:     ruleName,
			}, true
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

// backgroundProcessCmds is the set of commands that launch background processes.
var backgroundProcessCmds = map[string]bool{
	"nohup": true, "disown": true,
}

// backgroundProcessRule escalates commands that run processes in the background:
// nohup, trailing &, disown, screen, and tmux new-session.
func backgroundProcessRule() rule {
	const ruleName = "background-process"
	const reason = "background process execution requires approval"
	result := ClassifyResult{
		Decision: Escalated,
		Reason:   reason,
		Rule:     ruleName,
	}

	return rule{
		Name: ruleName,
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			if isBackgroundCommand(fields, command) {
				return result, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if backgroundProcessCmds[base] {
				return result, true
			}
			for _, a := range args {
				if a == "disown" {
					return result, true
				}
			}
			if isScreenOrTmuxSession(base, args) {
				return result, true
			}
			// Trailing & in args.
			if len(args) > 0 && args[len(args)-1] == "&" {
				return result, true
			}
			return ClassifyResult{}, false
		},
	}
}

// isBackgroundCommand checks whether the parsed fields or raw command string
// indicate a background process launch (nohup, disown, screen, tmux, trailing &).
func isBackgroundCommand(fields []string, command string) bool {
	base := baseCommand(fields[0])

	if backgroundProcessCmds[base] {
		return true
	}
	for _, f := range fields[1:] {
		if f == "disown" {
			return true
		}
	}
	if isScreenOrTmuxSession(base, fields[1:]) {
		return true
	}
	return hasTrailingAmpersand(command)
}

// isScreenOrTmuxSession reports whether the base command and args indicate a
// screen or tmux session creation.
func isScreenOrTmuxSession(base string, args []string) bool {
	if base == "screen" && len(args) > 0 {
		return true
	}
	if base == "tmux" && len(args) > 0 {
		return args[0] == "new-session" || args[0] == "new"
	}
	return false
}

// hasTrailingAmpersand reports whether the command ends with a single &
// (background operator), not && (logical AND).
func hasTrailingAmpersand(command string) bool {
	trimmed := strings.TrimSpace(command)
	if len(trimmed) == 0 || trimmed[len(trimmed)-1] != '&' {
		return false
	}
	return len(trimmed) < 2 || trimmed[len(trimmed)-2] != '&'
}

// inPlaceEditRule escalates in-place file editing commands: sed -i and perl -i.
// Plain sed (without -i) is handled by the allow text-processing rule.
func inPlaceEditRule() rule {
	const ruleName = "in-place-edit"
	const reason = "in-place file editing requires approval"
	result := ClassifyResult{
		Decision: Escalated,
		Reason:   reason,
		Rule:     ruleName,
	}

	checkInPlace := func(base string, args []string) bool {
		switch base {
		case "sed":
			return hasSedInPlaceFlag(args)
		case "perl":
			for _, a := range args {
				if a == "-i" || a == "-pi" || a == "-ip" {
					return true
				}
				// -i.bak or -pi.bak style (suffix after -i/-pi).
				if len(a) > 2 && a[:2] == "-i" && a[2] != '-' {
					return true
				}
				if len(a) > 3 && a[:3] == "-pi" {
					return true
				}
			}
		}
		return false
	}

	return rule{
		Name: ruleName,
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) < 2 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if checkInPlace(base, fields[1:]) {
				return result, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if checkInPlace(base, args) {
				return result, true
			}
			return ClassifyResult{}, false
		},
	}
}

// containerEscapeRule escalates commands that can manipulate namespaces or
// change the root filesystem: nsenter, chroot, unshare. These are commonly
// used for container escapes and privilege boundary changes.
func containerEscapeRule() rule {
	const ruleName = "container-escape"
	cmds := map[string]bool{
		"nsenter": true, "chroot": true, "unshare": true,
	}
	result := ClassifyResult{
		Decision: Escalated,
		Reason:   "namespace/chroot manipulation requires approval",
		Rule:     ruleName,
	}
	return rule{
		Name: ruleName,
		Match: func(command string) (ClassifyResult, bool) {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				return ClassifyResult{}, false
			}
			base := baseCommand(fields[0])
			if !cmds[base] {
				return ClassifyResult{}, false
			}
			if escalatedHasInfoFlag(fields[1:]) {
				return ClassifyResult{}, false
			}
			return result, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			base := baseCommand(name)
			if !cmds[base] {
				return ClassifyResult{}, false
			}
			if escalatedHasInfoFlag(args) {
				return ClassifyResult{}, false
			}
			return result, true
		},
	}
}

// escalatedHasInfoFlag reports whether args contains --help, -h, or --version.
// Commands invoked with these flags only display usage information and are safe.
// NOTE: -h is included because most CLI tools use it for help. Database client
// rules use a separate check since tools like psql use -h for --host.
func escalatedHasInfoFlag(args []string) bool {
	for _, a := range args {
		switch a {
		case flagHelp, "-h", flagVersion:
			return true
		}
	}
	return false
}
