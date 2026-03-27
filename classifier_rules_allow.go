// classifier_rules_allow.go contains all Allow-category rule functions and
// their supporting data. Allow rules auto-approve commands that are known to
// be safe read-only operations.

package agentbox

import "strings"

// commonSafeCommands is the set of commands considered safe for Allow.
var commonSafeCommands = map[string]bool{
	"ls": true, "cat": true, "echo": true, "pwd": true,
	"whoami": true, "date": true, "head": true, "tail": true,
	"wc": true, "sort": true, "uniq": true, "grep": true,
	"which": true, "file": true, "basename": true,
	"dirname": true, "realpath": true, "stat": true, "du": true,
	"df": true, "printenv": true, "id": true,
	"uname": true, "hostname": true, "true": true, "false": true,
	"test": true, "[": true,
}

// gitReadSubcommands lists git subcommands that are read-only.
var gitReadSubcommands = map[string]bool{
	"status": true, "log": true, "diff": true, "show": true,
	"branch": true, "tag": true,
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
			if commonSafeCommands[cmd] {
				return result, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if commonSafeCommands[cmd] {
				return result, true
			}
			return ClassifyResult{}, false
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
			if gitReadSubcommands[sub] {
				return result, true
			}
			// git remote -v (read-only variant of git remote).
			if sub == "remote" && containsFlag(fields[1:], "-v") {
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
			if gitReadSubcommands[sub] {
				return result, true
			}
			if sub == "remote" && containsFlag(args, "-v") {
				return result, true
			}
			return ClassifyResult{}, false
		},
	}
}

// versionHelpFlags is the set of flags that indicate a version/help check.
var versionHelpFlags = map[string]bool{
	flagVersion: true, "-v": true, "-V": true,
	flagHelp: true, "-h": true,
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
			if versionHelpFlags[fields[1]] {
				return result, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			if len(args) != 1 {
				return ClassifyResult{}, false
			}
			if versionHelpFlags[args[0]] {
				return result, true
			}
			return ClassifyResult{}, false
		},
	}
}

// windowsSafeCmds is the set of Windows/cmd.exe safe read-only commands.
var windowsSafeCmds = map[string]bool{
	"where": true, "dir": true, "type": true, "findstr": true,
	"ipconfig": true, "systeminfo": true, "tasklist": true,
}

// psCmdletsSafe is the set of PowerShell cmdlets considered safe (lowercase).
var psCmdletsSafe = map[string]bool{
	"get-command": true, "get-process": true, "get-childitem": true,
	"get-content": true, "get-location": true,
	"select-object": true, "format-list": true, "format-table": true,
	"write-output": true, "write-host": true, "test-path": true,
}

// windowsSafeCommandsRule matches Windows/PowerShell safe read-only commands.
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
			cmd := baseCommand(fields[0])
			if windowsSafeCmds[cmd] {
				return result, true
			}
			// PowerShell cmdlets (case-insensitive).
			if psCmdletsSafe[strings.ToLower(cmd)] {
				return result, true
			}
			// $env: variable reads (e.g. "$env:PATH").
			if strings.HasPrefix(cmd, "$env:") {
				return result, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if windowsSafeCmds[cmd] {
				return result, true
			}
			if psCmdletsSafe[strings.ToLower(cmd)] {
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
var cdSleepCmds = map[string]bool{
	"cd": true, "pushd": true, "popd": true,
	"sleep": true,
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
			if !cdSleepCmds[cmd] {
				return ClassifyResult{}, false
			}
			return result, true
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if !cdSleepCmds[cmd] {
				return ClassifyResult{}, false
			}
			return result, true
		},
	}
}

// processListCmds is the set of read-only process inspection commands.
var processListCmds = map[string]bool{
	"ps": true, "top": true, "htop": true, "pgrep": true,
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
			if processListCmds[cmd] {
				return result, true
			}
			return ClassifyResult{}, false
		},
		MatchArgs: func(name string, args []string) (ClassifyResult, bool) {
			cmd := baseCommand(name)
			if processListCmds[cmd] {
				return result, true
			}
			return ClassifyResult{}, false
		},
	}
}
