package agentbox

// RuleName is a typed identifier for a built-in classification rule.
// Use the exported constants (e.g., RuleForkBomb, RuleSudo) for type safety
// and IDE autocomplete when working with [WithRuleOverrides].
type RuleName string

const (
	// Forbidden rules — commands that must not be executed.

	RuleForkBomb             RuleName = "fork-bomb"
	RuleRecursiveDeleteRoot  RuleName = "recursive-delete-root"
	RuleDiskWipe             RuleName = "disk-wipe"
	RuleReverseShell         RuleName = "reverse-shell"
	RuleRecursivePermRoot    RuleName = "recursive-perm-root"
	RuleFilesystemFormat     RuleName = "filesystem-format"
	RulePipeToShell          RuleName = "pipe-to-shell"
	RuleIFSBypass            RuleName = "ifs-bypass"
	RuleShutdownReboot       RuleName = "shutdown-reboot"
	RuleKernelModule         RuleName = "kernel-module"
	RulePartitionManagement  RuleName = "partition-management"
	RuleHistoryExec          RuleName = "history-exec"
	RuleDestructiveFind      RuleName = "destructive-find"
	RuleDestructiveXargs     RuleName = "destructive-xargs"
	RuleOutputRedirectSystem RuleName = "output-redirect-system"
	RuleShellWrapperUnwrap   RuleName = "shell-wrapper-unwrap"
	RuleWindowsRecursiveDel  RuleName = "windows-recursive-delete"
	RuleWindowsDelRecursive  RuleName = "windows-del-recursive"
	RuleWindowsFormat        RuleName = "windows-format"
	RulePowershellDestructive RuleName = "powershell-destructive"

	// Escalated rules — commands requiring user approval.

	RuleSudo                 RuleName = "sudo"
	RuleSUPrivilege          RuleName = "su-privilege"
	RuleCredentialAccess     RuleName = "credential-access" //nolint:gosec // G101: rule name, not a credential
	RuleUserManagement       RuleName = "user-management"
	RuleGlobalInstall        RuleName = "global-install"
	RuleDockerBuild          RuleName = "docker-build"
	RuleSystemPackageInstall RuleName = "system-package-install"
	RuleProcessKill          RuleName = "process-kill"
	RuleGitWrite             RuleName = "git-write"
	RuleSSHCommand           RuleName = "ssh-command"
	RuleFileTransfer         RuleName = "file-transfer"
	RuleDownloadToFile       RuleName = "download-to-file"
	RuleServiceManagement    RuleName = "service-management"
	RuleCrontabAt            RuleName = "crontab-at"
	RuleFilePermission       RuleName = "file-permission"
	RuleFirewallManagement   RuleName = "firewall-management"
	RuleNetworkScan          RuleName = "network-scan"
	RuleDockerContainer      RuleName = "docker-container"
	RuleDockerCompose        RuleName = "docker-compose"
	RuleKubernetes           RuleName = "kubernetes"
	RuleDatabaseClient       RuleName = "database-client"
	RuleDatabaseBackup       RuleName = "database-backup"
	RuleGitStashDrop         RuleName = "git-stash-drop"
	RuleEvalExec             RuleName = "eval-exec"
	RulePackageInstall       RuleName = "package-install"
	RuleBackgroundProcess    RuleName = "background-process"
	RuleInPlaceEdit          RuleName = "in-place-edit"
	RuleContainerEscape      RuleName = "container-escape"

	// Allow rules — commands safe for automatic execution.

	RuleCommonSafeCommands  RuleName = "common-safe-commands"
	RuleGitReadCommands     RuleName = "git-read-commands"
	RuleVersionCheck        RuleName = "version-check"
	RuleWindowsSafeCommands RuleName = "windows-safe-commands"
	RuleCDSleep             RuleName = "cd-sleep"
	RuleProcessList         RuleName = "process-list"
	RuleDevToolRun          RuleName = "dev-tool-run"
	RuleBuildTool           RuleName = "build-tool"
	RuleGoTool              RuleName = "go-tool"
	RuleFileManagement      RuleName = "file-management"
	RuleTextProcessing      RuleName = "text-processing"
	RuleNetworkDiagnostic   RuleName = "network-diagnostic"
	RuleArchiveTool         RuleName = "archive-tool"
	RuleShellBuiltin        RuleName = "shell-builtin"
	RuleOpenCommand         RuleName = "open-command"
)

// BuiltinRuleNames returns all built-in rule names in evaluation order
// (forbidden, then escalated, then allow).
func BuiltinRuleNames() []RuleName {
	return []RuleName{
		// Forbidden
		RuleForkBomb,
		RuleRecursiveDeleteRoot,
		RuleDiskWipe,
		RuleReverseShell,
		RuleRecursivePermRoot,
		RuleFilesystemFormat,
		RulePipeToShell,
		RuleIFSBypass,
		RuleShutdownReboot,
		RuleKernelModule,
		RulePartitionManagement,
		RuleHistoryExec,
		RuleDestructiveFind,
		RuleDestructiveXargs,
		RuleOutputRedirectSystem,
		RuleShellWrapperUnwrap,
		RuleWindowsRecursiveDel,
		RuleWindowsDelRecursive,
		RuleWindowsFormat,
		RulePowershellDestructive,

		// Escalated
		RuleSudo,
		RuleSUPrivilege,
		RuleCredentialAccess,
		RuleUserManagement,
		RuleGlobalInstall,
		RuleDockerBuild,
		RuleDockerContainer,
		RuleDockerCompose,
		RuleKubernetes,
		RuleSystemPackageInstall,
		RuleProcessKill,
		RuleGitWrite,
		RuleSSHCommand,
		RuleFileTransfer,
		RuleDownloadToFile,
		RuleServiceManagement,
		RuleCrontabAt,
		RuleFilePermission,
		RuleFirewallManagement,
		RuleNetworkScan,
		RuleDatabaseBackup,
		RuleDatabaseClient,
		RuleGitStashDrop,
		RuleEvalExec,
		RulePackageInstall,
		RuleBackgroundProcess,
		RuleInPlaceEdit,
		RuleContainerEscape,

		// Allow
		RuleCommonSafeCommands,
		RuleGitReadCommands,
		RuleVersionCheck,
		RuleWindowsSafeCommands,
		RuleCDSleep,
		RuleProcessList,
		RuleDevToolRun,
		RuleBuildTool,
		RuleGoTool,
		RuleFileManagement,
		RuleTextProcessing,
		RuleNetworkDiagnostic,
		RuleArchiveTool,
		RuleShellBuiltin,
		RuleOpenCommand,
	}
}
