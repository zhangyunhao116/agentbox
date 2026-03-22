package agentbox

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Allow rules
// ---------------------------------------------------------------------------

func TestClassifierCommonSafeCommands(t *testing.T) {
	c := DefaultClassifier()
	safeCommands := []string{
		"ls", "ls -la", "cat file.txt", "echo hello", "pwd",
		"whoami", "date", "head -n 10 file", "tail -f log",
		"wc -l file", "sort file", "uniq", "grep pattern file",
		"which go", "file test.bin",
		"basename /path/to/file", "dirname /path/to/file",
		"realpath .", "stat file", "du -sh .", "df -h",
		"printenv HOME", "id", "uname -a", "hostname",
		"true", "false",
	}
	for _, cmd := range safeCommands {
		t.Run(cmd, func(t *testing.T) {
			r := c.Classify(cmd)
			if r.Decision != Allow {
				t.Errorf("Classify(%q) = %v, want Allow", cmd, r.Decision)
			}
			if r.Rule != "common-safe-commands" {
				t.Errorf("expected rule common-safe-commands, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierCommonSafeCommandsArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
	}{
		{"ls", "ls", []string{"-la"}},
		{"cat", "cat", []string{"file.txt"}},
		{"echo", "echo", []string{"hello"}},
		{"full path ls", "/bin/ls", []string{"-la"}},
		{"grep", "grep", []string{"-r", "pattern", "."}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.ClassifyArgs(tt.cmd, tt.args)
			if r.Decision != Allow {
				t.Errorf("ClassifyArgs(%q, %v) = %v, want Allow", tt.cmd, tt.args, r.Decision)
			}
		})
	}
}

func TestClassifierGitReadCommands(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"git status", "git status", Allow},
		{"git log", "git log --oneline", Allow},
		{"git diff", "git diff HEAD", Allow},
		{"git show", "git show HEAD", Allow},
		{"git branch", "git branch -a", Allow},
		{"git tag", "git tag", Allow},
		{"git remote -v", "git remote -v", Allow},
		{"git push", "git push origin main", Escalated},
		{"git commit", "git commit -m 'msg'", Sandboxed},
		{"git alone", "git", Sandboxed},
		{"git remote no -v", "git remote add origin url", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v, want %v", tt.cmd, r.Decision, tt.want)
			}
		})
	}
}

func TestClassifierGitReadCommandsArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"git status", "git", []string{"status"}, Allow},
		{"git log", "git", []string{"log", "--oneline"}, Allow},
		{"git diff", "git", []string{"diff"}, Allow},
		{"git remote -v", "git", []string{"remote", "-v"}, Allow},
		{"git push", "git", []string{"push"}, Escalated},
		{"git no args", "git", nil, Sandboxed},
		{"git empty args", "git", []string{}, Sandboxed},
		{"git remote no -v", "git", []string{"remote", "add"}, Sandboxed},
		{"not git", "echo", []string{"status"}, Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.ClassifyArgs(tt.cmd, tt.args)
			if r.Decision != tt.want {
				t.Errorf("ClassifyArgs(%q, %v) = %v, want %v", tt.cmd, tt.args, r.Decision, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// version-check rule tests
// ---------------------------------------------------------------------------

func TestClassifierVersionCheck(t *testing.T) {
	c := DefaultClassifier()

	allow := []struct {
		name string
		cmd  string
	}{
		{"python --version", "python --version"},
		{"node -v", "node -v"},
		{"go version", "go version"},
		{"java -V", "java -V"},
		{"cargo --help", "cargo --help"},
		{"rustc -h", "rustc -h"},
		{"python --version 2>&1", "python --version 2>&1"},
		{"node -v 2>&1", "node -v 2>&1"},
		{"rm --version", "rm --version"},
		{"/usr/bin/python --version", "/usr/bin/python --version"},
	}
	for _, tt := range allow {
		t.Run("allow_"+tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != Allow || r.Rule != "version-check" {
				t.Errorf("Classify(%q) = %v/%s, want Allow/version-check", tt.cmd, r.Decision, r.Rule)
			}
		})
	}

	notMatch := []struct {
		name string
		cmd  string
	}{
		{"too many args", "python --version --quiet extra"},
		{"compound", "python --version && rm -rf /"},
		{"no flag", "python"},
		{"verbose flag real cmd", "tar -xvf archive.tar -v"},
	}
	for _, tt := range notMatch {
		t.Run("not_"+tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Rule == "version-check" {
				t.Errorf("Classify(%q) matched version-check, should not", tt.cmd)
			}
		})
	}
}

func TestClassifierVersionCheckArgs(t *testing.T) {
	c := DefaultClassifier()

	r := c.ClassifyArgs("python", []string{"--version"})
	if r.Decision != Allow || r.Rule != "version-check" {
		t.Errorf("ClassifyArgs(python, --version) = %v/%s, want Allow/version-check", r.Decision, r.Rule)
	}

	r = c.ClassifyArgs("node", []string{"-v"})
	if r.Decision != Allow || r.Rule != "version-check" {
		t.Errorf("ClassifyArgs(node, -v) = %v/%s, want Allow/version-check", r.Decision, r.Rule)
	}

	// Too many args should not match.
	r = c.ClassifyArgs("python", []string{"--version", "--quiet"})
	if r.Rule == "version-check" {
		t.Errorf("ClassifyArgs(python, --version --quiet) matched version-check, should not")
	}
}

// ---------------------------------------------------------------------------
// windows-safe-commands rule tests
// ---------------------------------------------------------------------------

func TestClassifierWindowsSafeCommands(t *testing.T) {
	c := DefaultClassifier()

	allow := []struct {
		name string
		cmd  string
	}{
		{"where", "where python"},
		{"dir", "dir /b"},
		{"type", "type file.txt"},
		{"findstr", "findstr /i hello file.txt"},
		{"ipconfig", "ipconfig /all"},
		{"systeminfo", "systeminfo"},
		{"tasklist", "tasklist"},
		{"Get-Command", "Get-Command node"},
		{"get-command lowercase", "get-command node"},
		{"Get-Process", "Get-Process"},
		{"Get-ChildItem", "Get-ChildItem ."},
		{"Get-Content", "Get-Content file.txt"},
		{"Get-Location", "Get-Location"},
		{"Select-Object", "Select-Object Name"},
		{"Format-List", "Format-List"},
		{"Format-Table", "Format-Table"},
		{"Write-Output", "Write-Output hello"},
		{"Write-Host", "Write-Host hello"},
		{"Test-Path", "Test-Path ./file.txt"},
		{"env var", "$env:PATH"},
		{"env var HOME", "$env:HOME"},
		// Path-qualified Windows command (baseCommand strips the path).
		{"path-qualified where", "/c/Windows/System32/where python"},
	}
	for _, tt := range allow {
		t.Run("allow_"+tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != Allow || r.Rule != "windows-safe-commands" {
				t.Errorf("Classify(%q) = %v/%s, want Allow/windows-safe-commands", tt.cmd, r.Decision, r.Rule)
			}
		})
	}

	notMatch := []struct {
		name string
		cmd  string
	}{
		{"compound", "dir /b && rm -rf /"},
		{"unknown cmd", "Remove-Item file.txt"},
	}
	for _, tt := range notMatch {
		t.Run("not_"+tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Rule == "windows-safe-commands" {
				t.Errorf("Classify(%q) matched windows-safe-commands, should not", tt.cmd)
			}
		})
	}
}

func TestClassifierWindowsSafeCommandsArgs(t *testing.T) {
	c := DefaultClassifier()

	r := c.ClassifyArgs("where", []string{"python"})
	if r.Decision != Allow || r.Rule != "windows-safe-commands" {
		t.Errorf("ClassifyArgs(where, python) = %v/%s, want Allow/windows-safe-commands", r.Decision, r.Rule)
	}

	// Path-qualified Windows command should still match via baseCommand().
	r = c.ClassifyArgs("/usr/bin/where", []string{"python"})
	if r.Decision != Allow || r.Rule != "windows-safe-commands" {
		t.Errorf("ClassifyArgs(/usr/bin/where, python) = %v/%s, want Allow/windows-safe-commands", r.Decision, r.Rule)
	}

	r = c.ClassifyArgs("Get-Process", nil)
	if r.Decision != Allow || r.Rule != "windows-safe-commands" {
		t.Errorf("ClassifyArgs(Get-Process) = %v/%s, want Allow/windows-safe-commands", r.Decision, r.Rule)
	}

	r = c.ClassifyArgs("$env:PATH", nil)
	if r.Decision != Allow || r.Rule != "windows-safe-commands" {
		t.Errorf("ClassifyArgs($env:PATH) = %v/%s, want Allow/windows-safe-commands", r.Decision, r.Rule)
	}
}

// ---------------------------------------------------------------------------
// cd-sleep rule tests
// ---------------------------------------------------------------------------

func TestClassifierCdSleep(t *testing.T) {
	c := DefaultClassifier()

	allow := []struct {
		name string
		cmd  string
	}{
		{"cd dir", "cd /tmp"},
		{"cd home", "cd ~"},
		{"pushd", "pushd /tmp"},
		{"popd", "popd"},
		{"sleep", "sleep 5"},
		{"sleep decimal", "sleep 0.5"},
	}
	for _, tt := range allow {
		t.Run("allow_"+tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != Allow || r.Rule != "cd-sleep" {
				t.Errorf("Classify(%q) = %v/%s, want Allow/cd-sleep", tt.cmd, r.Decision, r.Rule)
			}
		})
	}

	notMatch := []struct {
		name string
		cmd  string
	}{
		{"compound cd", "cd /tmp && rm -rf /"},
	}
	for _, tt := range notMatch {
		t.Run("not_"+tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Rule == "cd-sleep" {
				t.Errorf("Classify(%q) matched cd-sleep, should not", tt.cmd)
			}
		})
	}

	// mkdir is no longer matched by this rule — falls through to Sandboxed.
	mkdirTests := []struct {
		name string
		cmd  string
	}{
		{"mkdir normal", "mkdir -p /tmp/test"},
		{"mkdir relative", "mkdir mydir"},
	}
	for _, tt := range mkdirTests {
		t.Run("sandboxed_"+tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Rule == "cd-sleep" {
				t.Errorf("Classify(%q) matched cd-sleep, mkdir should be Sandboxed", tt.cmd)
			}
		})
	}
}

func TestClassifierCdSleepArgs(t *testing.T) {
	c := DefaultClassifier()

	r := c.ClassifyArgs("cd", []string{"/tmp"})
	if r.Decision != Allow || r.Rule != "cd-sleep" {
		t.Errorf("ClassifyArgs(cd, /tmp) = %v/%s, want Allow/cd-sleep", r.Decision, r.Rule)
	}

	// mkdir is no longer matched — falls through to Sandboxed.
	r = c.ClassifyArgs("mkdir", []string{"-p", "testdir"})
	if r.Rule == "cd-sleep" {
		t.Errorf("ClassifyArgs(mkdir, -p testdir) matched cd-sleep, mkdir should be Sandboxed")
	}

	r = c.ClassifyArgs("sleep", []string{"10"})
	if r.Decision != Allow || r.Rule != "cd-sleep" {
		t.Errorf("ClassifyArgs(sleep, 10) = %v/%s, want Allow/cd-sleep", r.Decision, r.Rule)
	}
}

// ---------------------------------------------------------------------------
// process-list rule tests
// ---------------------------------------------------------------------------

func TestClassifierProcessList(t *testing.T) {
	c := DefaultClassifier()

	allow := []struct {
		name string
		cmd  string
	}{
		{"ps", "ps aux"},
		{"ps simple", "ps"},
		{"top", "top -n 1"},
		{"htop", "htop"},
		{"pgrep", "pgrep -f node"},
	}
	for _, tt := range allow {
		t.Run("allow_"+tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != Allow || r.Rule != "process-list" {
				t.Errorf("Classify(%q) = %v/%s, want Allow/process-list", tt.cmd, r.Decision, r.Rule)
			}
		})
	}

	notMatch := []struct {
		name string
		cmd  string
	}{
		{"compound", "ps aux && kill -9 1234"},
		{"kill", "kill -9 1234"},
	}
	for _, tt := range notMatch {
		t.Run("not_"+tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Rule == "process-list" {
				t.Errorf("Classify(%q) matched process-list, should not", tt.cmd)
			}
		})
	}
}

func TestClassifierProcessListArgs(t *testing.T) {
	c := DefaultClassifier()

	r := c.ClassifyArgs("ps", []string{"aux"})
	if r.Decision != Allow || r.Rule != "process-list" {
		t.Errorf("ClassifyArgs(ps, aux) = %v/%s, want Allow/process-list", r.Decision, r.Rule)
	}

	// lsof is no longer matched — falls through to Sandboxed.
	r = c.ClassifyArgs("lsof", []string{"-i", ":8080"})
	if r.Rule == "process-list" {
		t.Errorf("ClassifyArgs(lsof) matched process-list, lsof should be Sandboxed")
	}

	// Non-matching command.
	r = c.ClassifyArgs("kill", []string{"-9", "1234"})
	if r.Rule == "process-list" {
		t.Errorf("ClassifyArgs(kill) matched process-list, should not")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: compound commands MUST NOT be allowed by new rules
// ---------------------------------------------------------------------------

func TestClassifierNewRulesRejectCompoundCommands(t *testing.T) {
	c := DefaultClassifier()

	// Critical behavioral check: compound commands with safe first segment
	// must NOT be classified as Allow.
	cmds := []struct {
		name string
		cmd  string
	}{
		{"version and rm", "python --version && rm -rf /"},
		{"cd and rm", "cd /tmp && rm -rf /"},
		{"ps and kill", "ps aux && kill -9 1"},
		{"ping and rm", "ping google.com || rm -rf /"},
		{"mkdir semicolon rm", "mkdir test; rm -rf /"},
		{"dir and del", "dir && del /f /q *"},
	}
	for _, tt := range cmds {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision == Allow {
				t.Errorf("Classify(%q) = Allow (rule=%s), want non-Allow", tt.cmd, r.Rule)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// commonSafeCommands expansion: test and [
// ---------------------------------------------------------------------------

func TestClassifierTestBracketSafe(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		// Positive — should be Allow
		{"test -f", "test -f file.txt", Allow},
		{"test -d", "test -d /tmp", Allow},
		{"test -e", "test -e somefile", Allow},
		{"bracket -f", "[ -f file.txt ]", Allow},
		{"bracket -d", "[ -d /tmp ]", Allow},
		{"test bare", "test", Allow},
		// Negative (not triggered differently)
		{"echo still safe", "echo hello", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Allow && r.Rule != "common-safe-commands" && r.Rule != "version-check" {
				t.Errorf("expected rule common-safe-commands, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierTestBracketSafeArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"test -f args", "test", []string{"-f", "file.txt"}, Allow},
		{"test -d args", "test", []string{"-d", "/tmp"}, Allow},
		{"bracket -f args", "[", []string{"-f", "file.txt", "]"}, Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.ClassifyArgs(tt.cmd, tt.args)
			if r.Decision != tt.want {
				t.Errorf("ClassifyArgs(%q, %v) = %v (rule=%s), want %v", tt.cmd, tt.args, r.Decision, r.Rule, tt.want)
			}
		})
	}
}
