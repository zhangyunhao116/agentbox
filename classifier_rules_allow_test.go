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
		{"git branch list", "git branch -a", Allow},
		{"git branch bare", "git branch", Allow},
		{"git branch remote", "git branch -r", Allow},
		{"git branch verbose", "git branch -v", Allow},
		{"git branch show-current", "git branch --show-current", Allow},
		{"git branch --list", "git branch --list", Allow},
		// git branch write operations — NOT allowed (BUG-ALLOW-3).
		{"git branch create", "git branch myBranch", Sandboxed},
		{"git branch delete", "git branch -d myBranch", Sandboxed},
		{"git branch delete force", "git branch -D myBranch", Sandboxed},
		{"git branch delete long", "git branch --delete myBranch", Sandboxed},
		{"git branch rename", "git branch -m oldName newName", Sandboxed},
		{"git tag list", "git tag", Allow},
		{"git tag -l", "git tag -l", Allow},
		{"git tag -l pattern", "git tag -l v1.*", Allow},
		{"git tag --list", "git tag --list", Allow},
		{"git tag -v", "git tag -v v1.0", Allow},
		{"git tag --verify", "git tag --verify v1.0", Allow},
		{"git remote -v", "git remote -v", Allow},
		// Write operations — NOT allowed.
		{"git tag -a", "git tag -a v1.0 -m 'release'", Sandboxed},
		{"git tag -d", "git tag -d v1.0", Sandboxed},
		{"git tag -s", "git tag -s v1.0", Sandboxed},
		{"git tag -f", "git tag -f v1.0", Sandboxed},
		{"git tag create", "git tag v1.0", Sandboxed},
		{"git push", "git push origin main", Escalated},
		{"git commit", "git commit -m 'msg'", Sandboxed},
		{"git alone", "git", Sandboxed},
		{"git remote no -v", "git remote add origin url", Sandboxed},
		// git remote write subcommand rejection: -v does not auto-allow
		// when a write subcommand is present.
		{"git remote add origin -v", "git remote add origin -v https://example.com", Sandboxed},
		{"git remote remove origin", "git remote remove origin", Sandboxed},
		{"git remote set-url origin", "git remote set-url origin https://example.com", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
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
		{"git tag list", "git", []string{"tag"}, Allow},
		{"git tag -l", "git", []string{"tag", "-l"}, Allow},
		{"git tag --list", "git", []string{"tag", "--list"}, Allow},
		{"git tag -v", "git", []string{"tag", "-v", "v1.0"}, Allow},
		{"git tag --verify", "git", []string{"tag", "--verify", "v1.0"}, Allow},
		// Write operations — NOT allowed.
		{"git tag -a", "git", []string{"tag", "-a", "v1.0", "-m", "release"}, Sandboxed},
		{"git tag -d", "git", []string{"tag", "-d", "v1.0"}, Sandboxed},
		{"git tag create", "git", []string{"tag", "v1.0"}, Sandboxed},
		{"git push", "git", []string{"push"}, Escalated},
		{"git no args", "git", nil, Sandboxed},
		{"git empty args", "git", []string{}, Sandboxed},
		{"git remote no -v", "git", []string{"remote", "add"}, Sandboxed},
		// git remote write subcommand rejection: -v does not auto-allow
		// when a write subcommand (add, remove, set-url) is present.
		{"git remote add origin -v", "git", []string{"remote", "add", "origin", "-v", "https://example.com"}, Sandboxed},
		{"git remote remove origin", "git", []string{"remote", "remove", "origin"}, Sandboxed},
		{"git remote set-url origin", "git", []string{"remote", "set-url", "origin", "https://example.com"}, Sandboxed},
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
		// Bare "version" subcommand is tool-specific, not a universal flag.
		// e.g., "sqlite3 version" opens a file named "version", not a version check.
		{"bare version subcommand", "go version"},
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

func TestClassifierWindowsSafeCommandsDangerousPipe(t *testing.T) {
	c := DefaultClassifier()

	// Piped commands with dangerous cmdlets must NOT be allowed.
	notAllow := []struct {
		name string
		cmd  string
	}{
		{"Get-Process pipe Stop-Process", "Get-Process | Stop-Process -Force"},
		{"Get-Process pipe Stop-Process no flag", "Get-Process | Stop-Process"},
		{"Get-ChildItem pipe Remove-Item", "Get-ChildItem | Remove-Item"},
		{"Get-Content pipe Clear-Content", "Get-Content file.txt | Clear-Content"},
		{"Stop-Service bare", "Stop-Service MyService"},
		{"Restart-Service bare", "Restart-Service MyService"},
		{"Set-ExecutionPolicy", "Set-ExecutionPolicy Unrestricted"},
	}
	for _, tt := range notAllow {
		t.Run("not_"+tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Rule == "windows-safe-commands" {
				t.Errorf("Classify(%q) matched windows-safe-commands, should not", tt.cmd)
			}
		})
	}
}

func TestClassifierWindowsSafeCommandsDangerousPipeArgs(t *testing.T) {
	c := DefaultClassifier()

	// MatchArgs: dangerous cmdlet in args must prevent Allow.
	tests := []struct {
		name string
		cmd  string
		args []string
	}{
		{"Get-Process pipe Stop-Process", "Get-Process", []string{"|", "Stop-Process", "-Force"}},
		{"Get-ChildItem pipe Remove-Item", "Get-ChildItem", []string{"|", "Remove-Item"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.ClassifyArgs(tt.cmd, tt.args)
			if r.Rule == "windows-safe-commands" {
				t.Errorf("ClassifyArgs(%q, %v) matched windows-safe-commands, should not", tt.cmd, tt.args)
			}
		})
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

// ---------------------------------------------------------------------------
// New Allow rules
// ---------------------------------------------------------------------------

func TestClassifierDevToolRun(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"python3 script", "python3 script.py", Allow},
		{"node app", "node app.js", Allow},
		{"ruby script", "ruby test.rb", Allow},
		{"perl script", "perl script.pl", Allow},
		{"php script", "php index.php", Allow},
		{"java class", "java Main", Allow},
		{"deno run", "deno run server.ts", Allow},
		{"bun run", "bun run index.ts", Allow},
		{"npx tool", "npx prettier --write .", Allow},
		// npx with -y/--yes — NOT allowed (BUG-ALLOW-1).
		{"npx -y", "npx -y playwright-cli --version", Sandboxed},
		{"npx --yes", "npx --yes some-package", Sandboxed},
		{"npx -y mid arg", "npx some-pkg -y", Sandboxed},
		{"ts-node", "ts-node app.ts", Allow},
		{"uvx tool", "uvx ruff check .", Allow},
		{"full path python3", "/usr/bin/python3 script.py", Allow},
		{"python.exe", "python.exe script.py", Allow},
		{"swift script", "swift script.swift", Allow},
		{"julia script", "julia main.jl", Allow},
		// Negative: compound command should not match Allow.
		{"compound python", "python3 script.py && rm -rf /", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
		})
	}
}

func TestClassifierDevToolRunArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"python3 args", "python3", []string{"script.py"}, Allow},
		{"node args", "node", []string{"app.js"}, Allow},
		{"full path", "/usr/bin/python3", []string{"script.py"}, Allow},
		// npx -y via ClassifyArgs (BUG-ALLOW-1).
		{"npx -y args", "npx", []string{"-y", "some-package"}, Sandboxed},
		{"npx --yes args", "npx", []string{"--yes", "some-package"}, Sandboxed},
		{"npx ok args", "npx", []string{"prettier", "--write", "."}, Allow},
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

func TestClassifierBuildTool(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"make", "make all", Allow},
		{"make bare", "make", Allow},
		// make disallowed targets (BUG-ALLOW-8).
		{"make clean", "make clean", Sandboxed},
		{"make distclean", "make distclean", Sandboxed},
		{"make install", "make install", Sandboxed},
		{"make uninstall", "make uninstall", Sandboxed},
		// make with flags is fine.
		{"make -j8", "make -j8 all", Allow},
		{"cmake", "cmake -B build", Allow},
		{"ninja", "ninja -C build", Allow},
		{"cargo build", "cargo build --release", Allow},
		{"cargo test", "cargo test", Allow},
		{"cargo run", "cargo run", Allow},
		{"rustc", "rustc main.rs", Allow},
		{"mvn package", "mvn package -DskipTests", Allow},
		{"mvn compile", "mvn compile", Allow},
		{"mvn test", "mvn test", Allow},
		{"mvn verify", "mvn verify", Allow},
		{"mvn validate", "mvn validate", Allow},
		{"mvn clean", "mvn clean", Allow},
		{"mvn dependency:tree", "mvn dependency:tree", Allow},
		{"mvn help:effective-pom", "mvn help:effective-pom", Allow},
		{"mvn versions:display", "mvn versions:display-dependency-updates", Allow},
		// mvn disallowed goals (BUG-ALLOW-7).
		{"mvn install", "mvn install", Sandboxed},
		{"mvn deploy", "mvn deploy", Sandboxed},
		{"mvn archetype:generate", "mvn archetype:generate -DgroupId=com.example", Sandboxed},
		{"mvn clean install", "mvn clean install", Sandboxed},
		{"mvn -DskipTests install", "mvn -DskipTests install", Sandboxed},
		{"mvn -P prod deploy", "mvn -P prod deploy", Sandboxed},
		{"gradle build", "gradle build", Allow},
		{"gcc", "gcc -o main main.c", Allow},
		{"clang", "clang++ -std=c++17 main.cpp", Allow},
		{"bazel build", "bazel build //...", Allow},
		{"xcodebuild", "xcodebuild -scheme MyApp", Allow},
		{"dotnet build", "dotnet build", Allow},
		{"dotnet run", "dotnet run", Allow},
		{"dotnet test", "dotnet test", Allow},
		{"dotnet publish", "dotnet publish", Allow},
		{"dotnet restore", "dotnet restore", Allow},
		{"dotnet clean", "dotnet clean", Allow},
		{"dotnet format", "dotnet format", Allow},
		{"dotnet watch", "dotnet watch run", Allow},
		// Package install — NOT allowed (fall through to escalated/sandboxed).
		{"dotnet tool install", "dotnet tool install --global dotnetsay", Sandboxed},
		{"dotnet new install", "dotnet new install MyTemplate", Sandboxed},
		{"dotnet workload install", "dotnet workload install maui", Sandboxed},
		// New dotnet disallowed subcommands (BUG-ALLOW-2).
		{"dotnet new console", "dotnet new console -n Foo", Sandboxed},
		{"dotnet add package", "dotnet add package Foo", Sandboxed},
		{"dotnet nuget push", "dotnet nuget push pkg.nupkg", Sandboxed},
		{"dotnet --install-sdk", "dotnet --install-sdk 8.0", Sandboxed},
		// cargo install is escalated by the package-install rule.
		{"cargo install", "cargo install ripgrep", Escalated},
		// Negative: compound command.
		{"compound make", "make && rm -rf /", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
		})
	}
}

func TestClassifierBuildToolArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		// Allowed build commands.
		{"make args", "make", []string{"all"}, Allow},
		{"make bare args", "make", nil, Allow},
		{"cargo build args", "cargo", []string{"build", "--release"}, Allow},
		{"dotnet build args", "dotnet", []string{"build"}, Allow},
		{"dotnet test args", "dotnet", []string{"test"}, Allow},
		{"mvn test args", "mvn", []string{"test"}, Allow},
		{"mvn compile args", "mvn", []string{"compile"}, Allow},
		// Package install — NOT allowed.
		{"dotnet tool install args", "dotnet", []string{"tool", "install", "--global", "dotnetsay"}, Sandboxed},
		{"dotnet new install args", "dotnet", []string{"new", "install", "MyTemplate"}, Sandboxed},
		// dotnet disallowed subcommands (BUG-ALLOW-2).
		{"dotnet new args", "dotnet", []string{"new", "console", "-n", "Foo"}, Sandboxed},
		{"dotnet add args", "dotnet", []string{"add", "package", "Foo"}, Sandboxed},
		// mvn disallowed (BUG-ALLOW-7).
		{"mvn install args", "mvn", []string{"install"}, Sandboxed},
		{"mvn archetype args", "mvn", []string{"archetype:generate"}, Sandboxed},
		{"mvn clean install args", "mvn", []string{"clean", "install"}, Sandboxed},
		{"mvn -DskipTests install args", "mvn", []string{"-DskipTests", "install"}, Sandboxed},
		// make disallowed (BUG-ALLOW-8).
		{"make clean args", "make", []string{"clean"}, Sandboxed},
		{"make install args", "make", []string{"install"}, Sandboxed},
		// cargo install is escalated by the package-install rule.
		{"cargo install args", "cargo", []string{"install", "ripgrep"}, Escalated},
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

func TestClassifierGoTool(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"go build", "go build ./...", Allow},
		{"go test", "go test -v ./...", Allow},
		{"go vet", "go vet ./...", Allow},
		{"go mod tidy", "go mod tidy", Allow},
		{"gofmt", "gofmt -w .", Allow},
		{"golangci-lint", "golangci-lint run ./...", Allow},
		{"staticcheck", "staticcheck ./...", Allow},
		{"gopls", "gopls version", Allow},
		{"dlv test", "dlv test ./...", Allow},
		{"govulncheck", "govulncheck ./...", Allow},
		// go install is escalated by package-install rule.
		{"go install", "go install golang.org/x/tools/gopls@latest", Escalated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
		})
	}
}

func TestClassifierFileManagement(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"mkdir", "mkdir -p src/pkg", Allow},
		{"cp file", "cp file1.txt file2.txt", Allow},
		{"mv file", "mv old.txt new.txt", Allow},
		{"ln symlink", "ln -s target link", Allow},
		{"touch file", "touch newfile.txt", Allow},
		{"install", "install -m 755 binary /usr/local/bin/", Allow},
		{"full path mkdir", "/bin/mkdir -p dir", Allow},
		// rm is NOT in file-management (too dangerous).
		{"rm file", "rm file.txt", Sandboxed},
		// Compound command.
		{"compound mkdir", "mkdir dir && rm -rf /", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
		})
	}
}

func TestClassifierTextProcessing(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"awk", "awk '{print $1}' file.txt", Allow},
		{"sed substitute", "sed 's/foo/bar/' file.txt", Allow},
		{"jq filter", "jq '.name' data.json", Allow},
		{"cut field", "cut -d, -f1 file.csv", Allow},
		{"tr lower", "tr A-Z a-z", Allow},
		{"diff files", "diff file1.txt file2.txt", Allow},
		{"xxd hex", "xxd file.bin", Allow},
		// sed -i is escalated by in-place-edit rule, NOT allowed here.
		{"sed -i", "sed -i 's/foo/bar/' file.txt", Escalated},
		{"sed -i.bak", "sed -i.bak 's/foo/bar/' file.txt", Escalated},
		// Compound command.
		{"compound sed", "sed 's/foo/bar/' && rm /", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
		})
	}
}

func TestClassifierTextProcessingArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"sed normal args", "sed", []string{"s/foo/bar/", "file.txt"}, Allow},
		{"sed -i args", "sed", []string{"-i", "s/foo/bar/", "file.txt"}, Escalated},
		{"jq args", "jq", []string{".name", "data.json"}, Allow},
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

func TestClassifierNetworkDiagnostic(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"ping", "ping -c 3 8.8.8.8", Allow},
		{"dig", "dig example.com", Allow},
		{"nslookup", "nslookup example.com", Allow},
		{"traceroute", "traceroute example.com", Allow},
		{"host", "host example.com", Allow},
		{"netstat", "netstat -tulpn", Allow},
		{"ss", "ss -tulpn", Allow},
		{"lsof ports", "lsof -i :8080", Allow},
		{"ifconfig", "ifconfig eth0", Allow},
		{"mtr", "mtr example.com", Allow},
		// nc is NOT in network-diagnostic (escalated as network-scan).
		{"nc not allowed", "nc -l 8080", Sandboxed},
		// route: read-only is allowed, write subcommands are not.
		{"route no args", "route", Allow},
		{"route print", "route print", Allow},
		{"route -n", "route -n", Allow},
		{"route add rejected", "route add 10.0.0.0 mask 255.255.224.0 10.0.0.1", Sandboxed},
		{"route delete rejected", "route delete 10.0.0.0", Sandboxed},
		{"route del rejected", "route del 10.0.0.0", Sandboxed},
		{"route change rejected", "route change 10.0.0.0 mask 255.255.224.0 10.0.0.2", Sandboxed},
		{"route flush rejected", "route flush", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
		})
	}
}

func TestClassifierNetworkDiagnosticArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		// route: read-only is allowed, write subcommands are not.
		{"route no args", "route", nil, Allow},
		{"route print", "route", []string{"print"}, Allow},
		{"route -n", "route", []string{"-n"}, Allow},
		{"route add rejected", "route", []string{"add", "10.0.0.0", "mask", "255.255.224.0", "10.0.0.1"}, Sandboxed},
		{"route delete rejected", "route", []string{"delete", "10.0.0.0"}, Sandboxed},
		{"route change rejected", "route", []string{"change", "10.0.0.0"}, Sandboxed},
		{"route flush rejected", "route", []string{"flush"}, Sandboxed},
		// Other network diagnostic commands should be Allow.
		{"ping args", "ping", []string{"-c", "3", "8.8.8.8"}, Allow},
		{"dig args", "dig", []string{"example.com"}, Allow},
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

func TestClassifierArchiveTool(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		// Read-only tar operations — allowed.
		{"tar list", "tar tf archive.tar", Allow},
		{"tar list verbose", "tar tvf archive.tar.gz", Allow},
		{"tar list compressed", "tar -tzf archive.tar.gz", Allow},
		{"tar --list", "tar --list -f archive.tar", Allow},
		// Compression tools — read-only listing/test operations allowed.
		{"gzip list", "gzip -l file.txt.gz", Allow},
		{"gzip test", "gzip -t file.txt.gz", Allow},
		{"xz list", "xz -l file.txt.xz", Allow},
		{"zstd list", "zstd -l file.txt.zst", Allow},
		// Compression tools — write operations NOT allowed (BUG-ALLOW-5).
		{"gzip compress", "gzip file.txt", Sandboxed},
		{"gunzip decompress", "gunzip file.txt.gz", Sandboxed},
		{"xz compress", "xz file.txt", Sandboxed},
		{"zstd compress", "zstd file.txt", Sandboxed},
		// zip — read-only listing allowed, write NOT allowed (BUG-ALLOW-5).
		{"zip list", "zip -l archive.zip", Allow},
		{"zip create", "zip -r archive.zip dir/", Sandboxed},
		// unzip read-only flags — allowed.
		{"unzip list", "unzip -l archive.zip", Allow},
		{"unzip pipe", "unzip -p archive.zip", Allow},
		{"unzip test", "unzip -t archive.zip", Allow},
		// Extraction operations — NOT allowed (fall through to Sandboxed).
		{"tar extract xzf", "tar xzf archive.tar.gz", Sandboxed},
		{"tar extract -xf", "tar -xf archive.tar", Sandboxed},
		{"tar extract --extract", "tar --extract -f archive.tar", Sandboxed},
		{"tar create czf", "tar czf archive.tar.gz dir/", Sandboxed},
		{"tar create -cf", "tar -cf archive.tar dir/", Sandboxed},
		{"tar create --create", "tar --create -f archive.tar dir/", Sandboxed},
		{"unzip bare", "unzip archive.zip", Sandboxed},
		{"unzip overwrite", "unzip -o archive.zip", Sandboxed},
		// 7z — only list/test allowed, extract NOT allowed (BUG-ALLOW-5).
		{"7z extract", "7z x archive.7z", Sandboxed},
		{"7z list", "7z l archive.7z", Allow},
		{"7z test", "7z t archive.7z", Allow},
		// Compound command.
		{"compound tar", "tar xzf a.tgz && rm -rf /", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
		})
	}
}

func TestClassifierArchiveToolArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		// Read-only tar — allowed.
		{"tar list args", "tar", []string{"-tf", "archive.tar"}, Allow},
		{"tar list verbose args", "tar", []string{"-tvf", "archive.tar.gz"}, Allow},
		// Extraction tar — NOT allowed.
		{"tar extract args", "tar", []string{"-xzf", "archive.tar.gz"}, Sandboxed},
		{"tar extract flag", "tar", []string{"-x", "-f", "archive.tar"}, Sandboxed},
		{"tar create args", "tar", []string{"-czf", "out.tar.gz", "dir/"}, Sandboxed},
		// unzip read-only — allowed.
		{"unzip list args", "unzip", []string{"-l", "archive.zip"}, Allow},
		{"unzip pipe args", "unzip", []string{"-p", "archive.zip"}, Allow},
		{"unzip test args", "unzip", []string{"-t", "archive.zip"}, Allow},
		// unzip without read-only flag — NOT allowed.
		{"unzip bare args", "unzip", []string{"archive.zip"}, Sandboxed},
		{"unzip overwrite args", "unzip", []string{"-o", "archive.zip"}, Sandboxed},
		// Other tools — only read-only ops allowed (BUG-ALLOW-5).
		{"gzip list args", "gzip", []string{"-l", "file.txt.gz"}, Allow},
		{"gzip compress args", "gzip", []string{"file.txt"}, Sandboxed},
		{"7z list args", "7z", []string{"l", "archive.7z"}, Allow},
		{"7z extract args", "7z", []string{"x", "archive.7z"}, Sandboxed},
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

func TestClassifierShellBuiltin(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"export", "export PATH=/usr/local/bin:$PATH", Allow},
		{"set -e", "set -e", Allow},
		{"unset", "unset MYVAR", Allow},
		{"printf", "printf '%s\\n' hello", Allow},
		{"tput", "tput cols", Allow},
		{"alias", "alias ll='ls -la'", Allow},
		{"type", "type go", Allow},
		{"ulimit", "ulimit -n", Allow},
		{"umask", "umask 022", Allow},
		{"trap", "trap 'echo done' EXIT", Allow},
		{"wait", "wait", Allow},
		{"jobs", "jobs -l", Allow},
		{"declare", "declare -a arr", Allow},
		// env is NOT in shell-builtin (can be used as command runner).
		{"env not builtin", "env", Sandboxed},
		// nohup is NOT in shell-builtin (escalated as background-process).
		{"nohup not builtin", "nohup ./server", Escalated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
		})
	}
}

func TestClassifierOpenCommand(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"open url", "open https://example.com", Allow},
		{"open file", "open file.pdf", Allow},
		{"xdg-open", "xdg-open https://example.com", Allow},
		{"start url", "start https://example.com", Allow},
		{"wslview", "wslview https://example.com", Allow},
		// Compound command.
		{"compound open", "open url && rm -rf /", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helper function unit tests for bug fix verifications
// ---------------------------------------------------------------------------

func TestIsTarReadOnly(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"empty", nil, true},
		{"list tf", []string{"-tf", "archive.tar"}, true},
		{"list tvf", []string{"-tvf", "archive.tar"}, true},
		{"list tzf", []string{"-tzf", "archive.tar.gz"}, true},
		{"long list", []string{"--list", "-f", "archive.tar"}, true},
		{"list no dash", []string{"tf", "archive.tar"}, true},
		{"list no dash tvf", []string{"tvf", "archive.tar.gz"}, true},
		{"extract xzf", []string{"-xzf", "archive.tar.gz"}, false},
		{"extract -x", []string{"-x", "-f", "archive.tar"}, false},
		{"extract long", []string{"--extract", "-f", "archive.tar"}, false},
		{"extract --get", []string{"--get", "-f", "archive.tar"}, false},
		{"extract no dash xzf", []string{"xzf", "archive.tar.gz"}, false},
		{"create czf", []string{"-czf", "out.tar.gz", "dir/"}, false},
		{"create -c", []string{"-c", "-f", "out.tar"}, false},
		{"create long", []string{"--create", "-f", "out.tar"}, false},
		{"create no dash czf", []string{"czf", "out.tar.gz", "dir/"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTarReadOnly(tt.args)
			if got != tt.want {
				t.Errorf("isTarReadOnly(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestIsUnzipReadOnly(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"empty", nil, false},
		{"bare file", []string{"archive.zip"}, false},
		{"list", []string{"-l", "archive.zip"}, true},
		{"pipe", []string{"-p", "archive.zip"}, true},
		{"test", []string{"-t", "archive.zip"}, true},
		{"overwrite", []string{"-o", "archive.zip"}, false},
		{"dest dir", []string{"-d", "/tmp", "archive.zip"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnzipReadOnly(tt.args)
			if got != tt.want {
				t.Errorf("isUnzipReadOnly(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestIsGitTagReadOnly(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"bare", nil, true},
		{"list -l", []string{"-l"}, true},
		{"list --list", []string{"--list"}, true},
		{"list pattern", []string{"-l", "v1.*"}, true},
		{"verify -v", []string{"-v", "v1.0"}, true},
		{"verify --verify", []string{"--verify", "v1.0"}, true},
		{"create lightweight", []string{"v1.0"}, false},
		{"create annotated", []string{"-a", "v1.0", "-m", "tag"}, false},
		{"delete", []string{"-d", "v1.0"}, false},
		{"sign", []string{"-s", "v1.0"}, false},
		{"force", []string{"-f", "v1.0"}, false},
		{"contradictory list+delete", []string{"-l", "-d", "v1.0"}, false},
		{"contradictory list+annotate", []string{"-l", "-a", "v1.0"}, false},
		{"contradictory verify+force", []string{"-v", "-f", "v1.0"}, false},
		{"contradictory list+sign", []string{"--list", "-s", "v1.0"}, false},
		{"long delete", []string{"--delete", "v1.0"}, false},
		{"long force", []string{"--force", "v1.0"}, false},
		{"long sign", []string{"--sign", "v1.0"}, false},
		{"long annotate", []string{"--annotate", "v1.0", "-m", "msg"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGitTagReadOnly(tt.args)
			if got != tt.want {
				t.Errorf("isGitTagReadOnly(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestBuildToolHasInstall(t *testing.T) {
	tests := []struct {
		name string
		base string
		args []string
		want bool
	}{
		{"dotnet build", "dotnet", []string{"build"}, false},
		{"dotnet test", "dotnet", []string{"test"}, false},
		{"dotnet run", "dotnet", []string{"run"}, false},
		{"dotnet tool install", "dotnet", []string{"tool", "install", "--global", "dotnetsay"}, true},
		{"dotnet new install", "dotnet", []string{"new", "install", "MyTemplate"}, true},
		{"dotnet workload install", "dotnet", []string{"workload", "install", "maui"}, true},
		{"cargo build", "cargo", []string{"build"}, false},
		{"cargo test", "cargo", []string{"test"}, false},
		{"cargo install", "cargo", []string{"install", "ripgrep"}, true},
		// make targets now checked (BUG-ALLOW-8).
		{"make install", "make", []string{"install"}, true},
		{"make clean", "make", []string{"clean"}, true},
		{"make all", "make", []string{"all"}, false},
		// mvn goals now checked (BUG-ALLOW-7).
		{"mvn install", "mvn", []string{"install"}, true},
		{"mvn deploy", "mvn", []string{"deploy"}, true},
		{"mvn test", "mvn", []string{"test"}, false},
		{"mvn compile", "mvn", []string{"compile"}, false},
		{"mvn clean install", "mvn", []string{"clean", "install"}, true},
		{"mvn -DskipTests install", "mvn", []string{"-DskipTests", "install"}, true},
		// dotnet whitelist (BUG-ALLOW-2).
		{"dotnet new", "dotnet", []string{"new", "console"}, true},
		{"dotnet add", "dotnet", []string{"add", "package", "Foo"}, true},
		{"dotnet nuget", "dotnet", []string{"nuget", "push"}, true},
		{"dotnet --install-sdk", "dotnet", []string{"--install-sdk", "8.0"}, true},
		{"dotnet format", "dotnet", []string{"format"}, false},
		{"dotnet watch", "dotnet", []string{"watch", "run"}, false},
		{"dotnet bare", "dotnet", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildToolHasInstall(tt.base, tt.args)
			if got != tt.want {
				t.Errorf("buildToolHasInstall(%q, %v) = %v, want %v", tt.base, tt.args, got, tt.want)
			}
		})
	}
}

func TestHasDangerousPSCmdlet(t *testing.T) {
	tests := []struct {
		name   string
		fields []string
		want   bool
	}{
		{"empty", nil, false},
		{"safe cmdlet only", []string{"Get-Process"}, false},
		{"Stop-Process", []string{"|", "Stop-Process", "-Force"}, true},
		{"Remove-Item", []string{"|", "Remove-Item"}, true},
		{"case insensitive", []string{"|", "stop-process"}, true},
		{"Stop-Service", []string{"Stop-Service", "MyService"}, true},
		{"Restart-Service", []string{"Restart-Service"}, true},
		{"Clear-Content", []string{"Clear-Content", "file.txt"}, true},
		{"Set-ExecutionPolicy", []string{"Set-ExecutionPolicy", "Unrestricted"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasDangerousPSCmdlet(tt.fields)
			if got != tt.want {
				t.Errorf("hasDangerousPSCmdlet(%v) = %v, want %v", tt.fields, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests for helper functions added to fix allow-rule bugs.
// ---------------------------------------------------------------------------

func TestIsGitBranchReadOnly(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		// Read-only (listing) operations.
		{"bare", nil, true},
		{"-a", []string{"-a"}, true},
		{"--all", []string{"--all"}, true},
		{"-r", []string{"-r"}, true},
		{"--remotes", []string{"--remotes"}, true},
		{"-v", []string{"-v"}, true},
		{"-vv", []string{"-vv"}, true},
		{"--verbose", []string{"--verbose"}, true},
		{"-l", []string{"-l"}, true},
		{"--list", []string{"--list"}, true},
		{"--show-current", []string{"--show-current"}, true},
		{"--contains", []string{"--contains", "HEAD"}, true},
		{"--merged", []string{"--merged", "main"}, true},
		{"--sort=refname", []string{"--sort=refname"}, true},
		{"--sort refname", []string{"--sort", "refname"}, true},
		{"-a -v", []string{"-a", "-v"}, true},
		// Write operations.
		{"create branch", []string{"myBranch"}, false},
		{"-d delete", []string{"-d", "myBranch"}, false},
		{"-D force delete", []string{"-D", "myBranch"}, false},
		{"--delete", []string{"--delete", "myBranch"}, false},
		{"-m rename", []string{"-m", "old", "new"}, false},
		{"-M force rename", []string{"-M", "old", "new"}, false},
		{"-c copy", []string{"-c", "old", "new"}, false},
		{"--set-upstream-to", []string{"--set-upstream-to", "origin/main"}, false},
		{"--edit-description", []string{"--edit-description"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGitBranchReadOnly(tt.args)
			if got != tt.want {
				t.Errorf("isGitBranchReadOnly(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestIsMvnDisallowed(t *testing.T) {
	tests := []struct {
		name string
		sub  string
		want bool
	}{
		// Allowed goals.
		{"compile", "compile", false},
		{"test", "test", false},
		{"verify", "verify", false},
		{"package", "package", false},
		{"validate", "validate", false},
		{"clean", "clean", false},
		{"dependency:tree", "dependency:tree", false},
		{"help:effective-pom", "help:effective-pom", false},
		{"versions:display", "versions:display-dependency-updates", false},
		{"flag -DskipTests", "-DskipTests", false},
		// Disallowed goals.
		{"install", "install", true},
		{"deploy", "deploy", true},
		{"archetype:generate", "archetype:generate", true},
		{"site", "site", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMvnDisallowed(tt.sub)
			if got != tt.want {
				t.Errorf("isMvnDisallowed(%q) = %v, want %v", tt.sub, got, tt.want)
			}
		})
	}
}

func TestIsMakeDisallowed(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"bare", nil, false},
		{"all", []string{"all"}, false},
		{"build", []string{"build"}, false},
		{"-j8", []string{"-j8"}, false},
		{"-j8 all", []string{"-j8", "all"}, false},
		{"CC=gcc", []string{"CC=gcc"}, false},
		{"clean", []string{"clean"}, true},
		{"distclean", []string{"distclean"}, true},
		{"install", []string{"install"}, true},
		{"uninstall", []string{"uninstall"}, true},
		{"-j8 clean", []string{"-j8", "clean"}, true},
		{"all clean", []string{"all", "clean"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMakeDisallowed(tt.args)
			if got != tt.want {
				t.Errorf("isMakeDisallowed(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestDevToolRunHasInstallPattern_NpxYes(t *testing.T) {
	tests := []struct {
		name string
		base string
		args []string
		want bool
	}{
		// npx -y → should be rejected (BUG-ALLOW-1).
		{"npx -y", "npx", []string{"-y", "playwright-cli"}, true},
		{"npx --yes", "npx", []string{"--yes", "some-package"}, true},
		{"npx -y at end", "npx", []string{"some-pkg", "-y"}, true},
		// npx without -y → should be allowed.
		{"npx no y", "npx", []string{"prettier", "--write", "."}, false},
		{"npx version", "npx", []string{"playwright", "--version"}, false},
		// uvx does not check for -y.
		{"uvx -y", "uvx", []string{"-y", "pkg"}, false},
		// Other commands not affected.
		{"node -y", "node", []string{"-y", "app.js"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := devToolRunHasInstallPattern(tt.base, tt.args)
			if got != tt.want {
				t.Errorf("devToolRunHasInstallPattern(%q, %v) = %v, want %v", tt.base, tt.args, got, tt.want)
			}
		})
	}
}

func TestIsArchiveReadOnly_ExtendedTools(t *testing.T) {
	tests := []struct {
		name string
		base string
		args []string
		want bool
	}{
		// zip — only -l (list) or -sf (show files) allowed.
		{"zip list", "zip", []string{"-l", "archive.zip"}, true},
		{"zip -sf", "zip", []string{"-sf", "archive.zip"}, true},
		{"zip create", "zip", []string{"-r", "archive.zip", "dir/"}, false},
		{"zip bare", "zip", nil, false},
		// zipinfo — always read-only.
		{"zipinfo", "zipinfo", []string{"archive.zip"}, true},
		// 7z — only "l" (list) and "t" (test) allowed.
		{"7z list", "7z", []string{"l", "archive.7z"}, true},
		{"7z test", "7z", []string{"t", "archive.7z"}, true},
		{"7z extract", "7z", []string{"x", "archive.7z"}, false},
		{"7z add", "7z", []string{"a", "archive.7z", "file"}, false},
		{"7za list", "7za", []string{"l", "archive.7z"}, true},
		// gzip — only -l (list) and -t (test) allowed.
		{"gzip list", "gzip", []string{"-l", "file.gz"}, true},
		{"gzip test", "gzip", []string{"-t", "file.gz"}, true},
		{"gzip --list", "gzip", []string{"--list", "file.gz"}, true},
		{"gzip --test", "gzip", []string{"--test", "file.gz"}, true},
		{"gzip compress", "gzip", []string{"file.txt"}, false},
		{"gunzip", "gunzip", []string{"file.gz"}, false},
		// bzip2.
		{"bzip2 test", "bzip2", []string{"-t", "file.bz2"}, true},
		{"bzip2 compress", "bzip2", []string{"file.txt"}, false},
		{"bunzip2", "bunzip2", []string{"file.bz2"}, false},
		// xz.
		{"xz list", "xz", []string{"-l", "file.xz"}, true},
		{"xz test", "xz", []string{"-t", "file.xz"}, true},
		{"xz compress", "xz", []string{"file.txt"}, false},
		{"unxz", "unxz", []string{"file.xz"}, false},
		// zstd.
		{"zstd list", "zstd", []string{"-l", "file.zst"}, true},
		{"zstd test", "zstd", []string{"-t", "file.zst"}, true},
		{"zstd compress", "zstd", []string{"file.txt"}, false},
		{"unzstd", "unzstd", []string{"file.zst"}, false},
		// rar.
		{"rar list", "rar", []string{"l", "archive.rar"}, true},
		{"rar test", "rar", []string{"t", "archive.rar"}, true},
		{"rar add", "rar", []string{"a", "archive.rar", "file"}, false},
		// unrar.
		{"unrar list", "unrar", []string{"l", "archive.rar"}, true},
		{"unrar test", "unrar", []string{"t", "archive.rar"}, true},
		{"unrar extract", "unrar", []string{"x", "archive.rar"}, false},
		// Unknown tool.
		{"unknown", "lz4", []string{"file"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isArchiveReadOnly(tt.base, tt.args)
			if got != tt.want {
				t.Errorf("isArchiveReadOnly(%q, %v) = %v, want %v", tt.base, tt.args, got, tt.want)
			}
		})
	}
}
