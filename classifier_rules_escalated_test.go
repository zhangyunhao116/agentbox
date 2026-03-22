package agentbox

import (
	"strings"
	"testing"
)

func TestClassifierGlobalInstall(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"npm install -g", "npm install -g typescript", Escalated},
		{"npm i -g", "npm i -g typescript", Escalated},
		{"yarn global add", "yarn global add typescript", Escalated},
		{"pip install", "pip install requests", Sandboxed},
		{"pip3 install", "pip3 install requests", Sandboxed},
		{"pip install --user", "pip install --user requests", Sandboxed},
		{"pip install venv", "pip install -r requirements.txt venv", Sandboxed},
		{"npm install local", "npm install typescript", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v, want %v", tt.cmd, r.Decision, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "global-install" {
				t.Errorf("expected rule global-install, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierGlobalInstallArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"npm install -g", "npm", []string{"install", "-g", "typescript"}, Escalated},
		{"npm i --global", "npm", []string{"i", "--global", "typescript"}, Escalated},
		{"yarn global add", "yarn", []string{"global", "add", "typescript"}, Escalated},
		{"pip install", "pip", []string{"install", "requests"}, Sandboxed},
		{"pip3 install", "pip3", []string{"install", "requests"}, Sandboxed},
		{"pip install --user", "pip", []string{"install", "--user", "requests"}, Sandboxed},
		{"npm install local", "npm", []string{"install", "typescript"}, Sandboxed},
		{"not npm", "echo", []string{"install", "-g"}, Allow},
		{"npm no args", "npm", []string{}, Sandboxed},
		{"pip no args", "pip", []string{}, Sandboxed},
		{"yarn not global", "yarn", []string{"add", "typescript"}, Sandboxed},
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

func TestClassifierDockerBuild(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"docker build", "docker build -t myimage .", Escalated},
		{"docker push", "docker push myimage", Escalated},
		{"docker pull", "docker pull ubuntu", Escalated},
		{"docker run", "docker run ubuntu", Escalated},
		{"docker ps", "docker ps", Sandboxed},
		{"docker alone", "docker", Sandboxed},
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

func TestClassifierDockerBuildArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"docker build", "docker", []string{"build", "-t", "myimage", "."}, Escalated},
		{"docker push", "docker", []string{"push", "myimage"}, Escalated},
		{"docker pull", "docker", []string{"pull", "ubuntu"}, Escalated},
		{"docker run", "docker", []string{"run", "ubuntu"}, Escalated},
		{"docker no args", "docker", []string{}, Sandboxed},
		{"not docker", "echo", []string{"build"}, Allow},
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

func TestClassifierSystemPackageInstall(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"brew install", "brew install go", Escalated},
		{"apt install", "apt install curl", Escalated},
		{"apt-get install", "apt-get install curl", Escalated},
		{"yum install", "yum install curl", Escalated},
		{"dnf install", "dnf install curl", Escalated},
		{"brew update", "brew update", Sandboxed},
		{"apt update", "apt update", Sandboxed},
		{"brew alone", "brew", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v, want %v", tt.cmd, r.Decision, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "system-package-install" {
				t.Errorf("expected rule system-package-install, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierSystemPackageInstallArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"brew install", "brew", []string{"install", "go"}, Escalated},
		{"apt install", "apt", []string{"install", "curl"}, Escalated},
		{"apt-get install", "apt-get", []string{"install", "curl"}, Escalated},
		{"yum install", "yum", []string{"install", "curl"}, Escalated},
		{"dnf install", "dnf", []string{"install", "curl"}, Escalated},
		{"brew update", "brew", []string{"update"}, Sandboxed},
		{"brew no args", "brew", []string{}, Sandboxed},
		{"not brew", "echo", []string{"install"}, Allow},
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
func TestClassifierGlobalInstallPipVirtualenv(t *testing.T) {
	c := DefaultClassifier()
	// pip install with virtualenv keyword should not be escalated
	r := c.Classify("pip install -r requirements.txt virtualenv")
	if r.Decision == Escalated {
		t.Error("pip install with virtualenv should not be escalated")
	}
}

func TestClassifierGlobalInstallPip3User(t *testing.T) {
	c := DefaultClassifier()
	r := c.Classify("pip3 install --user requests")
	if r.Decision == Escalated {
		t.Error("pip3 install --user should not be escalated")
	}
}

func TestClassifierGlobalInstallArgsVirtualenv(t *testing.T) {
	c := DefaultClassifier()
	r := c.ClassifyArgs("pip", []string{"install", "virtualenv"})
	if r.Decision == Escalated {
		t.Error("pip install virtualenv should not be escalated")
	}
}

func TestClassifierGlobalInstallArgsYarnNotGlobal(t *testing.T) {
	c := DefaultClassifier()
	r := c.ClassifyArgs("yarn", []string{"add", "typescript"})
	if r.Decision == Escalated {
		t.Error("yarn add (not global) should not be escalated")
	}
}

func TestClassifierGlobalInstallArgsPipNoInstall(t *testing.T) {
	c := DefaultClassifier()
	r := c.ClassifyArgs("pip", []string{"list"})
	if r.Decision == Escalated {
		t.Error("pip list should not be escalated")
	}
}

func TestClassifierGlobalInstallArgsNpmNoArgs(t *testing.T) {
	c := DefaultClassifier()
	r := c.ClassifyArgs("npm", []string{})
	if r.Decision == Escalated {
		t.Error("npm with no args should not be escalated")
	}
}

func TestClassifierGlobalInstallArgsYarnShortArgs(t *testing.T) {
	c := DefaultClassifier()
	r := c.ClassifyArgs("yarn", []string{"global"})
	if r.Decision == Escalated {
		t.Error("yarn global (without add) should not be escalated")
	}
}

// ---------------------------------------------------------------------------
// Fix 3: Classifier bypass vector tests
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// sudo rule tests
// ---------------------------------------------------------------------------

func TestClassifierSudo(t *testing.T) {
	c := DefaultClassifier()

	// Positive cases: should be Escalated.
	escalated := []struct {
		name string
		cmd  string
	}{
		{"sudo simple", "sudo ls"},
		{"sudo rm", "sudo rm -rf /"},
		{"sudo with path", "/usr/bin/sudo ls"},
		{"doas simple", "doas ls"},
		{"doas rm", "doas rm -rf /tmp/foo"},
		{"sudo apt", "sudo apt-get install vim"},
	}
	for _, tt := range escalated {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != Escalated {
				t.Errorf("Classify(%q) = %v, want Escalated", tt.cmd, r.Decision)
			}
			if r.Rule != "sudo" {
				t.Errorf("Classify(%q).Rule = %q, want %q", tt.cmd, r.Rule, "sudo")
			}
		})
	}

	// Negative cases: should NOT match sudo rule.
	noMatch := []string{
		"echo sudo",
		"cat /etc/sudoers",
		"grep sudo /var/log/auth.log",
		"pseudorandom",
	}
	for _, cmd := range noMatch {
		t.Run(cmd, func(t *testing.T) {
			r := c.Classify(cmd)
			if r.Rule == "sudo" {
				t.Errorf("Classify(%q) matched sudo rule, should not", cmd)
			}
		})
	}
}

func TestClassifierSudoArgs(t *testing.T) {
	c := DefaultClassifier()

	r := c.ClassifyArgs("sudo", []string{"ls", "-la"})
	if r.Decision != Escalated || r.Rule != "sudo" {
		t.Errorf("ClassifyArgs(sudo, ls -la) = %v/%s, want Escalated/sudo", r.Decision, r.Rule)
	}

	r = c.ClassifyArgs("doas", []string{"cat", "/etc/passwd"})
	if r.Decision != Escalated || r.Rule != "sudo" {
		t.Errorf("ClassifyArgs(doas, ...) = %v/%s, want Escalated/sudo", r.Decision, r.Rule)
	}

	r = c.ClassifyArgs("/usr/bin/sudo", []string{"ls"})
	if r.Decision != Escalated || r.Rule != "sudo" {
		t.Errorf("ClassifyArgs(/usr/bin/sudo, ...) = %v/%s, want Escalated/sudo", r.Decision, r.Rule)
	}

	// Non-matching.
	r = c.ClassifyArgs("echo", []string{"sudo"})
	if r.Rule == "sudo" {
		t.Errorf("ClassifyArgs(echo, sudo) should not match sudo rule")
	}
}
// ---------------------------------------------------------------------------
// su-privilege rule tests
// ---------------------------------------------------------------------------

func TestClassifierSuPrivilege(t *testing.T) {
	c := DefaultClassifier()

	escalated := []struct {
		name string
		cmd  string
	}{
		{"su bare", "su"},
		{"su dash", "su -"},
		{"su root", "su root"},
		{"su user", "su someuser"},
		{"su path", "/bin/su"},
		{"su login", "su -l root"},
		{"su -c cmd", "su -c ls"},
		{"su user -c cmd", "su root -c whoami"},
	}
	for _, tt := range escalated {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != Escalated {
				t.Errorf("Classify(%q) = %v, want Escalated", tt.cmd, r.Decision)
			}
			if r.Rule != "su-privilege" {
				t.Errorf("Classify(%q).Rule = %q, want %q", tt.cmd, r.Rule, "su-privilege")
			}
		})
	}

	// Negative cases: should NOT match su-privilege (different commands).
	noMatch := []struct {
		name string
		cmd  string
	}{
		{"sudo", "sudo ls"},
		{"sum", "sum file.txt"},
		{"survey", "survey --help"},
		{"echo su", "echo su"},
		{"substring suid", "cat /etc/suid_debug"},
	}
	for _, tt := range noMatch {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Rule == "su-privilege" {
				t.Errorf("Classify(%q) matched su-privilege rule, should not", tt.cmd)
			}
		})
	}
}

func TestClassifierSuPrivilegeArgs(t *testing.T) {
	c := DefaultClassifier()

	r := c.ClassifyArgs("su", nil)
	if r.Decision != Escalated || r.Rule != "su-privilege" {
		t.Errorf("ClassifyArgs(su) = %v/%s, want Escalated/su-privilege", r.Decision, r.Rule)
	}

	r = c.ClassifyArgs("su", []string{"root"})
	if r.Decision != Escalated || r.Rule != "su-privilege" {
		t.Errorf("ClassifyArgs(su, root) = %v/%s, want Escalated/su-privilege", r.Decision, r.Rule)
	}

	r = c.ClassifyArgs("/bin/su", []string{"-"})
	if r.Decision != Escalated || r.Rule != "su-privilege" {
		t.Errorf("ClassifyArgs(/bin/su, -) = %v/%s, want Escalated/su-privilege", r.Decision, r.Rule)
	}

	// "su -c" is also Escalated (no exemption).
	r = c.ClassifyArgs("su", []string{"-c", "whoami"})
	if r.Decision != Escalated || r.Rule != "su-privilege" {
		t.Errorf("ClassifyArgs(su, -c whoami) = %v/%s, want Escalated/su-privilege", r.Decision, r.Rule)
	}

	// Non-matching.
	r = c.ClassifyArgs("sum", []string{"file.txt"})
	if r.Rule == "su-privilege" {
		t.Errorf("ClassifyArgs(sum, file.txt) matched su-privilege, should not")
	}
}

// ---------------------------------------------------------------------------
// version-check rule tests
// ---------------------------------------------------------------------------

func TestClassifierProcessKill(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"kill basic", "kill 1234", Escalated},
		{"kill -9", "kill -9 5678", Escalated},
		{"kill -0", "kill -0 1234", Escalated},
		{"pkill process", "pkill node", Escalated},
		{"killall process", "killall nginx", Escalated},
		{"taskkill windows", "taskkill /F /IM node.exe", Escalated},
		{"Stop-Process powershell", "Stop-Process -Name node", Escalated},
		{"stop-process lowercase", "stop-process -Name node", Escalated},
		{"path-qualified kill", "/bin/kill 1234", Escalated},
		// Negative cases
		{"echo kill", "echo kill", Allow},
		{"grep kill", "grep kill logfile.txt", Allow},
		{"skillshare", "cat skillshare.txt", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "process-kill" {
				t.Errorf("expected rule process-kill, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierProcessKillArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"kill", "kill", []string{"-9", "1234"}, Escalated},
		{"pkill", "pkill", []string{"node"}, Escalated},
		{"killall", "killall", []string{"nginx"}, Escalated},
		{"taskkill", "taskkill", []string{"/F", "/IM", "node.exe"}, Escalated},
		{"Stop-Process", "Stop-Process", []string{"-Name", "node"}, Escalated},
		{"stop-process lowercase", "stop-process", []string{"-Name", "node"}, Escalated},
		// Negative
		{"echo", "echo", []string{"kill"}, Allow},
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

func TestClassifierGitWrite(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		// Remote/destructive ops remain Escalated.
		{"git push", "git push origin main", Escalated},
		{"git pull", "git pull", Escalated},
		{"git clone", "git clone https://example.com/repo.git", Escalated},
		{"git reset", "git reset --hard HEAD~1", Escalated},
		{"git rebase", "git rebase main", Escalated},
		{"git merge", "git merge feature", Escalated},
		{"git fetch", "git fetch origin", Escalated},
		// Git with flags before subcommand
		{"git --no-pager push", "git --no-pager push", Escalated},
		// Local ops now fall through to Sandboxed.
		{"git add", "git add .", Sandboxed},
		{"git commit", "git commit -m 'msg'", Sandboxed},
		{"git checkout", "git checkout -b feature", Sandboxed},
		{"git stash", "git stash", Sandboxed},
		{"git cherry-pick", "git cherry-pick abc123", Sandboxed},
		{"git init", "git init", Sandboxed},
		{"git rm", "git rm file.txt", Sandboxed},
		{"git mv", "git mv old.txt new.txt", Sandboxed},
		{"git restore", "git restore file.txt", Sandboxed},
		{"git switch", "git switch main", Sandboxed},
		{"git revert", "git revert HEAD", Sandboxed},
		{"git -C path commit", "git -C /some/path commit -m 'msg'", Sandboxed},
		// Negative: read-only git operations should not be escalated
		{"git status", "git status", Allow},
		{"git log", "git log --oneline", Allow},
		{"git diff", "git diff HEAD", Allow},
		{"git show", "git show HEAD", Allow},
		{"git branch", "git branch -a", Allow},
		{"git tag", "git tag", Allow},
		// Read-only with global flags — findGitSubcommand skips flags.
		{"git -C path status", "git -C /some/path status", Allow},
		// git alone
		{"git alone", "git", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "git-write" {
				t.Errorf("expected rule git-write, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierGitWriteArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		// Remote/destructive ops remain Escalated.
		{"git push", "git", []string{"push", "origin", "main"}, Escalated},
		{"git -C commit", "git", []string{"-C", "/path", "push"}, Escalated},
		// Local ops now fall through to Sandboxed.
		{"git add", "git", []string{"add", "."}, Sandboxed},
		{"git commit", "git", []string{"commit", "-m", "msg"}, Sandboxed},
		// Negative
		{"git status", "git", []string{"status"}, Allow},
		{"git log", "git", []string{"log", "--oneline"}, Allow},
		{"not git", "echo", []string{"add"}, Allow},
		{"git no args", "git", []string{}, Sandboxed},
		// Read-only with global flags — findGitSubcommand skips flags.
		{"git -C status", "git", []string{"-C", "/path", "status"}, Allow},
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

func TestClassifierSSHCommand(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"ssh basic", "ssh user@host", Escalated},
		{"ssh with port", "ssh -p 22 user@host", Escalated},
		{"ssh path-qualified", "/usr/bin/ssh user@host", Escalated},
		{"ssh with command", "ssh user@host ls -la", Escalated},
		// Negative: related utilities are NOT escalated by this rule
		{"ssh-keygen", "ssh-keygen -t ed25519", Sandboxed},
		{"ssh-agent", "ssh-agent bash", Sandboxed},
		{"ssh-add", "ssh-add ~/.ssh/id_rsa", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "ssh-command" {
				t.Errorf("expected rule ssh-command, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierSSHCommandArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"ssh", "ssh", []string{"user@host"}, Escalated},
		{"ssh with port", "ssh", []string{"-p", "22", "user@host"}, Escalated},
		// Negative
		{"ssh-keygen", "ssh-keygen", []string{"-t", "ed25519"}, Sandboxed},
		{"ssh-add", "ssh-add", []string{"~/.ssh/id_rsa"}, Sandboxed},
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

func TestClassifierFileTransfer(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"scp", "scp file.txt user@host:/path", Escalated},
		{"rsync", "rsync -avz src/ dest/", Escalated},
		{"sftp", "sftp user@host", Escalated},
		{"ftp", "ftp ftp.example.com", Escalated},
		{"scp path-qualified", "/usr/bin/scp file.txt user@host:/tmp", Escalated},
		// Negative
		{"echo scp", "echo scp", Allow},
		{"grep rsync", "grep rsync config.txt", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "file-transfer" {
				t.Errorf("expected rule file-transfer, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierFileTransferArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"scp", "scp", []string{"file.txt", "user@host:/path"}, Escalated},
		{"rsync", "rsync", []string{"-avz", "src/", "dest/"}, Escalated},
		{"sftp", "sftp", []string{"user@host"}, Escalated},
		{"ftp", "ftp", []string{"ftp.example.com"}, Escalated},
		// Negative
		{"echo", "echo", []string{"scp"}, Allow},
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

func TestClassifierDownloadToFile(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"wget basic", "wget https://example.com/file.tar.gz", Escalated},
		{"wget quiet", "wget -q https://example.com/file", Escalated},
		{"curl -o", "curl -o output.txt https://example.com", Escalated},
		{"curl -O", "curl -O https://example.com/file.tar.gz", Escalated},
		{"curl --output", "curl --output file.txt https://example.com", Escalated},
		{"curl -Lo", "curl -Lo file https://example.com/file", Escalated},
		{"curl -sOL", "curl -sOL https://example.com/file", Escalated},
		// Negative: curl without download flags is NOT escalated
		{"curl api", "curl https://api.example.com/data", Sandboxed},
		{"curl -s", "curl -s https://api.example.com/health", Sandboxed},
		{"curl -X POST", "curl -X POST https://api.example.com/data", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "download-to-file" {
				t.Errorf("expected rule download-to-file, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierDownloadToFileArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"wget", "wget", []string{"https://example.com/file"}, Escalated},
		{"curl -o", "curl", []string{"-o", "output.txt", "https://example.com"}, Escalated},
		{"curl -O", "curl", []string{"-O", "https://example.com/file"}, Escalated},
		{"curl --output", "curl", []string{"--output", "file.txt", "https://example.com"}, Escalated},
		{"curl -Lo", "curl", []string{"-Lo", "file", "https://example.com"}, Escalated},
		// Negative
		{"curl plain", "curl", []string{"https://api.example.com/data"}, Sandboxed},
		{"curl -s", "curl", []string{"-s", "https://api.example.com"}, Sandboxed},
		{"not curl", "echo", []string{"-o", "file"}, Allow},
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

func TestClassifierServiceManagement(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"systemctl start", "systemctl start nginx", Escalated},
		{"systemctl status", "systemctl status sshd", Escalated},
		{"service start", "service nginx start", Escalated},
		{"launchctl load", "launchctl load com.example.plist", Escalated},
		{"sc.exe start", "sc.exe start MyService", Escalated},
		{"sc stop", "sc stop MyService", Escalated},
		{"sc query", "sc query MyService", Escalated},
		{"sc create", "sc create MyService binPath=...", Escalated},
		// Negative: sc without service subcommand
		{"sc alone", "sc", Sandboxed},
		{"sc random", "sc foo", Sandboxed},
		// Negative: unrelated commands
		{"echo systemctl", "echo systemctl", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "service-management" {
				t.Errorf("expected rule service-management, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierServiceManagementArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"systemctl", "systemctl", []string{"start", "nginx"}, Escalated},
		{"service", "service", []string{"nginx", "start"}, Escalated},
		{"launchctl", "launchctl", []string{"load", "com.example.plist"}, Escalated},
		{"sc.exe start", "sc.exe", []string{"start", "MyService"}, Escalated},
		{"sc stop", "sc", []string{"stop", "MyService"}, Escalated},
		// Negative
		{"sc no args", "sc", []string{}, Sandboxed},
		{"sc unknown", "sc", []string{"foo"}, Sandboxed},
		{"echo", "echo", []string{"systemctl"}, Allow},
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

func TestClassifierCrontabAt(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"crontab edit", "crontab -e", Escalated},
		{"crontab list", "crontab -l", Escalated},
		{"crontab file", "crontab mycron.txt", Escalated},
		{"at schedule", "at 10:00 PM", Escalated},
		{"atq list", "atq", Escalated},
		{"atrm remove", "atrm 5", Escalated},
		// Negative
		{"echo crontab", "echo crontab", Allow},
		{"cat crontab", "cat /etc/crontab", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "crontab-at" {
				t.Errorf("expected rule crontab-at, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierCrontabAtArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"crontab", "crontab", []string{"-e"}, Escalated},
		{"crontab -l", "crontab", []string{"-l"}, Escalated},
		{"at", "at", []string{"10:00", "PM"}, Escalated},
		{"atq", "atq", []string{}, Escalated},
		{"atrm", "atrm", []string{"5"}, Escalated},
		// Negative
		{"echo", "echo", []string{"crontab"}, Allow},
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
// P3-P4 Rule Tests
// ---------------------------------------------------------------------------

func TestClassifierCredentialAccess(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		// Positive cases — should be Escalated
		{"cat ssh id_rsa", "cat ~/.ssh/id_rsa", Escalated},
		{"head aws credentials", "head ~/.aws/credentials", Escalated},
		{"tail dotenv", "tail .env", Escalated},
		{"less npmrc", "less ~/.npmrc", Escalated},
		{"more pgpass", "more ~/.pgpass", Escalated},
		{"cat private key pem", "cat server.pem", Escalated},
		{"cat private key", "cat server.key", Escalated},
		{"type secret file", "type my_secret_config.txt", Escalated},
		{"cat password file", "cat password_store.txt", Escalated},
		{"cat credential file", "cat credential_cache.json", Escalated},
		{"cat ssh known_hosts", "cat ~/.ssh/known_hosts", Escalated},
		{"cat pypirc", "cat ~/.pypirc", Escalated},
		{"cat netrc", "cat ~/.netrc", Escalated},
		{"cat my.cnf", "cat ~/.my.cnf", Escalated},
		{"cat aws config", "cat ~/.aws/config", Escalated},
		// Negative cases — should NOT trigger
		{"cat readme", "cat README.md", Allow},
		{"echo env var", "echo $SECRET_KEY", Allow},
		{"cat environment", "cat .environment", Allow},
		{"head normal file", "head output.log", Allow},
		{"grep in pem", "grep pattern server.pem", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "credential-access" {
				t.Errorf("expected rule credential-access, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierCredentialAccessArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"cat ssh id_rsa", "cat", []string{"/home/user/.ssh/id_rsa"}, Escalated},
		{"head dotenv", "head", []string{"-n", "10", ".env"}, Escalated},
		{"tail pem", "tail", []string{"cert.pem"}, Escalated},
		{"cat key", "cat", []string{"private.key"}, Escalated},
		// Negative
		{"cat readme", "cat", []string{"README.md"}, Allow},
		{"echo env", "echo", []string{"$SECRET"}, Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.ClassifyArgs(tt.cmd, tt.args)
			if r.Decision != tt.want {
				t.Errorf("ClassifyArgs(%q, %v) = %v (rule=%s), want %v", tt.cmd, tt.args, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "credential-access" {
				t.Errorf("expected rule credential-access, got %q", r.Rule)
			}
		})
	}
}
func TestClassifierUserManagement(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"useradd", "useradd testuser", Escalated},
		{"userdel", "userdel testuser", Escalated},
		{"usermod", "usermod -aG docker testuser", Escalated},
		{"groupadd", "groupadd developers", Escalated},
		{"passwd", "passwd testuser", Escalated},
		{"chpasswd", "chpasswd", Escalated},
		{"adduser", "adduser testuser", Escalated},
		{"deluser", "deluser testuser", Escalated},
		{"addgroup", "addgroup developers", Escalated},
		{"delgroup", "delgroup developers", Escalated},
		{"groupdel", "groupdel developers", Escalated},
		{"groupmod", "groupmod -n newname oldname", Escalated},
		{"path passwd", "/usr/bin/passwd testuser", Escalated},
		// Negative
		{"echo useradd", "echo useradd", Allow},
		{"grep passwd", "grep passwd /etc/nsswitch.conf", Allow},
		{"cat /etc/passwd", "cat /etc/passwd", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "user-management" {
				t.Errorf("expected rule user-management, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierUserManagementArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"useradd", "useradd", []string{"testuser"}, Escalated},
		{"passwd", "passwd", []string{"testuser"}, Escalated},
		{"groupadd", "groupadd", []string{"developers"}, Escalated},
		{"adduser", "adduser", []string{"testuser"}, Escalated},
		// Negative
		{"echo", "echo", []string{"useradd"}, Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.ClassifyArgs(tt.cmd, tt.args)
			if r.Decision != tt.want {
				t.Errorf("ClassifyArgs(%q, %v) = %v (rule=%s), want %v", tt.cmd, tt.args, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "user-management" {
				t.Errorf("expected rule user-management, got %q", r.Rule)
			}
		})
	}
}
func TestClassifierFilePermission(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		// Non-recursive chmod/chown/chgrp → Escalated
		{"chmod file", "chmod 755 myfile.sh", Escalated},
		{"chown file", "chown user:group myfile.sh", Escalated},
		{"chgrp file", "chgrp developers myfile.sh", Escalated},
		{"chmod +x", "chmod +x script.sh", Escalated},
		{"path chmod", "/bin/chmod 644 config.txt", Escalated},
		// Recursive on root → Forbidden (forbidden rules take priority)
		{"chmod -R /", "chmod -R 777 /", Forbidden},
		{"chown -R /", "chown -R root:root /", Forbidden},
		// Negative
		{"echo chmod", "echo chmod", Allow},
		{"grep chown", "grep chown Makefile", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "file-permission" {
				t.Errorf("expected rule file-permission, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierFilePermissionArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"chmod", "chmod", []string{"755", "myfile.sh"}, Escalated},
		{"chown", "chown", []string{"user:group", "myfile.sh"}, Escalated},
		{"chgrp", "chgrp", []string{"developers", "myfile.sh"}, Escalated},
		// Negative
		{"echo", "echo", []string{"chmod"}, Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.ClassifyArgs(tt.cmd, tt.args)
			if r.Decision != tt.want {
				t.Errorf("ClassifyArgs(%q, %v) = %v (rule=%s), want %v", tt.cmd, tt.args, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "file-permission" {
				t.Errorf("expected rule file-permission, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierFirewallManagement(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"iptables list", "iptables -L", Escalated},
		{"iptables add rule", "iptables -A INPUT -p tcp --dport 80 -j ACCEPT", Escalated},
		{"ip6tables", "ip6tables -L", Escalated},
		{"ufw enable", "ufw enable", Escalated},
		{"ufw allow", "ufw allow 22/tcp", Escalated},
		{"nft list", "nft list ruleset", Escalated},
		{"firewall-cmd", "firewall-cmd --list-all", Escalated},
		{"path-qualified iptables", "/sbin/iptables -L", Escalated},
		// Negative cases
		{"nftables is not a CLI", "nftables list", Sandboxed},
		{"ip addr", "ip addr", Sandboxed},
		{"echo iptables", "echo iptables", Allow},
		{"grep ufw", "grep ufw /var/log/syslog", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "firewall-management" {
				t.Errorf("expected rule firewall-management, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierFirewallManagementArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"iptables", "iptables", []string{"-L"}, Escalated},
		{"ip6tables", "ip6tables", []string{"-A", "INPUT"}, Escalated},
		{"ufw", "ufw", []string{"enable"}, Escalated},
		{"nft", "nft", []string{"list", "ruleset"}, Escalated},
		{"firewall-cmd", "firewall-cmd", []string{"--list-all"}, Escalated},
		{"path-qualified", "/usr/sbin/iptables", []string{"-L"}, Escalated},
		// Negative
		{"ip", "ip", []string{"addr"}, Sandboxed},
		{"echo", "echo", []string{"iptables"}, Allow},
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

func TestClassifierNetworkScan(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"nmap scan", "nmap -sS 192.168.1.0/24", Escalated},
		{"nmap basic", "nmap localhost", Escalated},
		{"tcpdump", "tcpdump -i eth0", Escalated},
		{"tshark", "tshark -i eth0", Escalated},
		{"wireshark", "wireshark", Escalated},
		{"ettercap", "ettercap -T -q -i eth0", Escalated},
		{"masscan", "masscan 10.0.0.0/8 -p80", Escalated},
		{"path-qualified nmap", "/usr/bin/nmap -sV 10.0.0.1", Escalated},
		// Negative cases
		{"ping", "ping 8.8.8.8", Sandboxed},
		{"curl", "curl http://example.com", Sandboxed},
		{"echo nmap", "echo nmap", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "network-scan" {
				t.Errorf("expected rule network-scan, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierNetworkScanArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"nmap", "nmap", []string{"-sS", "192.168.1.0/24"}, Escalated},
		{"tcpdump", "tcpdump", []string{"-i", "eth0"}, Escalated},
		{"tshark", "tshark", []string{"-i", "eth0"}, Escalated},
		{"masscan", "masscan", []string{"10.0.0.0/8", "-p80"}, Escalated},
		// Negative
		{"ping", "ping", []string{"8.8.8.8"}, Sandboxed},
		{"echo", "echo", []string{"nmap"}, Allow},
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

func TestClassifierDockerRuntime(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
		rule RuleName
	}{
		// docker subcommands
		{"docker run", "docker run -it ubuntu bash", Escalated, "docker-runtime"},
		{"docker exec", "docker exec -it mycontainer bash", Escalated, "docker-runtime"},
		{"docker stop", "docker stop mycontainer", Escalated, "docker-runtime"},
		{"docker rm", "docker rm mycontainer", Escalated, "docker-runtime"},
		{"docker restart", "docker restart mycontainer", Escalated, "docker-runtime"},
		{"docker kill", "docker kill mycontainer", Escalated, "docker-runtime"},
		{"docker pause", "docker pause mycontainer", Escalated, "docker-runtime"},
		{"docker unpause", "docker unpause mycontainer", Escalated, "docker-runtime"},
		// docker object actions
		{"docker system prune", "docker system prune -a", Escalated, "docker-runtime"},
		{"docker volume rm", "docker volume rm myvol", Escalated, "docker-runtime"},
		{"docker volume prune", "docker volume prune", Escalated, "docker-runtime"},
		{"docker image rm", "docker image rm myimage", Escalated, "docker-runtime"},
		{"docker image prune", "docker image prune", Escalated, "docker-runtime"},
		{"docker container rm", "docker container rm mycontainer", Escalated, "docker-runtime"},
		{"docker container prune", "docker container prune", Escalated, "docker-runtime"},
		// podman
		{"podman run", "podman run -it alpine sh", Escalated, "docker-runtime"},
		{"podman exec", "podman exec -it mycontainer sh", Escalated, "docker-runtime"},
		// docker-compose (hyphenated)
		{"docker-compose up", "docker-compose up -d", Escalated, "docker-runtime"},
		{"docker-compose down", "docker-compose down", Escalated, "docker-runtime"},
		{"docker-compose restart", "docker-compose restart", Escalated, "docker-runtime"},
		{"docker-compose rm", "docker-compose rm", Escalated, "docker-runtime"},
		{"docker-compose stop", "docker-compose stop", Escalated, "docker-runtime"},
		{"docker-compose kill", "docker-compose kill", Escalated, "docker-runtime"},
		// docker compose (two-word)
		{"docker compose up", "docker compose up -d", Escalated, "docker-runtime"},
		{"docker compose down", "docker compose down", Escalated, "docker-runtime"},
		{"docker compose restart", "docker compose restart", Escalated, "docker-runtime"},
		{"docker compose rm", "docker compose rm", Escalated, "docker-runtime"},
		{"docker compose stop", "docker compose stop", Escalated, "docker-runtime"},
		{"docker compose kill", "docker compose kill", Escalated, "docker-runtime"},
		// kubectl
		{"kubectl apply", "kubectl apply -f deploy.yaml", Escalated, "docker-runtime"},
		{"kubectl exec", "kubectl exec -it pod -- bash", Escalated, "docker-runtime"},
		{"kubectl run", "kubectl run nginx --image=nginx", Escalated, "docker-runtime"},
		{"kubectl delete", "kubectl delete pod mypod", Escalated, "docker-runtime"},
		{"kubectl create", "kubectl create namespace test", Escalated, "docker-runtime"},
		{"kubectl edit", "kubectl edit deployment myapp", Escalated, "docker-runtime"},
		{"kubectl patch", "kubectl patch deployment myapp -p '{}'", Escalated, "docker-runtime"},
		{"kubectl scale", "kubectl scale --replicas=3 deployment/myapp", Escalated, "docker-runtime"},
		{"kubectl rollout", "kubectl rollout restart deployment/myapp", Escalated, "docker-runtime"},
		// docker build/push/pull handled by docker-build rule, NOT docker-runtime
		{"docker build", "docker build .", Escalated, "docker-build"},
		{"docker push", "docker push myimage", Escalated, "docker-build"},
		{"docker pull", "docker pull ubuntu", Escalated, "docker-build"},
		// Read-only docker commands — should NOT match docker-runtime
		{"docker ps", "docker ps", Sandboxed, ""},
		{"docker images", "docker images", Sandboxed, ""},
		{"docker version", "docker version", Allow, ""},
		{"docker info", "docker info", Sandboxed, ""},
		{"docker logs", "docker logs mycontainer", Sandboxed, ""},
		{"docker inspect", "docker inspect mycontainer", Sandboxed, ""},
		{"docker alone", "docker", Sandboxed, ""},
		{"kubectl alone", "kubectl", Sandboxed, ""},
		{"kubectl get", "kubectl get pods", Sandboxed, ""},
		{"kubectl describe", "kubectl describe pod mypod", Sandboxed, ""},
		{"kubectl logs", "kubectl logs mypod", Sandboxed, ""},
		{"docker-compose alone", "docker-compose", Sandboxed, ""},
		{"docker-compose ps", "docker-compose ps", Sandboxed, ""},
		{"docker compose ps", "docker compose ps", Sandboxed, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if tt.rule != "" && r.Rule != tt.rule {
				t.Errorf("Classify(%q) rule = %q, want %q", tt.cmd, r.Rule, tt.rule)
			}
		})
	}
}

func TestClassifierDockerRuntimeArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
		rule RuleName
	}{
		{"docker run", "docker", []string{"run", "-it", "ubuntu"}, Escalated, "docker-runtime"},
		{"docker exec", "docker", []string{"exec", "-it", "container", "bash"}, Escalated, "docker-runtime"},
		{"docker stop", "docker", []string{"stop", "container"}, Escalated, "docker-runtime"},
		{"docker rm", "docker", []string{"rm", "container"}, Escalated, "docker-runtime"},
		{"docker system prune", "docker", []string{"system", "prune"}, Escalated, "docker-runtime"},
		{"docker volume rm", "docker", []string{"volume", "rm", "myvol"}, Escalated, "docker-runtime"},
		{"docker compose up", "docker", []string{"compose", "up", "-d"}, Escalated, "docker-runtime"},
		{"docker compose down", "docker", []string{"compose", "down"}, Escalated, "docker-runtime"},
		{"docker-compose up", "docker-compose", []string{"up", "-d"}, Escalated, "docker-runtime"},
		{"podman run", "podman", []string{"run", "alpine"}, Escalated, "docker-runtime"},
		{"kubectl apply", "kubectl", []string{"apply", "-f", "deploy.yaml"}, Escalated, "docker-runtime"},
		{"kubectl delete", "kubectl", []string{"delete", "pod", "mypod"}, Escalated, "docker-runtime"},
		{"kubectl scale", "kubectl", []string{"scale", "--replicas=3", "deployment/myapp"}, Escalated, "docker-runtime"},
		// docker build -> docker-build rule
		{"docker build", "docker", []string{"build", "."}, Escalated, "docker-build"},
		// Negative
		{"docker ps", "docker", []string{"ps"}, Sandboxed, ""},
		{"docker no args", "docker", []string{}, Sandboxed, ""},
		{"kubectl get", "kubectl", []string{"get", "pods"}, Sandboxed, ""},
		{"echo run", "echo", []string{"run"}, Allow, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.ClassifyArgs(tt.cmd, tt.args)
			if r.Decision != tt.want {
				t.Errorf("ClassifyArgs(%q, %v) = %v (rule=%s), want %v", tt.cmd, tt.args, r.Decision, r.Rule, tt.want)
			}
			if tt.rule != "" && r.Rule != tt.rule {
				t.Errorf("ClassifyArgs(%q, %v) rule = %q, want %q", tt.cmd, tt.args, r.Rule, tt.rule)
			}
		})
	}
}

func TestClassifierDatabaseClient(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		{"mysql", "mysql -u root -p dbname", Escalated},
		{"psql", "psql -h localhost mydb", Escalated},
		{"sqlite3", "sqlite3 test.db", Escalated},
		{"redis-cli", "redis-cli FLUSHALL", Escalated},
		{"redis-cli get", "redis-cli GET mykey", Escalated},
		{"mongo", "mongo mydb", Escalated},
		{"mongosh", "mongosh mydb", Escalated},
		{"mongodump", "mongodump --db=mydb", Escalated},
		{"mongoexport", "mongoexport --db=mydb --collection=users", Escalated},
		{"mongoimport", "mongoimport --db=mydb --collection=users", Escalated},
		{"mongorestore", "mongorestore dump/", Escalated},
		{"pg_dump", "pg_dump mydb > backup.sql", Escalated},
		{"pg_restore", "pg_restore backup.dump", Escalated},
		{"mysqldump", "mysqldump mydb > backup.sql", Escalated},
		{"path-qualified mysql", "/usr/bin/mysql -u root mydb", Escalated},
		// Negative cases
		{"echo mysql", "echo mysql", Allow},
		{"grep psql", "grep psql /var/log/syslog", Allow},
		{"cat sqlite", "cat sqlite.txt", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "database-client" {
				t.Errorf("expected rule database-client, got %q", r.Rule)
			}
		})
	}
}

func TestClassifierDatabaseClientArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		{"mysql", "mysql", []string{"-u", "root", "-p", "mydb"}, Escalated},
		{"psql", "psql", []string{"-h", "localhost", "mydb"}, Escalated},
		{"sqlite3", "sqlite3", []string{"test.db"}, Escalated},
		{"redis-cli", "redis-cli", []string{"FLUSHALL"}, Escalated},
		{"mongo", "mongo", []string{"mydb"}, Escalated},
		{"mongosh", "mongosh", []string{}, Escalated},
		{"pg_dump", "pg_dump", []string{"mydb"}, Escalated},
		{"mysqldump", "mysqldump", []string{"mydb"}, Escalated},
		{"path-qualified", "/usr/bin/psql", []string{"mydb"}, Escalated},
		// Negative
		{"echo", "echo", []string{"mysql"}, Allow},
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
// git-stash-drop (Escalated)
// ---------------------------------------------------------------------------

func TestClassifierGitStashDrop(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		// Positive — should be Escalated
		{"git stash drop", "git stash drop", Escalated},
		{"git stash drop with ref", "git stash drop stash@{0}", Escalated},
		{"git stash clear", "git stash clear", Escalated},
		{"git with flag stash drop", "git --no-pager stash drop", Escalated},
		// Negative — should NOT trigger git-stash-drop
		{"git stash", "git stash", Sandboxed},
		{"git stash list", "git stash list", Sandboxed},
		{"git stash show", "git stash show", Sandboxed},
		{"git stash pop", "git stash pop", Sandboxed},
		{"git stash apply", "git stash apply", Sandboxed},
		{"git stash push", "git stash push -m 'wip'", Sandboxed},
		{"git status", "git status", Allow},
		{"git push", "git push origin main", Escalated},
		// Edge: bare git
		{"git alone", "git", Sandboxed},
		{"git stash alone", "git stash", Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			// For Escalated stash commands, verify the rule name.
			if tt.want == Escalated && r.Decision == Escalated && strings.Contains(tt.cmd, "stash") {
				if r.Rule != "git-stash-drop" {
					t.Errorf("expected rule git-stash-drop, got %q", r.Rule)
				}
			}
		})
	}
}

func TestClassifierGitStashDropArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		// Positive — should be Escalated
		{"git stash drop", "git", []string{"stash", "drop"}, Escalated},
		{"git stash drop ref", "git", []string{"stash", "drop", "stash@{1}"}, Escalated},
		{"git stash clear", "git", []string{"stash", "clear"}, Escalated},
		// Negative
		{"git stash", "git", []string{"stash"}, Sandboxed},
		{"git stash list", "git", []string{"stash", "list"}, Sandboxed},
		{"git stash pop", "git", []string{"stash", "pop"}, Sandboxed},
		{"git stash apply", "git", []string{"stash", "apply"}, Sandboxed},
		{"not git", "hg", []string{"stash", "drop"}, Sandboxed},
		{"too few args", "git", []string{"stash"}, Sandboxed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.ClassifyArgs(tt.cmd, tt.args)
			if r.Decision != tt.want {
				t.Errorf("ClassifyArgs(%q, %v) = %v (rule=%s), want %v", tt.cmd, tt.args, r.Decision, r.Rule, tt.want)
			}
			if tt.want == Escalated && r.Decision == Escalated {
				if r.Rule != "git-stash-drop" {
					t.Errorf("expected rule git-stash-drop, got %q", r.Rule)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// eval-exec (Escalated)
// ---------------------------------------------------------------------------

func TestClassifierEvalExec(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		// Positive — should be Escalated
		{"eval simple", `eval "echo hello"`, Escalated},
		{"eval complex", `eval "$(cat script.sh)"`, Escalated},
		{"source script", "source script.sh", Escalated},
		{"source with path", "source /etc/profile", Escalated},
		{"dot command", ". script.sh", Escalated},
		{"dot with path", ". /etc/profile", Escalated},
		{"dot with home", ". ~/.bashrc", Escalated},
		// Negative — should NOT trigger
		{"relative exec", "./script.sh", Sandboxed},
		{"dotslash path", "./build.sh", Sandboxed},
		{"echo eval", "echo eval is a builtin", Allow},
		{"echo source", "echo source", Allow},
		{"dot alone no args", ".", Sandboxed},
		{"eval alone no args", "eval", Sandboxed},
		{"source alone no args", "source", Sandboxed},
		{"ls normal", "ls -la", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if tt.want == Escalated && r.Decision == Escalated {
				if r.Rule != "eval-exec" {
					t.Errorf("expected rule eval-exec, got %q", r.Rule)
				}
			}
		})
	}
}

func TestClassifierEvalExecArgs(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		args []string
		want Decision
	}{
		// Positive
		{"eval args", "eval", []string{"echo", "hello"}, Escalated},
		{"source args", "source", []string{"script.sh"}, Escalated},
		{"dot args", ".", []string{"/etc/profile"}, Escalated},
		// Negative — no args means no code to exec
		{"eval no args", "eval", []string{}, Sandboxed},
		{"source no args", "source", []string{}, Sandboxed},
		{"dot no args", ".", []string{}, Sandboxed},
		{"not eval", "echo", []string{"eval"}, Allow},
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
// credential-access expansion: env/printenv pipe grep
func TestClassifierCredentialAccessEnvGrep(t *testing.T) {
	c := DefaultClassifier()
	tests := []struct {
		name string
		cmd  string
		want Decision
	}{
		// Positive — should be Escalated
		{"env grep secret", "env | grep -i secret", Escalated},
		{"env grep password", "env | grep -i password", Escalated},
		{"env grep key", "env | grep -i key", Escalated},
		{"env grep TOKEN", "env | grep TOKEN", Escalated},
		{"printenv grep secret", "printenv | grep -i secret", Escalated},
		{"printenv grep password", "printenv | grep password", Escalated},
		{"env grep credential", "env | grep credential", Escalated},
		{"env grep api_key", "env | grep api_key", Escalated},
		{"env grep apikey", "env | grep APIKEY", Escalated},
		// Negative — should NOT trigger credential-access
		{"env alone", "env", Sandboxed},
		{"printenv alone", "printenv", Allow},
		{"env grep safe", "env | grep PATH", Sandboxed},
		{"env grep HOME", "env | grep HOME", Sandboxed},
		{"env pipe wc", "env | wc -l", Sandboxed},
		{"cat env file", "cat .env", Escalated}, // file-based credential access
		{"grep key normal", "grep key file.txt", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := c.Classify(tt.cmd)
			if r.Decision != tt.want {
				t.Errorf("Classify(%q) = %v (rule=%s), want %v", tt.cmd, r.Decision, r.Rule, tt.want)
			}
			if r.Decision == Escalated && r.Rule != "credential-access" {
				t.Errorf("expected rule credential-access, got %q", r.Rule)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isCredentialSensitivePath helper tests
// ---------------------------------------------------------------------------

func TestIsCredentialSensitivePath(t *testing.T) {
	tests := []struct {
		arg  string
		want bool
	}{
		{"/home/user/.ssh/id_rsa", true},
		{"/home/user/.ssh/id_ed25519", true},
		{"/home/user/.ssh/known_hosts", true},
		{"/home/user/.aws/credentials", true},
		{"/home/user/.aws/config", true},
		{".env", true},
		{"/app/.env", true},
		{"/home/user/.npmrc", true},
		{"/home/user/.pypirc", true},
		{"/home/user/.netrc", true},
		{"/home/user/.pgpass", true},
		{"/home/user/.my.cnf", true},
		{"server.pem", true},
		{"server.key", true},
		{"my_secret.txt", true},
		{"credential_file.json", true},
		{"password_store", true},
		// Word-boundary positive: token delimited by _, -, or .
		{"my_secret_config.yml", true},
		{"app-secret.json", true},
		// Negative
		{"README.md", false},
		{".environment", false},
		{"config.yaml", false},
		{"output.log", false},
		{"envfile.txt", false},
		// Word-boundary negative: substring is not a standalone token.
		{"secretariat_report.txt", false},
		{"secretary_notes.txt", false},
		{"nosecrets_here.log", false},
	}
	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			got := isCredentialSensitivePath(tt.arg)
			if got != tt.want {
				t.Errorf("isCredentialSensitivePath(%q) = %v, want %v", tt.arg, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// commonSafeCommands expansion: test and [
// ---------------------------------------------------------------------------
