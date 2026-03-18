package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestShell(t *testing.T) {
	got := Shell()
	if runtime.GOOS == "windows" {
		want := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
		if got != want {
			t.Errorf("Shell() = %q on windows, want %q", got, want)
		}
	} else if got != "/bin/sh" {
		t.Errorf("Shell() = %q on unix, want %q", got, "/bin/sh")
	}
}

func TestShellFlag(t *testing.T) {
	got := ShellFlag()
	if runtime.GOOS == "windows" {
		if got != "/c" {
			t.Errorf("ShellFlag() = %q on windows, want %q", got, "/c")
		}
	} else if got != "-c" {
		t.Errorf("ShellFlag() = %q on unix, want %q", got, "-c")
	}
}

func TestShellArgs(t *testing.T) {
	args := ShellArgs("echo hello")
	if len(args) != 2 {
		t.Fatalf("ShellArgs() returned %d elements, want 2", len(args))
	}
	if args[0] != ShellFlag() {
		t.Errorf("ShellArgs()[0] = %q, want %q", args[0], ShellFlag())
	}
	if args[1] != "echo hello" {
		t.Errorf("ShellArgs()[1] = %q, want %q", args[1], "echo hello")
	}
}

func TestShellArgsEmpty(t *testing.T) {
	args := ShellArgs("")
	if len(args) != 2 {
		t.Fatalf("ShellArgs(\"\") returned %d elements, want 2", len(args))
	}
	if args[1] != "" {
		t.Errorf("ShellArgs(\"\")[1] = %q, want empty string", args[1])
	}
}

func TestShellArgsComplex(t *testing.T) {
	cmd := "ls -la /tmp && echo done"
	args := ShellArgs(cmd)
	if args[1] != cmd {
		t.Errorf("ShellArgs(%q)[1] = %q, want original command", cmd, args[1])
	}
}

func TestShellConsistency(t *testing.T) {
	// ShellArgs must use ShellFlag as its first element.
	args := ShellArgs("test")
	if args[0] != ShellFlag() {
		t.Errorf("ShellArgs first element %q != ShellFlag() %q", args[0], ShellFlag())
	}
}
