package testutil

import "strconv"

// EchoCommand returns a shell and argument list that, when executed, prints
// text to stdout. The returned values are intended for use with ExecArgs:
//
//	shell, args := testutil.EchoCommand("hello")
//	result, err := mgr.ExecArgs(ctx, shell, args)
func EchoCommand(text string) (string, []string) {
	return Shell(), ShellArgs("echo " + text)
}

// ExitCommand returns a shell and argument list that, when executed, exits
// with the given status code.
func ExitCommand(code int) (string, []string) {
	return Shell(), ShellArgs("exit " + strconv.Itoa(code))
}

// PrintEnvCommand returns a shell and argument list that, when executed,
// prints the value of the environment variable varName to stdout.
func PrintEnvCommand(varName string) (string, []string) {
	if isWindows() {
		return Shell(), ShellArgs("echo %" + varName + "%")
	}
	return Shell(), ShellArgs("echo $" + varName)
}

// PwdCommand returns a shell and argument list that, when executed, prints
// the current working directory to stdout.
func PwdCommand() (string, []string) {
	if isWindows() {
		return Shell(), ShellArgs("cd")
	}
	return Shell(), ShellArgs("pwd")
}

// StderrCommand returns a shell and argument list that, when executed, writes
// text to stderr.
func StderrCommand(text string) (string, []string) {
	return Shell(), ShellArgs("echo " + text + " >&2")
}

// SleepCommand returns a shell and argument list that, when executed, sleeps
// for the given number of seconds.  The returned command is suitable for
// timeout/cancellation tests.
func SleepCommand(seconds int) (string, []string) {
	s := strconv.Itoa(seconds)
	if isWindows() {
		// "ping -n <N+1> 127.0.0.1 >nul" sleeps ~N seconds on Windows
		// where there is no sleep(1).
		n := strconv.Itoa(seconds + 1)
		return Shell(), ShellArgs("ping -n " + n + " 127.0.0.1 >nul")
	}
	return Shell(), ShellArgs("sleep " + s)
}
