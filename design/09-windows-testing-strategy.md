# Windows Testing Strategy

## Background

Currently, many tests in the agentbox codebase skip execution on Windows with `t.Skip("requires Unix shell")`. This results in poor test coverage on Windows, even though the codebase has significant Windows-specific implementations in `platform/windows/`.

The goal is to enable meaningful test execution on Windows CI runners without compromising the quality or reliability of tests.

## Current State

### Why Tests Skip Windows

1. **Shell dependency**: Tests use `/bin/sh` which doesn't exist on Windows
2. **Unix paths**: Hardcoded paths like `/tmp`, `/bin/sh`, `/etc`
3. **Command syntax**: Unix-specific commands (`exit 42`, `echo $VAR`, `pwd`)
4. **Platform assumptions**: Tests assume Unix-like behavior

### Statistics

- ~57 test functions skip on Windows
- ~85 references to `/bin/sh` in test files
- Primary affected files:
  - `nop_test.go` - NopManager tests
  - `manager_test.go` - Manager tests
  - `manager_exec_test.go` - Execution tests
  - `manager_config_test.go` - Configuration tests
  - `sandbox_test.go` - Integration tests
  - `coverage_gap_test.go` - Coverage tests

## Proposed Solution

### Architecture

Create a platform abstraction layer for tests that automatically adapts to the host OS.

```
testutil/
├── shell.go      # Shell command helpers
├── paths.go      # Path utilities
├── commands.go   # Common test commands
└── cond.go       # Conditional test execution
```

### Implementation Details

#### 1. testutil/shell.go

```go
package testutil

import (
    "os"
    "runtime"
    "strconv"
)

// Shell returns the appropriate shell for the current platform
func Shell() string {
    if runtime.GOOS == "windows" {
        return "cmd.exe"
    }
    return "/bin/sh"
}

// ShellFlag returns the flag to pass commands to the shell
func ShellFlag() string {
    if runtime.GOOS == "windows" {
        return "/c"
    }
    return "-c"
}

// ShellArgs returns the complete arguments to run a command
func ShellArgs(cmd string) []string {
    return []string{ShellFlag(), cmd}
}
```

#### 2. testutil/commands.go

```go
package testutil

// EchoCommand returns a command that echoes text
// Usage: shell, args := testutil.EchoCommand("hello")
func EchoCommand(text string) (string, []string) {
    if runtime.GOOS == "windows" {
        // Windows: cmd.exe /c echo hello
        return "cmd.exe", []string{"/c", "echo " + text}
    }
    // Unix: /bin/sh -c "echo hello"
    return "/bin/sh", []string{"-c", "echo " + text}
}

// ExitCommand returns a command that exits with a specific code
func ExitCommand(code int) (string, []string) {
    if runtime.GOOS == "windows" {
        return "cmd.exe", []string{"/c", "exit " + strconv.Itoa(code)}
    }
    return "/bin/sh", []string{"-c", "exit " + strconv.Itoa(code)}
}

// PrintEnvCommand returns a command that prints an environment variable
func PrintEnvCommand(varName string) (string, []string) {
    if runtime.GOOS == "windows" {
        return "cmd.exe", []string{"/c", "echo %" + varName + "%"}
    }
    return "/bin/sh", []string{"-c", "echo $" + varName}
}

// PwdCommand returns a command that prints the working directory
func PwdCommand() (string, []string) {
    if runtime.GOOS == "windows" {
        return "cmd.exe", []string{"/c", "cd"}
    }
    return "/bin/sh", []string{"-c", "pwd"}
}

// StderrCommand returns a command that writes to stderr
func StderrCommand(text string) (string, []string) {
    if runtime.GOOS == "windows" {
        return "cmd.exe", []string{"/c", "echo " + text + " >&2"}
    }
    return "/bin/sh", []string{"-c", "echo " + text + " >&2"}
}
```

#### 3. testutil/paths.go

```go
package testutil

import (
    "os"
    "path/filepath"
    "runtime"
)

// TempDir returns a platform-appropriate temporary directory
func TempDir() string {
    return os.TempDir()
}

// TempPath returns a temporary file path
func TempPath(name string) string {
    return filepath.Join(TempDir(), name)
}

// HomeDir returns the user's home directory
func HomeDir() string {
    home, _ := os.UserHomeDir()
    if home == "" {
        return TempDir()
    }
    return home
}
```

#### 4. testutil/cond.go

```go
package testutil

import (
    "runtime"
    "testing"
)

// SkipIfWindows skips the test if running on Windows
// Use for tests that truly require Unix-specific features
func SkipIfWindows(t *testing.T, reason string) {
    if runtime.GOOS == "windows" {
        t.Skip("Skipped on Windows: " + reason)
    }
}

// SkipIfNotWindows skips the test if not running on Windows
func SkipIfNotWindows(t *testing.T, reason string) {
    if runtime.GOOS != "windows" {
        t.Skip("Skipped on non-Windows: " + reason)
    }
}

// RequireUnix skips the test if not on Unix-like system
func RequireUnix(t *testing.T) {
    if runtime.GOOS == "windows" {
        t.Skip("Requires Unix-like system")
    }
}
```

### Migration Strategy

#### Phase 1: Create testutil Package

1. Create `testutil/` directory
2. Implement core helper functions
3. Add unit tests for testutil itself

#### Phase 2: Update newTestConfig

Remove the Windows skip from `newTestConfig()`:

```go
// Before
func newTestConfig(t *testing.T) *Config {
    t.Helper()
    if runtime.GOOS == "windows" {
        t.Skip("requires Unix shell (/bin/sh)")
    }
    useStubPlatform(t)
    cfg := DefaultConfig()
    return cfg
}

// After
func newTestConfig(t *testing.T) *Config {
    t.Helper()
    useStubPlatform(t)
    cfg := DefaultConfig()
    return cfg
}
```

#### Phase 3: Migrate Test Files (Priority Order)

1. **nop_test.go** - Core NopManager functionality
2. **manager_test.go** - Manager lifecycle
3. **manager_exec_test.go** - Execution tests
4. **manager_config_test.go** - Configuration tests
5. **sandbox_test.go** - Integration tests
6. **coverage_gap_test.go** - Coverage tests
7. **exec_helper_test.go** - Helper tests
8. **config_test.go** - Config validation
9. **platform/platform_test.go** - Platform abstraction

#### Phase 4: Example Migration Pattern

**Before:**
```go
func TestNopManagerExec(t *testing.T) {
    if runtime.GOOS == "windows" {
        t.Skip("requires Unix shell (/bin/sh)")
    }
    mgr := NewNopManager()
    result, err := mgr.Exec(context.Background(), "echo hello")
    // ...
}
```

**After:**
```go
func TestNopManagerExec(t *testing.T) {
    mgr := NewNopManager()
    shell, args := testutil.EchoCommand("hello")
    result, err := mgr.ExecArgs(context.Background(), shell, args)
    // ...
}
```

### Handling Platform-Specific Tests

Some tests are inherently platform-specific and should remain skipped:

```go
// Tests that verify Unix-specific sandbox features
func TestLinuxNamespace(t *testing.T) {
    testutil.RequireUnix(t)
    // ...
}

// Tests that verify Windows-specific features
func TestWindowsWSL(t *testing.T) {
    testutil.SkipIfNotWindows(t, "WSL detection")
    // ...
}
```

### CI Configuration

Update `.github/workflows/ci.yml`:

```yaml
jobs:
  test:
    strategy:
      matrix:
        os: [macos-latest, ubuntu-latest, windows-latest]
        go: ['1.24']
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ matrix.go }}
      - name: Build
        run: go build ./...
      - name: Vet
        run: go vet ./...
      - name: Test
        run: go test -race -count=1 -coverprofile=coverage.out ./...
```

## Alternative Approaches Considered

### Option 1: Git Bash on Windows

Use Git Bash (included with Git for Windows) to provide `/bin/sh`.

**Pros:**
- Minimal code changes
- True Unix compatibility

**Cons:**
- Doesn't test Windows-native behavior
- Hides Windows-specific issues
- Requires PATH manipulation

**Verdict:** Not recommended - we want to test Windows behavior, not emulate Unix.

### Option 2: Conditional Test Files

Use build tags to separate Unix and Windows tests:

```go
// exec_unix_test.go
//go:build !windows

// exec_windows_test.go
//go:build windows
```

**Pros:**
- Clean separation
- Platform-specific optimizations

**Cons:**
- Code duplication
- Maintenance burden
- Divergent test coverage

**Verdict:** Not recommended - too much duplication.

### Option 3: Abstract Test Interface (Selected)

Use helper functions that adapt to the platform.

**Pros:**
- Single test codebase
- Tests real platform behavior
- Clear intent

**Cons:**
- Requires migration effort
- Some tests may need platform-specific variants

**Verdict:** Recommended - best balance of coverage and maintainability.

## Success Criteria

1. **All tests run on Windows CI** without `t.Skip` for shell reasons
2. **No regression** in Unix test coverage
3. **Windows-specific tests** exist for platform features
4. **CI passes** on all three platforms (macOS, Linux, Windows)

## Timeline

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| 1 | 1 hour | testutil package created |
| 2 | 30 min | newTestConfig updated |
| 3a | 2 hours | Core tests migrated (nop, manager) |
| 3b | 2 hours | Remaining tests migrated |
| 4 | 1 hour | CI updated and verified |
| **Total** | **~6.5 hours** | Full Windows test coverage |

## Future Enhancements

1. **PowerShell support** - Add PowerShell as an alternative to cmd.exe
2. **WSL integration tests** - Test WSL detection and bridging
3. **Cross-platform benchmarks** - Compare performance across platforms

## References

- [GitHub Actions Windows Runners](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners#supported-runners-and-hardware-resources)
- [Go Build Constraints](https://pkg.go.dev/go/build#hdr-Build_Constraints)
- [Windows CMD vs PowerShell](https://docs.microsoft.com/en-us/windows/terminal/)
