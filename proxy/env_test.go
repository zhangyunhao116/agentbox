package proxy

import (
	"runtime"
	"strings"
	"testing"
)

func TestGenerateProxyEnv_BothPorts(t *testing.T) {
	cfg := &EnvConfig{
		HTTPProxyPort:  8080,
		SOCKSProxyPort: 1080,
	}
	env := GenerateProxyEnv(cfg)

	expected := map[string]string{
		"SANDBOX_RUNTIME": "1",
		"NO_PROXY":        noProxyValue,
		"no_proxy":        noProxyValue,
		"HTTP_PROXY":      "http://127.0.0.1:8080",
		"http_proxy":      "http://127.0.0.1:8080",
		"HTTPS_PROXY":     "http://127.0.0.1:8080",
		"https_proxy":     "http://127.0.0.1:8080",
		"FTP_PROXY":       "http://127.0.0.1:8080",
		"ftp_proxy":       "http://127.0.0.1:8080",
		"ALL_PROXY":       "socks5h://127.0.0.1:1080",
		"all_proxy":       "socks5h://127.0.0.1:1080",
	}

	envMap := envSliceToMap(env)

	for key, wantVal := range expected {
		gotVal, ok := envMap[key]
		if !ok {
			t.Errorf("missing env var %s", key)
			continue
		}
		if gotVal != wantVal {
			t.Errorf("env var %s = %q, want %q", key, gotVal, wantVal)
		}
	}

	// GIT_SSH_COMMAND should be present.
	gitSSH, ok := envMap["GIT_SSH_COMMAND"]
	if !ok {
		t.Fatal("missing GIT_SSH_COMMAND")
	}

	if !strings.Contains(gitSSH, "1080") {
		t.Errorf("GIT_SSH_COMMAND should contain SOCKS port 1080, got %q", gitSSH)
	}
	// Platform-specific check.
	if runtime.GOOS == platformDarwin {
		if !strings.Contains(gitSSH, "nc -X 5") {
			t.Errorf("on darwin, GIT_SSH_COMMAND should use nc, got %q", gitSSH)
		}
	} else {
		if !strings.Contains(gitSSH, "ncat") {
			t.Errorf("on linux, GIT_SSH_COMMAND should use ncat, got %q", gitSSH)
		}
	}
}

func TestGenerateProxyEnv_WithTmpDir(t *testing.T) {
	cfg := &EnvConfig{
		HTTPProxyPort:  8080,
		SOCKSProxyPort: 1080,
		TmpDir:         "/sandbox/tmp",
	}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	tmpDir, ok := envMap["TMPDIR"]
	if !ok {
		t.Error("missing TMPDIR")
	} else if tmpDir != "/sandbox/tmp" {
		t.Errorf("TMPDIR = %q, want %q", tmpDir, "/sandbox/tmp")
	}
}

func TestGenerateProxyEnv_NoTmpDir(t *testing.T) {
	cfg := &EnvConfig{
		HTTPProxyPort: 8080,
	}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	if _, ok := envMap["TMPDIR"]; ok {
		t.Error("TMPDIR should not be set when TmpDir is empty")
	}
}

func TestGenerateProxyEnv_NilConfig(t *testing.T) {
	env := GenerateProxyEnv(nil)
	if env != nil {
		t.Errorf("expected nil for nil config, got %v", env)
	}
}

func TestGenerateProxyEnv_ZeroPorts(t *testing.T) {
	cfg := &EnvConfig{}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	// Should still have SANDBOX_RUNTIME and NO_PROXY.
	if _, ok := envMap["SANDBOX_RUNTIME"]; !ok {
		t.Error("missing SANDBOX_RUNTIME")
	}
	if _, ok := envMap["NO_PROXY"]; !ok {
		t.Error("missing NO_PROXY")
	}

	// Should NOT have HTTP_PROXY, ALL_PROXY, or GIT_SSH_COMMAND.
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "FTP_PROXY", "ftp_proxy", "ALL_PROXY", "all_proxy", "GIT_SSH_COMMAND"} {
		if _, ok := envMap[key]; ok {
			t.Errorf("unexpected env var %s with zero ports", key)
		}
	}
}

func TestGenerateProxyEnv_HTTPOnlyPort(t *testing.T) {
	cfg := &EnvConfig{
		HTTPProxyPort: 3128,
	}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	// HTTP proxy vars should be set.
	if v, ok := envMap["HTTP_PROXY"]; !ok || v != "http://127.0.0.1:3128" {
		t.Errorf("HTTP_PROXY = %q, want %q", v, "http://127.0.0.1:3128")
	}

	// SOCKS and GIT_SSH_COMMAND should NOT be set.
	if _, ok := envMap["ALL_PROXY"]; ok {
		t.Error("ALL_PROXY should not be set without SOCKS port")
	}
	if _, ok := envMap["GIT_SSH_COMMAND"]; ok {
		t.Error("GIT_SSH_COMMAND should not be set without SOCKS port")
	}
}

func TestGenerateProxyEnv_SOCKSOnlyPort(t *testing.T) {
	cfg := &EnvConfig{
		SOCKSProxyPort: 1080,
	}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	// SOCKS vars should be set.
	if v, ok := envMap["ALL_PROXY"]; !ok || v != "socks5h://127.0.0.1:1080" {
		t.Errorf("ALL_PROXY = %q, want %q", v, "socks5h://127.0.0.1:1080")
	}

	// HTTP proxy vars should NOT be set.
	if _, ok := envMap["HTTP_PROXY"]; ok {
		t.Error("HTTP_PROXY should not be set without HTTP port")
	}

	// GIT_SSH_COMMAND should be set.
	if _, ok := envMap["GIT_SSH_COMMAND"]; !ok {
		t.Error("GIT_SSH_COMMAND should be set with SOCKS port")
	}
}

func TestGenerateProxyEnv_NOPROXYContainsExpectedValues(t *testing.T) {
	cfg := &EnvConfig{
		HTTPProxyPort: 8080,
	}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	noProxy := envMap["NO_PROXY"]
	expectedEntries := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"*.local",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}
	for _, entry := range expectedEntries {
		if !strings.Contains(noProxy, entry) {
			t.Errorf("NO_PROXY missing expected entry %q, got %q", entry, noProxy)
		}
	}
}

// envSliceToMap converts a slice of "KEY=VALUE" strings to a map.
func envSliceToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}

func TestGenerateProxyEnvRsync(t *testing.T) {
	cfg := &EnvConfig{
		SOCKSProxyPort: 1080,
	}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	// RSYNC_PROXY should use host:port format without protocol prefix.
	rsync, ok := envMap["RSYNC_PROXY"]
	if !ok {
		t.Fatal("missing RSYNC_PROXY")
	}
	if rsync != "localhost:1080" {
		t.Errorf("RSYNC_PROXY = %q, want %q", rsync, "localhost:1080")
	}
	// Verify no protocol prefix.
	if strings.Contains(rsync, "://") {
		t.Errorf("RSYNC_PROXY should not contain protocol prefix, got %q", rsync)
	}
}

func TestGenerateProxyEnvDocker(t *testing.T) {
	cfg := &EnvConfig{
		HTTPProxyPort:  8080,
		SOCKSProxyPort: 1080,
	}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	// When HTTP proxy is available, Docker vars should use HTTP proxy.
	wantDockerProxy := "http://127.0.0.1:8080"
	if v, ok := envMap["DOCKER_HTTP_PROXY"]; !ok {
		t.Error("missing DOCKER_HTTP_PROXY")
	} else if v != wantDockerProxy {
		t.Errorf("DOCKER_HTTP_PROXY = %q, want %q", v, wantDockerProxy)
	}
	if v, ok := envMap["DOCKER_HTTPS_PROXY"]; !ok {
		t.Error("missing DOCKER_HTTPS_PROXY")
	} else if v != wantDockerProxy {
		t.Errorf("DOCKER_HTTPS_PROXY = %q, want %q", v, wantDockerProxy)
	}
}

func TestGenerateProxyEnvDockerFallback(t *testing.T) {
	cfg := &EnvConfig{
		SOCKSProxyPort: 1080,
	}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	// When no HTTP proxy, Docker vars should fall back to SOCKS5.
	wantDockerProxy := "socks5h://127.0.0.1:1080"
	if v, ok := envMap["DOCKER_HTTP_PROXY"]; !ok {
		t.Error("missing DOCKER_HTTP_PROXY")
	} else if v != wantDockerProxy {
		t.Errorf("DOCKER_HTTP_PROXY = %q, want %q", v, wantDockerProxy)
	}
	if v, ok := envMap["DOCKER_HTTPS_PROXY"]; !ok {
		t.Error("missing DOCKER_HTTPS_PROXY")
	} else if v != wantDockerProxy {
		t.Errorf("DOCKER_HTTPS_PROXY = %q, want %q", v, wantDockerProxy)
	}
}

func TestGenerateProxyEnvCloudSDK(t *testing.T) {
	cfg := &EnvConfig{
		HTTPProxyPort: 3128,
	}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	if v, ok := envMap["CLOUDSDK_PROXY_TYPE"]; !ok {
		t.Error("missing CLOUDSDK_PROXY_TYPE")
	} else if v != "http" {
		t.Errorf("CLOUDSDK_PROXY_TYPE = %q, want %q", v, "http")
	}
	if v, ok := envMap["CLOUDSDK_PROXY_ADDRESS"]; !ok {
		t.Error("missing CLOUDSDK_PROXY_ADDRESS")
	} else if v != "127.0.0.1" {
		t.Errorf("CLOUDSDK_PROXY_ADDRESS = %q, want %q", v, "127.0.0.1")
	}
	if v, ok := envMap["CLOUDSDK_PROXY_PORT"]; !ok {
		t.Error("missing CLOUDSDK_PROXY_PORT")
	} else if v != "3128" {
		t.Errorf("CLOUDSDK_PROXY_PORT = %q, want %q", v, "3128")
	}

	// CLOUDSDK vars should NOT be set without HTTP proxy.
	cfgNoHTTP := &EnvConfig{
		SOCKSProxyPort: 1080,
	}
	envNoHTTP := GenerateProxyEnv(cfgNoHTTP)
	envMapNoHTTP := envSliceToMap(envNoHTTP)
	for _, key := range []string{"CLOUDSDK_PROXY_TYPE", "CLOUDSDK_PROXY_ADDRESS", "CLOUDSDK_PROXY_PORT"} {
		if _, ok := envMapNoHTTP[key]; ok {
			t.Errorf("unexpected %s without HTTP proxy port", key)
		}
	}
}

func TestGenerateProxyEnvGRPC(t *testing.T) {
	cfg := &EnvConfig{
		SOCKSProxyPort: 1080,
	}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	wantGRPC := "socks5h://127.0.0.1:1080"
	if v, ok := envMap["GRPC_PROXY"]; !ok {
		t.Error("missing GRPC_PROXY")
	} else if v != wantGRPC {
		t.Errorf("GRPC_PROXY = %q, want %q", v, wantGRPC)
	}
	if v, ok := envMap["grpc_proxy"]; !ok {
		t.Error("missing grpc_proxy")
	} else if v != wantGRPC {
		t.Errorf("grpc_proxy = %q, want %q", v, wantGRPC)
	}

	// GRPC vars should NOT be set without SOCKS port.
	cfgNoSOCKS := &EnvConfig{
		HTTPProxyPort: 8080,
	}
	envNoSOCKS := GenerateProxyEnv(cfgNoSOCKS)
	envMapNoSOCKS := envSliceToMap(envNoSOCKS)
	for _, key := range []string{"GRPC_PROXY", "grpc_proxy"} {
		if _, ok := envMapNoSOCKS[key]; ok {
			t.Errorf("unexpected %s without SOCKS proxy port", key)
		}
	}
}

func TestGenerateProxyEnv_NOPROXYContainsCGNATAndIPv6(t *testing.T) {
	cfg := &EnvConfig{
		HTTPProxyPort: 8080,
	}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	noProxy := envMap["NO_PROXY"]
	cgnatEntries := []string{
		"100.64.0.0/10",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}
	for _, entry := range cgnatEntries {
		if !strings.Contains(noProxy, entry) {
			t.Errorf("NO_PROXY missing CGNAT/IPv6 entry %q, got %q", entry, noProxy)
		}
	}

	// Also verify no_proxy (lowercase) has the same entries.
	noProxyLower := envMap["no_proxy"]
	for _, entry := range cgnatEntries {
		if !strings.Contains(noProxyLower, entry) {
			t.Errorf("no_proxy missing CGNAT/IPv6 entry %q, got %q", entry, noProxyLower)
		}
	}
}

func TestGenerateProxyEnv_DarwinGitSSH(t *testing.T) {
	// Override goos to test the darwin branch.
	old := goos
	goos = platformDarwin
	defer func() { goos = old }()

	cfg := &EnvConfig{
		SOCKSProxyPort: 1080,
	}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	gitSSH, ok := envMap["GIT_SSH_COMMAND"]
	if !ok {
		t.Fatal("missing GIT_SSH_COMMAND")
	}
	if !strings.Contains(gitSSH, "nc -X 5") {
		t.Errorf("on darwin, GIT_SSH_COMMAND should use nc, got %q", gitSSH)
	}
	if !strings.Contains(gitSSH, "1080") {
		t.Errorf("GIT_SSH_COMMAND should contain SOCKS port 1080, got %q", gitSSH)
	}
}

func TestGenerateProxyEnv_LinuxGitSSH(t *testing.T) {
	// Override goos to test the linux (default) branch explicitly.
	old := goos
	goos = "linux"
	defer func() { goos = old }()

	cfg := &EnvConfig{
		SOCKSProxyPort: 1080,
	}
	env := GenerateProxyEnv(cfg)
	envMap := envSliceToMap(env)

	gitSSH, ok := envMap["GIT_SSH_COMMAND"]
	if !ok {
		t.Fatal("missing GIT_SSH_COMMAND")
	}
	if !strings.Contains(gitSSH, "ncat") {
		t.Errorf("on linux, GIT_SSH_COMMAND should use ncat, got %q", gitSSH)
	}
}
