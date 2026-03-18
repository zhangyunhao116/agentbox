//go:build windows

package windows

import (
	"strings"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
)

func TestWslConfContent(t *testing.T) {
	// Verify wsl.conf contains critical security settings.
	tests := []struct {
		name     string
		required string
	}{
		{"interop disabled", "enabled=false"},
		{"drives metadata", `options="metadata"`},
		{"sandbox user", "default=sandbox"},
		{"systemd disabled", "systemd=false"},
		{"windows path excluded", "appendWindowsPath=false"},
		{"hostname set", "hostname=agentbox-sb"},
		{"resolv.conf generated", "generateResolvConf=true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(wslConfContent, tt.required) {
				t.Errorf("wsl.conf must contain %q", tt.required)
			}
		})
	}
}

func TestAlpineConstants(t *testing.T) {
	if alpineVersion == "" {
		t.Error("alpineVersion must not be empty")
	}
	if !strings.Contains(alpineURL, alpineVersion) {
		t.Errorf("alpineURL %q must contain alpineVersion %q", alpineURL, alpineVersion)
	}
	if !strings.Contains(alpineURL, alpineArch) {
		t.Errorf("alpineURL %q must contain alpineArch %q", alpineURL, alpineArch)
	}
	if !strings.HasPrefix(alpineURL, "https://") {
		t.Error("alpineURL must use HTTPS")
	}
	if !strings.HasSuffix(alpineURL, ".tar.gz") {
		t.Error("alpineURL must point to a .tar.gz file")
	}
}

func TestWslConfSections(t *testing.T) {
	// Verify all required INI sections are present.
	sections := []string{"[interop]", "[automount]", "[user]", "[network]", "[boot]"}
	for _, s := range sections {
		if !strings.Contains(wslConfContent, s) {
			t.Errorf("wsl.conf must contain section %q", s)
		}
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "'hello'"},
		{"hello world", "'hello world'"},
		{"it's", "'it'\\''s'"},
		{"", "''"},
		{"a'b'c", "'a'\\''b'\\''c'"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := shellQuote(tt.input)
			if got != tt.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeEnv(t *testing.T) {
	p := &Platform{wslNetworkMode: "nat"}
	env := []string{
		"SYSTEMROOT=C:\\Windows",
		"PATH=C:\\Windows\\System32",
		"HOME=/home/user",
		"WINDIR=C:\\Windows",
		"MY_VAR=value",
	}
	cfg := &platform.WrapConfig{}
	got := p.sanitizeEnv(env, cfg)

	// Should filter Windows-specific vars.
	for _, e := range got {
		key, _, _ := strings.Cut(e, "=")
		upper := strings.ToUpper(key)
		if upper == "SYSTEMROOT" || upper == "PATH" || upper == "WINDIR" {
			t.Errorf("sanitizeEnv should have filtered %q", key)
		}
	}

	// Should keep non-Windows vars.
	found := map[string]bool{}
	for _, e := range got {
		key, _, _ := strings.Cut(e, "=")
		found[key] = true
	}
	if !found["HOME"] {
		t.Error("sanitizeEnv should keep HOME")
	}
	if !found["MY_VAR"] {
		t.Error("sanitizeEnv should keep MY_VAR")
	}
	if !found["WSL_UTF8"] {
		t.Error("sanitizeEnv should inject WSL_UTF8=1")
	}
}

func TestSanitizeEnvProxy(t *testing.T) {
	p := &Platform{wslNetworkMode: "mirrored"}
	env := []string{"HOME=/home/user"}
	cfg := &platform.WrapConfig{
		HTTPProxyPort:  8080,
		SOCKSProxyPort: 1080,
	}
	got := p.sanitizeEnv(env, cfg)

	foundHTTP := false
	foundHTTPS := false
	foundALL := false
	for _, e := range got {
		if strings.HasPrefix(e, "HTTP_PROXY=") {
			foundHTTP = true
			if !strings.Contains(e, "localhost:8080") {
				t.Errorf("HTTP_PROXY should use localhost in mirrored mode, got %q", e)
			}
		}
		if strings.HasPrefix(e, "HTTPS_PROXY=") {
			foundHTTPS = true
		}
		if strings.HasPrefix(e, "ALL_PROXY=") {
			foundALL = true
			if !strings.Contains(e, "localhost:1080") {
				t.Errorf("ALL_PROXY should use localhost in mirrored mode, got %q", e)
			}
		}
	}
	if !foundHTTP {
		t.Error("expected HTTP_PROXY to be set in mirrored mode")
	}
	if !foundHTTPS {
		t.Error("expected HTTPS_PROXY to be set in mirrored mode")
	}
	if !foundALL {
		t.Error("expected ALL_PROXY to be set in mirrored mode")
	}
}

func TestSanitizeEnvProxy_NATMode(t *testing.T) {
	// In NAT mode, proxy env vars should NOT be set by sanitizeEnv
	// because they are resolved via shell exports in the command string.
	p := &Platform{wslNetworkMode: "nat"}
	env := []string{"HOME=/home/user"}
	cfg := &platform.WrapConfig{
		HTTPProxyPort:  8080,
		SOCKSProxyPort: 1080,
	}
	got := p.sanitizeEnv(env, cfg)

	for _, e := range got {
		key, _, _ := strings.Cut(e, "=")
		upper := strings.ToUpper(key)
		if upper == "HTTP_PROXY" || upper == "HTTPS_PROXY" || upper == "ALL_PROXY" {
			t.Errorf("sanitizeEnv in NAT mode should not set %q (handled via shell exports)", key)
		}
	}
}

func TestPrependNATProxyExports(t *testing.T) {
	p := &Platform{wslNetworkMode: "nat"}

	t.Run("no proxy", func(t *testing.T) {
		cfg := &platform.WrapConfig{}
		got := p.prependNATProxyExports("echo hello", cfg)
		if got != "echo hello" {
			t.Errorf("expected unchanged command, got %q", got)
		}
	})

	t.Run("http proxy", func(t *testing.T) {
		cfg := &platform.WrapConfig{HTTPProxyPort: 8080}
		got := p.prependNATProxyExports("echo hello", cfg)
		if !strings.Contains(got, "_AGENTBOX_HOST=") {
			t.Error("expected _AGENTBOX_HOST assignment")
		}
		if !strings.Contains(got, "export HTTP_PROXY=http://$_AGENTBOX_HOST:8080") {
			t.Error("expected HTTP_PROXY export")
		}
		if !strings.Contains(got, "export HTTPS_PROXY=http://$_AGENTBOX_HOST:8080") {
			t.Error("expected HTTPS_PROXY export")
		}
		if !strings.HasSuffix(got, " && echo hello") {
			t.Errorf("expected command at end, got %q", got)
		}
	})

	t.Run("socks proxy", func(t *testing.T) {
		cfg := &platform.WrapConfig{SOCKSProxyPort: 1080}
		got := p.prependNATProxyExports("curl example.com", cfg)
		if !strings.Contains(got, "export ALL_PROXY=socks5://$_AGENTBOX_HOST:1080") {
			t.Error("expected ALL_PROXY export")
		}
	})

	t.Run("both proxies", func(t *testing.T) {
		cfg := &platform.WrapConfig{HTTPProxyPort: 8080, SOCKSProxyPort: 1080}
		got := p.prependNATProxyExports("cmd", cfg)
		if !strings.Contains(got, "HTTP_PROXY") || !strings.Contains(got, "ALL_PROXY") {
			t.Errorf("expected both proxy types, got %q", got)
		}
	})
}

func TestWslConfHostnameMatchesDistroName(t *testing.T) {
	expected := "hostname=" + defaultDistroName
	if !strings.Contains(wslConfContent, expected) {
		t.Errorf("wslConfContent hostname does not match defaultDistroName %q; want %q in content",
			defaultDistroName, expected)
	}
}

func TestProxyHostAddr(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{"mirrored", "localhost"},
		// In NAT mode, proxyHostAddr returns "localhost" as a fallback;
		// the actual host IP resolution is done via shell exports in
		// prependNATProxyExports.
		{"nat", "localhost"},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			p := &Platform{wslNetworkMode: tt.mode}
			got := p.proxyHostAddr()
			if got != tt.want {
				t.Errorf("proxyHostAddr() = %q, want %q", got, tt.want)
			}
		})
	}
}
