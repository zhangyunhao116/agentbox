package proxy

import (
	"fmt"
	"runtime"
	"strconv"
)

// goos is the operating system identifier used for platform-specific logic.
// It defaults to runtime.GOOS and can be overridden in tests.
var goos = runtime.GOOS

// EnvConfig configures proxy environment variable generation.
type EnvConfig struct {
	// HTTPProxyPort is the port number for the HTTP/CONNECT proxy.
	HTTPProxyPort int

	// SOCKSProxyPort is the port number for the SOCKS5 proxy.
	SOCKSProxyPort int

	// TmpDir overrides the TMPDIR environment variable if set.
	TmpDir string
}

// platformDarwin is the GOOS value for macOS, extracted as a constant to
// satisfy goconst across env.go and env_test.go.
const platformDarwin = "darwin"

// noProxyValue lists addresses that should bypass the proxy. This includes
// localhost, loopback, link-local, and RFC 1918 private address ranges.
const noProxyValue = "localhost,127.0.0.1,::1,*.local,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16,fc00::/7,fe80::/10"

// GenerateProxyEnv generates environment variables for proxy configuration.
// It returns a slice of "KEY=VALUE" strings suitable for use in exec.Cmd.Env.
func GenerateProxyEnv(cfg *EnvConfig) []string {
	if cfg == nil {
		return nil
	}

	var env []string

	// Sandbox runtime marker.
	env = append(env, "SANDBOX_RUNTIME=1")

	// TMPDIR override.
	if cfg.TmpDir != "" {
		env = append(env, "TMPDIR="+cfg.TmpDir)
	}

	// NO_PROXY / no_proxy.
	env = append(env,
		"NO_PROXY="+noProxyValue,
		"no_proxy="+noProxyValue,
	)

	// HTTP proxy settings.
	if cfg.HTTPProxyPort > 0 {
		httpProxy := "http://127.0.0.1:" + strconv.Itoa(cfg.HTTPProxyPort)
		env = append(env,
			"HTTP_PROXY="+httpProxy,
			"http_proxy="+httpProxy,
			"HTTPS_PROXY="+httpProxy,
			"https_proxy="+httpProxy,
			"FTP_PROXY="+httpProxy,
			"ftp_proxy="+httpProxy,
		)
	}

	// SOCKS5 proxy settings.
	if cfg.SOCKSProxyPort > 0 {
		socksProxy := "socks5h://127.0.0.1:" + strconv.Itoa(cfg.SOCKSProxyPort)
		env = append(env,
			"ALL_PROXY="+socksProxy,
			"all_proxy="+socksProxy,
		)
	}

	// GIT_SSH_COMMAND: platform-specific SSH proxy command.
	if cfg.SOCKSProxyPort > 0 {
		var gitSSHCmd string
		switch goos {
		case platformDarwin:
			// macOS: use nc (netcat) with SOCKS proxy.
			gitSSHCmd = fmt.Sprintf(
				"ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:%d %%h %%p'",
				cfg.SOCKSProxyPort,
			)
		default:
			// Linux and others: use ncat with SOCKS5 proxy.
			gitSSHCmd = fmt.Sprintf(
				"ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:%d %%h %%p'",
				cfg.SOCKSProxyPort,
			)
		}
		env = append(env, "GIT_SSH_COMMAND="+gitSSHCmd)
	}

	// RSYNC_PROXY: rsync uses host:port format without protocol prefix.
	if cfg.SOCKSProxyPort > 0 {
		env = append(env, "RSYNC_PROXY=localhost:"+strconv.Itoa(cfg.SOCKSProxyPort))
	}

	// GRPC_PROXY / grpc_proxy: gRPC proxy settings via SOCKS5.
	if cfg.SOCKSProxyPort > 0 {
		grpcProxy := "socks5h://127.0.0.1:" + strconv.Itoa(cfg.SOCKSProxyPort)
		env = append(env,
			"GRPC_PROXY="+grpcProxy,
			"grpc_proxy="+grpcProxy,
		)
	}

	// DOCKER_HTTP_PROXY / DOCKER_HTTPS_PROXY: Docker daemon proxy settings.
	// Prefer HTTP proxy; fall back to SOCKS5 if only SOCKS is available.
	if cfg.HTTPProxyPort > 0 {
		dockerProxy := "http://127.0.0.1:" + strconv.Itoa(cfg.HTTPProxyPort)
		env = append(env,
			"DOCKER_HTTP_PROXY="+dockerProxy,
			"DOCKER_HTTPS_PROXY="+dockerProxy,
		)
	} else if cfg.SOCKSProxyPort > 0 {
		dockerProxy := "socks5h://127.0.0.1:" + strconv.Itoa(cfg.SOCKSProxyPort)
		env = append(env,
			"DOCKER_HTTP_PROXY="+dockerProxy,
			"DOCKER_HTTPS_PROXY="+dockerProxy,
		)
	}

	// CLOUDSDK_PROXY_*: Google Cloud SDK proxy settings.
	if cfg.HTTPProxyPort > 0 {
		env = append(env,
			"CLOUDSDK_PROXY_TYPE=http",
			"CLOUDSDK_PROXY_ADDRESS=127.0.0.1",
			"CLOUDSDK_PROXY_PORT="+strconv.Itoa(cfg.HTTPProxyPort),
		)
	}

	return env
}
