# Security Policy

## Supported Versions

agentbox is currently in **pre-1.0 beta**. Security fixes are applied to the latest release on the `main` branch only.

| Version | Supported          |
|---------|--------------------|
| v0.x    | ✅ Latest release  |
| < v0.1  | ❌ Not supported   |

Once v1.0 is released, this policy will be updated with a formal support window.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use one of the following private channels:

1. **GitHub Security Advisories (preferred)** — open a private advisory at
   [https://github.com/zhangyunhao116/agentbox/security/advisories/new](https://github.com/zhangyunhao116/agentbox/security/advisories/new).
2. **Email** — if you cannot use GitHub advisories, contact the maintainer directly via the email listed on the [GitHub profile](https://github.com/zhangyunhao116).

Include as much of the following as possible:

- A description of the vulnerability and its potential impact.
- Step-by-step reproduction instructions or a proof-of-concept.
- The affected component (sandbox, proxy, classifier, platform backend, etc.).
- The OS and kernel version where the issue was observed.

## What Qualifies as a Security Issue

agentbox is a sandbox isolation library. The following categories are considered security-relevant:

| Category | Examples |
|----------|----------|
| **Sandbox escape** | A sandboxed process gains write access outside `WritableRoots`, or reads paths listed in `DenyRead`. |
| **Command injection bypass** | Crafted input causes the classifier to misclassify a dangerous command as safe (e.g., a `rm -rf /` variant that passes as `Allow`). |
| **Network filter bypass** | A sandboxed process reaches a domain or IP that should be blocked by the proxy or network policy. |
| **Private IP / SSRF bypass** | A sandboxed process connects to loopback, RFC 1918, link-local, or cloud metadata addresses despite the default block list. |
| **Privilege escalation** | A sandboxed process escalates privileges, attaches a debugger, or disables `NO_NEW_PRIVS` / seccomp filters. |
| **Resource limit escape** | A sandboxed process exceeds configured memory, process, or file-descriptor limits in a way that affects the host. |

Issues that are **not** typically security-relevant:

- Bugs that require the caller to intentionally weaken the sandbox configuration (e.g., setting `FallbackWarn` or `NetworkAllowed`).
- Denial-of-service against the sandboxed process itself (the sandbox is designed to constrain it).
- Vulnerabilities in dependencies that do not affect agentbox's usage of them.

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | Within **3 business days** |
| Initial assessment | Within **7 business days** |
| Fix or mitigation | Depends on severity — critical issues are prioritized for the next patch release |
| Public disclosure | Coordinated with the reporter after a fix is available |

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). We will credit reporters in the advisory unless they prefer to remain anonymous.

## Security Design Principles

For context on how agentbox approaches security, see the [README](README.md). Key design principles:

- **Default deny** — writes are blocked everywhere unless explicitly allowed; network access requires an allowlist.
- **Defense in depth** — multiple independent layers (classifier → filesystem → network → process hardening) so no single bypass compromises the system.
- **Minimal trust** — all commands run inside the sandbox regardless of classification.
- **Fail closed** — if the sandbox cannot be established, execution is refused by default (`FallbackStrict`).
