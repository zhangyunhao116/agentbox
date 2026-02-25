- The design/directory contains design documents. Refer to them for the overall direction, but if you encounter difficulties during actual development, follow engineering best practices rather than sticking rigidly to details in the design documents.
- In the actual code, all comments and documentation (including README) must be written in English.
- Never call `kill(-1, ...)` or manipulate a PID to a value ≤ 1 before calling kill/signal. `kill(-1)` kills ALL processes owned by the current user. Always guard kill(-pid) calls with `pid > 1`.
- Some syscall error branches (e.g., EPERM from kill(2)) are intentionally left uncovered when the only way to trigger them in a test would risk catastrophic side effects. When leaving such a branch uncovered, add a comment block explaining why, and add defensive guards in the production code.

- All code must pass `golangci-lint run` (config: `.golangci.yml`). Read `.golangci.yml` before writing code and follow the enabled linters and rules.
