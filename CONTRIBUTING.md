# Contributing to agentbox

Thank you for your interest in contributing to agentbox! This document provides
guidelines and instructions for contributing.

## Development Setup

### Prerequisites

- Go 1.24 or later
- [golangci-lint](https://golangci-lint.run/) v2 (for linting)
- macOS or Linux (for running sandbox tests)

### Getting Started

```bash
git clone https://github.com/zhangyunhao116/agentbox.git
cd agentbox
make check   # runs vet + lint + tests
```

## Development Workflow

### Common Commands

```bash
make build      # compile all packages
make test       # run tests
make test-race  # run tests with race detector
make lint       # run golangci-lint
make vet        # run go vet
make cover      # generate coverage report
make bench      # run benchmarks
make check      # run full CI suite (vet + lint + test-race)
```

### Running Tests

```bash
# All tests
make test-race

# Specific package
go test -race -count=1 ./proxy/...

# With coverage
make cover
open coverage.html
```

## Code Guidelines

### Style

- Follow standard Go conventions (`gofmt`, `go vet`).
- All comments and documentation must be in **English**.
- Run `make lint` before submitting — CI enforces the same checks.

### Testing

- All new code must include tests.
- Use table-driven tests with `t.Run()` subtests.
- Bug fixes must include a regression test.
- Aim for >95% coverage on new code.
- Add benchmarks for performance-sensitive code paths.

### Error Handling

- Use sentinel errors (defined in `errors.go`) where callers need to match.
- Wrap errors with `fmt.Errorf("%w: ...", ErrXxx)` for context.
- Never silently discard errors — log at `slog.Debug` level at minimum.

### Security

This is a security library. Extra care is required:

- **Fail closed**: deny by default, allow explicitly.
- **Validate inputs**: paths, domains, command arguments.
- **No sensitive data in logs**: no credentials, tokens, or request bodies.
- **Document security decisions**: explain why, not just what.

## Pull Request Process

1. Fork the repository and create a feature branch.
2. Make your changes with tests.
3. Run `make check` to verify everything passes.
4. Submit a pull request with a clear description of the change.
5. Ensure CI passes on both macOS and Linux.

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests.
- For security vulnerabilities, please email the maintainer directly
  (do not open a public issue).

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.
