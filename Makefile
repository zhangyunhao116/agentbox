# Makefile for agentbox
# See CONTRIBUTING.md for development workflow.

.PHONY: build test test-race lint vet cover bench clean check fmt fmt-check

# Default target runs the full CI check suite.
check: fmt-check vet lint test-race

build:
	go build ./...

test:
	CGO_ENABLED=0 go test -count=1 ./...

test-race:
	CGO_ENABLED=0 go test -race -count=1 ./...

lint:
	golangci-lint run

vet:
	go vet ./...

cover:
	CGO_ENABLED=0 go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

bench:
	CGO_ENABLED=0 go test -bench=. -benchmem -run=^$$ ./...

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || { echo "Files not formatted:"; gofmt -l .; exit 1; }

clean:
	rm -f coverage.out coverage.html
	rm -f proxy/coverage.out proxy/coverage.html
	rm -rf .build
