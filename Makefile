.PHONY: build fmt fmt-check lint clean test check help integration-test integration-test-full
.DEFAULT_GOAL := help

# Build the binary
build: check
	CGO_ENABLED=0 go build --ldflags '-w -s -extldflags "-static"' -o cloudflare_exporter .

# Format Go code
fmt:
	go fmt ./...
	goimports -w .

vet:
	go vet ./...

# Check if code is properly formatted (CI-friendly)
fmt-check:
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "The following files are not properly formatted:"; \
		gofmt -l .; \
		echo "Please run 'make fmt' to fix formatting issues."; \
		exit 1; \
	fi
	@if command -v goimports >/dev/null 2>&1; then \
		if [ -n "$$(goimports -l .)" ]; then \
			echo "The following files have import issues:"; \
			goimports -l .; \
			echo "Please run 'make fmt' to fix import issues."; \
			exit 1; \
		fi; \
	fi

# Run linter
lint:
	golangci-lint run

# Run all checks (formatting + linting)
check: fmt-check lint

# Run unit tests only
unit-tests:
	go test ./... -v

# Run comprehensive tests for release/PR submission (without e2e)
pr-tests: clean fmt-check lint build test
	@echo "🎉 All release tests passed! Ready for PR submission."

# Clean build artifacts
clean:
	rm -f cloudflare_exporter venom*.log basic_tests.* pprof_cpu*

# Run integration tests (requires ~/.cloudflare_token and CF_TEST_ZONE_ID)
integration-test:
	@test -n "$(CF_TEST_ZONE_ID)" || (echo "error: CF_TEST_ZONE_ID is required (e.g. make integration-test CF_TEST_ZONE_ID=abc123)"; exit 1)
	CF_API_TOKEN="$$(cat ~/.cloudflare_token)" CF_TEST_ZONE_ID="$(CF_TEST_ZONE_ID)" go test ./cfetch/... -count=1 -v -run TestIntegration

# Run integration tests including backfill+push (requires VM_PUSH_ENDPOINT)
integration-test-full:
	@test -n "$(CF_TEST_ZONE_ID)" || (echo "error: CF_TEST_ZONE_ID is required"; exit 1)
	@test -n "$(VM_PUSH_ENDPOINT)" || (echo "error: VM_PUSH_ENDPOINT is required (e.g. http://localhost:8428/api/v1/write)"; exit 1)
	CF_API_TOKEN="$$(cat ~/.cloudflare_token)" CF_TEST_ZONE_ID="$(CF_TEST_ZONE_ID)" VM_PUSH_ENDPOINT="$(VM_PUSH_ENDPOINT)" VM_PUSH_USER="$(VM_PUSH_USER)" VM_PUSH_PASSWORD="$(VM_PUSH_PASSWORD)" go test ./. ./cfetch/... -count=1 -v -run TestIntegration

# Run end-to-end tests
test:
	./run_e2e.sh

# Show help information
help:
	@echo "Available targets:"
	@echo "  build      - Build the cloudflare_exporter binary (runs check first)"
	@echo "  fmt        - Format Go code using go fmt and goimports"
	@echo "  fmt-check  - Check if code is properly formatted (CI-friendly)"
	@echo "  lint       - Run golangci-lint to check code quality"
	@echo "  check      - Run all checks (fmt-check + lint)"
	@echo "  test       - Run end-to-end tests (requires additional setup)"
	@echo "  pr-tests   - Run comprehensive tests for PR submission"
	@echo "  clean      - Remove build artifacts and temporary files"
	@echo "  vet        - Run go vet to check code quality"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Common workflows:"
	@echo "  make fmt && make build  - Format code and build"
	@echo "  make check             - Run all code quality checks"
	@echo "  make integration-test       - Run cfetch integration tests (needs ~/.cloudflare_token)"
	@echo "  make integration-test-full  - Run full pipeline tests (needs VM_PUSH_ENDPOINT too)"
	@echo "  make unit-tests        - Run unit tests only"
	@echo "  make pr-tests          - Run full test suite for PR/release"
	@echo "  make clean build       - Clean and rebuild"
