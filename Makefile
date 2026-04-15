# NothingDNS Makefile
# Provides convenient shortcuts for common development tasks

.PHONY: all build build-server build-cli build-web build-docker test test-short test-verbose test-race vet fmt lint clean install dev help

# Binary names
SERVER_BINARY := nothingdns
CLI_BINARY := dnsctl
DOCKER_IMAGE := nothingdns

# Build flags
BUILD_FLAGS := -trimpath -ldflags "-s -w"
CGO_ENABLED := 0

# Default target: build everything
all: build

# =============================================================================
# Build Targets
# =============================================================================

## Build all binaries (server + cli)
build: build-server build-cli
	@echo "✓ Build complete: $(SERVER_BINARY), $(CLI_BINARY)"

## Build the DNS server binary
build-server:
	@echo "Building $(SERVER_BINARY)..."
	@CGO_ENABLED=$(CGO_ENABLED) go build $(BUILD_FLAGS) -o $(SERVER_BINARY) ./cmd/nothingdns

## Build the CLI tool binary
build-cli:
	@echo "Building $(CLI_BINARY)..."
	@CGO_ENABLED=$(CGO_ENABLED) go build $(BUILD_FLAGS) -o $(CLI_BINARY) ./cmd/dnsctl

## Build static binaries for release (no symbols, smaller size)
build-release:
	@echo "Building release binaries..."
	@CGO_ENABLED=$(CGO_ENABLED) go build -trimpath -ldflags "-s -w -extldflags '-static'" -o $(SERVER_BINARY) ./cmd/nothingdns
	@CGO_ENABLED=$(CGO_ENABLED) go build -trimpath -ldflags "-s -w -extldflags '-static'" -o $(CLI_BINARY) ./cmd/dnsctl

## Build the web dashboard
build-web:
	@echo "Building web dashboard..."
	@cd web && npm run build

## Build all including web
build-all: build build-web
	@echo "✓ Full build complete"

# =============================================================================
# Docker Targets
# =============================================================================

## Build Docker image
build-docker:
	@echo "Building Docker image..."
	@docker build -t $(DOCKER_IMAGE):latest .

## Build Docker image for multiple architectures
build-docker-multi:
	@echo "Building multi-arch Docker image..."
	@docker buildx build --platform linux/amd64,linux/arm64 -t $(DOCKER_IMAGE):latest .

## Run with docker-compose
up:
	@docker-compose up -d

## Stop docker-compose
down:
	@docker-compose down

# =============================================================================
# Test Targets
# =============================================================================

## Run all tests (short mode)
test:
	@echo "Running tests..."
	@go test ./... -count=1 -short

## Run tests with verbose output
test-verbose:
	@echo "Running tests (verbose)..."
	@go test ./... -count=1 -short -v

## Run all tests including long-running ones
test-full:
	@echo "Running full test suite..."
	@go test ./... -count=1

## Run end-to-end tests
test-e2e:
	@echo "Running e2e tests..."
	@go test ./internal/e2e/... -v

## Run tests with race detector (requires CGO)
test-race:
	@echo "Running tests with race detector..."
	@go test ./... -race -count=1 -short

## Run tests for a specific package (usage: make test-pkg PKG=./internal/cache)
test-pkg:
	@test -n "$(PKG)" || (echo "Usage: make test-pkg PKG=./internal/package"; exit 1)
	@go test $(PKG) -v

## Run a specific test (usage: make test-run TEST=TestName)
test-run:
	@test -n "$(TEST)" || (echo "Usage: make test-run TEST=TestName"; exit 1)
	@go test ./... -run $(TEST) -v

## Generate test coverage report
test-coverage:
	@echo "Generating coverage report..."
	@go test ./... -count=1 -short -coverprofile=coverage.out
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# =============================================================================
# Lint & Format Targets
# =============================================================================

## Run go vet on all packages
vet:
	@echo "Running go vet..."
	@go vet ./...

## Format all Go code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

## Check formatting (fails if not formatted)
fmt-check:
	@echo "Checking formatting..."
	@test -z "$$(gofmt -l .)" || (echo "Code not formatted. Run 'make fmt'"; exit 1)

## Run all linters (vet + fmt-check)
lint: vet fmt-check
	@echo "✓ All linters passed"

## Run staticcheck (if installed)
staticcheck:
	@which staticcheck > /dev/null 2>&1 || (echo "staticcheck not installed. Run: go install honnef.co/go/tools/cmd/staticcheck@latest"; exit 1)
	@staticcheck ./...

# =============================================================================
# Development Targets
# =============================================================================

## Install binaries to $GOPATH/bin
install:
	@echo "Installing binaries..."
	@go install ./cmd/nothingdns
	@go install ./cmd/dnsctl
	@echo "✓ Installed to $$(go env GOPATH)/bin"

## Run the server with default config (for development)
dev:
	@echo "Starting NothingDNS server..."
	@go run ./cmd/nothingdns --config config.example.yaml

## Run the server with hot reload on file changes (requires entr or similar)
dev-watch:
	@which entr > /dev/null 2>&1 || (echo "entr not installed. Install with: apt-get install entr"; exit 1)
	@find . -name '*.go' | entr -r make dev

## Validate configuration file (usage: make validate-config CONFIG=config.yaml)
validate-config:
	@test -n "$(CONFIG)" || (echo "Usage: make validate-config CONFIG=config.yaml"; exit 1)
	@go run ./cmd/nothingdns --config $(CONFIG) --validate-config

# =============================================================================
# Maintenance Targets
# =============================================================================

## Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -f $(SERVER_BINARY) $(CLI_BINARY) $(SERVER_BINARY).exe $(CLI_BINARY).exe
	@rm -f coverage.out coverage.html
	@rm -rf web/dist web/node_modules
	@echo "✓ Clean complete"

## Clean everything including Go module cache
clean-all: clean
	@go clean -cache
	@echo "✓ Full clean complete"

## Download and verify dependencies
deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod verify

## Tidy go modules
tidy:
	@echo "Tidying modules..."
	@go mod tidy

## Update all dependencies
update-deps:
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy

# =============================================================================
# CI/CD Targets
# =============================================================================

## Run CI pipeline locally (build, test, vet)
ci: vet test build
	@echo "✓ CI checks passed"

## Prepare for release (clean build with all checks)
release: clean vet test build-release
	@echo "✓ Release build complete"

# =============================================================================
# Help
# =============================================================================

## Show this help message
help:
	@echo "NothingDNS - Makefile Targets"
	@echo "=============================="
	@echo ""
	@echo "Build Targets:"
	@echo "  make build           - Build server and CLI binaries"
	@echo "  make build-server    - Build only the DNS server"
	@echo "  make build-cli       - Build only the CLI tool"
	@echo "  make build-release   - Build optimized release binaries"
	@echo "  make build-web       - Build the web dashboard"
	@echo "  make build-docker    - Build Docker image"
	@echo ""
	@echo "Test Targets:"
	@echo "  make test            - Run all tests (short mode)"
	@echo "  make test-verbose    - Run tests with verbose output"
	@echo "  make test-full       - Run all tests (including long-running)"
	@echo "  make test-e2e        - Run end-to-end tests"
	@echo "  make test-pkg        - Run tests for specific package"
	@echo "  make test-run        - Run specific test by name"
	@echo "  make test-coverage   - Generate coverage report"
	@echo ""
	@echo "Lint Targets:"
	@echo "  make vet             - Run go vet"
	@echo "  make fmt             - Format Go code"
	@echo "  make fmt-check       - Check if code is formatted"
	@echo "  make lint            - Run all linters"
	@echo ""
	@echo "Development:"
	@echo "  make dev             - Run server in development mode"
	@echo "  make install         - Install binaries to GOPATH/bin"
	@echo "  make validate-config - Validate a config file"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean           - Remove build artifacts"
	@echo "  make deps            - Download dependencies"
	@echo "  make tidy            - Tidy go modules"
	@echo ""
	@echo "CI/CD:"
	@echo "  make ci              - Run CI checks (vet, test, build)"
	@echo "  make release         - Prepare release build"
