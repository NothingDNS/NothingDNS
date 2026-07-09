# NothingDNS Makefile
# Provides convenient shortcuts for common development tasks

.PHONY: all build build-server build-cli build-web build-docker build-release test test-short test-verbose test-race test-race-critical test-e2e test-pkg test-run test-coverage vet fmt fmt-check fmt-all lint staticcheck clean clean-all install dev dev-watch validate-config deps tidy update-deps ci release help benchmark security-check docs docker-push helm-install helm-template setup-hooks lint-ci backup health-check

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

## Build cross-platform release binaries and SHA256SUMS into dist/
build-release:
	@echo "Building release binaries..."
	@./scripts/build-release.sh

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

## Run critical race-detector shards for concurrency-heavy packages
test-race-critical:
	@echo "Running critical race detector shards..."
	@go test ./internal/protocol ./internal/dnssec ./internal/dns64 ./internal/dnscookie ./internal/doh ./internal/odoh ./internal/dso ./internal/mdns ./internal/filter -race -count=1 -short
	@go test ./internal/server ./internal/cache ./internal/resolver -race -count=1 -short
	@go test ./internal/upstream ./internal/dashboard ./internal/websocket ./internal/metrics ./internal/memory ./internal/load ./internal/otel -race -count=1 -short
	@go test ./internal/cluster/raft ./internal/cluster -race -count=1 -short
	@go test ./internal/storage ./internal/zone ./internal/rpz ./internal/blocklist ./internal/geodns -race -count=1 -short
	@go test ./internal/transfer -race -count=1 -short -run 'Test.*AXFR'
	@go test ./internal/transfer -race -count=1 -short -run 'Test.*IXFR'
	@go test ./internal/transfer -race -count=1 -short -run 'Test.*Journal|Test.*KVJournal'
	@go test ./internal/transfer -race -count=1 -short -run 'Test.*TSIG|Test.*TKEY|Test.*HMAC|Test.*XoT'
	@go test ./internal/transfer -race -count=1 -short -run 'Test.*DDNS|Test.*Update|Test.*NOTIFY|Test.*Notify|Test.*Slave'
	@go test ./internal/api -race -count=1 -short -run 'TestHandle(ACL|Upstreams|Blocklist|Blocklists|RPZ|Config|ServerConfig|Health|Readiness|Liveness|Status|Metrics|QueryLog|TopDomains|Dashboard|GeoDNS|SlaveZones|ODoH|DNSSEC)'
	@go test ./internal/api -race -count=1 -short -run 'TestHandle(Zones|ZoneActions|ZoneReload|BulkPTR|Ptr6|ListZones|GetZone|DeleteZone|ExportZone)|TestZone|TestReverse|TestValidateZone'
	@go test ./internal/api -race -count=1 -short -run 'Test(Start|NewServer|Middleware|Integration|ErrorResponse|Options|Concurrent|OpenAPI|Swagger|Write|Cors|WithUser|ServerRuntime|Retry|CookieMax|APIServer|APIStatus|APICache|APIAuth|APIDisabled|BlocklistService|CacheService|ValidateUpstream|Redact)'
	@go test ./internal/api -race -count=1 -short -run 'TestHandle(Login|Logout|Bootstrap)'
	@go test ./internal/api -race -count=1 -short -run 'TestHandle(Users|Roles)|TestAuth|TestCookie|TestDoH|TestLegacy'
	@go test ./internal/api -race -count=1 -short -run 'TestAPIRate|TestLoginRate|TestCheck|TestRecord|TestCleanup'
	@go test ./internal/config ./cmd/nothingdns ./cmd/dnsctl -race -count=1 -short
	@go test ./internal/auth -race -count=1 -short -run 'TestStoreConcurrentAccess|TestConcurrentTokenCreation|TestConcurrentUserOperations'
	@go test ./internal/auth -race -count=1 -short -run 'TestSaveLoad|TestSaveTokensSigned|TestLoadTokensSigned|TestTokenFormat|TestTokenExpiry'

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
# Benchmark Targets
# =============================================================================

## Run benchmarks for a specific package (usage: make benchmark PKG=./internal/cache)
benchmark:
	@test -n "$(PKG)" || (echo "Usage: make benchmark PKG=./internal/package"; exit 1)
	@go test $(PKG) -bench=. -benchmem -count=3

# =============================================================================
# Security Targets
# =============================================================================

## Run security checks (govulncheck, staticcheck)
security-check:
	@echo "Running security checks..."
	@go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
	@govulncheck ./...
	@go install honnef.co/go/tools/cmd/staticcheck@2025.1.1
	@staticcheck ./...
	@echo "✓ Security checks passed"

# =============================================================================
# Documentation Targets
# =============================================================================

## Generate API documentation (requires swag)
docs:
	@test -n "$(SWAG)" || (which swag > /dev/null 2>&1) || (echo "swag not installed. Run: go install github.com/swaggo/swag/cmd/swag@latest"; exit 1)
	@swag init -g cmd/nothingdns/main.go -o docs/api
	@echo "✓ API docs generated"

## Serve API documentation locally
docs-serve:
	@test -n "$(SWAGGER_PORT)" || SWAGGER_PORT=8081
	@npx swagger-ui-cli serve docs/api/swagger.yaml --port=$(SWAGGER_PORT)

# =============================================================================
# Docker & Helm Targets
# =============================================================================

## Build and push Docker image (usage: make docker-push TAG=v1.0.0)
docker-push:
	@test -n "$(TAG)" || (echo "Usage: make docker-push TAG=v1.0.0"; exit 1)
	@docker build -t $(DOCKER_IMAGE):$(TAG) -t $(DOCKER_IMAGE):latest .
	@docker push $(DOCKER_IMAGE):$(TAG)
	@docker push $(DOCKER_IMAGE):latest

## Install using Helm
helm-install:
	@test -n "$(RELEASE)" || (echo "Usage: make helm-install RELEASE=my-release"; exit 1)
	@helm install $(RELEASE) deploy/helm/nothingdns

## Template Helm chart (dry-run)
helm-template:
	@test -n "$(RELEASE)" || (echo "Usage: make helm-template RELEASE=my-release"; exit 1)
	@helm template $(RELEASE) deploy/helm/nothingdns

# =============================================================================
# Development Helpers
# =============================================================================

## Format all code (Go + others)
fmt-all:
	@echo "Formatting all code..."
	@go fmt ./...
	@cd web && npm run format 2>/dev/null || true
	@find . -name '*.sh' -exec shfmt -w {} \; 2>/dev/null || true
	@echo "✓ Formatting complete"

## Setup git hooks and development environment
setup-hooks:
	@echo "Setting up git hooks..."
	@chmod +x scripts/pre-commit scripts/install-hooks.sh
	@./scripts/install-hooks.sh

## Run CI-style linting (golangci-lint)
lint-ci:
	@which golangci-lint > /dev/null 2>&1 || (echo "Installing golangci-lint..."; go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	@golangci-lint run ./...

## Run backup script
backup:
	@chmod +x scripts/backup.sh
	@./scripts/backup.sh /var/backups/nothingdns

## Run health check script
health-check:
	@chmod +x scripts/health-check.sh
	@./scripts/health-check.sh localhost:8080

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
	@echo "  make fmt-all         - Format all code (Go, JS, shell)"
	@echo "  make fmt-check       - Check if code is formatted"
	@echo "  make lint            - Run all linters"
	@echo "  make staticcheck     - Run staticcheck"
	@echo ""
	@echo "Benchmark Targets:"
	@echo "  make benchmark       - Run benchmarks (usage: make benchmark PKG=./internal/cache)"
	@echo ""
	@echo "Security Targets:"
	@echo "  make security-check  - Run govulncheck and staticcheck"
	@echo ""
	@echo "Documentation Targets:"
	@echo "  make docs            - Generate API docs with swag"
	@echo ""
	@echo "Development:"
	@echo "  make dev             - Run server in development mode"
	@echo "  make dev-watch       - Run server with hot reload on file changes"
	@echo "  make install         - Install binaries to GOPATH/bin"
	@echo "  make validate-config - Validate a config file"
	@echo "  make setup-hooks     - Install git hooks"
	@echo "  make lint-ci         - Run golangci-lint"
	@echo "  make health-check    - Run health checks"
	@echo ""
	@echo "Docker & Helm:"
	@echo "  make up              - Run with docker-compose"
	@echo "  make down            - Stop docker-compose"
	@echo "  make docker-push     - Build and push Docker image (TAG=v1.0.0)"
	@echo "  make helm-install    - Install using Helm (RELEASE=my-release)"
	@echo "  make helm-template   - Dry-run Helm template (RELEASE=my-release)"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean           - Remove build artifacts"
	@echo "  make clean-all       - Remove everything including Go cache"
	@echo "  make deps            - Download dependencies"
	@echo "  make tidy            - Tidy go modules"
	@echo "  make update-deps     - Update all dependencies"
	@echo ""
	@echo "CI/CD:"
	@echo "  make ci              - Run CI checks (vet, test, build)"
	@echo "  make release         - Prepare release build"
