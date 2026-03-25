# NothingDNS Makefile
# Zero-dependency DNS server written in pure Go

# Variables
NAME := nothingdns
CLI_NAME := dnsctl
VERSION := 0.1.0
BUILD_DIR := build
CMD_DIR := cmd

# Go settings
GO := go
GOFLAGS := -trimpath
LDFLAGS := -ldflags "-s -w -X main.Version=$(VERSION)"

# Build targets
.PHONY: all build build-cli build-all test bench lint fmt vet clean install release docker

# Default target: build both binaries
all: build build-cli

# Build the main server binary
build:
	@echo "Building $(NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(NAME) ./$(CMD_DIR)/$(NAME)
	@echo "Built: $(BUILD_DIR)/$(NAME)"

# Build the CLI tool
build-cli:
	@echo "Building $(CLI_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(CLI_NAME) ./$(CMD_DIR)/$(CLI_NAME)
	@echo "Built: $(BUILD_DIR)/$(CLI_NAME)"

# Build both binaries
build-all: build build-cli

# Run all tests
test:
	@echo "Running tests..."
	$(GO) test -v -race -count=1 ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(BUILD_DIR)
	$(GO) test -race -coverprofile=$(BUILD_DIR)/coverage.out ./...
	$(GO) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "Coverage report: $(BUILD_DIR)/coverage.html"

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	$(GO) test -bench=. -benchmem ./...

# Run linter (requires golangci-lint)
lint: fmt vet
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping..."; \
	fi

# Format code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

# Run go vet
vet:
	@echo "Running go vet..."
	$(GO) vet ./...

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@$(GO) clean -cache

# Install binaries to GOPATH/bin
install: build-all
	@echo "Installing binaries..."
	$(GO) install ./$(CMD_DIR)/$(NAME)
	$(GO) install ./$(CMD_DIR)/$(CLI_NAME)

# Cross-compile for multiple platforms
release:
	@echo "Building release binaries..."
	@mkdir -p $(BUILD_DIR)/release

	# Linux AMD64
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/release/$(NAME)-$(VERSION)-linux-amd64 ./$(CMD_DIR)/$(NAME)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/release/$(CLI_NAME)-$(VERSION)-linux-amd64 ./$(CMD_DIR)/$(CLI_NAME)

	# Linux ARM64
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/release/$(NAME)-$(VERSION)-linux-arm64 ./$(CMD_DIR)/$(NAME)
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/release/$(CLI_NAME)-$(VERSION)-linux-arm64 ./$(CMD_DIR)/$(CLI_NAME)

	# macOS AMD64
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/release/$(NAME)-$(VERSION)-darwin-amd64 ./$(CMD_DIR)/$(NAME)
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/release/$(CLI_NAME)-$(VERSION)-darwin-amd64 ./$(CMD_DIR)/$(CLI_NAME)

	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/release/$(NAME)-$(VERSION)-darwin-arm64 ./$(CMD_DIR)/$(NAME)
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/release/$(CLI_NAME)-$(VERSION)-darwin-arm64 ./$(CMD_DIR)/$(CLI_NAME)

	# Windows AMD64
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/release/$(NAME)-$(VERSION)-windows-amd64.exe ./$(CMD_DIR)/$(NAME)
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/release/$(CLI_NAME)-$(VERSION)-windows-amd64.exe ./$(CMD_DIR)/$(CLI_NAME)

	# FreeBSD AMD64
	GOOS=freebsd GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/release/$(NAME)-$(VERSION)-freebsd-amd64 ./$(CMD_DIR)/$(NAME)
	GOOS=freebsd GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/release/$(CLI_NAME)-$(VERSION)-freebsd-amd64 ./$(CMD_DIR)/$(CLI_NAME)

	@echo "Release binaries built in $(BUILD_DIR)/release/"
	@ls -la $(BUILD_DIR)/release/

# Build Docker image
docker:
	@echo "Building Docker image..."
	docker build -t $(NAME):$(VERSION) -t $(NAME):latest .

# Build and push Docker image
docker-push: docker
	@echo "Pushing Docker image..."
	docker push $(NAME):$(VERSION)
	docker push $(NAME):latest

# Run the server locally (for development)
run: build
	@echo "Running $(NAME)..."
	./$(BUILD_DIR)/$(NAME) -config configs/nothingdns.yaml

# Run the server with debug logging
debug: build
	@echo "Running $(NAME) in debug mode..."
	./$(BUILD_DIR)/$(NAME) -config configs/nothingdns.yaml -log-level debug

# Generate test coverage report
coverage: test-coverage

# Run fuzz tests
fuzz:
	@echo "Running fuzz tests..."
	$(GO) test -fuzz=FuzzMessage -fuzztime=30s ./internal/protocol/

# Show module dependencies (should be empty!)
deps:
	@echo "Module dependencies:"
	$(GO) list -m all | grep -v "^github.com/ecostack/nothingdns" || true
	@echo ""
	@echo "Direct dependencies:"
	$(GO) list -f '{{if not .Indirect}}{{.}}{{end}}' -m all | grep -v "^github.com/ecostack/nothingdns$$" || echo "None (zero dependencies!)"

# Verify zero dependencies
verify-zero-deps:
	@echo "Verifying zero dependencies..."
	@if [ -s go.sum ]; then \
		echo "ERROR: go.sum is not empty!"; \
		cat go.sum; \
		exit 1; \
	else \
		echo "OK: Zero dependencies verified (go.sum is empty)"; \
	fi

# Show help
help:
	@echo "NothingDNS Makefile targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  make build        - Build the main server binary"
	@echo "  make build-cli    - Build the CLI tool (dnsctl)"
	@echo "  make build-all    - Build both binaries"
	@echo "  make release      - Cross-compile for all platforms"
	@echo ""
	@echo "Test targets:"
	@echo "  make test         - Run all tests"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make bench        - Run benchmarks"
	@echo "  make fuzz         - Run fuzz tests"
	@echo ""
	@echo "Quality targets:"
	@echo "  make fmt          - Format code with go fmt"
	@echo "  make vet          - Run go vet"
	@echo "  make lint         - Run all linters"
	@echo ""
	@echo "Docker targets:"
	@echo "  make docker       - Build Docker image"
	@echo "  make docker-push  - Build and push Docker image"
	@echo ""
	@echo "Other targets:"
	@echo "  make run          - Build and run server locally"
	@echo "  make debug        - Run server with debug logging"
	@echo "  make install      - Install binaries to GOPATH/bin"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make deps         - Show module dependencies"
	@echo "  make verify-zero-deps - Verify go.sum is empty"
