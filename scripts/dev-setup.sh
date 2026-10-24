#!/bin/bash
# NothingDNS Development Environment Setup v1.1
# Run: ./scripts/dev-setup.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Check prerequisites
check_prereq() {
    print_step "Checking prerequisites..."

    local missing=()

    if ! command -v go &> /dev/null; then
        missing+=("Go")
    fi

    if ! command -v git &> /dev/null; then
        missing+=("Git")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        print_error "Missing dependencies: ${missing[*]}"
        echo "Please install:"
        echo "  - Go 1.26.9+: https://go.dev/dl/"
        echo "  - Git: https://git-scm.com/"
        exit 1
    fi

    print_success "Prerequisites OK"
}

# Install Go tools
install_tools() {
    print_step "Installing Go tools..."

    go install golang.org/x/vuln/cmd/govulncheck@latest
    go install honnef.co/go/tools/cmd/staticcheck@latest
    go install golang.org/x/tools/cmd/goimports@latest

    print_success "Go tools installed"
}

# Setup git hooks
setup_hooks() {
    print_step "Setting up git hooks..."

    HOOKS_DIR=".git/hooks"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Create pre-commit hook
    if [ ! -f "$HOOKS_DIR/pre-commit" ] || [ "$(readlink -f "$HOOKS_DIR/pre-commit" 2>/dev/null)" != "$SCRIPT_DIR/pre-commit" ]; then
        ln -sf "$SCRIPT_DIR/pre-commit" "$HOOKS_DIR/pre-commit"
        chmod +x "$SCRIPT_DIR/pre-commit"
        print_success "Git hooks installed"
    else
        print_success "Git hooks already installed"
    fi
}

# Setup web dashboard dependencies
setup_web() {
    print_step "Setting up web dashboard..."

    if [ ! -d "web" ] && [ -f "web/package.json" ]; then
        print_warning "web/ directory not found, skipping npm setup"
        return
    fi

    if command -v npm &> /dev/null; then
        cd web
        npm install
        cd ..
        print_success "Web dependencies installed"
    else
        print_warning "npm not found, skipping web setup"
    fi
}

# Create necessary directories
setup_dirs() {
    print_step "Creating directories..."

    mkdir -p /tmp/nothingdns-test-zones
    mkdir -p /tmp/nothingdns-test-data

    print_success "Directories created"
}

# Download root hints
download_hints() {
    print_step "Downloading root hints..."

    HINTS_FILE="internal/resolver/root.hints"
    if [ ! -f "$HINTS_FILE" ]; then
        curl -sSL "https://www.internic.net/domain/named.root" -o "$HINTS_FILE" 2>/dev/null || true
        if [ -f "$HINTS_FILE" ]; then
            print_success "Root hints downloaded"
        else
            print_warning "Could not download root hints (optional)"
        fi
    else
        print_success "Root hints already exist"
    fi
}

# Verify build
verify_build() {
    print_step "Verifying build..."

    if go build -o /tmp/nothingdns-test ./cmd/nothingdns; then
        print_success "Build verified"
        rm -f /tmp/nothingdns-test
    else
        print_error "Build failed"
        exit 1
    fi
}

# Run tests
run_tests() {
    print_step "Running tests..."

    if go test -short ./...; then
        print_success "Tests passed"
    else
        print_error "Some tests failed"
        exit 1
    fi
}

# Main
main() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   NothingDNS Development Setup          ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
    echo ""

    check_prereq
    install_tools
    setup_hooks
    setup_web
    setup_dirs
    download_hints
    verify_build
    run_tests

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   Setup Complete!                        ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Copy config.example.yaml to config.yaml and customize"
    echo "  2. Run: go run ./cmd/nothingdns"
    echo "  3. Or run tests: go test -short ./..."
    echo ""
}

main "$@"