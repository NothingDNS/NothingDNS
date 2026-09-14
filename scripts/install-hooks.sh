#!/bin/bash
# scripts/install-hooks.sh
# Installs git hooks for NothingDNS development

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS_DIR="$PROJECT_ROOT/.git/hooks"

echo "Installing NothingDNS git hooks..."

# Create hooks directory if it doesn't exist
mkdir -p "$HOOKS_DIR"

# Install pre-commit hook
if [ -f "$SCRIPT_DIR/pre-commit" ]; then
    cp "$SCRIPT_DIR/pre-commit" "$HOOKS_DIR/pre-commit"
    chmod +x "$HOOKS_DIR/pre-commit"
    echo "Installed pre-commit hook"
else
    echo "Warning: pre-commit script not found at $SCRIPT_DIR/pre-commit"
fi

echo "Done!"
echo ""
echo "Git hooks are now active. They will run before each commit:"
echo "  - go vet"
echo "  - gofmt check"
echo "  - Tests for modified packages"
echo "  - Build verification"