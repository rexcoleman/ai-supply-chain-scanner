#!/bin/bash
# Reproduce all experiments from scratch.
# Usage: bash reproduce.sh
set -euo pipefail

GOVML_DIR="$HOME/ml-governance-templates"

echo "=== AI Supply Chain Scanner — Reproduction ==="

# Run tests if they exist
if [ -d tests ]; then
    echo "--- Running tests ---"
    python -m pytest tests/ -v --tb=short
fi

# --- Gate Validation (R50) ---
if [ -f "$GOVML_DIR/scripts/check_all_gates.sh" ]; then
    echo "--- Gate Validation (R50) ---"
    bash "$GOVML_DIR/scripts/check_all_gates.sh" .
else
    echo "WARN: govML not found at $GOVML_DIR — skipping gate validation"
    echo "  Install: git clone <govml-repo> $GOVML_DIR"
fi
