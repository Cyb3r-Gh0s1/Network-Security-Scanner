#!/bin/bash
# Quick runner script - automatically activates venv and runs scanner

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Run setup first: ./setup.sh"
    exit 1
fi

# Activate venv
source venv/bin/activate

# Run scanner with all arguments passed through
python network_scanner.py "$@"

# Deactivate when done
deactivate
