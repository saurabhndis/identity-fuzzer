#!/bin/bash
# Post-removal script for Identity Fuzzer .deb package

set -e

# Update desktop database
if command -v update-desktop-database > /dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications 2>/dev/null || true
fi

# Clean up any cached Python files
if [ "$1" = "purge" ]; then
    rm -rf "/opt/Identity Fuzzer" 2>/dev/null || true
fi
