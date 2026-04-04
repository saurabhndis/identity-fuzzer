#!/usr/bin/env bash
# generate_certs.sh — Generate self-signed SSL certificates for AD Simulator LDAPS
#
# Usage:
#   ./certs/generate_certs.sh [domain] [output_dir]
#
# Defaults:
#   domain     = testlab.local
#   output_dir = ./certs

set -euo pipefail

DOMAIN="${1:-testlab.local}"
OUTPUT_DIR="${2:-./certs}"

# Use the Python-based generator from the ad_simulator package
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Generating self-signed certificates for ${DOMAIN}..."
echo "Output directory: ${OUTPUT_DIR}"

cd "${SCRIPT_DIR}"

if [ -f ".venv/bin/python" ]; then
    .venv/bin/python -c "
from ad_simulator.server.ssl_config import generate_server_certs
cert, key = generate_server_certs('${DOMAIN}', '${OUTPUT_DIR}')
print(f'Certificate: {cert}')
print(f'Private key: {key}')
print('Done!')
"
else
    echo "Virtual environment not found. Using system Python..."
    python3 -c "
import sys
sys.path.insert(0, 'src')
from ad_simulator.server.ssl_config import generate_server_certs
cert, key = generate_server_certs('${DOMAIN}', '${OUTPUT_DIR}')
print(f'Certificate: {cert}')
print(f'Private key: {key}')
print('Done!')
"
fi
