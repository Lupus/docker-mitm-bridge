#!/bin/bash
set -euo pipefail

# Generate test CA and certificates for multi-SNI testing
# This creates CA-signed certificates for two test domains on the same IP

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-${SCRIPT_DIR}/test-certs}"

mkdir -p "$OUTPUT_DIR"

echo "=== Generating Test CA and Certificates ==="
echo "Output directory: $OUTPUT_DIR"
echo

# 1. Generate CA private key
echo "1. Generating CA private key..."
openssl genrsa -out "$OUTPUT_DIR/test-ca.key" 2048

# 2. Generate CA certificate
echo "2. Generating CA certificate..."
openssl req -new -x509 -days 365 -key "$OUTPUT_DIR/test-ca.key" \
  -out "$OUTPUT_DIR/test-ca.crt" \
  -subj "/C=US/ST=CA/O=Test-CA/CN=Multi-SNI-Test-CA"

# 3. Generate server certificate for test-a.local
echo "3. Generating certificate for test-a.local..."
openssl genrsa -out "$OUTPUT_DIR/test-a.local.key" 2048
openssl req -new -key "$OUTPUT_DIR/test-a.local.key" \
  -out "$OUTPUT_DIR/test-a.local.csr" \
  -subj "/C=US/ST=CA/O=Test-A/CN=test-a.local"

# Create extensions file for SAN
cat > "$OUTPUT_DIR/test-a.ext" <<EOF
subjectAltName = DNS:test-a.local
EOF

openssl x509 -req -in "$OUTPUT_DIR/test-a.local.csr" \
  -CA "$OUTPUT_DIR/test-ca.crt" -CAkey "$OUTPUT_DIR/test-ca.key" \
  -CAcreateserial -out "$OUTPUT_DIR/test-a.local.crt" \
  -days 365 -extfile "$OUTPUT_DIR/test-a.ext"

# 4. Generate server certificate for test-b.local
echo "4. Generating certificate for test-b.local..."
openssl genrsa -out "$OUTPUT_DIR/test-b.local.key" 2048
openssl req -new -key "$OUTPUT_DIR/test-b.local.key" \
  -out "$OUTPUT_DIR/test-b.local.csr" \
  -subj "/C=US/ST=CA/O=Test-B/CN=test-b.local"

# Create extensions file for SAN
cat > "$OUTPUT_DIR/test-b.ext" <<EOF
subjectAltName = DNS:test-b.local
EOF

openssl x509 -req -in "$OUTPUT_DIR/test-b.local.csr" \
  -CA "$OUTPUT_DIR/test-ca.crt" -CAkey "$OUTPUT_DIR/test-ca.key" \
  -CAcreateserial -out "$OUTPUT_DIR/test-b.local.crt" \
  -days 365 -extfile "$OUTPUT_DIR/test-b.ext"

# 5. Verify certificates
echo
echo "=== Verifying Certificates ==="
echo "test-a.local certificate:"
openssl x509 -in "$OUTPUT_DIR/test-a.local.crt" -noout -subject -issuer
echo
echo "test-b.local certificate:"
openssl x509 -in "$OUTPUT_DIR/test-b.local.crt" -noout -subject -issuer

echo
echo "=== Certificate Generation Complete ==="
echo "Files created:"
echo "  CA: $OUTPUT_DIR/test-ca.crt, $OUTPUT_DIR/test-ca.key"
echo "  test-a.local: $OUTPUT_DIR/test-a.local.crt, $OUTPUT_DIR/test-a.local.key"
echo "  test-b.local: $OUTPUT_DIR/test-b.local.crt, $OUTPUT_DIR/test-b.local.key"
echo
echo "Next steps:"
echo "  1. Create Kubernetes Secrets from these certificates"
echo "  2. Configure nginx to use different certificates for each virtual server"
echo "  3. Configure Envoy to trust the test CA"
