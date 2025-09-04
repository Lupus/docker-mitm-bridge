#!/bin/sh
set -e

# Default values
LISTEN_HOST="${LISTEN_HOST:-0.0.0.0}"
LISTEN_PORT="${LISTEN_PORT:-8080}"

# Build OPA bundle from mounted policy files
if [ ! -d "/app/bundle" ] || [ -z "$(ls -A /app/bundle 2>/dev/null)" ]; then
    echo "Error: No policy files found in /app/bundle/"
    echo "Please mount the opa-policies directory to /app/bundle"
    exit 1
fi

echo "Building OPA bundle from mounted policy files..."

# Create a clean directory to avoid symlink issues with ConfigMap
mkdir -p /tmp/opa-build
cp /app/bundle/*.rego /tmp/opa-build/ 2>/dev/null || true
cp /app/bundle/*.yaml /tmp/opa-build/ 2>/dev/null || true
cp /app/bundle/*.json /tmp/opa-build/ 2>/dev/null || true

# Build the WASM bundle with the correct entrypoint
/usr/local/bin/opa build -t wasm -e mitmproxy/policy/decision /tmp/opa-build -o /app/opa-output/bundle.tar.gz

# Clean up
rm -rf /tmp/opa-build
echo "OPA bundle built successfully"

# Add custom addon for serving CA certificate and install script
cat > /tmp/cert_server.py << 'ADDON_EOF'
from mitmproxy import http
import base64

class CertServer:
    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.path == "/ca.crt":
            # Serve the CA certificate
            with open("/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem", "rb") as f:
                cert_data = f.read()
            flow.response = http.Response.make(
                200,
                cert_data,
                {"Content-Type": "application/x-pem-file",
                 "Content-Disposition": "attachment; filename=mitmproxy-ca.crt"}
            )
        elif flow.request.path == "/install-ca.sh":
            # Serve the installation script
            with open("/scripts/install-ca.sh", "r") as f:
                script_data = f.read()
            flow.response = http.Response.make(
                200,
                script_data,
                {"Content-Type": "text/plain"}
            )
        elif flow.request.path == "/setup.sh":
            # Serve the complete setup script
            with open("/scripts/setup.sh", "r") as f:
                script_data = f.read()
            flow.response = http.Response.make(
                200,
                script_data,
                {"Content-Type": "text/plain"}
            )

addons = [CertServer()]
ADDON_EOF

# Run mitmdump with both addons (no web interface for security)
exec mitmdump \
    --listen-host "$LISTEN_HOST" \
    --listen-port "$LISTEN_PORT" \
    --set block_global=false \
    --set confdir=/home/mitmproxy/.mitmproxy \
    --scripts /scripts/run_opa_filter.py \
    --scripts /tmp/cert_server.py \
    "$@"