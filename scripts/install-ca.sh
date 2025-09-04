#!/bin/bash
# CA Certificate Installation Script for mitmproxy
# This script can be run inside containers to install the mitmproxy CA certificate

set -e

PROXY_HOST="${PROXY_HOST:-mitm-boundary-proxy}"
PROXY_PORT="${PROXY_PORT:-8080}"

echo "Installing mitmproxy CA certificate..."

# Detect the operating system
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect operating system"
    exit 1
fi

# Download the CA certificate
echo "Downloading CA certificate from http://${PROXY_HOST}:${PROXY_PORT}/ca.crt..."
curl -sSL "http://${PROXY_HOST}:${PROXY_PORT}/ca.crt" -o /tmp/mitmproxy-ca.crt

if [ ! -f /tmp/mitmproxy-ca.crt ]; then
    echo "Failed to download CA certificate"
    exit 1
fi

# Install based on OS
case "$OS" in
    ubuntu|debian)
        echo "Installing for Ubuntu/Debian..."
        # Ensure ca-certificates is installed
        if ! command -v update-ca-certificates &> /dev/null; then
            apt-get update && apt-get install -y ca-certificates
        fi
        # Copy certificate to the trusted store
        cp /tmp/mitmproxy-ca.crt /usr/local/share/ca-certificates/mitmproxy-ca.crt
        update-ca-certificates
        echo "CA certificate installed successfully"
        ;;
        
    alpine)
        echo "Installing for Alpine Linux..."
        # Ensure ca-certificates is installed
        if ! command -v update-ca-certificates &> /dev/null; then
            apk add --no-cache ca-certificates
        fi
        # Copy certificate to the trusted store
        cp /tmp/mitmproxy-ca.crt /usr/local/share/ca-certificates/mitmproxy-ca.crt
        update-ca-certificates
        echo "CA certificate installed successfully"
        ;;
        
    centos|rhel|fedora|rocky|almalinux)
        echo "Installing for RHEL-based system..."
        # Ensure ca-certificates is installed
        if ! command -v update-ca-trust &> /dev/null; then
            yum install -y ca-certificates || dnf install -y ca-certificates
        fi
        # Copy certificate to the trusted store
        cp /tmp/mitmproxy-ca.crt /etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt
        update-ca-trust
        echo "CA certificate installed successfully"
        ;;
        
    *)
        echo "Unsupported OS: $OS"
        echo "Manual installation required. Certificate saved to /tmp/mitmproxy-ca.crt"
        echo ""
        echo "For manual installation:"
        echo "- Ubuntu/Debian: Copy to /usr/local/share/ca-certificates/ and run update-ca-certificates"
        echo "- RHEL/CentOS: Copy to /etc/pki/ca-trust/source/anchors/ and run update-ca-trust"
        echo "- Alpine: Copy to /usr/local/share/ca-certificates/ and run update-ca-certificates"
        exit 1
        ;;
esac

# Clean up
rm -f /tmp/mitmproxy-ca.crt

# Test the certificate installation
echo ""
echo "Testing HTTPS connection through proxy..."
if curl -s -o /dev/null -w "%{http_code}" https://github.com --proxy "http://${PROXY_HOST}:${PROXY_PORT}" | grep -q "200\|301\|302"; then
    echo "Success! HTTPS connections through the proxy are working."
else
    echo "Warning: Could not verify HTTPS connection. Please check proxy settings."
fi

echo ""
echo "CA certificate installation complete!"
echo "HTTP_PROXY and HTTPS_PROXY should be set to: http://${PROXY_HOST}:${PROXY_PORT}"