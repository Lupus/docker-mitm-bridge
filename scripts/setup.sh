#!/bin/bash
# Complete Client Setup Script for mitmproxy
# This script configures proxy settings, apt proxy, shell environment, and installs CA certificate
# Usage: curl -sSL http://mitm-proxy:8080/setup.sh | bash

set -e

PROXY_HOST="${PROXY_HOST:-mitm-boundary-proxy}"
PROXY_PORT="${PROXY_PORT:-8080}"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"

echo "=== Setting up client for mitmproxy proxy ==="
echo "Proxy URL: $PROXY_URL"

# 1. Configure APT to use proxy
echo ""
echo "1. Configuring APT to use proxy..."
if [ -w /etc/apt/apt.conf.d/ ]; then
    cat > /etc/apt/apt.conf.d/01proxy <<EOF
Acquire::http::Proxy "$PROXY_URL";
Acquire::https::Proxy "$PROXY_URL";
EOF
    echo "   ✓ APT proxy configured system-wide"
elif command -v sudo >/dev/null 2>&1; then
    sudo tee /etc/apt/apt.conf.d/01proxy > /dev/null <<EOF
Acquire::http::Proxy "$PROXY_URL";
Acquire::https::Proxy "$PROXY_URL";
EOF
    echo "   ✓ APT proxy configured system-wide (using sudo)"
else
    mkdir -p ~/.apt
    cat > ~/.apt/proxy.conf <<EOF
Acquire::http::Proxy "$PROXY_URL";
Acquire::https::Proxy "$PROXY_URL";
EOF
    export APT_CONFIG=~/.apt/proxy.conf
    echo "   ✓ APT proxy configured for current user"
    echo "   Note: APT_CONFIG set to ~/.apt/proxy.conf"
fi

# 2. Configure shell environment variables
echo ""
echo "2. Configuring shell environment variables..."

# Function to add proxy variables to shell rc file
configure_shell_rc() {
    local rc_file="$1"
    local temp_file=$(mktemp)
    
    # Remove any existing proxy configurations
    if [ -f "$rc_file" ]; then
        grep -v -E '^(export )?(HTTP_PROXY|HTTPS_PROXY|http_proxy|https_proxy|NO_PROXY|no_proxy|NODE_EXTRA_CA_CERTS)=' "$rc_file" > "$temp_file" 2>/dev/null || true
        cp "$temp_file" "$rc_file"
    fi
    
    # Add new proxy configuration
    cat >> "$rc_file" <<EOF

# Proxy configuration for mitmproxy
export HTTP_PROXY="$PROXY_URL"
export HTTPS_PROXY="$PROXY_URL"
export http_proxy="$PROXY_URL"
export https_proxy="$PROXY_URL"
export NO_PROXY="localhost,127.0.0.1,$PROXY_HOST"
export no_proxy="localhost,127.0.0.1,$PROXY_HOST"
export NODE_EXTRA_CA_CERTS="/etc/ssl/certs/mitmproxy-ca.pem"
EOF
    
    rm -f "$temp_file"
}

# Configure for current user
if [ -n "$HOME" ]; then
    # Detect shell and configure appropriate rc file
    if [ -n "$BASH_VERSION" ] || [ "$SHELL" = "/bin/bash" ]; then
        configure_shell_rc "$HOME/.bashrc"
        echo "   ✓ Configured bash ($HOME/.bashrc)"
    fi
    
    if [ -n "$ZSH_VERSION" ] || [ "$SHELL" = "/bin/zsh" ]; then
        configure_shell_rc "$HOME/.zshrc"
        echo "   ✓ Configured zsh ($HOME/.zshrc)"
    fi
    
    # Also configure .profile for universal compatibility
    configure_shell_rc "$HOME/.profile"
    echo "   ✓ Configured universal profile ($HOME/.profile)"
    
    # Set environment variables for current session
    export HTTP_PROXY="$PROXY_URL"
    export HTTPS_PROXY="$PROXY_URL"
    export http_proxy="$PROXY_URL"
    export https_proxy="$PROXY_URL"
    export NO_PROXY="localhost,127.0.0.1,$PROXY_HOST"
    export no_proxy="localhost,127.0.0.1,$PROXY_HOST"
    export NODE_EXTRA_CA_CERTS="/etc/ssl/certs/mitmproxy-ca.pem"
    echo "   ✓ Environment variables set for current session"
else
    echo "   ⚠ Warning: HOME not set, skipping shell configuration"
fi

# 3. Download and install CA certificate
echo ""
echo "3. Installing mitmproxy CA certificate..."

# Detect the operating system
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "   ⚠ Warning: Cannot detect operating system, attempting generic installation"
    OS="unknown"
fi

# Download the CA certificate
echo "   Downloading CA certificate from ${PROXY_URL}/ca.crt..."
if curl -sSL "${PROXY_URL}/ca.crt" -o /tmp/mitmproxy-ca.crt; then
    echo "   ✓ CA certificate downloaded"
else
    echo "   ✗ Failed to download CA certificate"
    exit 1
fi

# Install based on OS
case "$OS" in
    ubuntu|debian)
        echo "   Installing for Ubuntu/Debian..."
        # Ensure ca-certificates is installed
        if ! command -v update-ca-certificates &> /dev/null; then
            if [ -w /var/lib/dpkg/ ]; then
                apt-get update && apt-get install -y ca-certificates
            elif command -v sudo >/dev/null 2>&1; then
                sudo apt-get update && sudo apt-get install -y ca-certificates
            else
                echo "   ⚠ Warning: Cannot install ca-certificates package"
            fi
        fi
        
        # Copy certificate to the trusted store and Node.js location
        if [ -w /usr/local/share/ca-certificates/ ]; then
            cp /tmp/mitmproxy-ca.crt /usr/local/share/ca-certificates/mitmproxy-ca.crt
            mkdir -p /etc/ssl/certs
            cp /tmp/mitmproxy-ca.crt /etc/ssl/certs/mitmproxy-ca.pem
            update-ca-certificates
        elif command -v sudo >/dev/null 2>&1; then
            sudo cp /tmp/mitmproxy-ca.crt /usr/local/share/ca-certificates/mitmproxy-ca.crt
            sudo mkdir -p /etc/ssl/certs
            sudo cp /tmp/mitmproxy-ca.crt /etc/ssl/certs/mitmproxy-ca.pem
            sudo update-ca-certificates
        else
            echo "   ⚠ Warning: Cannot install system-wide, trying user-level installation"
            mkdir -p ~/.local/share/ca-certificates
            cp /tmp/mitmproxy-ca.crt ~/.local/share/ca-certificates/
            export SSL_CERT_FILE=/tmp/mitmproxy-ca.crt
            export REQUESTS_CA_BUNDLE=/tmp/mitmproxy-ca.crt
            export NODE_EXTRA_CA_CERTS=/tmp/mitmproxy-ca.crt
            echo "   ✓ CA certificate installed for current user"
        fi
        echo "   ✓ CA certificate installed successfully"
        ;;
        
    alpine)
        echo "   Installing for Alpine Linux..."
        if ! command -v update-ca-certificates &> /dev/null; then
            if command -v apk >/dev/null 2>&1; then
                apk add --no-cache ca-certificates
            else
                echo "   ⚠ Warning: Cannot install ca-certificates package"
            fi
        fi
        
        if [ -w /usr/local/share/ca-certificates/ ]; then
            cp /tmp/mitmproxy-ca.crt /usr/local/share/ca-certificates/mitmproxy-ca.crt
            mkdir -p /etc/ssl/certs
            cp /tmp/mitmproxy-ca.crt /etc/ssl/certs/mitmproxy-ca.pem
            update-ca-certificates
        elif command -v sudo >/dev/null 2>&1; then
            sudo cp /tmp/mitmproxy-ca.crt /usr/local/share/ca-certificates/mitmproxy-ca.crt
            sudo mkdir -p /etc/ssl/certs
            sudo cp /tmp/mitmproxy-ca.crt /etc/ssl/certs/mitmproxy-ca.pem
            sudo update-ca-certificates
        fi
        echo "   ✓ CA certificate installed successfully"
        ;;
        
    centos|rhel|fedora|rocky|almalinux)
        echo "   Installing for RHEL-based system..."
        if ! command -v update-ca-trust &> /dev/null; then
            if command -v yum >/dev/null 2>&1; then
                yum install -y ca-certificates
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y ca-certificates
            else
                echo "   ⚠ Warning: Cannot install ca-certificates package"
            fi
        fi
        
        if [ -w /etc/pki/ca-trust/source/anchors/ ]; then
            cp /tmp/mitmproxy-ca.crt /etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt
            mkdir -p /etc/ssl/certs
            cp /tmp/mitmproxy-ca.crt /etc/ssl/certs/mitmproxy-ca.pem
            update-ca-trust
        elif command -v sudo >/dev/null 2>&1; then
            sudo cp /tmp/mitmproxy-ca.crt /etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt
            sudo mkdir -p /etc/ssl/certs
            sudo cp /tmp/mitmproxy-ca.crt /etc/ssl/certs/mitmproxy-ca.pem
            sudo update-ca-trust
        fi
        echo "   ✓ CA certificate installed successfully"
        ;;
        
    *)
        echo "   ⚠ Unsupported OS: $OS - attempting generic installation"
        mkdir -p ~/.local/share/ca-certificates
        cp /tmp/mitmproxy-ca.crt ~/.local/share/ca-certificates/
        
        # Also try to create the standard Node.js location
        if [ -w /etc/ssl/certs ] || command -v sudo >/dev/null 2>&1; then
            if [ -w /etc/ssl/certs ]; then
                mkdir -p /etc/ssl/certs
                cp /tmp/mitmproxy-ca.crt /etc/ssl/certs/mitmproxy-ca.pem
            else
                sudo mkdir -p /etc/ssl/certs
                sudo cp /tmp/mitmproxy-ca.crt /etc/ssl/certs/mitmproxy-ca.pem
            fi
        fi
        
        # Set certificate environment variables
        export SSL_CERT_FILE=/etc/ssl/certs/mitmproxy-ca.pem
        export REQUESTS_CA_BUNDLE=/etc/ssl/certs/mitmproxy-ca.pem
        export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/mitmproxy-ca.pem
        
        # Add to shell configuration
        if [ -n "$HOME" ]; then
            for rc_file in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
                if [ -f "$rc_file" ]; then
                    cat >> "$rc_file" <<EOF

# CA certificate configuration for mitmproxy
export SSL_CERT_FILE=/etc/ssl/certs/mitmproxy-ca.pem
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/mitmproxy-ca.pem
export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/mitmproxy-ca.pem
EOF
                fi
            done
        fi
        
        echo "   ✓ CA certificate configured for current user"
        echo ""
        echo "   Manual installation required for system-wide trust. Certificate saved to:"
        echo "   - /tmp/mitmproxy-ca.crt"
        echo "   - ~/.local/share/ca-certificates/"
        echo ""
        echo "   For manual system installation:"
        echo "   - Ubuntu/Debian: Copy to /usr/local/share/ca-certificates/ and run update-ca-certificates"
        echo "   - RHEL/CentOS: Copy to /etc/pki/ca-trust/source/anchors/ and run update-ca-trust"
        echo "   - Alpine: Copy to /usr/local/share/ca-certificates/ and run update-ca-certificates"
        ;;
esac

# 4. Test the configuration
echo ""
echo "4. Testing configuration..."

# Test proxy environment variables
echo "   Current proxy environment:"
echo "   - HTTP_PROXY: $HTTP_PROXY"
echo "   - HTTPS_PROXY: $HTTPS_PROXY"

# Test HTTPS connection through proxy
if command -v curl >/dev/null 2>&1; then
    echo "   Testing HTTPS connection through proxy..."
    if curl -s -o /dev/null -w "%{http_code}" https://github.com --proxy "$PROXY_URL" --max-time 10 | grep -q "200\|301\|302"; then
        echo "   ✓ HTTPS connections through proxy are working"
    else
        echo "   ⚠ Warning: Could not verify HTTPS connection through proxy"
    fi
else
    echo "   ⚠ curl not available, skipping connection test"
fi

# Clean up temporary files
rm -f /tmp/mitmproxy-ca.crt

echo ""
echo "=== Setup completed successfully! ==="
echo ""
echo "Summary of changes:"
echo "• APT configured to use proxy: $PROXY_URL"
echo "• Shell environment configured with proxy variables"
echo "• CA certificate installed and configured"
echo "• NODE_EXTRA_CA_CERTS set to /etc/ssl/certs/mitmproxy-ca.pem"
echo "• Current session environment variables set"
echo ""
echo "Note: For new shell sessions, proxy variables will be automatically loaded."
echo "To apply changes to current session immediately, run: source ~/.profile"
echo ""
echo "To test the setup:"
echo "  curl https://httpbin.org/ip"
echo "  apt update (if using apt)"