# Main stage - Python app with mitmproxy and OPA integration
FROM python:3.12-slim

# Copy OPA binary from static image
COPY --from=openpolicyagent/opa:latest-static /opa /usr/local/bin/opa

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip and install Python dependencies
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir \
    mitmproxy==12.1.2 \
    opa-wasm==0.3.2 \
    wasmer==1.1.0 \
    wasmer-compiler-cranelift==1.1.0

# Create directories
RUN mkdir -p /app/bundle /app/opa-output /scripts

# Copy OPA filter addon package
COPY docker/mitmproxy_opa /app/mitmproxy_opa

# Copy addon loader script
COPY docker/scripts/run_opa_filter.py /scripts/run_opa_filter.py

# Copy scripts
COPY scripts/entrypoint.sh /entrypoint.sh
COPY scripts/install-ca.sh /scripts/install-ca.sh
COPY scripts/setup.sh /scripts/setup.sh
RUN chmod +x /entrypoint.sh /scripts/install-ca.sh /scripts/setup.sh

# Create mitmproxy user
RUN groupadd --gid 3000 mitmproxy && \
    useradd --uid 3000 --gid 3000 --create-home --shell /bin/bash mitmproxy

# Create mitmproxy config directory and set ownership
RUN mkdir -p /home/mitmproxy/.mitmproxy && \
    chown -R 3000:3000 /home/mitmproxy && \
    chown -R 3000:3000 /app/opa-output

# Set proper permissions for scripts
RUN chmod -R 755 /scripts && \
    chmod +x /scripts/run_opa_filter.py

# Run as mitmproxy user
USER 3000

# Expose ports
EXPOSE 8080 8081

# Use the entrypoint script
ENTRYPOINT ["/entrypoint.sh"]