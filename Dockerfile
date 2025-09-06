# Build stage - Build Regorus Python bindings
FROM python:3.12-slim as regorus-builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install maturin
RUN pip install maturin

# Clone and build Regorus Python bindings
RUN git clone https://github.com/microsoft/regorus.git /tmp/regorus
WORKDIR /tmp/regorus/bindings/python
RUN maturin build --release

# Main stage - Python app with mitmproxy and OPA integration
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Regorus wheel from build stage  
COPY --from=regorus-builder /tmp/regorus/bindings/python/target/wheels/regorus*.whl /tmp/

# Upgrade pip and install Python dependencies
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir \
    mitmproxy==12.1.2 \
    PyYAML \
    /tmp/*.whl && \
    rm -rf /tmp/*.whl

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