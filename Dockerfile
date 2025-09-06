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

# Python dependencies stage - Install all Python packages
FROM python:3.12-slim as python-builder

# Install system dependencies needed for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt /tmp/requirements.txt

# Copy Regorus wheel from build stage  
COPY --from=regorus-builder /tmp/regorus/bindings/python/target/wheels/regorus*.whl /tmp/

# Create virtual environment and install all dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# Upgrade pip and install Python dependencies
RUN /opt/venv/bin/python -m pip install --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir \
    mitmproxy==12.1.2 \
    PyYAML \
    /tmp/*.whl \
    -r /tmp/requirements.txt

# Final stage - Minimal Python slim image (compatible with glibc dependencies)
FROM python:3.12-slim

# Remove unnecessary packages to minimize attack surface
RUN apt-get update && apt-get remove -y \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && find /usr -type f -name "*.pyc" -delete \
    && find /usr -type f -name "*.pyo" -delete

# Copy Python virtual environment from builder stage
COPY --from=python-builder /opt/venv /opt/venv

# Set environment to use the virtual environment
ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONPATH="/opt/venv/lib/python3.12/site-packages"
ENV VIRTUAL_ENV="/opt/venv"

# Set the working directory in the container
WORKDIR /app

# Create non-root user and directories
RUN groupadd --gid 3000 mitmproxy && \
    useradd --uid 3000 --gid 3000 --create-home --shell /bin/bash mitmproxy && \
    mkdir -p /app/bundle /app/opa-output /scripts /home/mitmproxy/.mitmproxy && \
    chown -R 3000:3000 /home/mitmproxy /app/opa-output

# Copy application files
COPY docker/mitmproxy_opa /app/mitmproxy_opa
COPY docker/scripts/run_opa_filter.py /scripts/run_opa_filter.py
COPY scripts/entrypoint.sh /entrypoint.sh
COPY scripts/install-ca.sh /scripts/install-ca.sh
COPY scripts/setup.sh /scripts/setup.sh

# Set proper permissions
RUN chmod +x /entrypoint.sh /scripts/install-ca.sh /scripts/setup.sh /scripts/run_opa_filter.py && \
    chmod -R 755 /scripts

# Run as non-root user
USER 3000:3000

# Expose ports
EXPOSE 8080 8081

# Use the entrypoint script
ENTRYPOINT ["/entrypoint.sh"]