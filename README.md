# Docker MITM Bridge

A tool to manage a persistent Docker network with HTTP/HTTPS filtering through mitmproxy and Open Policy Agent (OPA). This creates an isolated network environment where containers can only access the internet through a filtering proxy with configurable policies.

## Features

- **Persistent External Network**: Create a Docker network that persists across tool restarts and can be shared by multiple projects
- **HTTP/HTTPS Filtering**: All traffic goes through mitmproxy with OPA-based policy enforcement
- **Easy Certificate Management**: Simple CA certificate installation for containers via curl pipe bash
- **Policy-Based Access Control**: Configure allowed domains and HTTP methods through OPA policies
- **Web Interface**: Monitor traffic through mitmproxy's web UI
- **Multi-Project Support**: Any Docker project can join the filtered network

## Architecture

```
┌─────────────────────────────────────────────┐
│         docker-mitm-bridge tool             │
│  - Creates: "mitm-filtered" network         │
│  - Manages: boundary proxy container        │
└─────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────┐
│     "mitm-filtered" Docker Network          │
│         (Internal, no direct internet)      │
│                                             │
│  ┌──────────────┐      ┌─────────────┐      │
│  │  mitmproxy   │      │   Your      │      │
│  │  boundary    │◄─────│  Containers │      │
│  │  container   │      │             │      │
│  └──────┬───────┘      └─────────────┘      │
└─────────┴───────────────────────────────────┘
          │
          ▼
    Docker Bridge (internet)
```

## Prerequisites

- Docker and Docker Compose
- Python 3.7+
- pip

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/docker-mitm-bridge.git
cd docker-mitm-bridge
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Make the CLI executable:
```bash
chmod +x docker-mitm-bridge
```

## Quick Start

1. Initialize the network and start the boundary proxy:
```bash
./docker-mitm-bridge init
```

2. View the status:
```bash
./docker-mitm-bridge status
```

3. Access the mitmproxy web interface:
```
http://localhost:8081
```

## Using the Filtered Network

### From Docker Compose

Add this to your `docker-compose.yml`:

```yaml
networks:
  mitm-filtered:
    external: true
    name: mitm-filtered

services:
  your-service:
    image: your-image
    networks:
      - mitm-filtered
    environment:
      - HTTP_PROXY=http://mitm-boundary-proxy:8080
      - HTTPS_PROXY=http://mitm-boundary-proxy:8080
      - http_proxy=http://mitm-boundary-proxy:8080
      - https_proxy=http://mitm-boundary-proxy:8080
```

### Installing CA Certificate in Containers

From inside any container in the filtered network:

```bash
# Automatic installation
curl -sSL http://mitm-boundary-proxy:8080/install-ca.sh | bash

# Or download the certificate manually
curl -O http://mitm-boundary-proxy:8080/ca.crt
```

### From Docker Run

```bash
docker run -it \
  --network mitm-filtered \
  -e HTTP_PROXY=http://mitm-boundary-proxy:8080 \
  -e HTTPS_PROXY=http://mitm-boundary-proxy:8080 \
  ubuntu:latest bash
```

## CLI Commands

```bash
# Initialize network and start proxy
./docker-mitm-bridge init

# Start the proxy (network must exist)
./docker-mitm-bridge start

# Stop the proxy (network remains)
./docker-mitm-bridge stop

# Remove everything
./docker-mitm-bridge destroy

# Show status
./docker-mitm-bridge status

# List connected containers
./docker-mitm-bridge list-containers

# Export CA certificate
./docker-mitm-bridge get-ca

# Update OPA policies (restart proxy)
./docker-mitm-bridge update-policy

# View proxy logs
./docker-mitm-bridge logs

# Show configuration
./docker-mitm-bridge config

# Get docker-compose snippet for external projects
./docker-mitm-bridge get-compose-snippet
```

## Configuration

### Tool Configuration (`config.yaml`)

```yaml
network:
  name: mitm-filtered
  subnet: 172.30.0.0/16

proxy:
  container_name: mitm-boundary-proxy
  listen_port: 8080
  web_port: 8081
  
opa:
  policy_dir: ./opa-policies
```

### OPA Policies (`opa-policies/data.yaml`)

Configure allowed and unrestricted domains:

```yaml
# Domains with restricted access (only GET/HEAD allowed)
allowed_domains:
  - pypi.org
  - registry.npmjs.org
  - github.com
  
# Domains with unrestricted access (all HTTP methods allowed)
unrestricted_domains:
  - api.anthropic.com
  - api.openai.com
```

After modifying policies, apply changes:
```bash
./docker-mitm-bridge update-policy
```

## Example: Deploying an AI Agent

1. Create a Docker Compose file for your agent:

```yaml
version: '3.8'

networks:
  mitm-filtered:
    external: true
    name: mitm-filtered

services:
  ai-agent:
    image: python:3.10
    networks:
      - mitm-filtered
    environment:
      - HTTP_PROXY=http://mitm-boundary-proxy:8080
      - HTTPS_PROXY=http://mitm-boundary-proxy:8080
    volumes:
      - ./agent-code:/app
    working_dir: /app
    command: python agent.py
```

2. Install CA certificate in the container:

```dockerfile
FROM python:3.10

# Install CA certificate
RUN apt-get update && apt-get install -y curl ca-certificates
RUN curl -sSL http://mitm-boundary-proxy:8080/ca.crt -o /tmp/mitmproxy-ca.crt && \
    cp /tmp/mitmproxy-ca.crt /usr/local/share/ca-certificates/ && \
    update-ca-certificates

# Your application setup
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "agent.py"]
```

## Troubleshooting

### Network already exists
If you get an error about the network already existing, you can either:
- Use the existing network: `./docker-mitm-bridge start`
- Remove it first: `docker network rm mitm-filtered`

### Cannot remove network
If containers are still connected:
```bash
# List connected containers
./docker-mitm-bridge list-containers

# Stop all connected containers first
docker stop $(docker ps -q --filter network=mitm-filtered)
```

### Certificate errors
Make sure to install the CA certificate in your containers:
```bash
curl -sSL http://mitm-boundary-proxy:8080/install-ca.sh | bash
```

### Proxy not accessible
Ensure the proxy container is running:
```bash
./docker-mitm-bridge status
./docker-mitm-bridge start
```

## Security Considerations

- The mitmproxy CA certificate allows decryption of HTTPS traffic
- Only install the CA certificate in development/testing environments
- Configure OPA policies to restrict access to sensitive domains
- The filtered network has no direct internet access by design

## License

MIT