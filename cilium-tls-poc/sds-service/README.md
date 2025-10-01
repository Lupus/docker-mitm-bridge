# Hybrid xDS/SDS Control Plane for TLS Interception

A lightweight xDS control plane that provides dynamic Envoy configuration and certificate provisioning for transparent TLS interception.

## Overview

This service implements a hybrid xDS/SDS control plane that:
- **Queries OPA**: Fetches domain list from OPA's `required_domains` rule on startup
- **Pre-generates certificates**: Creates TLS certificates for all domains using CA from Secret
- **Serves LDS**: Provides dynamic listener configuration with SNI-based filter chains
- **Serves SDS**: Delivers pre-generated certificates to Envoy on demand
- **Lightweight**: Minimal container image (~15MB) with statically compiled Go binary
- **Integrated**: Works seamlessly with Kyverno-injected sidecars

## Architecture

```
┌─────────────────────────────────────┐
│      OPA Sidecar (port 15020)       │
│  • Aggregates required_domains from │
│    policy configuration             │
└──────────────┬──────────────────────┘
               │ HTTP API query
               ▼
┌─────────────────────────────────────┐
│    xDS/SDS Control Plane (this)     │
│  1. Loads CA from K8s Secret        │
│  2. Queries OPA for domain list     │
│  3. Pre-generates all certificates  │
│  4. Caches certificates in memory   │
│  5. Serves LDS (listener config)    │
│  6. Serves SDS (certificates)       │
│  • gRPC port: 15090                 │
└──────────────┬──────────────────────┘
               │ xDS gRPC (LDS + SDS)
               ▼
┌─────────────────────────────────────┐
│          Envoy Proxy                │
│  • Connects to xDS on startup       │
│  • Receives dynamic listeners       │
│  • Requests certs for each domain   │
│  • Configures SNI-based routing     │
└─────────────────────────────────────┘
```

## Features

- **Hybrid xDS approach**: Combines benefits of static (known domains) and dynamic (xDS configuration) approaches
- **OPA integration**: Automatically discovers required domains from OPA policy
- **CA from Secret**: Loads CA certificate and key from Kubernetes Secret (not self-generated)
- **Pre-generation**: Creates all certificates at startup for fast serving
- **LDS (Listener Discovery Service)**: Dynamically configures Envoy listeners with per-domain filter chains
- **SDS (Secret Discovery Service)**: Serves pre-generated certificates on demand
- **Certificate caching**: Certificates cached in memory for repeated requests
- **SNI-based routing**: Each domain gets its own filter chain with SNI matching
- **Dynamic forward proxy**: Configures Envoy HTTP filters for upstream resolution
- **Minimal image**: Multi-stage Docker build with statically compiled binary

## Building

### Prerequisites

- Docker
- Access to push to `ghcr.io/lupus/docker-mitm-bridge`

### Build and Push

```bash
# Build and push in one command
make build-push

# Or separately
make build    # Build Docker image
make push     # Push to registry
```

The Dockerfile uses a multi-stage build:
1. **Build stage**: Uses `golang:1.23-alpine` to compile static binary
2. **Final stage**: Uses `scratch` for minimal image size (~5MB)

## Deployment

### Quick Start

```bash
# Deploy to Kubernetes
make deploy

# Check status
make status

# View logs
make logs
```

### Manual Deployment

```bash
# Create namespace and apply manifests
kubectl create namespace kyverno-intercept
kubectl apply -f k8s/

# Verify deployment
kubectl get pods -n kyverno-intercept -l app=sds-service
kubectl logs -n kyverno-intercept -l app=sds-service
```

### Full Rebuild and Redeploy

```bash
make redeploy  # Builds, pushes, deletes old deployment, and deploys new
```

## How It Works

### 1. Startup and Initialization Flow

```
1. SDS service container starts in pod
   ↓
2. Loads CA certificate and private key from mounted Secret
   ↓
3. Queries OPA HTTP API for required_domains list
   ↓
4. Pre-generates TLS certificates for all domains using CA
   ↓
5. Builds LDS listener configuration with filter chains per domain
   ↓
6. Starts gRPC server on port 15090
   ↓
7. Waits for Envoy to connect
```

### 2. Dynamic Configuration Flow

```
1. Envoy connects to xDS endpoint (localhost:15090)
   ↓
2. Envoy sends LDS request (ListenerDiscoveryService)
   ↓
3. SDS returns listener with:
   - tls_inspector filter for SNI extraction
   - Per-domain filter chains with SNI matching
   - ext_authz filter for OPA authorization
   - dynamic_forward_proxy filter for upstream
   ↓
4. Envoy sends SDS requests for each domain certificate
   ↓
5. SDS returns pre-generated certificates from cache
   ↓
6. Envoy configures and activates listener with all filter chains
```

### 3. Envoy Integration

Envoy bootstrap configuration (dynamic):

```yaml
dynamic_resources:
  lds_config:
    resource_api_version: V3
    api_config_source:
      api_type: GRPC
      transport_api_version: V3
      grpc_services:
      - envoy_grpc:
          cluster_name: xds_cluster

static_resources:
  clusters:
  - name: xds_cluster  # SDS service providing both LDS and SDS
    type: STATIC
    connect_timeout: 1s
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
    load_assignment:
      cluster_name: xds_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 15090
```

The service automatically configures:
- **SNI-based routing**: Each domain gets its own filter chain
- **TLS termination**: Using pre-generated certificates
- **ext_authz integration**: Queries OPA for authorization
- **Dynamic forward proxy**: Resolves and connects to upstream servers

## Testing

### Deploy Test Pod

```bash
kubectl apply -f k8s/test-pod.yaml
```

This creates:
- Envoy proxy configured to use SDS
- Test client container for making requests

### Test Certificate Generation

```bash
# Check Envoy logs to see SDS communication
kubectl logs -n kyverno-intercept sds-test -c envoy | grep -i sds

# Check SDS service logs to see certificate generation
kubectl logs -n kyverno-intercept -l app=sds-service | grep "Generating"

# Access Envoy admin interface
kubectl port-forward -n kyverno-intercept pod/sds-test 15000:15000
curl http://localhost:15000/config_dump | jq '.configs[] | select(.["@type"] | contains("Secret"))'
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SDS_GRPC_PORT` | Port for xDS/SDS gRPC server | `15090` |
| `CA_CERT_PATH` | Path to CA certificate in Secret mount | `/ca-secret/tls.crt` |
| `CA_KEY_PATH` | Path to CA private key in Secret mount | `/ca-secret/tls.key` |
| `OPA_URL` | OPA HTTP API endpoint | `http://localhost:15020` |

### Deployment Customization

Edit `k8s/deployment.yaml`:

```yaml
env:
- name: SDS_GRPC_PORT
  value: "8080"
- name: CA_OUTPUT_PATH
  value: /ca/ca-cert.pem
```

## Advantages of Hybrid Approach

### vs. Static Certificate Pre-generation
1. **No per-domain Secrets**: All certificates in memory, not stored individually
2. **Dynamic configuration**: Envoy listeners configured at runtime
3. **Easier updates**: Change OPA policy, restart pods - no Helm upgrade needed
4. **Smaller footprint**: Single CA Secret instead of dozens of certificate Secrets

### vs. Pure Dynamic SDS
1. **Known domains**: All domains defined in OPA policy upfront
2. **Pre-generation**: Faster first request (no generation delay)
3. **Simpler**: No need for on-the-fly certificate generation logic
4. **Predictable**: Domain list validated at startup, not discovered dynamically

## Limitations

1. **Domain list at startup**: All domains must be in OPA policy before pod starts
2. **No dynamic discovery**: Cannot intercept new domains without pod restart
3. **In-memory certificates**: Certificate cache lost on SDS service restart
4. **Single CA**: Uses shared CA from Secret, no per-domain CA support
5. **No certificate rotation**: Certificates valid for 1 year, no automatic renewal

## Future Improvements

Possible enhancements:

- [ ] Dynamic domain discovery (watch OPA policy changes, update listeners)
- [ ] Metrics endpoint (Prometheus-compatible stats from Envoy)
- [ ] Health checks (gRPC health protocol for Kubernetes probes)
- [ ] Certificate rotation (shorter TTL with automatic renewal)
- [ ] Multi-replica support (shared CA and certificate cache)
- [ ] Rate limiting configuration per domain
- [ ] Custom HTTP filters configuration via OPA

## Implementation Details

### Key Components

1. **LDSServer**: Implements Listener Discovery Service
   - Builds single listener on port 15001
   - Creates filter chain per domain with SNI matching
   - Adds tls_inspector for SNI extraction
   - Configures HTTP Connection Manager with ext_authz and dynamic_forward_proxy

2. **SDSServer**: Implements Secret Discovery Service
   - Serves pre-generated certificates from cache
   - Supports streaming and fetch modes
   - Handles certificate requests by resource name (domain)

3. **OPAClient**: Queries OPA for domain list
   - HTTP GET to `/v1/data/intercept/required_domains`
   - Parses JSON response for domain array
   - Used once at startup to build domain list

4. **CertificateAuthority**: Manages certificates
   - Loads CA from Kubernetes Secret mount
   - Generates certificates signed by CA
   - Caches certificates in memory map
   - Creates SAN certificates with CN and DNS alternative name

### File Structure

```
sds-service/
├── main.go              # Main entry point, initialization
├── Dockerfile           # Multi-stage build (Go → scratch)
├── docker-build-push.sh # Build and push script
├── Makefile            # Build, deploy, test targets
└── README.md           # This file
```

## Troubleshooting

### SDS service not starting

```bash
# Check pod status
kubectl get pods -n kyverno-intercept -l app=sds-service

# Check logs
kubectl logs -n kyverno-intercept -l app=sds-service

# Check events
kubectl get events -n kyverno-intercept --field-selector involvedObject.kind=Pod

# Check if image was pulled successfully
kubectl describe pod -n kyverno-intercept -l app=sds-service | grep -A 5 "Events:"
```

### Envoy not connecting to SDS

```bash
# Check Envoy logs
kubectl logs -n kyverno-intercept <pod-name> -c envoy-proxy | grep SDS

# Verify service DNS resolution
kubectl exec -n kyverno-intercept <pod-name> -c envoy-proxy -- \
  nslookup sds-service.kyverno-intercept.svc.cluster.local

# Check gRPC connectivity
kubectl exec -n kyverno-intercept <pod-name> -c envoy-proxy -- \
  nc -zv sds-service.kyverno-intercept.svc.cluster.local 8080
```

## License

See LICENSE file in parent repository.