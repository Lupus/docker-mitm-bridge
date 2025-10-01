# Full Dynamic xDS Control Plane for TLS Interception

A lightweight xDS control plane that provides complete dynamic Envoy configuration and certificate provisioning for transparent TLS interception.

## Overview

This service implements a full dynamic xDS control plane that:
- **Queries OPA**: Fetches domain list from OPA's `required_domains` rule on startup
- **Pre-generates certificates**: Creates TLS certificates for all domains using CA from Secret
- **Serves CDS**: Provides dynamic cluster configuration (ext_authz, dynamic_forward_proxy)
- **Serves LDS**: Provides dynamic listener configuration with SNI-based filter chains
- **Serves SDS**: Delivers pre-generated certificates to Envoy on demand
- **Single Source of Truth**: All Envoy configuration managed in Go code, minimal bootstrap
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
│  Full Dynamic xDS Control Plane     │
│              (this)                 │
│  1. Loads CA from K8s Secret        │
│  2. Queries OPA for domain list     │
│  3. Pre-generates all certificates  │
│  4. Caches certificates in memory   │
│  5. Serves CDS (cluster config)     │
│  6. Serves LDS (listener config)    │
│  7. Serves SDS (certificates)       │
│  • gRPC port: 15090                 │
└──────────────┬──────────────────────┘
               │ xDS gRPC (CDS+LDS+SDS)
               ▼
┌─────────────────────────────────────┐
│          Envoy Proxy                │
│  • Minimal bootstrap (xds_cluster)  │
│  • Receives dynamic clusters (CDS)  │
│  • Receives dynamic listeners (LDS) │
│  • Requests certs for domains (SDS) │
│  • Configures SNI-based routing     │
└─────────────────────────────────────┘
```

## Features

- **Full Dynamic xDS**: Follows Envoy best practices with minimal bootstrap, all config via xDS
- **Single Source of Truth**: All Envoy configuration (clusters, listeners, secrets) managed in one place
- **OPA integration**: Automatically discovers required domains from OPA policy
- **CA from Secret**: Loads CA certificate and key from Kubernetes Secret (not self-generated)
- **Pre-generation**: Creates all certificates at startup for fast serving
- **CDS (Cluster Discovery Service)**: Dynamically provides ext_authz and dynamic_forward_proxy clusters
- **LDS (Listener Discovery Service)**: Dynamically configures Envoy listeners with per-domain filter chains
- **SDS (Secret Discovery Service)**: Serves pre-generated certificates on demand
- **Certificate caching**: Certificates cached in memory for repeated requests
- **SNI-based routing**: Each domain gets its own filter chain with SNI matching
- **Minimal bootstrap**: Envoy bootstrap contains ONLY xds_cluster, everything else via xDS
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
1. xDS Control Plane starts in pod
   ↓
2. Loads CA certificate and private key from mounted Secret
   ↓
3. Queries OPA HTTP API for required_domains list
   ↓
4. Pre-generates TLS certificates for all domains using CA
   ↓
5. Builds CDS cluster configuration (ext_authz, dynamic_forward_proxy)
   ↓
6. Builds LDS listener configuration with filter chains per domain
   ↓
7. Starts gRPC server on port 15090
   ↓
8. Waits for Envoy to connect
```

### 2. Dynamic Configuration Flow

```
1. Envoy starts with minimal bootstrap → connects to xDS (localhost:15090)
   ↓
2. Envoy sends CDS request (ClusterDiscoveryService)
   ↓
3. xDS returns 2 clusters:
   - ext_authz_cluster (gRPC to OPA on port 15021)
   - dynamic_forward_proxy_cluster (for upstream connections)
   ↓
4. Envoy sends LDS request (ListenerDiscoveryService)
   ↓
5. xDS returns listener with:
   - tls_inspector filter for SNI extraction
   - Per-domain filter chains with SNI matching
   - ext_authz filter referencing ext_authz_cluster
   - dynamic_forward_proxy filter referencing dynamic_forward_proxy_cluster
   ↓
6. Envoy sends SDS requests for each domain certificate
   ↓
7. xDS returns pre-generated certificates from cache
   ↓
8. Envoy activates with fully dynamic configuration
```

### 3. Envoy Integration

Envoy bootstrap configuration (minimal - follows best practices):

```yaml
node:
  id: envoy-sidecar
  cluster: intercept-proxy

admin:
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 15000

dynamic_resources:
  cds_config:  # Cluster Discovery Service
    resource_api_version: V3
    api_config_source:
      api_type: GRPC
      transport_api_version: V3
      grpc_services:
      - envoy_grpc:
          cluster_name: xds_cluster

  lds_config:  # Listener Discovery Service
    resource_api_version: V3
    api_config_source:
      api_type: GRPC
      transport_api_version: V3
      grpc_services:
      - envoy_grpc:
          cluster_name: xds_cluster

static_resources:
  clusters:
  # ONLY xds_cluster - everything else provided dynamically
  - name: xds_cluster
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

The control plane automatically configures via xDS:
- **Clusters (CDS)**: ext_authz_cluster, dynamic_forward_proxy_cluster
- **Listeners (LDS)**: SNI-based routing with per-domain filter chains
- **Secrets (SDS)**: TLS certificates for each intercepted domain
- **ext_authz integration**: Queries OPA for authorization decisions
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
| `OPA_GRPC_PORT` | OPA gRPC ext_authz port (for CDS config) | `15021` |

### Deployment Customization

Edit `k8s/deployment.yaml`:

```yaml
env:
- name: SDS_GRPC_PORT
  value: "8080"
- name: CA_OUTPUT_PATH
  value: /ca/ca-cert.pem
```

## Advantages of Full Dynamic xDS Approach

### vs. Static Configuration
1. **Single Source of Truth**: All Envoy config (clusters, listeners, secrets) in one place (Go code)
2. **No Circular Dependencies**: Bootstrap only contains xDS cluster, everything else via xDS
3. **Follows Best Practices**: Aligns with Envoy documentation and production service meshes (Istio, Consul)
4. **Easier Maintenance**: Change cluster config without touching YAML templates
5. **Dynamic configuration**: All resources configured at runtime via xDS

### vs. Hybrid Static/Dynamic
1. **No per-domain Secrets**: All certificates in memory, not stored individually
2. **Minimal bootstrap**: Envoy bootstrap contains ONLY xds_cluster
3. **Easier updates**: Change OPA policy, restart pods - no Helm upgrade needed
4. **Smaller footprint**: Single CA Secret instead of dozens of certificate Secrets
5. **Predictable**: Domain list validated at startup, known set of domains

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

1. **CDSServer**: Implements Cluster Discovery Service
   - Provides ext_authz_cluster (gRPC to OPA on port 15021)
   - Provides dynamic_forward_proxy_cluster (for upstream connections)
   - Supports streaming and fetch modes
   - Configures HTTP/2 protocol options for gRPC clusters

2. **LDSServer**: Implements Listener Discovery Service
   - Builds single listener on port 15001
   - Creates filter chain per domain with SNI matching
   - Adds tls_inspector for SNI extraction
   - Configures HTTP Connection Manager with ext_authz and dynamic_forward_proxy

3. **SDSServer**: Implements Secret Discovery Service
   - Serves pre-generated certificates from cache
   - Supports streaming and fetch modes
   - Handles certificate requests by resource name (domain)

4. **OPAClient**: Queries OPA for domain list
   - HTTP GET to `/v1/data/intercept/required_domains`
   - Parses JSON response for domain array
   - Used once at startup to build domain list

5. **CertificateAuthority**: Manages certificates
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