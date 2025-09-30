# Kyverno TLS Intercept Chart

A Helm chart for transparent TLS/HTTPS interception using Kyverno policy-based sidecar injection with Envoy proxy and OPA policy enforcement via gRPC.

## Overview

This Helm chart provides a complete TLS interception solution that:
- Uses **Kyverno** to automatically inject Envoy proxy sidecars into annotated pods
- Performs **TLS interception** with pre-generated certificates for known domains
- Enforces **OPA policies** via gRPC ext_authz for fine-grained access control
- Works transparently with existing applications via iptables rules (no proxy environment variables needed)
- Implements **Istio-style port isolation** for security and stability

## Architecture

```
┌──────────────────────────────────────────────────┐
│              Application Pod                     │
├──────────────────────────────────────────────────┤
│ Init Container (proxy-init):                     │
│ • Installs CA certificate                        │
│ • Sets up iptables NAT rules (redirect traffic)  │
│ • Sets up iptables FILTER rules (port isolation) │
│ • UID-based exclusion (prevents infinite loops)  │
├──────────────────────────────────────────────────┤
│ Envoy Sidecar (UID 101):                        │
│ • Proxy port: 15001 (HTTPS traffic)             │
│ • Admin port: 15000 (metrics/config)            │
│ • TLS termination with internal CA              │
│ • gRPC ext_authz to OPA                         │
│ • Upstream TLS re-encryption                    │
├──────────────────────────────────────────────────┤
│ OPA Sidecar (UID 102):                          │
│ • HTTP API: 15020 (health checks)               │
│ • gRPC authz: 15021 (Envoy queries)             │
│ • Policy evaluation and decision logs           │
├──────────────────────────────────────────────────┤
│ Application Container(s) (UID 1000):            │
│ • No proxy env vars needed                      │
│ • Traffic via iptables redirect                 │
│ • CA cert auto-trusted                          │
│ • Can use localhost for development             │
│ • Blocked from sidecar ports (15000-15099)      │
└──────────────────────────────────────────────────┘
```

## Key Features

### UID-Based Traffic Isolation
- **Prevents infinite loops**: Envoy and OPA traffic excluded from redirection by UID
- **Port isolation**: Main container cannot access sidecar infrastructure ports (15000-15099)
- **Security**: All sidecars run as non-root with dropped capabilities

### Port Allocation (Istio-style)
- **15000-15099**: Reserved for sidecar infrastructure
- **15001**: Envoy proxy port (HTTPS redirection target)
- **15000**: Envoy admin interface
- **15020**: OPA HTTP API (health checks)
- **15021**: OPA gRPC ext_authz (Envoy communication)
- **1024-14999, 15100-65535**: Available for application use on localhost

## Prerequisites

- Kubernetes cluster (1.24+)
- Kyverno installed in the cluster
- Helm 3.x

### Installing Kyverno

```bash
# Install Kyverno if not already present
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
```

## Installation

### Quick Start

```bash
# Install the chart with namespace creation (recommended)
helm install intercept-proxy ./kyverno-intercept-chart \
  --create-namespace -n kyverno-intercept

# Verify installation
kubectl get pods -n kyverno-intercept
kubectl get clusterpolicy intercept-proxy-inject-proxy
```

### Custom Configuration

Create a custom `values.yaml`:

```yaml
# Configure domains to intercept
interceptDomains:
  github:
    enabled: true
    domains:
      - "github.com"
      - "api.github.com"

  custom:
    enabled: true
    domains:
      - "internal-api.company.com"

# Configure Envoy
envoy:
  port: 15001      # Proxy port
  adminPort: 15000 # Admin interface
  uid: 101         # Run as UID 101
  gid: 101
  resources:
    limits:
      memory: "512Mi"
      cpu: "500m"

# Configure OPA
opa:
  port: 15020      # HTTP API
  grpcPort: 15021  # gRPC ext_authz
  uid: 102         # Run as UID 102
  gid: 102
  policy:
    allowedDomains:
      - "github.com"
      - "internal-api.company.com"
    githubAllowedRepos:
      - "myorg/myrepo"

# Configure port isolation
initContainer:
  sidecarPortRangeStart: 15000  # Start of reserved range
  sidecarPortRangeEnd: 15099    # End of reserved range
  privilegedPortEnd: 1023       # Block privileged ports
```

Install with custom values:

```bash
helm install intercept-proxy ./kyverno-intercept-chart \
  --create-namespace -n kyverno-intercept \
  -f custom-values.yaml
```

## Usage

### Enabling Interception for a Pod

Add the label to your pod/deployment to enable interception:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    metadata:
      labels:
        intercept-proxy/enabled: "true"  # This triggers sidecar injection
    spec:
      containers:
      - name: my-app
        image: my-app:latest
```

### Testing the Setup

Deploy a test application:

```bash
# Create test deployment
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: kyverno-intercept
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-app
  template:
    metadata:
      labels:
        app: test-app
        intercept-proxy/enabled: "true"
    spec:
      containers:
      - name: test
        image: curlimages/curl:latest
        command: ["sleep", "3600"]
EOF

# Wait for pod to be ready (all 3 containers)
kubectl wait --for=condition=ready pod -l app=test-app -n kyverno-intercept

# Test HTTPS interception (no -k flag needed!)
kubectl exec -n kyverno-intercept deploy/test-app -c test -- \
  curl -I https://api.github.com

# Verify certificate is from internal CA
kubectl exec -n kyverno-intercept deploy/test-app -c test -- \
  curl -v https://api.github.com 2>&1 | grep "issuer:"
# Should show: issuer: C=US; ST=CA; O=Internal-CA; CN=Kyverno-Intercept-CA

# Test OPA policy enforcement (POST should be blocked)
kubectl exec -n kyverno-intercept deploy/test-app -c test -- \
  curl -X POST https://api.github.com/user
# Should return: 403 Forbidden

# Verify port isolation (should fail)
kubectl exec -n kyverno-intercept deploy/test-app -c test -- \
  curl http://localhost:15000
# Should timeout or be rejected
```

## How It Works

### 1. Certificate Generation
- On installation, a Helm hook job generates:
  - Internal CA certificate
  - TLS certificates for all configured domains
- Certificates are stored as Kubernetes secrets

### 2. Sidecar Injection
When a pod with label `intercept-proxy/enabled: true` is created:
- **Init Container**: Sets up iptables rules for traffic redirection and port isolation
- **Envoy Sidecar**: Handles TLS interception and forwarding
- **OPA Sidecar**: Evaluates access policies

### 3. Traffic Flow
1. Application makes HTTPS request
2. iptables NAT redirects to Envoy (port 15001) - no proxy env vars needed
3. Envoy terminates TLS using pre-generated certificate
4. Envoy queries OPA via gRPC (port 15021) for authorization
5. OPA evaluates policy and returns allow/deny decision
6. If allowed, Envoy re-encrypts and forwards to destination

### 4. iptables Rules

The init container sets up two sets of rules:

**NAT Table (Traffic Redirection)**:
- Exclude Envoy traffic (UID 101) to prevent infinite loops
- Exclude OPA traffic (UID 102) to prevent infinite loops
- Redirect ports 80/443 to Envoy proxy port (15001)

**FILTER Table (Port Isolation)**:
- Allow all traffic from Envoy (UID 101) and OPA (UID 102)
- Block main container from accessing privileged ports (0-1023)
- Allow main container to reach Envoy proxy port (15001) after NAT redirect
- Block main container from accessing sidecar ports (15000-15099)
- Allow main container to use other localhost ports for development
- Allow DNS resolution (port 53)
- Allow outbound HTTP/HTTPS (will be redirected by NAT)
- Drop all other traffic from main container

## Configuration Reference

### Key Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `namespace` | Namespace for chart resources | `kyverno-intercept` |
| `ca.generate` | Generate internal CA | `true` |
| `interceptDomains` | Domains to intercept (grouped) | See values.yaml |
| **Envoy Configuration** | | |
| `envoy.image` | Envoy proxy image | `envoyproxy/envoy:v1.28-latest` |
| `envoy.port` | Envoy proxy port | `15001` |
| `envoy.adminPort` | Envoy admin interface port | `15000` |
| `envoy.uid` | Run Envoy as UID | `101` |
| `envoy.gid` | Run Envoy as GID | `101` |
| **OPA Configuration** | | |
| `opa.enabled` | Enable OPA policy enforcement | `true` |
| `opa.port` | OPA HTTP API port | `15020` |
| `opa.grpcPort` | OPA gRPC ext_authz port | `15021` |
| `opa.uid` | Run OPA as UID | `102` |
| `opa.gid` | Run OPA as GID | `102` |
| `opa.policy.allowedDomains` | Domains allowed for GET/HEAD | Various |
| `opa.policy.unrestrictedDomains` | Domains with all methods allowed | API endpoints |
| **Port Isolation** | | |
| `initContainer.sidecarPortRangeStart` | Start of sidecar port range | `15000` |
| `initContainer.sidecarPortRangeEnd` | End of sidecar port range | `15099` |
| `initContainer.privilegedPortEnd` | Privileged ports to block | `1023` |
| **Other** | | |
| `kyverno.injectEnvVars` | Inject proxy env vars | `false` (uses iptables) |
| `cleanup.enabled` | Enable pre-delete cleanup hook | `true` |

### OPA Policy Configuration

The OPA policy supports:
- Domain-based access control
- HTTP method filtering (GET/HEAD vs all methods)
- GitHub-specific rules for repositories and users
- Customizable allowed/blocked domain lists

Example policy configuration:

```yaml
opa:
  policy:
    # Restricted access (only GET/HEAD)
    allowedDomains:
      - github.com
      - api.github.com
      - pypi.org

    # Unrestricted access (all HTTP methods)
    unrestrictedDomains:
      - api.anthropic.com
      - api.openai.com

    # GitHub-specific rules
    githubReadAccessEnabled: true
    githubAllowedUsers:
      - myusername
    githubAllowedRepos:
      - myorg/myrepo
```

## Troubleshooting

### Check Sidecar Injection

```bash
# Verify Kyverno policy is active
kubectl get cpol intercept-proxy-inject-proxy

# Check if sidecars were injected (should see 3 containers)
kubectl get pod <pod-name> -n kyverno-intercept
# Should show: READY 3/3

# Verify all containers
kubectl get pod <pod-name> -o yaml | grep -E "name: (envoy-proxy|opa-sidecar|proxy-init)"
```

### Debug Envoy Proxy

```bash
# Check Envoy admin interface
kubectl port-forward <pod-name> -n kyverno-intercept 15000:15000
curl http://localhost:15000/stats
curl http://localhost:15000/clusters

# View Envoy logs
kubectl logs <pod-name> -n kyverno-intercept -c envoy-proxy

# Check Envoy is listening on correct port
kubectl exec <pod-name> -n kyverno-intercept -c envoy-proxy -- \
  netstat -tlnp | grep 15001
```

### Debug OPA Policies

```bash
# Check OPA decision logs
kubectl logs <pod-name> -n kyverno-intercept -c opa-sidecar

# Check OPA health
kubectl exec <pod-name> -n kyverno-intercept -c opa-sidecar -- \
  curl http://localhost:15020/health

# Test OPA policy directly (from outside pod)
kubectl port-forward <pod-name> -n kyverno-intercept 15020:15020
curl -X POST http://localhost:15020/v1/data/intercept/allow \
  -H "Content-Type: application/json" \
  -d '{"input": {"attributes": {"request": {"http": {"method": "GET", "host": "github.com", "path": "/"}}}}}'
```

### Verify iptables Rules

```bash
# Check init container logs for iptables setup
kubectl logs <pod-name> -n kyverno-intercept -c proxy-init

# View NAT table rules
kubectl logs <pod-name> -n kyverno-intercept -c proxy-init | grep -A 20 "NAT table"

# View FILTER table rules
kubectl logs <pod-name> -n kyverno-intercept -c proxy-init | grep -A 30 "FILTER table"

# Verify UID configuration
kubectl logs <pod-name> -n kyverno-intercept -c proxy-init | grep "_UID="
```

### Verify Security Context

```bash
# Check Envoy runs as UID 101
kubectl get pod <pod-name> -n kyverno-intercept -o jsonpath='{.spec.containers[?(@.name=="envoy-proxy")].securityContext}'

# Check OPA runs as UID 102
kubectl get pod <pod-name> -n kyverno-intercept -o jsonpath='{.spec.containers[?(@.name=="opa-sidecar")].securityContext}'
```

### Common Issues

1. **Sidecars not injected**
   - Verify Kyverno is installed and running
   - Check pod has correct label: `intercept-proxy/enabled: "true"`
   - Review Kyverno policy events: `kubectl describe cpol intercept-proxy-inject-proxy`

2. **TLS errors**
   - Ensure CA certificate is properly installed in container
   - Check certificate generation job completed: `kubectl logs job/intercept-proxy-cert-generator -n kyverno-intercept`
   - Verify certificate for domain exists: `kubectl get secrets -n kyverno-intercept | grep cert-`

3. **Traffic not intercepted**
   - Verify iptables rules in init container logs
   - Check Envoy is listening on port 15001
   - Ensure main container is not running as UID 101 (would bypass proxy)

4. **OPA container restarting**
   - Check liveness probe configuration matches OPA port (15020)
   - Verify OPA UID (102) is included in FILTER table allow rules
   - Review OPA logs for startup errors

5. **Infinite forwarding loops**
   - Verify Envoy and OPA UIDs are excluded in NAT table
   - Check init container set up UID-based exclusion correctly
   - Ensure iptables rules use `--uid-owner` for sidecar exclusion

## Features & Best Practices

This chart follows security and operational best practices:

- **No namespace creation in templates** - Uses `helm install --create-namespace` instead
- **Cluster resource cleanup** - Pre-delete hooks clean up ClusterPolicy
- **Transparent interception** - No proxy environment variables needed
- **gRPC communication** - Envoy and OPA communicate via efficient gRPC
- **Automatic CA trust** - CA certificates automatically distributed to all containers
- **Non-root containers** - All sidecars run as non-root users with dropped capabilities
- **UID-based isolation** - Prevents traffic loops and ensures stability
- **Port isolation** - Main container blocked from accessing sidecar infrastructure
- **Read-only root filesystem** - Enhanced security where possible

## Limitations

- Requires known domains in advance (no dynamic certificate generation)
- Certificates must be pre-generated for all intercepted domains
- Wildcard certificates supported but must be explicitly configured
- No automatic certificate rotation (requires chart upgrade)
- iptables rules require init container with NET_ADMIN capability

## Security Considerations

### Certificates and Secrets
- CA private key is stored as Kubernetes secret
- Certificates are distributed via secrets (ensure RBAC is properly configured)
- Consider using sealed-secrets or external-secrets for production

### OPA Policies
- Default policy denies all requests (`default allow = false`)
- Policies are configurable via ConfigMap (review before deployment)
- Decision logs available for audit

### Container Security
- All sidecars run as non-root users
- Capabilities dropped (ALL) except NET_ADMIN for init container
- No privilege escalation allowed
- Security contexts enforced via Kyverno policy

### Network Isolation
- Main container blocked from accessing sidecar infrastructure ports
- Privileged ports (0-1023) blocked from main container
- UID-based traffic isolation prevents bypassing

## Uninstall

```bash
# Uninstall the chart (pre-delete hook will clean up ClusterPolicy)
helm uninstall intercept-proxy -n kyverno-intercept

# Delete namespace if desired
kubectl delete ns kyverno-intercept

# Verify ClusterPolicy was cleaned up
kubectl get cpol | grep intercept-proxy
```

## Contributing

This is a proof-of-concept implementation. Improvements welcome:
- Add support for dynamic certificate generation (e.g., cert-manager integration)
- Implement certificate rotation
- Add Prometheus metrics export from Envoy and OPA
- Enhance OPA policy templates with more examples
- Support for more authentication methods
- Add NetworkPolicy examples for additional isolation

## License

See LICENSE file in the parent repository.