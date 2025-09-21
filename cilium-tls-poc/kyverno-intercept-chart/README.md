# Kyverno TLS Intercept Chart

A Helm chart for transparent TLS/HTTPS interception using Kyverno policy-based sidecar injection with Envoy proxy and OPA policy enforcement via gRPC.

## Overview

This Helm chart provides a complete TLS interception solution that:
- Uses **Kyverno** to automatically inject Envoy proxy sidecars into annotated pods
- Performs **TLS interception** with pre-generated certificates for known domains
- Enforces **OPA policies** via gRPC ext_authz for fine-grained access control
- Works transparently with existing applications via iptables rules (no proxy environment variables needed)

## Architecture

```
┌──────────────────────────────────┐
│         Application Pod          │
├──────────────────────────────────┤
│ Init Container (proxy-init):     │
│ • Installs CA certificate        │
│ • Sets up iptables rules         │
├──────────────────────────────────┤
│ Envoy Sidecar (port 8080):      │
│ • TLS termination               │
│ • gRPC ext_authz to OPA         │
│ • Upstream TLS re-encryption    │
├──────────────────────────────────┤
│ OPA Sidecar:                    │
│ • HTTP API (port 8181)          │
│ • gRPC authz (port 9191)        │
│ • Policy evaluation             │
├──────────────────────────────────┤
│ Application Container(s):        │
│ • No proxy env vars needed      │
│ • Traffic via iptables redirect │
│ • CA cert auto-trusted          │
└──────────────────────────────────┘
```

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

# Configure OPA policies
opa:
  policy:
    allowedDomains:
      - "github.com"
      - "internal-api.company.com"

    githubAllowedRepos:
      - "myorg/myrepo"

# Configure resource limits
envoy:
  resources:
    limits:
      memory: "512Mi"
      cpu: "500m"
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

# Wait for pod to be ready
kubectl wait --for=condition=ready pod -l app=test-app -n kyverno-intercept

# Test HTTPS interception (no -k flag needed!)
kubectl exec -n kyverno-intercept deploy/test-app -- \
  curl -I https://api.github.com

# Verify certificate is from internal CA
kubectl exec -n kyverno-intercept deploy/test-app -- \
  curl -v https://api.github.com 2>&1 | grep "issuer:"
# Should show: issuer: CN=Kyverno-Intercept-CA
```

## How It Works

### 1. Certificate Generation
- On installation, a Helm hook job generates:
  - Internal CA certificate
  - TLS certificates for all configured domains
- Certificates are stored as Kubernetes secrets

### 2. Sidecar Injection
When a pod with label `intercept-proxy/enabled: true` is created:
- **Init Container**: Sets up iptables rules to redirect traffic
- **Envoy Sidecar**: Handles TLS interception and forwarding
- **OPA Sidecar**: Evaluates access policies

### 3. Traffic Flow
1. Application makes HTTPS request
2. iptables redirects to Envoy (port 8080) - no proxy env vars needed
3. Envoy terminates TLS using pre-generated certificate
4. Envoy queries OPA via gRPC (port 9191) for authorization
5. OPA evaluates policy and returns allow/deny decision
6. If allowed, Envoy re-encrypts and forwards to destination

## Configuration Reference

### Key Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `namespace` | Namespace for chart resources | `kyverno-intercept` |
| `ca.generate` | Generate internal CA | `true` |
| `interceptDomains` | Domains to intercept (grouped) | See values.yaml |
| `envoy.image` | Envoy proxy image | `envoyproxy/envoy:v1.28-latest` |
| `envoy.port` | Envoy proxy port | `8080` |
| `opa.enabled` | Enable OPA policy enforcement | `true` |
| `opa.policy.allowedDomains` | Domains allowed for GET/HEAD | Various |
| `opa.policy.unrestrictedDomains` | Domains with all methods allowed | API endpoints |
| `kyverno.injectEnvVars` | Inject proxy env vars | `false` (uses iptables) |
| `cleanup.enabled` | Enable pre-delete cleanup hook | `true` |

### OPA Policy Configuration

The OPA policy supports:
- Domain-based access control
- HTTP method filtering
- GitHub-specific rules for repositories and users
- Customizable allowed/blocked domain lists

## Troubleshooting

### Check Sidecar Injection

```bash
# Verify Kyverno policy is active
kubectl get cpol intercept-proxy-inject-proxy

# Check if sidecars were injected
kubectl get pod <pod-name> -o yaml | grep -A5 "envoy-proxy"
```

### Debug Envoy Proxy

```bash
# Check Envoy admin interface
kubectl port-forward <pod-name> 9901:9901
curl http://localhost:9901/stats

# View Envoy logs
kubectl logs <pod-name> -c envoy-proxy
```

### Debug OPA Policies

```bash
# Check OPA decision logs
kubectl logs <pod-name> -c opa-sidecar

# Test OPA policy directly
kubectl port-forward <pod-name> 8181:8181
curl -X POST http://localhost:8181/v1/data/intercept/allow \
  -H "Content-Type: application/json" \
  -d '{"input": {"attributes": {"request": {"http": {"method": "GET", "headers": {"host": "github.com"}}}}}}'
```

### Common Issues

1. **Sidecars not injected**
   - Verify Kyverno is installed and running
   - Check pod has correct label: `intercept-proxy/enabled: true`
   - Review Kyverno policy events: `kubectl describe cpol intercept-proxy-inject-proxy`

2. **TLS errors**
   - Ensure CA certificate is properly installed in container
   - Check certificate generation job completed: `kubectl logs job/intercept-proxy-cert-generator -n kyverno-intercept`

3. **Traffic not intercepted**
   - Verify iptables rules in init container logs
   - Check Envoy is listening: `netstat -tlnp | grep 8080` inside pod

## Features & Best Practices

This chart follows Helm best practices:

- **No namespace creation in templates** - Uses `helm install --create-namespace` instead
- **Cluster resource cleanup** - Pre-delete hooks clean up ClusterPolicy
- **Transparent interception** - No proxy environment variables needed
- **gRPC communication** - Envoy and OPA communicate via efficient gRPC
- **Automatic CA trust** - CA certificates automatically distributed to all containers

## Limitations

- Requires known domains in advance (no dynamic certificate generation)
- Certificates must be pre-generated for all intercepted domains
- Wildcard certificates supported but must be explicitly configured
- No automatic certificate rotation (requires chart upgrade)

## Security Considerations

- CA private key is stored as Kubernetes secret
- Certificates are distributed via secrets (ensure RBAC is properly configured)
- OPA policies control access but are configurable via ConfigMap
- Default policy denies all requests (`default allow = false`)
- Consider using sealed-secrets or external-secrets for production

## Uninstall

```bash
# Uninstall the chart (pre-delete hook will clean up ClusterPolicy)
helm uninstall intercept-proxy -n kyverno-intercept

# Delete namespace if desired
kubectl delete ns kyverno-intercept
```

## Contributing

This is a proof-of-concept implementation. Improvements welcome:
- Add support for dynamic certificate generation
- Implement certificate rotation
- Add Prometheus metrics export
- Enhance OPA policy templates
- Support for more authentication methods

## License

See LICENSE file in the parent repository.