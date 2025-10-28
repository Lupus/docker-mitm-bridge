# Kyverno TLS Intercept Chart

A Helm chart for transparent TLS/HTTPS interception using Kyverno policy-based sidecar injection with Envoy proxy and OPA policy enforcement via gRPC.

## Overview

This Helm chart provides a complete TLS interception solution that:
- Uses **Kyverno** to automatically inject Envoy proxy sidecars into annotated pods
- Performs **TLS interception** with dynamically configured certificates via full dynamic xDS
- Enforces **OPA policies** via gRPC ext_authz for fine-grained access control
- Works transparently with existing applications via iptables rules (no proxy environment variables needed)
- Implements **Istio-style port isolation** for security and stability
- Uses **full dynamic xDS approach**: Control plane provides all Envoy configuration (CDS+LDS+SDS) following best practices with minimal bootstrap

## Architecture

```
┌──────────────────────────────────────────────────┐
│              Application Pod                     │
├──────────────────────────────────────────────────┤
│ Init Container (proxy-init):                     │
│ • Installs CA certificate from Secret            │
│ • Sets up iptables NAT rules (redirect traffic)  │
│ • Sets up iptables FILTER rules (port isolation) │
│ • UID-based exclusion (prevents infinite loops)  │
├──────────────────────────────────────────────────┤
│ Envoy Sidecar (UID 101):                        │
│ • Proxy port: 15001 (HTTPS traffic)             │
│ • Admin port: 15000 (metrics/config)            │
│ • Dynamic xDS config from xDS service           │
│ • TLS termination with internal CA              │
│ • gRPC ext_authz to OPA                         │
│ • Dynamic forward proxy for upstream            │
│ • Upstream TLS re-encryption                    │
├──────────────────────────────────────────────────┤
│ OPA Sidecar (UID 102):                          │
│ • HTTP API: 15020 (health checks)               │
│ • gRPC authz: 15021 (Envoy queries)             │
│ • Policy evaluation and decision logs           │
├──────────────────────────────────────────────────┤
│ xDS Service (UID 103):                          │
│ • xDS control plane: 15090 (CDS+LDS+SDS)        │
│ • Queries OPA for domain list on startup        │
│ • Pre-generates certificates for all domains    │
│ • Serves dynamic cluster configuration (CDS)    │
│ • Serves dynamic listener configuration (LDS)   │
│ • Serves certificates on demand (SDS)           │
│ • Caches certificates in memory                 │
├──────────────────────────────────────────────────┤
│ Application Container(s) (e.g., UID 12345):     │
│ • No proxy env vars needed                      │
│ • Traffic via iptables redirect                 │
│ • CA cert auto-trusted                          │
│ • Can use localhost for development             │
│ • Blocked from sidecar ports (15000-15099)      │
│ • MUST NOT use UIDs 101, 102, or 103            │
└──────────────────────────────────────────────────┘
```

## Key Features

### Multi-SNI Support with TLS Session Resumption Disabled
- **Correct handling of multiple hostnames on same IP**: TLS session resumption is disabled to prevent validation context caching per IP
- **Different certificates per hostname**: Supports CDN and cloud provider scenarios where multiple domains share an IP with different TLS certificates
- **Optimized connection pooling**: 600-second idle timeout and unlimited requests per connection maintain performance
- **No access-order dependency**: All hostnames work correctly regardless of which is accessed first

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
# IMPORTANT: Application MUST run with UID different from sidecars (101, 102, 103)
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
        intercept-proxy/enabled: "true"  # Triggers sidecar injection
    spec:
      securityContext:
        runAsUser: 12345    # REQUIRED: Must NOT be 101, 102, or 103
        runAsGroup: 12345
        fsGroup: 12345
      containers:
      - name: test
        image: curlimages/curl:latest
        command: ["sh", "-c", "while true; do sleep 3600; done"]
EOF

# Wait for pod to be ready (all 4 containers: init + 3 sidecars + app)
kubectl wait --for=condition=ready pod -l app=test-app -n kyverno-intercept --timeout=120s

# Verify sidecars are running
kubectl get pod -l app=test-app -n kyverno-intercept
# Should show: READY 4/4

# Test HTTPS interception (no -k flag needed!)
kubectl exec -n kyverno-intercept deploy/test-app -c test -- \
  curl -I https://api.github.com

# Verify certificate is from internal CA
kubectl exec -n kyverno-intercept deploy/test-app -c test -- \
  curl -v https://api.github.com 2>&1 | grep "issuer:"
# Should show: issuer: C=US; ST=CA; O=Internal-CA; CN=Kyverno-Intercept-CA

# Test multiple domains
kubectl exec -n kyverno-intercept deploy/test-app -c test -- \
  curl -s https://github.com | head -10

# Test OPA policy enforcement (POST should be blocked)
kubectl exec -n kyverno-intercept deploy/test-app -c test -- \
  curl -X POST https://api.github.com/user
# Should return: 403 Forbidden

# Verify port isolation (should fail)
kubectl exec -n kyverno-intercept deploy/test-app -c test -- \
  curl http://localhost:15000
# Should timeout or be rejected
```

**Common Issue: UID Collision**

If interception isn't working, check the application UID:

```bash
kubectl exec -n kyverno-intercept deploy/test-app -c test -- id
# If this shows UID 101, 102, or 103, traffic bypasses interception!
# Fix by setting securityContext.runAsUser to a different UID (e.g., 12345)
```

## How It Works

### 1. CA and Certificate Setup

**On Helm Install:**
- Pre-install hook job generates only the CA certificate (not per-domain certificates)
- CA public and private keys stored in Kubernetes Secret
- CA certificate distributed to all pods via init container

**On Pod Startup:**
- xDS service sidecar starts and loads CA from Secret
- xDS queries OPA's `required_domains` rule to get full domain list
- xDS pre-generates TLS certificates for all required domains
- Certificates cached in memory for Envoy to request

### 2. ConfigMap Cloning
When a pod with label `intercept-proxy/enabled: true` is created in any namespace:
- **Automatic Cloning**: Kyverno automatically clones required ConfigMaps from the chart namespace to the pod's namespace
- **Synchronized Updates**: ConfigMaps stay synchronized - updates to source ConfigMaps are propagated automatically
- **ConfigMaps Cloned**:
  - `{release-name}-envoy-config`: Envoy proxy configuration
  - `{release-name}-opa-policy`: OPA policy rules and data
  - `{release-name}-opa-config`: OPA runtime configuration

### 3. Sidecar Injection
When a pod with label `intercept-proxy/enabled: true` is created:
- **Init Container**: Sets up iptables rules for traffic redirection and port isolation, installs CA
- **Envoy Sidecar**: Minimal bootstrap, connects to xDS service for full dynamic xDS configuration
- **OPA Sidecar**: Provides policy evaluation and domain list aggregation
- **xDS Service**: Acts as full xDS control plane (CDS+LDS+SDS) serving all dynamic configuration

### 4. Dynamic Configuration Flow

```
1. Envoy starts with minimal bootstrap → connects to xDS service (port 15090)
   ↓
2. xDS service has already queried OPA for required_domains on startup
   ↓
3. Envoy sends CDS request → receives ext_authz and dynamic_forward_proxy clusters
   ↓
4. Envoy sends LDS request → receives listener with filter chains for each domain
   ↓
5. Envoy sends SDS requests → receives pre-generated certificates from cache
   ↓
6. Envoy activates with fully dynamic configuration (no static clusters/listeners)
```

### 5. Traffic Flow
1. Application makes HTTPS request (e.g., to api.github.com)
2. iptables NAT redirects to Envoy (port 15001) - no proxy env vars needed
3. Envoy receives connection, extracts SNI via tls_inspector listener filter
4. Envoy routes to correct filter chain based on SNI
5. Envoy terminates TLS using certificate from SDS
6. Envoy queries OPA via gRPC (port 15021) for authorization via ext_authz filter
7. OPA evaluates policy and returns allow/deny decision
8. If allowed, Envoy uses dynamic_forward_proxy to resolve and connect to upstream
9. Envoy re-encrypts with real server certificate and forwards request

### 6. iptables Rules

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

### Per-Pod Custom OPA Policies

You can override the default OPA policy on a per-pod basis using the `intercept-proxy/opa-data` annotation. This is useful when different workloads need different access policies.

#### Basic Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    metadata:
      labels:
        intercept-proxy/enabled: "true"
      annotations:
        intercept-proxy/opa-data: |
          allowed_domains: []
          unrestricted_domains:
            - "api.anthropic.com"
            - "api.openai.com"
            - "internal-api.company.local"
          github_read_access_enabled: false
          github_allowed_users: []
          github_allowed_repos: []
          aws_access_enabled: false
          aws_allowed_services: []
    spec:
      securityContext:
        runAsUser: 12345
      containers:
      - name: my-app
        image: my-app:latest
```

#### How It Works

The per-pod OPA policy feature uses Kubernetes **downwardAPI volumes** to pass annotation data to containers:

1. **Annotation to Volume**: When a pod with the `intercept-proxy/opa-data` annotation is created, Kyverno injects a downwardAPI volume (`podinfo`) that exposes the annotation content as a file at `/podinfo/opa-data`

2. **Init Container Preparation**: An init container (`opa-data-setup`) runs before OPA starts:
   - Checks if `/podinfo/opa-data` exists and is non-empty
   - If yes: copies the custom annotation data to `/opa-data/data.yaml`
   - If no: copies the default data from the shared ConfigMap to `/opa-data/data.yaml`

3. **OPA Sidecar Startup**: The OPA sidecar loads policy data from `/opa-data/data.yaml` at startup
   - Policy rules (`policy.rego`) are loaded from the shared ConfigMap (same for all pods)
   - Policy data varies per pod based on annotations

4. **Runtime**: Each pod's OPA instance enforces its own custom policy data independently

**Why downwardAPI volumes instead of environment variables?**
Kubernetes Downward API does not properly handle multiline annotation values when exposed as environment variables. Volumes handle multiline YAML content correctly.

#### Updating Policies

⚠️ **Important**: Policy data is loaded when the pod starts (via init container). **Running pods won't pick up annotation changes without a restart**.

**To update a policy:**

```bash
# For Deployments (recommended approach)
# 1. Update the annotation in your deployment manifest
kubectl apply -f deployment.yaml

# 2. Trigger a rolling update
kubectl rollout restart deployment/my-app -n my-namespace

# For individual Pods
# Delete and recreate the pod with updated annotation
kubectl delete pod my-pod -n my-namespace
kubectl apply -f pod.yaml
```

**GitOps Workflow (Recommended):**
```yaml
# In your Git repository, update the deployment:
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    metadata:
      annotations:
        intercept-proxy/opa-data: |
          unrestricted_domains:
            - "api.example.com"
            - "new-api.company.com"  # Added new domain
```

When CI/CD applies this change, Kubernetes performs a rolling update, creating new pods with the updated policy.

#### Testing Custom Policies

You can test OPA policies locally before deploying:

```bash
# Navigate to the policies directory
cd cilium-tls-poc/kyverno-intercept-chart/policies/

# Test with OPA CLI
opa eval -d policy.rego -d data.yml \
  -i input.json \
  'data.intercept.allow'

# Or run policy tests
opa test policy.rego policy_test.rego
```

#### Multiple Workloads with Different Policies

Each pod can have completely different policies:

```yaml
---
apiVersion: v1
kind: Pod
metadata:
  name: frontend-app
  labels:
    intercept-proxy/enabled: "true"
  annotations:
    intercept-proxy/opa-data: |
      unrestricted_domains:
        - "api.stripe.com"
        - "cdn.example.com"
---
apiVersion: v1
kind: Pod
metadata:
  name: backend-worker
  labels:
    intercept-proxy/enabled: "true"
  annotations:
    intercept-proxy/opa-data: |
      allowed_domains:
        - "github.com"
      unrestricted_domains:
        - "api.openai.com"
```

Each pod's OPA instance loads its own data from the annotation (via downwardAPI volume), and they operate independently. No per-pod ConfigMaps are created.

#### Fallback Behavior

- Pods **WITH** the `intercept-proxy/opa-data` annotation use their custom policy
- Pods **WITHOUT** the annotation use the default policy from Helm `values.yaml`
- This ensures backward compatibility with existing deployments

#### Troubleshooting Per-Pod Policies

**Verify which policy data is being used:**

```bash
# Check init container logs to see which data source was used
kubectl logs <pod-name> -c opa-data-setup -n <namespace>

# You should see one of:
# "Using custom OPA policy data from annotation"
# "Using default OPA policy data from ConfigMap"
```

**Query OPA data endpoint to verify loaded data:**

```bash
# Query OPA's data endpoint (returns all loaded data)
kubectl exec <pod-name> -c test-container -n <namespace> -- \
  curl -s http://localhost:15020/v1/data

# Check specific domains in policy data
kubectl exec <pod-name> -c test-container -n <namespace> -- \
  curl -s http://localhost:15020/v1/data/unrestricted_domains
```

**Check OPA decision logs:**

```bash
# View OPA sidecar logs to see policy decisions
kubectl logs <pod-name> -c opa-sidecar -n <namespace> | tail -50

# Look for decision log entries showing allow/deny decisions
```

**Common Issues:**

1. **Invalid YAML in annotation** - Init container will fail with YAML parse error. Check init container logs.
2. **Empty annotation** - Pod will use default ConfigMap data (check init container logs for confirmation).
3. **Policy not updating** - Pods must be restarted to load new annotation data. Use `kubectl rollout restart` for Deployments.
4. **Annotation too large** - Kubernetes annotations have a 256KB limit. If exceeded, pod creation will fail with error.

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

### Check ConfigMap Cloning

```bash
# Verify the ConfigMap clone policy is active
kubectl get cpol {{ .Release.Name }}-clone-configmaps

# Check if ConfigMaps were cloned to the target namespace
kubectl get configmap -n <target-namespace> | grep {{ .Release.Name }}
# Should show: {release-name}-envoy-config, {release-name}-opa-policy, {release-name}-opa-config

# Verify ConfigMap content matches source
kubectl get configmap {{ .Release.Name }}-envoy-config -n kyverno-intercept -o yaml
kubectl get configmap {{ .Release.Name }}-envoy-config -n <target-namespace> -o yaml
```

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
# Note: Envoy admin port (15000) is blocked by iptables for security
# Access it via ephemeral debug container or pod IP instead

# Using ephemeral debug container (bypasses iptables via pod IP)
POD_IP=$(kubectl get pod <pod-name> -n kyverno-intercept -o jsonpath='{.status.podIP}')
kubectl debug <pod-name> -n kyverno-intercept --image=nicolaka/netshoot:latest \
  --target=envoy-proxy -- curl http://$POD_IP:15000/clusters

# Check Envoy logs
kubectl logs <pod-name> -n kyverno-intercept -c envoy-proxy

# Verify CDS is working (look for "cds: add 2 cluster(s)")
kubectl logs <pod-name> -n kyverno-intercept -c envoy-proxy | grep cds

# Check Envoy is listening on correct ports
kubectl debug <pod-name> -n kyverno-intercept --image=nicolaka/netshoot:latest \
  --target=envoy-proxy -- netstat -tlnp
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

1. **ConfigMaps not found in target namespace**
   - Verify the clone policy is active: `kubectl get cpol {release-name}-clone-configmaps`
   - Check Kyverno logs for cloning errors: `kubectl logs -n kyverno -l app.kubernetes.io/name=kyverno`
   - Ensure source ConfigMaps exist in chart namespace: `kubectl get cm -n kyverno-intercept`
   - Delete and recreate the pod to trigger ConfigMap cloning again

2. **Sidecars not injected**
   - Verify Kyverno is installed and running
   - Check pod has correct label: `intercept-proxy/enabled: "true"`
   - Review Kyverno policy events: `kubectl describe cpol intercept-proxy-inject-proxy`

3. **TLS errors**
   - Ensure CA certificate is properly installed in container
   - Check certificate generation job completed: `kubectl logs job/intercept-proxy-cert-generator -n kyverno-intercept`
   - Verify certificate for domain exists: `kubectl get secrets -n kyverno-intercept | grep cert-`

4. **Traffic not intercepted**
   - **Most common cause**: Application container running as UID 101, 102, or 103
     - Check: `kubectl exec <pod> -c <container> -- id`
     - Fix: Set `securityContext.runAsUser` to different UID (e.g., 12345)
   - Verify iptables rules in init container logs
   - Check Envoy is listening on port 15001
   - Verify xDS service logs show certificates were generated

5. **OPA container restarting**
   - Check liveness probe configuration matches OPA port (15020)
   - Verify OPA UID (102) is included in FILTER table allow rules
   - Review OPA logs for startup errors

6. **Infinite forwarding loops**
   - Verify Envoy and OPA UIDs are excluded in NAT table
   - Check init container set up UID-based exclusion correctly
   - Ensure iptables rules use `--uid-owner` for sidecar exclusion

## Features & Best Practices

This chart follows security and operational best practices:

- **No namespace creation in templates** - Uses `helm install --create-namespace` instead
- **Cluster resource cleanup** - Pre-delete hooks clean up ClusterPolicy
- **Cross-namespace ConfigMap cloning** - Kyverno automatically clones configuration to target namespaces with synchronization
- **Transparent interception** - No proxy environment variables needed
- **gRPC communication** - Envoy and OPA communicate via efficient gRPC
- **Automatic CA trust** - CA certificates automatically distributed to all containers
- **Non-root containers** - All sidecars run as non-root users with dropped capabilities
- **UID-based isolation** - Prevents traffic loops and ensures stability
- **Port isolation** - Main container blocked from accessing sidecar infrastructure
- **Read-only root filesystem** - Enhanced security where possible

## Limitations

- Requires domains configured in OPA policy (via `required_domains` rule)
- All domains must be known at pod startup (no dynamic domain discovery)
- Certificates cached in memory only (lost on xDS service restart)
- CA regenerated on chart upgrade (all existing certificates become invalid)
- iptables rules require init container with NET_ADMIN capability
- Application containers must NOT use UIDs 101, 102, or 103 (reserved for sidecars)

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