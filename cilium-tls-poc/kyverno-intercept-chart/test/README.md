# Kyverno Interceptor Chart - E2E Tests

Comprehensive end-to-end test suite for the Kyverno TLS Interceptor Helm Chart using BATS (Bash Automated Testing System) and DETIK.

## Overview

This test suite validates all security and functional features of the interceptor chart:

- ✅ Chart deployment and sidecar injection
- ✅ ConfigMap cloning across namespaces
- ✅ TLS interception with internal CA
- ✅ OPA policy enforcement (allow/deny rules)
- ✅ Port isolation (sidecar ports blocked)
- ✅ Network isolation (pod-to-pod and internet blocking)
- ✅ UID-based traffic isolation

## Quick Start

### Prerequisites

- **kubectl** (v1.24+)
- **helm** (v3.x)
- **kind** (for local cluster)
- **bats** (Bash testing framework)

### Installation

```bash
# Install kubectl, helm, kind (see official docs)

# Install BATS
npm install -g bats

# Or on macOS
brew install bats-core

# Or on Linux
git clone https://github.com/bats-core/bats-core.git
cd bats-core && sudo ./install.sh /usr/local
```

### Running Tests Locally

**Option 1: Automated (Recommended)**

```bash
# Run all tests with automatic setup
cd cilium-tls-poc/kyverno-intercept-chart
./scripts/run-e2e-tests.sh
```

**Option 2: Manual**

```bash
# 1. Create kind cluster
kind create cluster --name kyverno-test

# 2. Install Kyverno
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno -n kyverno --create-namespace --wait

# 3. Install chart
cd cilium-tls-poc/kyverno-intercept-chart
helm install intercept-proxy . -n kyverno-intercept --create-namespace --wait

# 4. Run tests
bats test/e2e/test-deployment.bats
bats test/e2e/test-configmap-cloning.bats
bats test/e2e/test-tls.bats
bats test/e2e/test-opa-policy.bats
bats test/e2e/test-port-isolation.bats
bats test/e2e/test-network-isolation.bats
```

## Test Structure

```
test/
├── e2e/                              # BATS test files
│   ├── test-deployment.bats         # Sidecar injection & deployment
│   ├── test-configmap-cloning.bats # Cross-namespace ConfigMap cloning
│   ├── test-tls.bats                # TLS interception
│   ├── test-opa-policy.bats        # OPA policy enforcement
│   ├── test-port-isolation.bats    # Port blocking rules
│   └── test-network-isolation.bats # Network restrictions
├── fixtures/                         # Test pod manifests
│   ├── test-pod.yaml                # Pod with interception enabled
│   ├── external-pod.yaml            # Pod without interception
│   └── http-server.yaml             # Simple HTTP server
└── lib/                              # Testing libraries
    ├── detik.bash                   # DETIK Kubernetes testing library
    ├── utils.bash                   # DETIK utilities
    ├── linter.bash                  # DETIK linter
    └── helpers.bash                 # Custom helper functions
```

## Test Coverage

### 1. Deployment Tests (`test-deployment.bats`)

**What it tests:**
- Chart resources created (ClusterPolicy, ConfigMaps, Secrets)
- Sidecar injection works (4 containers: app + 3 sidecars)
- Correct UIDs (101=Envoy, 102=OPA, 103=xDS, 12345=App)
- Init container completed successfully
- CA certificate mounted
- All sidecars healthy
- Pre-delete cleanup hooks work

**Sample test:**
```bats
@test "Pod has correct number of containers (1 app + 3 sidecars)" {
    POD_NAME=$(get_pod_name "test-app")
    CONTAINER_COUNT=$(count_pod_containers "$POD_NAME")
    [ "$CONTAINER_COUNT" -eq 4 ]
}
```

### 2. ConfigMap Cloning Tests (`test-configmap-cloning.bats`)

**What it tests:**
- ConfigMap clone ClusterPolicy exists
- Source ConfigMaps exist in chart namespace
- ConfigMaps are automatically cloned to different namespaces
- Cloned ConfigMaps have correct content
- Pods in different namespaces get sidecars injected
- Sidecars can access cloned ConfigMaps
- Cross-namespace pods can make HTTPS requests
- ConfigMap updates are synchronized across namespaces

**Sample test:**
```bats
@test "ConfigMaps are automatically cloned to target namespace" {
    TEST_NS="cross-namespace-test"
    # Deploy pod with intercept-proxy/enabled label in different namespace
    # Verify all 3 ConfigMaps are cloned automatically
    run kubectl get configmap -n "$TEST_NS" -o name
    [[ "$output" =~ "intercept-proxy-envoy-config" ]]
    [[ "$output" =~ "intercept-proxy-opa-policy" ]]
    [[ "$output" =~ "intercept-proxy-opa-config" ]]
}
```

### 3. TLS Interception Tests (`test-tls.bats`)

**What it tests:**
- HTTPS requests succeed
- Certificate issuer is internal CA (not real CA)
- Multiple domains work (github.com, api.github.com, etc.)
- Traffic flows through Envoy
- xDS provides certificates dynamically
- DNS resolution works
- SNI preserved
- Upstream re-encryption works

**Sample test:**
```bats
@test "Certificate issuer is internal CA (not real GitHub CA)" {
    POD_NAME=$(get_pod_name "test-app")
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -v --silent https://api.github.com 2>&1 | grep 'issuer:'"

    [[ "$output" =~ "Kyverno-Intercept-CA" ]]
    [[ ! "$output" =~ "DigiCert" ]]
}
```

### 4. OPA Policy Tests (`test-opa-policy.bats`)

**What it tests:**
- GET/HEAD allowed to restricted domains (github.com)
- POST/PUT/DELETE blocked to restricted domains
- All methods allowed to unrestricted domains (api.anthropic.com)
- OPA decision logs generated
- gRPC ext_authz working
- Consistent enforcement

**Sample test:**
```bats
@test "OPA blocks POST requests to github.com (restricted domain)" {
    POD_NAME=$(get_pod_name "test-app")
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' -X POST https://api.github.com/user"

    [ "$output" = "403" ]
}
```

### 5. Port Isolation Tests (`test-port-isolation.bats`)

**What it tests:**
- Envoy admin port (15000) blocked
- OPA ports (15020, 15021) blocked
- xDS ports (15080, 15081) blocked
- All sidecar range (15000-15099) blocked
- Privileged ports (0-1023) blocked
- High ports (1024-14999) accessible
- Ports above range (15100+) accessible
- iptables rules applied correctly
- DNS still works

**Sample test:**
```bats
@test "App container CANNOT access Envoy admin port (15000)" {
    POD_NAME=$(get_pod_name "test-app")
    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 3 curl -f http://localhost:15000/stats"

    [ "$status" -ne 0 ]
}
```

### 6. Network Isolation Tests (`test-network-isolation.bats`)

**What it tests:**
- Pod-to-pod connectivity blocked
- SSH to external services blocked
- Random internet ports blocked
- HTTP/HTTPS work (via Envoy)
- Kubernetes API blocked
- DNS works
- ICMP/ping blocked
- Only DNS and HTTP/HTTPS allowed
- Sidecars NOT restricted (UID bypass)

**Sample test:**
```bats
@test "App container CANNOT connect to other pods directly" {
    POD_NAME=$(get_pod_name "test-app")
    EXTERNAL_POD=$(get_pod_name "external-app")
    EXTERNAL_IP=$(kubectl get pod "$EXTERNAL_POD" -o jsonpath='{.status.podIP}')

    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 3 nc -zv $EXTERNAL_IP 8080"

    [ "$status" -ne 0 ]
}
```

## Helper Functions

The test suite includes custom helper functions in `test/lib/helpers.bash`:

### Logging
- `log_info()` - Info messages
- `log_warn()` - Warnings
- `log_error()` - Errors

### Pod Operations
- `wait_for_pod_ready()` - Wait for pod with timeout
- `get_pod_name()` - Get pod name by label
- `exec_in_pod()` - Execute command in container
- `count_pod_containers()` - Count containers in pod
- `get_container_uid()` - Get container's UID

### Testing
- `test_http_access()` - Test HTTP connectivity
- `test_port_blocked()` - Verify port is blocked
- `test_port_accessible()` - Verify port is accessible
- `verify_cert_issuer()` - Check certificate issuer
- `test_opa_decision()` - Test OPA policy decision

## Running Specific Tests

```bash
# Run single test file
bats test/e2e/test-deployment.bats

# Run specific test
bats test/e2e/test-deployment.bats -f "Pod has correct number"

# Verbose output
bats test/e2e/test-deployment.bats -t

# Continue on failure
bats test/e2e/*.bats --no-tempdir-cleanup
```

## Test Runner Options

The `run-e2e-tests.sh` script supports several options:

```bash
# Use existing cluster (don't create new one)
./scripts/run-e2e-tests.sh --skip-cluster-creation

# Keep resources after tests (for debugging)
./scripts/run-e2e-tests.sh --skip-cleanup

# Keep kind cluster after tests
./scripts/run-e2e-tests.sh --keep-cluster

# All options
./scripts/run-e2e-tests.sh --skip-cluster-creation --skip-cleanup
```

**Environment variables:**

```bash
# Custom cluster name
KIND_CLUSTER_NAME=my-cluster ./scripts/run-e2e-tests.sh

# Skip cluster creation
SKIP_CLUSTER_CREATION=true ./scripts/run-e2e-tests.sh

# Skip cleanup
SKIP_CLEANUP=true ./scripts/run-e2e-tests.sh
```

## GitHub CI

Tests run automatically on:
- Pull requests (changes to chart)
- Push to main branch
- Manual workflow dispatch

Workflow: `.github/workflows/kyverno-chart-e2e.yaml`

## Debugging Failed Tests

### View test pod logs
```bash
POD_NAME=$(kubectl get pod -l app=test-app -n kyverno-intercept -o jsonpath='{.items[0].metadata.name}')

# Init container logs (iptables setup)
kubectl logs -n kyverno-intercept $POD_NAME -c proxy-init

# Envoy logs
kubectl logs -n kyverno-intercept $POD_NAME -c envoy-proxy

# OPA logs
kubectl logs -n kyverno-intercept $POD_NAME -c opa-sidecar

# xDS logs
kubectl logs -n kyverno-intercept $POD_NAME -c xds-service

# App container logs
kubectl logs -n kyverno-intercept $POD_NAME -c test-container
```

### Exec into test pod
```bash
kubectl exec -it $POD_NAME -n kyverno-intercept -c test-container -- sh

# Test connectivity manually
curl -v https://api.github.com
nc -zv localhost 15000
nslookup github.com
```

### Check iptables rules
```bash
# View init container logs to see iptables rules
kubectl logs $POD_NAME -n kyverno-intercept -c proxy-init | grep -A 30 "NAT table"
kubectl logs $POD_NAME -n kyverno-intercept -c proxy-init | grep -A 50 "FILTER table"
```

### Verify Kyverno policy
```bash
kubectl get clusterpolicy intercept-proxy-inject-proxy -o yaml
kubectl describe clusterpolicy intercept-proxy-inject-proxy
```

## Common Issues

### Tests timeout
- Increase timeouts in test files
- Check cluster resources: `kubectl top nodes`
- Verify internet connectivity

### Sidecar injection not working
- Check Kyverno is running: `kubectl get pods -n kyverno`
- Verify ClusterPolicy exists: `kubectl get clusterpolicy`
- Check pod labels match policy selector

### Port blocking tests fail
- Verify iptables rules in init logs
- Check UIDs are correct
- Ensure app container doesn't use UIDs 101, 102, 103

### Network isolation tests fail
- Some tests depend on external services (github.com)
- Check DNS resolution works
- Verify Envoy can reach external services

## Performance

Typical test run times:

- **Deployment tests**: ~30-60 seconds
- **ConfigMap cloning tests**: ~60-90 seconds
- **TLS tests**: ~60-90 seconds
- **OPA tests**: ~60-90 seconds
- **Port isolation tests**: ~90-120 seconds
- **Network isolation tests**: ~90-120 seconds

**Total runtime**: ~6-10 minutes (including setup)

## Contributing

When adding new tests:

1. Create test file in `test/e2e/`
2. Use BATS format and DETIK for Kubernetes assertions
3. Add helper functions to `test/lib/helpers.bash` if needed
4. Update this README with test coverage
5. Add test to `run-e2e-tests.sh` script
6. Add test step to GitHub workflow

## References

- [BATS Core](https://github.com/bats-core/bats-core)
- [DETIK](https://github.com/bats-core/bats-detik)
- [kind](https://kind.sigs.k8s.io/)
- [Helm Chart Testing](https://helm.sh/docs/topics/chart_tests/)
