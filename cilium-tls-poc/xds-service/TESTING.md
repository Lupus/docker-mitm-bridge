# xDS Service Testing Guide

This document provides step-by-step instructions for testing and debugging the xDS service with Envoy and OPA in a local kind cluster.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Manual Testing](#manual-testing)
- [Debugging Guide](#debugging-guide)
- [Common Issues](#common-issues)
- [Cleaning Up](#cleaning-up)

## Overview

This guide helps you test the xDS service in an isolated kind cluster environment without the complexity of Kyverno iptables rules. This is useful for:

- Debugging xDS configuration issues
- Testing Envoy access log configuration
- Verifying OPA integration
- Reproducing issues in a minimal environment

## Prerequisites

- Docker
- kind (Kubernetes in Docker)
- kubectl
- openssl (for generating test CA certificates)

## Quick Start

Use the provided script to set up a complete test environment:

```bash
cd /home/kolkhovskiy/git/docker-mitm-bridge/cilium-tls-poc/xds-service
./test-local.sh
```

This script will:
1. Create a kind cluster named `xds-test`
2. Build and load the xDS service image
3. Deploy OPA, xDS service, and Envoy in a test pod
4. Run test requests and show access logs

## Manual Testing

### 1. Create Kind Cluster

```bash
# Set isolated kubeconfig
export KUBECONFIG=/tmp/xds-test-kubeconfig

# Create kind cluster
cat > /tmp/kind-config.yaml <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: xds-test
nodes:
- role: control-plane
EOF

kind create cluster --config /tmp/kind-config.yaml
```

### 2. Build and Load xDS Service Image

```bash
# Build image
docker build -t xds-service:test .

# Load into kind cluster
kind load docker-image xds-service:test --name xds-test
```

### 3. Create Test Namespace and Resources

```bash
# Create namespace
kubectl create namespace xds-test

# Generate CA certificate
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /tmp/test-ca-key.pem \
  -out /tmp/test-ca-cert.pem \
  -subj "/CN=Test CA"

# Create CA secret
kubectl create secret tls mitm-ca-secret \
  --cert=/tmp/test-ca-cert.pem \
  --key=/tmp/test-ca-key.pem \
  -n xds-test

# Create OPA policy
kubectl create configmap opa-policy -n xds-test \
  --from-literal='policy.rego=package intercept

allow := false

allow if {
    input.attributes.request.http.host == "example.com"
}

required_domains := ["example.com"]'

# Create Envoy bootstrap config
kubectl create configmap envoy-bootstrap -n xds-test \
  --from-literal='envoy.yaml=node:
  id: envoy-test
  cluster: test-cluster

admin:
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 15000

dynamic_resources:
  cds_config:
    resource_api_version: V3
    api_config_source:
      api_type: GRPC
      transport_api_version: V3
      grpc_services:
      - envoy_grpc:
          cluster_name: xds_cluster

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
                port_value: 15090'
```

### 4. Deploy Test Pod

```bash
kubectl apply -n xds-test -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: xds-test-pod
spec:
  containers:
  # OPA for ext_authz
  - name: opa
    image: openpolicyagent/opa:latest
    args:
      - "run"
      - "--server"
      - "--addr=:15020"
      - "--addr=:15021"
      - "--log-level=info"
      - "/policies"
    ports:
    - containerPort: 15020
      name: http
    - containerPort: 15021
      name: grpc
    volumeMounts:
    - name: opa-policy
      mountPath: /policies
      readOnly: true

  # xDS service
  - name: xds-service
    image: xds-service:test
    imagePullPolicy: Never
    env:
    - name: SDS_GRPC_PORT
      value: "15090"
    - name: CA_CERT_PATH
      value: "/ca-secret/tls.crt"
    - name: CA_KEY_PATH
      value: "/ca-secret/tls.key"
    - name: OPA_URL
      value: "http://localhost:15020"
    - name: OPA_GRPC_PORT
      value: "15021"
    ports:
    - containerPort: 15090
      name: xds-grpc
    volumeMounts:
    - name: ca-secret
      mountPath: /ca-secret
      readOnly: true

  # Envoy proxy
  - name: envoy
    image: envoyproxy/envoy:v1.32.2
    args:
      - "-c"
      - "/etc/envoy/envoy.yaml"
      - "--log-level"
      - "info"
    ports:
    - containerPort: 15001
      name: proxy
    - containerPort: 15000
      name: admin
    volumeMounts:
    - name: envoy-config
      mountPath: /etc/envoy
      readOnly: true

  # Curl for testing
  - name: curl
    image: curlimages/curl:8.5.0
    command: ["sleep", "infinity"]

  volumes:
  - name: opa-policy
    configMap:
      name: opa-policy
  - name: ca-secret
    secret:
      secretName: mitm-ca-secret
  - name: envoy-config
    configMap:
      name: envoy-bootstrap
EOF

# Wait for pod to be ready
kubectl wait --for=condition=ready pod xds-test-pod -n xds-test --timeout=120s
```

### 5. Run Test Requests

```bash
# Test HTTP request (should get 403 from OPA)
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl -v http://127.0.0.1:15001/ -H "Host: example.com"

# Test POST request with data
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl -X POST http://127.0.0.1:15001/api/v1/resource \
  -H "Host: example.com" \
  -d "test data"

# Test with custom User-Agent
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl http://127.0.0.1:15001/test/path \
  -H "Host: example.com" \
  -H "User-Agent: TestAgent/1.0"
```

### 6. Check Access Logs

```bash
# View Envoy access logs (stderr)
kubectl logs -n xds-test xds-test-pod -c envoy | grep -E '^\[20'

# Example output:
# [2025-10-11T13:22:33.994Z] "GET /test/path HTTP/1.1" 403 UAEX 0 0 3 - "example.com" "127.0.0.1:39348" "dynamic_forward_proxy_cluster" "-" "32c04bfc-a923-405b-b907-dd59db559431" "TestAgent/1.0" "127.0.0.1:15001" "-" "-"
```

## Debugging Guide

### Check Pod Status

```bash
# Check if all containers are ready
kubectl get pod xds-test-pod -n xds-test

# Check pod events
kubectl describe pod xds-test-pod -n xds-test
```

### Check Container Logs

```bash
# OPA logs
kubectl logs -n xds-test xds-test-pod -c opa --tail=50

# xDS service logs
kubectl logs -n xds-test xds-test-pod -c xds-service --tail=50

# Envoy logs
kubectl logs -n xds-test xds-test-pod -c envoy --tail=50

# Follow logs in real-time
kubectl logs -n xds-test xds-test-pod -c envoy -f
```

### Inspect Envoy Configuration

```bash
# Get full config dump
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl -s http://127.0.0.1:15000/config_dump | jq '.' > /tmp/envoy-config.json

# Check access log configuration
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl -s http://127.0.0.1:15000/config_dump | \
  jq '.configs[] | select(."@type" | contains("Listeners")) | .dynamic_listeners[].active_state.listener.filter_chains[].filters[].typed_config.access_log'

# Check listener configuration
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl -s http://127.0.0.1:15000/config_dump?resource=dynamic_listeners | jq '.'

# Check cluster configuration
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl -s http://127.0.0.1:15000/config_dump?resource=dynamic_active_clusters | jq '.'

# Check Envoy stats
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl -s http://127.0.0.1:15000/stats
```

### Test OPA Directly

```bash
# Check OPA health
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl -s http://localhost:15020/health

# Query OPA for required domains
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl -s http://localhost:15020/v1/data/intercept/required_domains | jq '.'

# Test authorization decision
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl -s http://localhost:15020/v1/data/intercept/allow \
  -d '{"input": {"attributes": {"request": {"http": {"host": "example.com"}}}}}' | jq '.'
```

### Test xDS Service

```bash
# Check xDS service health
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl -s http://localhost:15081/health

# Check xDS logs for certificate generation
kubectl logs -n xds-test xds-test-pod -c xds-service | grep -i "certificate"

# Check xDS logs for OPA queries
kubectl logs -n xds-test xds-test-pod -c xds-service | grep -i "opa"
```

### Debug Access Log Issues

If access logs are not appearing:

1. **Check Envoy configuration**:
   ```bash
   kubectl exec -n xds-test xds-test-pod -c curl -- \
     curl -s http://127.0.0.1:15000/config_dump | \
     grep -A 20 "access_log"
   ```

2. **Verify logger type**:
   - Look for `envoy.access_loggers.stderr` (works with xDS)
   - Avoid `envoy.access_loggers.stdout` (doesn't work with xDS)

3. **Check Envoy logs level**:
   ```bash
   kubectl logs -n xds-test xds-test-pod -c envoy | grep -i "access"
   ```

4. **Verify requests are reaching Envoy**:
   ```bash
   # Check Envoy stats
   kubectl exec -n xds-test xds-test-pod -c curl -- \
     curl -s http://127.0.0.1:15000/stats | grep http.ingress
   ```

## Common Issues

### Issue: Pod stuck in "ImagePullBackOff"

**Symptom**: xDS service container shows `ImagePullBackOff` status

**Solution**:
```bash
# Rebuild and reload image
docker build -t xds-service:test .
kind load docker-image xds-service:test --name xds-test

# Delete and recreate pod
kubectl delete pod xds-test-pod -n xds-test
kubectl apply -f <pod-manifest>
```

### Issue: OPA policy parse errors

**Symptom**: OPA container logs show `rego_parse_error`

**Solution**: Update OPA policy syntax for newer versions:
```rego
# Old syntax (doesn't work with latest OPA)
default allow = false
allow { ... }

# New syntax (required)
default allow := false
allow if { ... }
```

### Issue: CA certificate decode errors

**Symptom**: xDS service logs show "failed to decode CA cert PEM"

**Solution**: Regenerate CA certificate:
```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /tmp/test-ca-key.pem \
  -out /tmp/test-ca-cert.pem \
  -subj "/CN=Test CA"

kubectl delete secret mitm-ca-secret -n xds-test
kubectl create secret tls mitm-ca-secret \
  --cert=/tmp/test-ca-cert.pem \
  --key=/tmp/test-ca-key.pem \
  -n xds-test

# Restart pod
kubectl delete pod xds-test-pod -n xds-test
```

### Issue: Envoy can't connect to xDS service

**Symptom**: Envoy logs show "Connection refused" to 127.0.0.1:15090

**Solution**: Check xDS service is running and port is correct:
```bash
# Check xDS service logs
kubectl logs -n xds-test xds-test-pod -c xds-service

# Verify xDS service is listening
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl -v http://localhost:15081/health
```

### Issue: Access logs not appearing

**Symptom**: Requests work but no access logs in Envoy output

**Root Cause**: `StdoutAccessLog` doesn't work when configured via xDS

**Solution**: Already implemented in main.go - uses `StderrAccessLog` instead:
```go
// Use StderrAccessLog instead of StdoutAccessLog
stderrAccessLog := &stdout_accesslog.StderrAccessLog{
    // ... configuration
}
```

Verify in config dump:
```bash
kubectl exec -n xds-test xds-test-pod -c curl -- \
  curl -s http://127.0.0.1:15000/config_dump | \
  grep -A 5 "envoy.access_loggers.stderr"
```

## Cleaning Up

```bash
# Delete the test cluster
kind delete cluster --name xds-test

# Remove temporary files
rm -f /tmp/xds-test-kubeconfig
rm -f /tmp/test-ca-*.pem
rm -f /tmp/kind-config.yaml
```

## Automated Test Script

Save this as `test-local.sh` for quick testing:

```bash
#!/bin/bash
set -e

CLUSTER_NAME="xds-test"
NAMESPACE="xds-test"
export KUBECONFIG="/tmp/${CLUSTER_NAME}-kubeconfig"

echo "==> Setting up ${CLUSTER_NAME} cluster..."

# Check if cluster exists
if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Cluster ${CLUSTER_NAME} already exists, reusing it"
    kind get kubeconfig --name ${CLUSTER_NAME} > ${KUBECONFIG}
else
    echo "Creating new cluster ${CLUSTER_NAME}"
    cat > /tmp/kind-config.yaml <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
nodes:
- role: control-plane
EOF
    kind create cluster --config /tmp/kind-config.yaml
fi

echo "==> Building and loading xDS service image..."
docker build -t xds-service:test .
kind load docker-image xds-service:test --name ${CLUSTER_NAME}

echo "==> Creating namespace..."
kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

echo "==> Generating CA certificate..."
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /tmp/test-ca-key.pem \
  -out /tmp/test-ca-cert.pem \
  -subj "/CN=Test CA" 2>/dev/null

kubectl create secret tls mitm-ca-secret \
  --cert=/tmp/test-ca-cert.pem \
  --key=/tmp/test-ca-key.pem \
  -n ${NAMESPACE} \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Creating OPA policy..."
kubectl create configmap opa-policy -n ${NAMESPACE} \
  --from-literal='policy.rego=package intercept

allow := false

allow if {
    input.attributes.request.http.host == "example.com"
}

required_domains := ["example.com"]' \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Creating Envoy bootstrap..."
kubectl create configmap envoy-bootstrap -n ${NAMESPACE} \
  --from-literal='envoy.yaml=node:
  id: envoy-test
  cluster: test-cluster

admin:
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 15000

dynamic_resources:
  cds_config:
    resource_api_version: V3
    api_config_source:
      api_type: GRPC
      transport_api_version: V3
      grpc_services:
      - envoy_grpc:
          cluster_name: xds_cluster

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
                port_value: 15090' \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Deploying test pod..."
kubectl delete pod xds-test-pod -n ${NAMESPACE} --ignore-not-found=true
kubectl apply -n ${NAMESPACE} -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: xds-test-pod
spec:
  containers:
  - name: opa
    image: openpolicyagent/opa:latest
    args: ["run", "--server", "--addr=:15020", "--addr=:15021", "--log-level=info", "/policies"]
    ports:
    - containerPort: 15020
    - containerPort: 15021
    volumeMounts:
    - name: opa-policy
      mountPath: /policies
      readOnly: true

  - name: xds-service
    image: xds-service:test
    imagePullPolicy: Never
    env:
    - name: SDS_GRPC_PORT
      value: "15090"
    - name: CA_CERT_PATH
      value: "/ca-secret/tls.crt"
    - name: CA_KEY_PATH
      value: "/ca-secret/tls.key"
    - name: OPA_URL
      value: "http://localhost:15020"
    - name: OPA_GRPC_PORT
      value: "15021"
    ports:
    - containerPort: 15090
    volumeMounts:
    - name: ca-secret
      mountPath: /ca-secret
      readOnly: true

  - name: envoy
    image: envoyproxy/envoy:v1.32.2
    args: ["-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]
    ports:
    - containerPort: 15001
    - containerPort: 15000
    volumeMounts:
    - name: envoy-config
      mountPath: /etc/envoy
      readOnly: true

  - name: curl
    image: curlimages/curl:8.5.0
    command: ["sleep", "infinity"]

  volumes:
  - name: opa-policy
    configMap:
      name: opa-policy
  - name: ca-secret
    secret:
      secretName: mitm-ca-secret
  - name: envoy-config
    configMap:
      name: envoy-bootstrap
EOF

echo "==> Waiting for pod to be ready..."
kubectl wait --for=condition=ready pod xds-test-pod -n ${NAMESPACE} --timeout=120s || {
    echo "Pod failed to become ready, checking logs..."
    kubectl get pod xds-test-pod -n ${NAMESPACE}
    kubectl describe pod xds-test-pod -n ${NAMESPACE}
    exit 1
}

echo ""
echo "==> Pod is ready!"
echo ""

echo "==> Running test requests..."
echo ""
echo "Test 1: GET request"
kubectl exec -n ${NAMESPACE} xds-test-pod -c curl -- \
  curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  http://127.0.0.1:15001/ -H "Host: example.com"

sleep 1

echo ""
echo "Test 2: POST request with data"
kubectl exec -n ${NAMESPACE} xds-test-pod -c curl -- \
  curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://127.0.0.1:15001/api/v1/resource \
  -H "Host: example.com" -d "test data"

sleep 1

echo ""
echo "Test 3: Custom path and user agent"
kubectl exec -n ${NAMESPACE} xds-test-pod -c curl -- \
  curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  http://127.0.0.1:15001/test/path \
  -H "Host: example.com" -H "User-Agent: TestAgent/1.0"

sleep 2

echo ""
echo "==> Access logs from Envoy:"
kubectl logs -n ${NAMESPACE} xds-test-pod -c envoy | grep -E '^\[20' || echo "(No access logs found)"

echo ""
echo "==> Test complete!"
echo ""
echo "Useful commands:"
echo "  export KUBECONFIG=${KUBECONFIG}"
echo "  kubectl logs -n ${NAMESPACE} xds-test-pod -c envoy -f"
echo "  kubectl logs -n ${NAMESPACE} xds-test-pod -c xds-service"
echo "  kubectl logs -n ${NAMESPACE} xds-test-pod -c opa"
echo "  kubectl exec -n ${NAMESPACE} xds-test-pod -c curl -- curl http://127.0.0.1:15000/config_dump"
echo ""
echo "To cleanup:"
echo "  kind delete cluster --name ${CLUSTER_NAME}"
```

Make the script executable:
```bash
chmod +x test-local.sh
```

## Access Log Format Reference

The access logs use the following format:

```
[START_TIME] "METHOD PATH PROTOCOL" RESPONSE_CODE RESPONSE_FLAGS BYTES_RX BYTES_TX DURATION UPSTREAM_TIME "AUTHORITY" "CLIENT_ADDR" "UPSTREAM_CLUSTER" "UPSTREAM_HOST" "REQUEST_ID" "USER_AGENT" "LOCAL_ADDR" "SNI" "FAILURE_REASON"
```

Example:
```
[2025-10-11T13:22:33.994Z] "GET /test/path HTTP/1.1" 403 UAEX 0 0 3 - "example.com" "127.0.0.1:39348" "dynamic_forward_proxy_cluster" "-" "32c04bfc-a923-405b-b907-dd59db559431" "TestAgent/1.0" "127.0.0.1:15001" "-" "-"
```

### Response Flags

Common response flags you might see:

- `UAEX` - Unauthorized by external authorization service (OPA denied)
- `UH` - Upstream connection failure
- `UF` - Upstream connection failure
- `UO` - Upstream overflow (circuit breaker open)
- `NR` - No route configured
- `DC` - Downstream connection termination
- `-` - No flags (successful proxying)

For full list, see: https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log/usage#config-access-log-format-response-flags
