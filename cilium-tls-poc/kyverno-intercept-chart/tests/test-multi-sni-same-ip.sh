#!/bin/bash
set -euo pipefail

# Test script for multi-SNI same-IP TLS validation
# This test verifies that Envoy correctly handles multiple hostnames on the same IP
# with different certificates, testing the fix for TLS session resumption caching issue

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${NAMESPACE:-kyverno-intercept}"
CHART_NAME="${CHART_NAME:-intercept-proxy}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

cleanup() {
    log_info "Cleaning up test resources..."
    kubectl delete pod test-client -n "$NAMESPACE" --ignore-not-found=true --wait=false || true
    kubectl delete configmap test-ca-bundle -n "$NAMESPACE" --ignore-not-found=true || true
    kubectl delete -f "$SCRIPT_DIR/test-nginx-multi-sni.yaml" --ignore-not-found=true || true
    rm -rf "$SCRIPT_DIR/test-certs" || true
}

# Trap errors and cleanup
trap cleanup EXIT

echo "========================================"
echo "Multi-SNI Same-IP TLS Validation Test"
echo "========================================"
echo

# Step 1: Generate test certificates
log_info "Step 1: Generating test CA and certificates..."
"$SCRIPT_DIR/generate-test-ca.sh" "$SCRIPT_DIR/test-certs"
if [ ! -f "$SCRIPT_DIR/test-certs/test-ca.crt" ]; then
    log_error "Failed to generate test certificates"
    exit 1
fi
log_success "Certificates generated"
echo

# Step 2: Create Kubernetes Secrets with generated certificates
log_info "Step 2: Creating Kubernetes Secrets..."

# Encode certificates in base64
TEST_CA_B64=$(base64 -w 0 "$SCRIPT_DIR/test-certs/test-ca.crt")
TEST_A_CRT_B64=$(base64 -w 0 "$SCRIPT_DIR/test-certs/test-a.local.crt")
TEST_A_KEY_B64=$(base64 -w 0 "$SCRIPT_DIR/test-certs/test-a.local.key")
TEST_B_CRT_B64=$(base64 -w 0 "$SCRIPT_DIR/test-certs/test-b.local.crt")
TEST_B_KEY_B64=$(base64 -w 0 "$SCRIPT_DIR/test-certs/test-b.local.key")

# Apply manifests with base64-encoded certificates
sed -e "s|ca.crt: \"\"|ca.crt: $TEST_CA_B64|" \
    -e "/name: test-a-tls/,/^---/ s|tls.crt: \"\"|tls.crt: $TEST_A_CRT_B64|" \
    -e "/name: test-a-tls/,/^---/ s|tls.key: \"\"|tls.key: $TEST_A_KEY_B64|" \
    -e "/name: test-b-tls/,/^---/ s|tls.crt: \"\"|tls.crt: $TEST_B_CRT_B64|" \
    -e "/name: test-b-tls/,/^---/ s|tls.key: \"\"|tls.key: $TEST_B_KEY_B64|" \
    "$SCRIPT_DIR/test-nginx-multi-sni.yaml" | kubectl apply -f -

log_success "Secrets and nginx deployment created"
echo

# Step 3: Wait for nginx to be ready
log_info "Step 3: Waiting for nginx to be ready..."
kubectl wait --for=condition=ready pod -l app=test-nginx-multi-sni -n "$NAMESPACE" --timeout=120s
NGINX_POD=$(kubectl get pod -l app=test-nginx-multi-sni -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}')
log_success "Nginx pod ready: $NGINX_POD"

# Get service IP
SERVICE_IP=$(kubectl get service test-nginx-multi-sni -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
log_info "Service IP: $SERVICE_IP"
echo

# Step 4: Create ConfigMap with test CA for mounting in test pod
log_info "Step 4: Creating ConfigMap with test CA..."
kubectl create configmap test-ca-bundle -n "$NAMESPACE" \
  --from-file=test-ca.crt="$SCRIPT_DIR/test-certs/test-ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -

log_success "Test CA ConfigMap created"
echo

# Step 5: Deploy test client pod with interception
log_info "Step 5: Deploying test client pod with interception enabled..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-client
  namespace: $NAMESPACE
  labels:
    intercept-proxy/enabled: "true"
  annotations:
    intercept-proxy/opa-data: |
      allowed_domains: []
      unrestricted_domains:
        - test-a.local
        - test-b.local
      github_read_access_enabled: false
      github_allowed_users: []
      github_allowed_repos: []
      aws_access_enabled: false
      aws_allowed_services: []
spec:
  securityContext:
    runAsUser: 12345
    runAsGroup: 12345
    fsGroup: 12345
  initContainers:
  - name: setup-ca-and-hosts
    image: curlimages/curl:latest
    command:
    - sh
    - -c
    - |
      # Add test CA to system CA bundle
      cat /etc/ssl/certs/ca-certificates.crt > /shared-ca/ca-bundle.crt
      echo "" >> /shared-ca/ca-bundle.crt
      cat /test-ca/test-ca.crt >> /shared-ca/ca-bundle.crt

      # Save SERVICE_IP env var to a file for use by main container
      echo \$SERVICE_IP > /shared-hosts/service-ip
    env:
    - name: SERVICE_IP
      value: "$SERVICE_IP"
    volumeMounts:
    - name: shared-ca
      mountPath: /shared-ca
    - name: shared-hosts
      mountPath: /shared-hosts
    - name: test-ca
      mountPath: /test-ca
      readOnly: true
    securityContext:
      runAsUser: 12345
      runAsGroup: 12345
  containers:
  - name: test
    image: curlimages/curl:latest
    command:
    - sh
    - -c
    - |
      # Read the service IP from the file created by init container
      export SERVICE_IP=$(cat /shared-hosts/service-ip)
      echo "SERVICE_IP is: \$SERVICE_IP"
      # Sleep to keep container running
      sleep 3600
    env:
    - name: SSL_CERT_FILE
      value: /shared-ca/ca-bundle.crt
    volumeMounts:
    - name: shared-ca
      mountPath: /shared-ca
      readOnly: true
    - name: shared-hosts
      mountPath: /shared-hosts
      readOnly: true
    securityContext:
      runAsUser: 12345
      runAsGroup: 12345
  volumes:
  - name: shared-ca
    emptyDir: {}
  - name: shared-hosts
    emptyDir: {}
  - name: test-ca
    configMap:
      name: test-ca-bundle
  restartPolicy: Never
EOF

kubectl wait --for=condition=ready pod/test-client -n "$NAMESPACE" --timeout=120s
log_success "Test client pod ready"
echo

# Give sidecars a moment to fully initialize
log_info "Waiting for sidecars to initialize..."
sleep 10

# Step 6: Run test sequence 1 (test-a.local first, then test-b.local)
log_info "Step 6: Test Sequence 1 - Access test-a.local first, then test-b.local"
echo

log_info "Testing test-a.local..."
RESULT_A1=$(kubectl exec test-client -n "$NAMESPACE" -c test -- sh -c 'SERVICE_IP=$(cat /shared-hosts/service-ip); curl -s -w "\nHTTP_CODE:%{http_code}" --resolve "test-a.local:443:$SERVICE_IP" https://test-a.local/' 2>&1 || echo "FAILED")
HTTP_CODE_A1=$(echo "$RESULT_A1" | grep "HTTP_CODE:" | cut -d: -f2)
RESPONSE_A1=$(echo "$RESULT_A1" | grep -v "HTTP_CODE:")

if [ "$HTTP_CODE_A1" = "200" ] && echo "$RESPONSE_A1" | grep -q "test-a.local"; then
    log_success "test-a.local: HTTP $HTTP_CODE_A1 - PASS"
    echo "    Response: $RESPONSE_A1"
else
    log_error "test-a.local: HTTP $HTTP_CODE_A1 - FAIL"
    echo "    Response: $RESPONSE_A1"
    exit 1
fi
echo

log_info "Testing test-b.local..."
RESULT_B1=$(kubectl exec test-client -n "$NAMESPACE" -c test -- sh -c 'SERVICE_IP=$(cat /shared-hosts/service-ip); curl -s -w "\nHTTP_CODE:%{http_code}" --resolve "test-b.local:443:$SERVICE_IP" https://test-b.local/' 2>&1 || echo "FAILED")
HTTP_CODE_B1=$(echo "$RESULT_B1" | grep "HTTP_CODE:" | cut -d: -f2)
RESPONSE_B1=$(echo "$RESULT_B1" | grep -v "HTTP_CODE:")

if [ "$HTTP_CODE_B1" = "200" ] && echo "$RESPONSE_B1" | grep -q "test-b.local"; then
    log_success "test-b.local: HTTP $HTTP_CODE_B1 - PASS"
    echo "    Response: $RESPONSE_B1"
else
    log_error "test-b.local: HTTP $HTTP_CODE_B1 - FAIL (This would fail without the fix!)"
    echo "    Response: $RESPONSE_B1"
    exit 1
fi
echo

# Step 7: Restart pod to clear any cached state
log_info "Step 7: Restarting test client pod to clear state..."
kubectl delete pod test-client -n "$NAMESPACE" --wait=true
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-client
  namespace: $NAMESPACE
  labels:
    intercept-proxy/enabled: "true"
  annotations:
    intercept-proxy/opa-data: |
      allowed_domains: []
      unrestricted_domains:
        - test-a.local
        - test-b.local
      github_read_access_enabled: false
      github_allowed_users: []
      github_allowed_repos: []
      aws_access_enabled: false
      aws_allowed_services: []
spec:
  securityContext:
    runAsUser: 12345
    runAsGroup: 12345
    fsGroup: 12345
  initContainers:
  - name: setup-ca-and-hosts
    image: curlimages/curl:latest
    command:
    - sh
    - -c
    - |
      # Add test CA to system CA bundle
      cat /etc/ssl/certs/ca-certificates.crt > /shared-ca/ca-bundle.crt
      echo "" >> /shared-ca/ca-bundle.crt
      cat /test-ca/test-ca.crt >> /shared-ca/ca-bundle.crt

      # Save SERVICE_IP env var to a file for use by main container
      echo \$SERVICE_IP > /shared-hosts/service-ip
    env:
    - name: SERVICE_IP
      value: "$SERVICE_IP"
    volumeMounts:
    - name: shared-ca
      mountPath: /shared-ca
    - name: shared-hosts
      mountPath: /shared-hosts
    - name: test-ca
      mountPath: /test-ca
      readOnly: true
    securityContext:
      runAsUser: 12345
      runAsGroup: 12345
  containers:
  - name: test
    image: curlimages/curl:latest
    command:
    - sh
    - -c
    - |
      # Read the service IP from the file created by init container
      export SERVICE_IP=$(cat /shared-hosts/service-ip)
      echo "SERVICE_IP is: \$SERVICE_IP"
      # Sleep to keep container running
      sleep 3600
    env:
    - name: SSL_CERT_FILE
      value: /shared-ca/ca-bundle.crt
    volumeMounts:
    - name: shared-ca
      mountPath: /shared-ca
      readOnly: true
    - name: shared-hosts
      mountPath: /shared-hosts
      readOnly: true
    securityContext:
      runAsUser: 12345
      runAsGroup: 12345
  volumes:
  - name: shared-ca
    emptyDir: {}
  - name: shared-hosts
    emptyDir: {}
  - name: test-ca
    configMap:
      name: test-ca-bundle
  restartPolicy: Never
EOF

kubectl wait --for=condition=ready pod/test-client -n "$NAMESPACE" --timeout=120s
log_success "Test client pod restarted"
sleep 10
echo

# Step 8: Run test sequence 2 (test-b.local first, then test-a.local)
log_info "Step 8: Test Sequence 2 - Access test-b.local first, then test-a.local"
echo

log_info "Testing test-b.local..."
RESULT_B2=$(kubectl exec test-client -n "$NAMESPACE" -c test -- sh -c 'SERVICE_IP=$(cat /shared-hosts/service-ip); curl -s -w "\nHTTP_CODE:%{http_code}" --resolve "test-b.local:443:$SERVICE_IP" https://test-b.local/' 2>&1 || echo "FAILED")
HTTP_CODE_B2=$(echo "$RESULT_B2" | grep "HTTP_CODE:" | cut -d: -f2)
RESPONSE_B2=$(echo "$RESULT_B2" | grep -v "HTTP_CODE:")

if [ "$HTTP_CODE_B2" = "200" ] && echo "$RESPONSE_B2" | grep -q "test-b.local"; then
    log_success "test-b.local: HTTP $HTTP_CODE_B2 - PASS"
    echo "    Response: $RESPONSE_B2"
else
    log_error "test-b.local: HTTP $HTTP_CODE_B2 - FAIL"
    echo "    Response: $RESPONSE_B2"
    exit 1
fi
echo

log_info "Testing test-a.local..."
RESULT_A2=$(kubectl exec test-client -n "$NAMESPACE" -c test -- sh -c 'SERVICE_IP=$(cat /shared-hosts/service-ip); curl -s -w "\nHTTP_CODE:%{http_code}" --resolve "test-a.local:443:$SERVICE_IP" https://test-a.local/' 2>&1 || echo "FAILED")
HTTP_CODE_A2=$(echo "$RESULT_A2" | grep "HTTP_CODE:" | cut -d: -f2)
RESPONSE_A2=$(echo "$RESULT_A2" | grep -v "HTTP_CODE:")

if [ "$HTTP_CODE_A2" = "200" ] && echo "$RESPONSE_A2" | grep -q "test-a.local"; then
    log_success "test-a.local: HTTP $HTTP_CODE_A2 - PASS"
    echo "    Response: $RESPONSE_A2"
else
    log_error "test-a.local: HTTP $HTTP_CODE_A2 - FAIL (This would fail without the fix!)"
    echo "    Response: $RESPONSE_A2"
    exit 1
fi
echo

# Step 9: Check Envoy logs for TLS errors
log_info "Step 9: Checking Envoy access logs for TLS errors..."
ENVOY_LOGS=$(kubectl logs test-client -n "$NAMESPACE" -c envoy-proxy --tail=50 || true)

if echo "$ENVOY_LOGS" | grep -q "CERTIFICATE_VERIFY_FAILED"; then
    log_error "Found CERTIFICATE_VERIFY_FAILED errors in Envoy logs!"
    echo "$ENVOY_LOGS" | grep "CERTIFICATE_VERIFY_FAILED"
    exit 1
else
    log_success "No CERTIFICATE_VERIFY_FAILED errors found in Envoy logs"
fi
echo

# Step 10: Summary
echo "========================================"
echo "           TEST RESULTS"
echo "========================================"
echo
log_success "✓ Sequence 1: test-a.local → test-b.local (both succeeded)"
log_success "✓ Sequence 2: test-b.local → test-a.local (both succeeded)"
log_success "✓ No TLS validation errors in Envoy logs"
echo
log_success "ALL TESTS PASSED!"
echo
echo "This test verifies that the fix for TLS session resumption"
echo "correctly handles multiple hostnames on the same IP with"
echo "different certificates. Without the fix (max_session_keys=0),"
echo "the second hostname tested would fail with CERTIFICATE_VERIFY_FAILED."
echo
