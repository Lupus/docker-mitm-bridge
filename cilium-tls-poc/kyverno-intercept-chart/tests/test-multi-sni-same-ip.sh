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

# Step 4: Add test CA to the intercept-proxy CA bundle
log_info "Step 4: Adding test CA to Envoy's trusted CA bundle..."
# We need to append test CA to the existing CA Secret used by the chart
EXISTING_CA=$(kubectl get secret "${CHART_NAME}-ca" -n "$NAMESPACE" -o jsonpath='{.data.tls\.crt}' | base64 -d)
COMBINED_CA=$(cat <<EOF
$EXISTING_CA

# Test CA for multi-SNI testing
$(cat "$SCRIPT_DIR/test-certs/test-ca.crt")
EOF
)
COMBINED_CA_B64=$(echo "$COMBINED_CA" | base64 -w 0)

# Update the CA Secret
kubectl patch secret "${CHART_NAME}-ca" -n "$NAMESPACE" --type='json' \
  -p="[{\"op\": \"replace\", \"path\": \"/data/tls.crt\", \"value\": \"$COMBINED_CA_B64\"}]"

log_success "Test CA added to Envoy's trusted CA bundle"
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
      unrestricted_domains:
        - test-a.local
        - test-b.local
spec:
  securityContext:
    runAsUser: 12345
    runAsGroup: 12345
    fsGroup: 12345
  containers:
  - name: test
    image: curlimages/curl:latest
    command: ["sh", "-c", "echo '$SERVICE_IP test-a.local test-b.local' >> /etc/hosts && sleep 3600"]
    securityContext:
      runAsUser: 12345
      runAsGroup: 12345
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
RESULT_A1=$(kubectl exec test-client -n "$NAMESPACE" -c test -- curl -s -w "\nHTTP_CODE:%{http_code}" https://test-a.local/ 2>&1 || echo "FAILED")
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
RESULT_B1=$(kubectl exec test-client -n "$NAMESPACE" -c test -- curl -s -w "\nHTTP_CODE:%{http_code}" https://test-b.local/ 2>&1 || echo "FAILED")
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
      unrestricted_domains:
        - test-a.local
        - test-b.local
spec:
  securityContext:
    runAsUser: 12345
    runAsGroup: 12345
    fsGroup: 12345
  containers:
  - name: test
    image: curlimages/curl:latest
    command: ["sh", "-c", "echo '$SERVICE_IP test-a.local test-b.local' >> /etc/hosts && sleep 3600"]
    securityContext:
      runAsUser: 12345
      runAsGroup: 12345
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
RESULT_B2=$(kubectl exec test-client -n "$NAMESPACE" -c test -- curl -s -w "\nHTTP_CODE:%{http_code}" https://test-b.local/ 2>&1 || echo "FAILED")
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
RESULT_A2=$(kubectl exec test-client -n "$NAMESPACE" -c test -- curl -s -w "\nHTTP_CODE:%{http_code}" https://test-a.local/ 2>&1 || echo "FAILED")
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
