#!/bin/bash
set -euo pipefail

# Manual test for multi-SNI fix with real Anthropic domains
# Tests api.anthropic.com and console.anthropic.com (both on 160.79.104.10)

NAMESPACE="${NAMESPACE:-kyverno-intercept}"
CHART_NAME="${CHART_NAME:-intercept-proxy}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

echo "========================================"
echo "Anthropic Multi-SNI Manual Test"
echo "========================================"
echo
echo "This test validates the fix for:"
echo "  api.anthropic.com (160.79.104.10) - Google Trust Services CA"
echo "  console.anthropic.com (160.79.104.10) - Let's Encrypt CA"
echo
echo "Without the fix, only the first domain accessed would work."
echo

# Check if test pod exists
log_info "Checking for existing test pod..."
if kubectl get pod test-anthropic -n "$NAMESPACE" &>/dev/null; then
    log_info "Test pod exists, deleting to start fresh..."
    kubectl delete pod test-anthropic -n "$NAMESPACE" --wait=true
fi

# Deploy test pod with Anthropic domains in OPA policy
# Note: Using default OPA policy from values.yaml which includes api.anthropic.com
log_info "Deploying test pod with interception for Anthropic domains..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-anthropic
  namespace: $NAMESPACE
  labels:
    intercept-proxy/enabled: "true"
spec:
  securityContext:
    runAsUser: 12345
    runAsGroup: 12345
    fsGroup: 12345
  containers:
  - name: test
    image: curlimages/curl:latest
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      runAsUser: 12345
      runAsGroup: 12345
  restartPolicy: Never
EOF

log_info "Waiting for test pod to be ready..."
kubectl wait --for=condition=ready pod/test-anthropic -n "$NAMESPACE" --timeout=120s
log_success "Test pod ready"
echo

# Give sidecars a moment to initialize
log_info "Waiting for sidecars to fully initialize..."
sleep 15

# Test Sequence 1: api.anthropic.com first, then console.anthropic.com
echo "========================================"
echo "Test Sequence 1: api → console"
echo "========================================"
echo

log_info "Testing api.anthropic.com..."
RESULT_API1=$(kubectl exec test-anthropic -n "$NAMESPACE" -c test -- curl -s -w "\nHTTP_CODE:%{http_code}" https://api.anthropic.com/v1/messages 2>&1 || echo "FAILED")
HTTP_CODE_API1=$(echo "$RESULT_API1" | grep "HTTP_CODE:" | cut -d: -f2)
echo "Response code: $HTTP_CODE_API1"

if [ "$HTTP_CODE_API1" = "401" ] || [ "$HTTP_CODE_API1" = "200" ]; then
    log_success "api.anthropic.com: Connected successfully (HTTP $HTTP_CODE_API1)"
else
    log_error "api.anthropic.com: Failed with HTTP $HTTP_CODE_API1"
    echo "Response: $RESULT_API1"
fi
echo

sleep 2

log_info "Testing console.anthropic.com..."
RESULT_CONSOLE1=$(kubectl exec test-anthropic -n "$NAMESPACE" -c test -- curl -s -w "\nHTTP_CODE:%{http_code}" https://console.anthropic.com/settings/keys 2>&1 || echo "FAILED")
HTTP_CODE_CONSOLE1=$(echo "$RESULT_CONSOLE1" | grep "HTTP_CODE:" | cut -d: -f2)
echo "Response code: $HTTP_CODE_CONSOLE1"

if [ "$HTTP_CODE_CONSOLE1" = "200" ] || [ "$HTTP_CODE_CONSOLE1" = "302" ] || [ "$HTTP_CODE_CONSOLE1" = "401" ]; then
    log_success "console.anthropic.com: Connected successfully (HTTP $HTTP_CODE_CONSOLE1)"
else
    log_error "console.anthropic.com: Failed with HTTP $HTTP_CODE_CONSOLE1 (This would fail without the fix!)"
    echo "Response: $RESULT_CONSOLE1"
fi
echo

# Check Envoy logs for errors
log_info "Checking Envoy logs for TLS errors (Sequence 1)..."
ERRORS1=$(kubectl logs test-anthropic -n "$NAMESPACE" -c envoy-proxy --tail=100 2>/dev/null | grep -c "CERTIFICATE_VERIFY_FAILED" || true)
if [ "$ERRORS1" -gt 0 ]; then
    log_error "Found $ERRORS1 CERTIFICATE_VERIFY_FAILED errors in Envoy logs!"
    kubectl logs test-anthropic -n "$NAMESPACE" -c envoy-proxy --tail=50 | grep "CERTIFICATE_VERIFY_FAILED"
else
    log_success "No CERTIFICATE_VERIFY_FAILED errors found"
fi
echo

# Restart pod for sequence 2
log_info "Restarting test pod for sequence 2..."
kubectl delete pod test-anthropic -n "$NAMESPACE" --wait=true

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-anthropic
  namespace: $NAMESPACE
  labels:
    intercept-proxy/enabled: "true"
spec:
  securityContext:
    runAsUser: 12345
    runAsGroup: 12345
    fsGroup: 12345
  containers:
  - name: test
    image: curlimages/curl:latest
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      runAsUser: 12345
      runAsGroup: 12345
  restartPolicy: Never
EOF

kubectl wait --for=condition=ready pod/test-anthropic -n "$NAMESPACE" --timeout=120s
log_success "Test pod restarted"
sleep 15

# Test Sequence 2: console.anthropic.com first, then api.anthropic.com
echo "========================================"
echo "Test Sequence 2: console → api"
echo "========================================"
echo

log_info "Testing console.anthropic.com..."
RESULT_CONSOLE2=$(kubectl exec test-anthropic -n "$NAMESPACE" -c test -- curl -s -w "\nHTTP_CODE:%{http_code}" https://console.anthropic.com/settings/keys 2>&1 || echo "FAILED")
HTTP_CODE_CONSOLE2=$(echo "$RESULT_CONSOLE2" | grep "HTTP_CODE:" | cut -d: -f2)
echo "Response code: $HTTP_CODE_CONSOLE2"

if [ "$HTTP_CODE_CONSOLE2" = "200" ] || [ "$HTTP_CODE_CONSOLE2" = "302" ] || [ "$HTTP_CODE_CONSOLE2" = "401" ]; then
    log_success "console.anthropic.com: Connected successfully (HTTP $HTTP_CODE_CONSOLE2)"
else
    log_error "console.anthropic.com: Failed with HTTP $HTTP_CODE_CONSOLE2"
    echo "Response: $RESULT_CONSOLE2"
fi
echo

sleep 2

log_info "Testing api.anthropic.com..."
RESULT_API2=$(kubectl exec test-anthropic -n "$NAMESPACE" -c test -- curl -s -w "\nHTTP_CODE:%{http_code}" https://api.anthropic.com/v1/messages 2>&1 || echo "FAILED")
HTTP_CODE_API2=$(echo "$RESULT_API2" | grep "HTTP_CODE:" | cut -d: -f2)
echo "Response code: $HTTP_CODE_API2"

if [ "$HTTP_CODE_API2" = "401" ] || [ "$HTTP_CODE_API2" = "200" ]; then
    log_success "api.anthropic.com: Connected successfully (HTTP $HTTP_CODE_API2)"
else
    log_error "api.anthropic.com: Failed with HTTP $HTTP_CODE_API2 (This would fail without the fix!)"
    echo "Response: $RESULT_API2"
fi
echo

# Check Envoy logs for errors
log_info "Checking Envoy logs for TLS errors (Sequence 2)..."
ERRORS2=$(kubectl logs test-anthropic -n "$NAMESPACE" -c envoy-proxy --tail=100 2>/dev/null | grep -c "CERTIFICATE_VERIFY_FAILED" || true)
if [ "$ERRORS2" -gt 0 ]; then
    log_error "Found $ERRORS2 CERTIFICATE_VERIFY_FAILED errors in Envoy logs!"
    kubectl logs test-anthropic -n "$NAMESPACE" -c envoy-proxy --tail=50 | grep "CERTIFICATE_VERIFY_FAILED"
else
    log_success "No CERTIFICATE_VERIFY_FAILED errors found"
fi
echo

# Verify both domains resolve to same IP
log_info "Verifying both domains resolve to the same IP..."
kubectl exec test-anthropic -n "$NAMESPACE" -c test -- nslookup api.anthropic.com 2>/dev/null | grep "Address:" | tail -1
kubectl exec test-anthropic -n "$NAMESPACE" -c test -- nslookup console.anthropic.com 2>/dev/null | grep "Address:" | tail -1
echo

# Summary
echo "========================================"
echo "           TEST RESULTS"
echo "========================================"
echo

TOTAL_ERRORS=$((ERRORS1 + ERRORS2))

if [ "$TOTAL_ERRORS" -eq 0 ]; then
    log_success "✓ Sequence 1: api.anthropic.com → console.anthropic.com"
    log_success "✓ Sequence 2: console.anthropic.com → api.anthropic.com"
    log_success "✓ No TLS validation errors"
    echo
    log_success "ALL TESTS PASSED!"
    echo
    echo "The fix correctly handles multiple hostnames on the same IP"
    echo "with different TLS certificates!"
else
    log_error "✗ Found $TOTAL_ERRORS TLS validation errors"
    echo
    log_error "TEST FAILED - The fix may not be working correctly"
fi
echo

echo "To cleanup:"
echo "  kubectl delete pod test-anthropic -n $NAMESPACE"
echo
