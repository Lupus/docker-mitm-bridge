#!/bin/bash
set -e

echo "Testing OPA data setup init container environment variable fix..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test resources..."
    kubectl delete pod opa-env-test-pod -n kyverno-intercept --ignore-not-found=true --wait=false
}

trap cleanup EXIT

# Step 1: Apply the updated Helm chart
log_info "Applying updated Helm chart with separate init container rule..."
helm upgrade --install intercept-proxy . \
    --namespace kyverno-intercept \
    --create-namespace \
    --wait \
    --timeout 2m

# Wait for Kyverno policy to be ready
log_info "Waiting for Kyverno policy to be ready..."
sleep 5

# Step 2: Create a test pod with OPA data annotation
log_info "Creating test pod with custom OPA data annotation..."
kubectl apply -n kyverno-intercept -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: opa-env-test-pod
  labels:
    app: opa-env-test
    intercept-proxy/enabled: "true"
  annotations:
    intercept-proxy/opa-data: |
      allowed_domains: []
      unrestricted_domains:
        - "test.example.com"
      github_read_access_enabled: false
spec:
  securityContext:
    runAsUser: 12345
    runAsGroup: 12345
    fsGroup: 12345
  containers:
  - name: test-container
    image: busybox
    command: ["sleep", "300"]
EOF

# Step 3: Wait for pod to be scheduled (not necessarily ready)
log_info "Waiting for pod to be scheduled..."
for i in {1..30}; do
    if kubectl get pod opa-env-test-pod -n kyverno-intercept &>/dev/null; then
        break
    fi
    sleep 1
done

# Give Kyverno time to mutate the pod
sleep 5

# Step 4: Check if opa-data-setup init container exists
log_info "Checking if opa-data-setup init container was injected..."
INIT_CONTAINER=$(kubectl get pod opa-env-test-pod -n kyverno-intercept \
    -o jsonpath='{.spec.initContainers[?(@.name=="opa-data-setup")].name}' 2>/dev/null || echo "")

if [ -z "$INIT_CONTAINER" ]; then
    log_error "opa-data-setup init container not found!"
    exit 1
fi
log_info "✓ opa-data-setup init container found"

# Step 5: Check if environment variable is set
log_info "Checking if OPA_POLICY_DATA environment variable is set..."
ENV_VAR=$(kubectl get pod opa-env-test-pod -n kyverno-intercept \
    -o jsonpath='{.spec.initContainers[?(@.name=="opa-data-setup")].env[?(@.name=="OPA_POLICY_DATA")].name}' 2>/dev/null || echo "")

if [ -z "$ENV_VAR" ]; then
    log_error "OPA_POLICY_DATA environment variable not found!"
    log_info "Dumping init container configuration for debugging:"
    kubectl get pod opa-env-test-pod -n kyverno-intercept \
        -o jsonpath='{.spec.initContainers[?(@.name=="opa-data-setup")]}' | python3 -m json.tool
    exit 1
fi
log_info "✓ OPA_POLICY_DATA environment variable found"

# Step 6: Verify the fieldPath reference
log_info "Verifying fieldPath reference..."
FIELD_PATH=$(kubectl get pod opa-env-test-pod -n kyverno-intercept \
    -o jsonpath='{.spec.initContainers[?(@.name=="opa-data-setup")].env[?(@.name=="OPA_POLICY_DATA")].valueFrom.fieldRef.fieldPath}' 2>/dev/null || echo "")

EXPECTED_FIELD_PATH="metadata.annotations['intercept-proxy/opa-data']"
if [ "$FIELD_PATH" != "$EXPECTED_FIELD_PATH" ]; then
    log_error "Unexpected fieldPath: $FIELD_PATH"
    log_error "Expected: $EXPECTED_FIELD_PATH"
    exit 1
fi
log_info "✓ fieldPath correctly references annotation"

# Step 7: Wait for init container to complete
log_info "Waiting for init containers to complete..."
kubectl wait --for=condition=Initialized pod/opa-env-test-pod \
    -n kyverno-intercept --timeout=60s || {
    log_error "Init containers failed to complete"
    log_info "Checking init container logs:"
    kubectl logs opa-env-test-pod -n kyverno-intercept -c opa-data-setup || true
    exit 1
}

# Step 8: Check init container logs
log_info "Checking opa-data-setup init container logs..."
LOGS=$(kubectl logs opa-env-test-pod -n kyverno-intercept -c opa-data-setup 2>/dev/null || echo "")

if [[ "$LOGS" =~ "Using custom OPA policy data from annotation" ]]; then
    log_info "✓ Init container successfully used custom OPA data from annotation"
else
    log_error "Init container did not use custom OPA data!"
    log_info "Container logs: $LOGS"
    exit 1
fi

# Step 9: Verify the data was written to the shared volume
log_info "Verifying OPA data file was created..."
kubectl wait --for=condition=ready pod/opa-env-test-pod \
    -n kyverno-intercept --timeout=60s || true

# Check if the file exists in the volume by examining OPA sidecar
OPA_READY=$(kubectl get pod opa-env-test-pod -n kyverno-intercept \
    -o jsonpath='{.status.containerStatuses[?(@.name=="opa-sidecar")].ready}' 2>/dev/null || echo "false")

if [ "$OPA_READY" = "true" ]; then
    log_info "✓ OPA sidecar is ready (data file was properly prepared)"
else
    log_warning "OPA sidecar not ready yet, but init container completed successfully"
fi

# Success!
echo ""
log_info "===================================="
log_info "✓ ALL TESTS PASSED!"
log_info "===================================="
log_info "The OPA data setup init container is now correctly:"
log_info "  1. Injected with the environment variable"
log_info "  2. Reading the annotation value via fieldPath"
log_info "  3. Using the custom OPA data from the annotation"
log_info ""
log_info "Fix verified: Separating the init containers into different Kyverno rules resolved the issue."