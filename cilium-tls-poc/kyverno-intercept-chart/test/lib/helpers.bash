#!/usr/bin/env bash

# Helper functions for Kyverno Interceptor Chart E2E tests

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Wait for pod to be ready with timeout
wait_for_pod_ready() {
    local pod_name=$1
    local namespace=${2:-kyverno-intercept}
    local timeout=${3:-120}

    log_info "Waiting for pod $pod_name in namespace $namespace to be ready..."

    kubectl wait --for=condition=ready pod -l app="$pod_name" \
        -n "$namespace" --timeout="${timeout}s" 2>&1
}

# Get pod name by label
get_pod_name() {
    local app_label=$1
    local namespace=${2:-kyverno-intercept}

    kubectl get pod -l app="$app_label" -n "$namespace" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# Execute command in pod container
exec_in_pod() {
    local pod_name=$1
    local container=$2
    shift 2
    local cmd="$*"

    kubectl exec -n kyverno-intercept "$pod_name" -c "$container" -- sh -c "$cmd" 2>&1
}

# Test HTTP/HTTPS connectivity from pod
test_http_access() {
    local pod_name=$1
    local container=$2
    local url=$3
    local expected_code=${4:-200}

    local actual_code
    actual_code=$(exec_in_pod "$pod_name" "$container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 10 '$url'")

    if [ "$actual_code" = "$expected_code" ]; then
        return 0
    else
        log_error "Expected HTTP $expected_code but got $actual_code for $url"
        return 1
    fi
}

# Test that port is blocked (connection should fail)
test_port_blocked() {
    local pod_name=$1
    local container=$2
    local host=$3
    local port=$4

    log_info "Testing that $host:$port is blocked in $pod_name..."

    # Use timeout to avoid hanging, expect failure
    if exec_in_pod "$pod_name" "$container" \
        "timeout 2 nc -zv $host $port" &>/dev/null; then
        log_error "Port $host:$port should be blocked but is accessible"
        return 1
    else
        log_info "Port $host:$port is correctly blocked"
        return 0
    fi
}

# Test that port is accessible (or at least not blocked by iptables)
test_port_accessible() {
    local pod_name=$1
    local container=$2
    local host=$3
    local port=$4

    log_info "Testing that $host:$port is not blocked in $pod_name..."

    # Connection may be refused (no service listening), but shouldn't timeout
    # Exit code 0 = connected, 1 = connection refused (OK), 124 = timeout (BLOCKED)
    local output
    local exit_code
    output=$(exec_in_pod "$pod_name" "$container" \
        "timeout 2 nc -zv $host $port 2>&1")
    exit_code=$?

    # If timeout (124) or connection filtered, it's blocked
    if echo "$output" | grep -q "timeout\|Connection timed out"; then
        log_error "Port $host:$port appears to be blocked (timeout)"
        return 1
    fi

    log_info "Port $host:$port is accessible (exit code: $exit_code)"
    return 0
}

# Verify certificate issuer
verify_cert_issuer() {
    local pod_name=$1
    local container=$2
    local url=$3
    local expected_issuer=$4

    log_info "Checking certificate issuer for $url..."

    local issuer
    issuer=$(exec_in_pod "$pod_name" "$container" \
        "curl -v --silent --max-time 10 '$url' 2>&1 | grep 'issuer:' | head -1")

    if echo "$issuer" | grep -q "$expected_issuer"; then
        log_info "Certificate issuer matches: $issuer"
        return 0
    else
        log_error "Certificate issuer doesn't match. Got: $issuer"
        return 1
    fi
}

# Count containers in pod
count_pod_containers() {
    local pod_name=$1
    local namespace=${2:-kyverno-intercept}

    kubectl get pod "$pod_name" -n "$namespace" \
        -o jsonpath='{.spec.containers[*].name}' 2>/dev/null | wc -w
}

# Get container UID
get_container_uid() {
    local pod_name=$1
    local container=$2
    local namespace=${3:-kyverno-intercept}

    # First try container-level security context
    local uid
    uid=$(kubectl get pod "$pod_name" -n "$namespace" \
        -o jsonpath="{.spec.containers[?(@.name=='$container')].securityContext.runAsUser}" 2>/dev/null)

    # If not found, fall back to pod-level security context
    if [ -z "$uid" ]; then
        uid=$(kubectl get pod "$pod_name" -n "$namespace" \
            -o jsonpath="{.spec.securityContext.runAsUser}" 2>/dev/null)
    fi

    echo "$uid"
}

# Check if init container completed successfully
check_init_container() {
    local pod_name=$1
    local init_container=$2
    local namespace=${3:-kyverno-intercept}

    local status
    status=$(kubectl get pod "$pod_name" -n "$namespace" \
        -o jsonpath="{.status.initContainerStatuses[?(@.name=='$init_container')].state.terminated.reason}" 2>/dev/null)

    [ "$status" = "Completed" ]
}

# Get logs from container
get_container_logs() {
    local pod_name=$1
    local container=$2
    local namespace=${3:-kyverno-intercept}

    kubectl logs -n "$namespace" "$pod_name" -c "$container" 2>/dev/null || true
}

# Clean up test resources
cleanup_test_resources() {
    local namespace=${1:-kyverno-intercept}

    log_info "Cleaning up test resources in namespace $namespace..."

    kubectl delete deployment,service,pod --all -n "$namespace" --wait=false 2>/dev/null || true

    # Give some time for deletion to start
    sleep 2
}

# Verify OPA policy decision
test_opa_decision() {
    local pod_name=$1
    local method=$2
    local url=$3
    local expected_code=$4

    local actual_code
    actual_code=$(exec_in_pod "$pod_name" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X $method '$url'")

    if [ "$actual_code" = "$expected_code" ]; then
        log_info "OPA policy correctly returned $expected_code for $method $url"
        return 0
    else
        log_error "Expected $expected_code but got $actual_code for $method $url"
        return 1
    fi
}

# Wait for log entry matching pattern to appear in container logs
# Uses polling/retry pattern to handle kubectl logs API delays
wait_for_log_entry() {
    local pod_name=$1
    local container=$2
    local pattern=$3
    local namespace=${4:-kyverno-intercept}
    local timeout=${5:-10}
    local interval=${6:-0.5}

    log_info "Waiting for log entry matching '$pattern' in $container..."

    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        local logs
        logs=$(kubectl logs -n "$namespace" "$pod_name" -c "$container" 2>/dev/null || true)

        if echo "$logs" | grep -q "$pattern"; then
            log_info "Found matching log entry after ${elapsed}s"
            return 0
        fi

        sleep "$interval"
        elapsed=$(echo "$elapsed + $interval" | bc)
    done

    log_error "Timeout waiting for log entry matching '$pattern' after ${timeout}s"
    return 1
}

# Export functions for use in tests
export -f log_info log_warn log_error
export -f wait_for_pod_ready get_pod_name exec_in_pod
export -f test_http_access test_port_blocked test_port_accessible
export -f verify_cert_issuer count_pod_containers get_container_uid
export -f check_init_container get_container_logs cleanup_test_resources
export -f test_opa_decision wait_for_log_entry
