#!/usr/bin/env bash

set -euo pipefail

# Kyverno Interceptor Chart - E2E Test Runner
# This script sets up a test environment and runs end-to-end tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DIR="$CHART_DIR/test"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kyverno-test}"
KYVERNO_NAMESPACE="kyverno"
TEST_NAMESPACE="kyverno-intercept"
HELM_RELEASE_NAME="intercept-proxy"
SKIP_CLUSTER_CREATION="${SKIP_CLUSTER_CREATION:-false}"
SKIP_CLEANUP="${SKIP_CLEANUP:-false}"
KEEP_CLUSTER="${KEEP_CLUSTER:-false}"

# Log functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_section() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$*${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    log_section "Checking Prerequisites"

    local missing_tools=()

    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi

    if ! command -v helm &> /dev/null; then
        missing_tools+=("helm")
    fi

    if ! command -v bats &> /dev/null; then
        missing_tools+=("bats")
    fi

    if [ "$SKIP_CLUSTER_CREATION" = "false" ]; then
        if ! command -v kind &> /dev/null; then
            missing_tools+=("kind")
        fi
    fi

    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        echo ""
        echo "Installation instructions:"
        echo "  - kubectl: https://kubernetes.io/docs/tasks/tools/"
        echo "  - helm: https://helm.sh/docs/intro/install/"
        echo "  - kind: https://kind.sigs.k8s.io/docs/user/quick-start/"
        echo "  - bats: npm install -g bats OR https://github.com/bats-core/bats-core"
        exit 1
    fi

    log_info "All prerequisites satisfied"
}

# Create kind cluster
create_kind_cluster() {
    if [ "$SKIP_CLUSTER_CREATION" = "true" ]; then
        log_info "Skipping cluster creation (SKIP_CLUSTER_CREATION=true)"
        # Still need to set KUBECONFIG for existing cluster
        setup_kubeconfig
        return
    fi

    log_section "Creating kind Cluster"

    if kind get clusters | grep -q "^${KIND_CLUSTER_NAME}$"; then
        log_warn "Cluster $KIND_CLUSTER_NAME already exists"
        read -p "Delete and recreate? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            kind delete cluster --name "$KIND_CLUSTER_NAME"
        else
            log_info "Using existing cluster"
            setup_kubeconfig
            return
        fi
    fi

    log_info "Creating kind cluster: $KIND_CLUSTER_NAME"

    # Set isolated KUBECONFIG before creating cluster to prevent modifying ~/.kube/config
    # When KUBECONFIG env var is set, kind writes to that file instead of ~/.kube/config
    export KUBECONFIG="/tmp/kind-${KIND_CLUSTER_NAME}-kubeconfig.yaml"

    # Use K8s version matching CI workflow
    kind create cluster --name "$KIND_CLUSTER_NAME" --image kindest/node:v1.31.9 --wait 120s

    log_info "Cluster created successfully"
    log_info "Using isolated KUBECONFIG: $KUBECONFIG (user's ~/.kube/config not modified)"

    # Verify cluster access
    kubectl cluster-info
}

# Setup kubeconfig to use kind cluster (for existing cluster case)
setup_kubeconfig() {
    log_info "Setting up kubeconfig for existing kind cluster..."

    # Export kind kubeconfig to temp file to avoid modifying user's ~/.kube/config
    export KUBECONFIG="/tmp/kind-${KIND_CLUSTER_NAME}-kubeconfig.yaml"
    kind get kubeconfig --name "$KIND_CLUSTER_NAME" > "$KUBECONFIG"

    log_info "Using KUBECONFIG: $KUBECONFIG"

    # Verify cluster access
    kubectl cluster-info
}

# Install Kyverno
install_kyverno() {
    log_section "Installing Kyverno"

    # Check if Kyverno is already installed
    if helm list -n "$KYVERNO_NAMESPACE" 2>/dev/null | grep -q "^kyverno"; then
        log_info "Kyverno already installed, verifying it's ready..."

        # Verify Kyverno pods are ready
        log_info "Waiting for Kyverno pods to be ready..."
        kubectl wait --for=condition=ready pod \
            --all \
            -n "$KYVERNO_NAMESPACE" \
            --timeout=30s 2>/dev/null || {
            log_warn "Some Kyverno pods not ready, checking status..."
            kubectl get pods -n "$KYVERNO_NAMESPACE"
        }
    else
        log_info "Adding Kyverno Helm repository"
        helm repo add kyverno https://kyverno.github.io/kyverno/ 2>/dev/null || true
        helm repo update

        log_info "Installing Kyverno (latest stable)"
        helm install kyverno kyverno/kyverno \
            -n "$KYVERNO_NAMESPACE" \
            --create-namespace \
            --wait \
            --timeout 5m

        log_info "Verifying Kyverno installation..."
        kubectl get pods -n "$KYVERNO_NAMESPACE"

        # Wait for admission controller specifically (matching CI)
        kubectl wait --for=condition=ready pod \
            -l app.kubernetes.io/component=admission-controller \
            -n "$KYVERNO_NAMESPACE" \
            --timeout=300s || true
    fi

    log_info "Kyverno is ready"
}

# Install interceptor chart
install_chart() {
    log_section "Installing Interceptor Chart"

    # Create namespace if it doesn't exist
    kubectl create namespace "$TEST_NAMESPACE" 2>/dev/null || true

    log_info "Installing chart: $HELM_RELEASE_NAME"

    helm upgrade --install "$HELM_RELEASE_NAME" "$CHART_DIR" \
        -n "$TEST_NAMESPACE" \
        --wait \
        --timeout 5m \
        --set testWorkload.enabled=false

    log_info "Chart installed successfully"

    log_info "Verifying chart resources..."
    kubectl get clusterpolicy,configmap,secret -n "$TEST_NAMESPACE"
}

# Run tests
run_tests() {
    log_section "Running E2E Tests"

    cd "$CHART_DIR"

    log_info "Running BATS tests..."
    echo ""

    local test_files=(
        "test/e2e/test-deployment.bats"
        "test/e2e/test-tls.bats"
        "test/e2e/test-opa-policy.bats"
        "test/e2e/test-port-isolation.bats"
        "test/e2e/test-network-isolation.bats"
    )

    local failed_tests=()

    for test_file in "${test_files[@]}"; do
        if [ -f "$test_file" ]; then
            log_info "Running: $test_file"
            if ! bats "$test_file"; then
                failed_tests+=("$test_file")
            fi
            echo ""
        else
            log_warn "Test file not found: $test_file"
        fi
    done

    if [ ${#failed_tests[@]} -ne 0 ]; then
        log_error "Some tests failed: ${failed_tests[*]}"
        return 1
    fi

    log_info "All tests passed!"
}

# Cleanup
cleanup() {
    if [ "$SKIP_CLEANUP" = "true" ]; then
        log_info "Skipping cleanup (SKIP_CLEANUP=true)"
        return
    fi

    log_section "Cleanup"

    log_info "Uninstalling chart..."
    helm uninstall "$HELM_RELEASE_NAME" -n "$TEST_NAMESPACE" --timeout 30s 2>/dev/null || true

    log_info "Deleting test resources..."
    kubectl delete namespace "$TEST_NAMESPACE" --timeout=30s 2>/dev/null &
    # Don't wait for namespace deletion, just fire and forget

    if [ "$KEEP_CLUSTER" = "false" ] && [ "$SKIP_CLUSTER_CREATION" = "false" ]; then
        log_info "Deleting kind cluster..."
        kind delete cluster --name "$KIND_CLUSTER_NAME"

        # Clean up temporary kubeconfig
        if [ -n "${KUBECONFIG:-}" ] && [ -f "${KUBECONFIG:-}" ]; then
            log_info "Removing temporary kubeconfig: $KUBECONFIG"
            rm -f "$KUBECONFIG"
        fi
    else
        log_info "Keeping cluster: $KIND_CLUSTER_NAME"
        log_info "Kubeconfig preserved at: ${KUBECONFIG:-/tmp/kind-${KIND_CLUSTER_NAME}-kubeconfig.yaml}"
    fi
}

# Main execution
main() {
    log_section "Kyverno Interceptor E2E Tests"

    log_info "Configuration:"
    echo "  Cluster: $KIND_CLUSTER_NAME"
    echo "  Namespace: $TEST_NAMESPACE"
    echo "  Release: $HELM_RELEASE_NAME"
    echo "  Chart Dir: $CHART_DIR"
    echo "  Kubeconfig: /tmp/kind-${KIND_CLUSTER_NAME}-kubeconfig.yaml (isolated from user config)"
    echo ""

    # Setup trap for cleanup
    trap cleanup EXIT

    check_prerequisites
    create_kind_cluster
    install_kyverno
    install_chart
    run_tests

    log_section "Tests Complete!"
    log_info "All tests passed successfully"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-cluster-creation)
            SKIP_CLUSTER_CREATION=true
            shift
            ;;
        --skip-cleanup)
            SKIP_CLEANUP=true
            shift
            ;;
        --keep-cluster)
            KEEP_CLUSTER=true
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --skip-cluster-creation  Use existing cluster instead of creating new one"
            echo "  --skip-cleanup           Don't cleanup resources after tests"
            echo "  --keep-cluster           Don't delete kind cluster after tests"
            echo "  --help                   Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  KIND_CLUSTER_NAME        Name of kind cluster (default: kyverno-test)"
            echo "  SKIP_CLUSTER_CREATION    Skip cluster creation (default: false)"
            echo "  SKIP_CLEANUP             Skip cleanup (default: false)"
            echo "  KEEP_CLUSTER             Keep cluster after tests (default: false)"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main
main
