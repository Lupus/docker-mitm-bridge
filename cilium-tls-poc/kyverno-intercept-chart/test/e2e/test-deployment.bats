#!/usr/bin/env bats

# Test deployment and sidecar injection

load '../lib/detik'
load '../lib/helpers'

DETIK_CLIENT_NAME="kubectl"
DETIK_CLIENT_NAMESPACE="kyverno-intercept"

@test "Chart resources are created" {
    # Verify ClusterPolicy exists
    run kubectl get clusterpolicy -o name
    [ "$status" -eq 0 ]
    [[ "$output" =~ "intercept-proxy-inject-proxy" ]]

    # Verify ConfigMaps exist
    verify "there is 1 configmap named 'intercept-proxy-envoy-config'"
    verify "there is 1 configmap named 'intercept-proxy-opa-policy'"
    verify "there is 1 configmap named 'intercept-proxy-opa-config'"

    # Note: CA is now generated inline in emptyDir, not stored as Secret
}

@test "Test pod deploys successfully with sidecar injection" {
    # Deploy test pod
    kubectl apply -f test/fixtures/test-pod.yaml

    # Wait for pod to be ready (all containers pass readiness probes)
    log_info "Waiting for test-app pod to be ready..."
    try "at most 10 times every 15s to get pods named 'test-app' and verify that '.status.conditions[?(@.type==\"Ready\")].status' is 'True'"

    # Get pod name
    POD_NAME=$(get_pod_name "test-app")
    log_info "Test pod name: $POD_NAME"

    # Verify pod name exists
    [ -n "$POD_NAME" ]
}

@test "Pod has correct number of containers (1 app + 3 sidecars)" {
    POD_NAME=$(get_pod_name "test-app")

    # Count containers (should be 4: test-container + envoy-proxy + opa-sidecar + xds-service)
    CONTAINER_COUNT=$(count_pod_containers "$POD_NAME")
    log_info "Container count: $CONTAINER_COUNT"
    [ "$CONTAINER_COUNT" -eq 4 ]

    # Verify container names
    run kubectl get pod "$POD_NAME" -n kyverno-intercept -o jsonpath='{.spec.containers[*].name}'
    [ "$status" -eq 0 ]
    [[ "$output" =~ "test-container" ]]
    [[ "$output" =~ "envoy-proxy" ]]
    [[ "$output" =~ "opa-sidecar" ]]
    [[ "$output" =~ "xds-service" ]]
}

@test "Sidecars run with correct UIDs" {
    POD_NAME=$(get_pod_name "test-app")

    # Verify Envoy runs as UID 101
    ENVOY_UID=$(get_container_uid "$POD_NAME" "envoy-proxy")
    log_info "Envoy UID: $ENVOY_UID"
    [ "$ENVOY_UID" -eq 101 ]

    # Verify OPA runs as UID 102
    OPA_UID=$(get_container_uid "$POD_NAME" "opa-sidecar")
    log_info "OPA UID: $OPA_UID"
    [ "$OPA_UID" -eq 102 ]

    # Verify xDS runs as UID 103
    XDS_UID=$(get_container_uid "$POD_NAME" "xds-service")
    log_info "xDS UID: $XDS_UID"
    [ "$XDS_UID" -eq 103 ]

    # Verify app container runs as different UID (12345 in our fixture)
    APP_UID=$(get_container_uid "$POD_NAME" "test-container")
    log_info "App UID: $APP_UID"
    [ "$APP_UID" -eq 12345 ]
}

@test "Init container completed successfully" {
    POD_NAME=$(get_pod_name "test-app")

    # Check proxy-init completed
    run check_init_container "$POD_NAME" "proxy-init"
    [ "$status" -eq 0 ]

    # Verify iptables rules were applied (check logs)
    INIT_LOGS=$(get_container_logs "$POD_NAME" "proxy-init")
    [[ "$INIT_LOGS" =~ "Init container completed successfully" ]]
    [[ "$INIT_LOGS" =~ "NAT table" ]]
    [[ "$INIT_LOGS" =~ "FILTER table" ]]
}

@test "CA certificate is mounted in app container" {
    POD_NAME=$(get_pod_name "test-app")

    # Check SSL_CERT_FILE env var is set
    run exec_in_pod "$POD_NAME" "test-container" "echo \$SSL_CERT_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "/etc/ssl/certs/ca-certificates.crt" ]

    # Verify CA certificate file exists
    run exec_in_pod "$POD_NAME" "test-container" "test -f /etc/ssl/certs/intercept-ca.crt && echo exists"
    [ "$status" -eq 0 ]
    [ "$output" = "exists" ]

    # Verify merged CA bundle exists
    run exec_in_pod "$POD_NAME" "test-container" "test -f /etc/ssl/certs/ca-certificates.crt && echo exists"
    [ "$status" -eq 0 ]
    [ "$output" = "exists" ]
}

@test "Envoy sidecar is healthy" {
    POD_NAME=$(get_pod_name "test-app")

    # Check Envoy container is ready (readiness probe checks admin interface)
    # Note: We can't check from test-container because proxy-init blocks sidecar ports
    ENVOY_READY=$(kubectl get pod "$POD_NAME" -n kyverno-intercept \
        -o jsonpath='{.status.containerStatuses[?(@.name=="envoy-proxy")].ready}')
    log_info "Envoy ready status: $ENVOY_READY"
    [ "$ENVOY_READY" = "true" ]

    # Verify Envoy logs show activity (may not contain xDS strings immediately after startup)
    ENVOY_LOGS=$(get_container_logs "$POD_NAME" "envoy-proxy")
    # Check for any indication that Envoy is running (logs should not be empty)
    [ -n "$ENVOY_LOGS" ]
}

@test "OPA sidecar is healthy" {
    POD_NAME=$(get_pod_name "test-app")

    # Check OPA container is ready (readiness probe checks health endpoint)
    # Note: We can't check from test-container because proxy-init blocks sidecar ports
    OPA_READY=$(kubectl get pod "$POD_NAME" -n kyverno-intercept \
        -o jsonpath='{.status.containerStatuses[?(@.name=="opa-sidecar")].ready}')
    [ "$OPA_READY" = "true" ]

    # Verify OPA is processing requests (check logs)
    OPA_LOGS=$(get_container_logs "$POD_NAME" "opa-sidecar")
    [[ "$OPA_LOGS" =~ "health" ]] || [[ "$OPA_LOGS" =~ "Received request" ]]
}

@test "xDS service is healthy" {
    POD_NAME=$(get_pod_name "test-app")

    # Check xDS container is ready (readiness probe checks health endpoint)
    # Note: We can't check from test-container because proxy-init blocks sidecar ports
    XDS_READY=$(kubectl get pod "$POD_NAME" -n kyverno-intercept \
        -o jsonpath='{.status.containerStatuses[?(@.name=="xds-service")].ready}')
    [ "$XDS_READY" = "true" ]

    # Verify xDS is serving requests (check logs)
    XDS_LOGS=$(get_container_logs "$POD_NAME" "xds-service")
    [[ "$XDS_LOGS" =~ "Received" ]] || [[ "$XDS_LOGS" =~ "request" ]]
}

@test "Envoy receives dynamic configuration from xDS" {
    POD_NAME=$(get_pod_name "test-app")

    # Check Envoy logs for xDS configuration updates
    ENVOY_LOGS=$(get_container_logs "$POD_NAME" "envoy-proxy")
    log_info "Checking Envoy logs for xDS configuration..."

    # Look for successful xDS connections (CDS, LDS, or SDS)
    [[ "$ENVOY_LOGS" =~ "cds" ]] || [[ "$ENVOY_LOGS" =~ "lds" ]] || [[ "$ENVOY_LOGS" =~ "sds" ]]

    # Verify xDS service is sending configuration
    XDS_LOGS=$(get_container_logs "$POD_NAME" "xds-service")
    [[ "$XDS_LOGS" =~ "SDS request" ]] || [[ "$XDS_LOGS" =~ "CDS request" ]] || [[ "$XDS_LOGS" =~ "LDS request" ]]
}

@test "Cleanup job template has correct pre-delete hook annotations" {
    # Change to chart directory to run helm template
    cd "$(dirname "$BATS_TEST_DIRNAME")/.."

    # Render the template with helm template
    RENDERED=$(helm template test-release . --set cleanup.enabled=true)

    # Verify Job has pre-delete hook annotation
    echo "$RENDERED" | grep -A 10 'kind: Job' | grep -q '"helm.sh/hook": pre-delete'

    # Verify hook weight
    echo "$RENDERED" | grep -A 10 'kind: Job' | grep -q '"helm.sh/hook-weight": "-5"'

    # Verify hook delete policy
    echo "$RENDERED" | grep -A 10 'kind: Job' | grep -q '"helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded'

    # Verify ServiceAccount has pre-delete hook
    echo "$RENDERED" | grep -B 5 -A 5 'name: test-release-cleanup' | grep -q '"helm.sh/hook": pre-delete'

    # Verify ClusterRole has correct RBAC permissions
    echo "$RENDERED" | grep -A 20 'kind: ClusterRole' | grep -q 'clusterpolicies'
    echo "$RENDERED" | grep -A 20 'kind: ClusterRole' | grep -q 'delete'

    # Verify cleanup job deletes both ClusterPolicies (using test-release name from helm template)
    echo "$RENDERED" | grep -A 30 'kind: Job' | grep -q 'test-release-inject-proxy'
    echo "$RENDERED" | grep -A 30 'kind: Job' | grep -q 'test-release-clone-configmaps'
}

@test "Pre-delete hook removes ClusterPolicies on uninstall" {
    # Create a temporary namespace
    TEMP_NS="test-cleanup-ns-$RANDOM"
    TEMP_RELEASE="test-cleanup"

    kubectl create namespace "$TEMP_NS"
    log_info "Installing temporary release: $TEMP_RELEASE in namespace $TEMP_NS"

    # Change to chart directory
    cd "$(dirname "$BATS_TEST_DIRNAME")/.."

    # Install the release
    helm install "$TEMP_RELEASE" . -n "$TEMP_NS" --wait --timeout 120s

    # Verify both ClusterPolicies exist
    run kubectl get clusterpolicy "${TEMP_RELEASE}-inject-proxy"
    [ "$status" -eq 0 ]
    log_info "ClusterPolicy ${TEMP_RELEASE}-inject-proxy exists"

    run kubectl get clusterpolicy "${TEMP_RELEASE}-clone-configmaps"
    [ "$status" -eq 0 ]
    log_info "ClusterPolicy ${TEMP_RELEASE}-clone-configmaps exists"

    # Uninstall the release (this should trigger the pre-delete hook)
    log_info "Uninstalling release: $TEMP_RELEASE"
    helm uninstall "$TEMP_RELEASE" -n "$TEMP_NS" --wait --timeout 120s

    # Wait for both ClusterPolicies to be deleted by cleanup job
    kubectl wait --for=delete clusterpolicy/"${TEMP_RELEASE}-inject-proxy" --timeout=30s
    log_info "ClusterPolicy ${TEMP_RELEASE}-inject-proxy successfully removed"

    kubectl wait --for=delete clusterpolicy/"${TEMP_RELEASE}-clone-configmaps" --timeout=30s
    log_info "ClusterPolicy ${TEMP_RELEASE}-clone-configmaps successfully removed"

    # Clean up namespace
    kubectl delete namespace "$TEMP_NS" --ignore-not-found=true
}

@test "Chart uninstall succeeds gracefully when cleanup job cannot find target ClusterPolicy" {
    # This test verifies that helm uninstall completes successfully even when the
    # pre-delete cleanup job doesn't find the expected ClusterPolicy to delete.
    # This ensures graceful degradation and prevents uninstall from hanging.

    # Create a temporary namespace
    TEMP_NS="test-cleanup-fail-ns-$RANDOM"
    TEMP_RELEASE="test-cleanup-fail"

    kubectl create namespace "$TEMP_NS"
    log_info "Installing temporary release: $TEMP_RELEASE in namespace $TEMP_NS"

    # Change to chart directory
    cd "$(dirname "$BATS_TEST_DIRNAME")/.."

    # Install with cleanup disabled initially
    helm install "$TEMP_RELEASE" . -n "$TEMP_NS" --set cleanup.enabled=false --wait --timeout 120s

    # Manually create a ClusterPolicy with a different name than what cleanup job expects
    # This simulates a scenario where the cleanup job cannot find its target
    kubectl create -f - <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: ${TEMP_RELEASE}-test-orphan-policy
spec:
  rules: []
EOF

    # Upgrade to enable cleanup, but the cleanup job will look for "${TEMP_RELEASE}-inject-proxy"
    # which doesn't exist (only the orphan policy exists)
    helm upgrade "$TEMP_RELEASE" . -n "$TEMP_NS" --set cleanup.enabled=true --wait --timeout 120s

    # Uninstall should succeed even though cleanup job doesn't find its target ClusterPolicy
    log_info "Uninstalling release: $TEMP_RELEASE (cleanup job won't find expected policy)"
    run helm uninstall "$TEMP_RELEASE" -n "$TEMP_NS" --wait --timeout 120s
    [ "$status" -eq 0 ]
    log_info "Uninstall succeeded gracefully despite missing target policy"

    # Clean up the orphan policy and namespace
    kubectl delete clusterpolicy "${TEMP_RELEASE}-test-orphan-policy" --ignore-not-found=true
    kubectl delete namespace "$TEMP_NS" --ignore-not-found=true
}
