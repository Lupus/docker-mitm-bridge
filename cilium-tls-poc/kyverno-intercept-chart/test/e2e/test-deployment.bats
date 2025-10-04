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

    # Verify CA Secret exists
    verify "there is 1 secret named 'intercept-proxy-ca'"
}

@test "Test pod deploys successfully with sidecar injection" {
    # Deploy test pod
    kubectl apply -f test/fixtures/test-pod.yaml

    # Wait for pod to be ready
    log_info "Waiting for test-app pod to be ready..."
    try "at most 10 times every 15s to get pods named 'test-app' and verify that 'status' is 'running'"

    # Get pod name
    POD_NAME=$(get_pod_name "test-app")
    log_info "Test pod name: $POD_NAME"

    # Verify pod is running
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

    # Check Envoy is listening on proxy port (15001)
    run exec_in_pod "$POD_NAME" "envoy-proxy" "netstat -tln | grep ':15001'"
    [ "$status" -eq 0 ]

    # Check Envoy admin endpoint is healthy
    run exec_in_pod "$POD_NAME" "envoy-proxy" "curl -s http://localhost:15000/ready"
    [ "$status" -eq 0 ]
    [ "$output" = "LIVE" ]
}

@test "OPA sidecar is healthy" {
    POD_NAME=$(get_pod_name "test-app")

    # Check OPA HTTP port (15020)
    run exec_in_pod "$POD_NAME" "opa-sidecar" "netstat -tln | grep ':15020'"
    [ "$status" -eq 0 ]

    # Check OPA gRPC port (15021)
    run exec_in_pod "$POD_NAME" "opa-sidecar" "netstat -tln | grep ':15021'"
    [ "$status" -eq 0 ]

    # Check OPA health endpoint
    run exec_in_pod "$POD_NAME" "opa-sidecar" "curl -s http://localhost:15020/health"
    [ "$status" -eq 0 ]
}

@test "xDS service is healthy" {
    POD_NAME=$(get_pod_name "test-app")

    # Check xDS gRPC port (15080)
    run exec_in_pod "$POD_NAME" "xds-service" "netstat -tln | grep ':15080'"
    [ "$status" -eq 0 ]

    # Check xDS health endpoint
    run exec_in_pod "$POD_NAME" "xds-service" "curl -s http://localhost:15081/health"
    [ "$status" -eq 0 ]
}

@test "Envoy receives dynamic configuration from xDS" {
    POD_NAME=$(get_pod_name "test-app")

    # Check Envoy logs for CDS success
    ENVOY_LOGS=$(get_container_logs "$POD_NAME" "envoy-proxy")
    log_info "Checking Envoy logs for xDS configuration..."

    # Look for successful xDS connections
    [[ "$ENVOY_LOGS" =~ "cds" ]] || [[ "$ENVOY_LOGS" =~ "lds" ]] || [[ "$ENVOY_LOGS" =~ "sds" ]]

    # Check Envoy config dump shows clusters
    run exec_in_pod "$POD_NAME" "envoy-proxy" "curl -s http://localhost:15000/config_dump | grep -q 'dynamic_active_clusters'"
    [ "$status" -eq 0 ]
}
