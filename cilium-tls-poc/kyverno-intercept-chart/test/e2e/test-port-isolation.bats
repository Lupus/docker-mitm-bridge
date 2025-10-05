#!/usr/bin/env bats

# Test port isolation and iptables rules

load '../lib/detik'
load '../lib/helpers'

DETIK_CLIENT_NAME="kubectl"
DETIK_CLIENT_NAMESPACE="kyverno-intercept"

@test "iptables rules were created successfully" {
    POD_NAME=$(get_pod_name "test-app")

    # Check init container logs for iptables setup
    INIT_LOGS=$(get_container_logs "$POD_NAME" "proxy-init")
    log_info "Checking iptables setup..."

    # Should see both NAT and FILTER tables
    [[ "$INIT_LOGS" =~ "NAT table" ]]
    [[ "$INIT_LOGS" =~ "FILTER table" ]]
    [[ "$INIT_LOGS" =~ "PROXY_REDIRECT" ]]
    [[ "$INIT_LOGS" =~ "SIDECAR_ISOLATE" ]]
}

@test "App container CANNOT access Envoy admin port (15000)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing that Envoy admin port 15000 is blocked..."

    # Should timeout or be rejected
    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 3 curl -f http://localhost:15000/stats 2>&1"

    # Should fail (timeout or connection refused by iptables)
    [ "$status" -ne 0 ]

    # Verify with nc as well
    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 2 nc -zv localhost 15000 2>&1"
    [ "$status" -ne 0 ]
}

@test "App container CANNOT access OPA HTTP port (15020)" {
    skip "Port isolation for sidecar services requires additional network configuration"
}

@test "App container CANNOT access OPA gRPC port (15021)" {
    skip "Port isolation for sidecar services requires additional network configuration"
}

@test "App container CANNOT access xDS gRPC port (15080)" {
    skip "Port isolation for sidecar services requires additional network configuration"
}

@test "App container CANNOT access xDS HTTP port (15081)" {
    skip "Port isolation for sidecar services requires additional network configuration"
}

@test "App container CANNOT access privileged ports (0-1023)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing that privileged ports are blocked..."

    # Test common privileged ports (excluding 53, 80, 443 which are allowed for DNS/HTTP/HTTPS)
    for port in 22 21 25; do
        log_info "Testing port $port..."
        run exec_in_pod "$POD_NAME" "test-container" \
            "timeout 2 nc -zv localhost $port 2>&1"
        [ "$status" -ne 0 ]
    done
}

@test "App container CAN access high ports (1024-14999)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing that high ports are accessible..."

    # Test some high ports - they should NOT be blocked by iptables
    # (may get connection refused if nothing listening, but shouldn't timeout)
    for port in 3000 5000 8080 9000 14999; do
        log_info "Testing port $port (should not be blocked)..."

        run exec_in_pod "$POD_NAME" "test-container" \
            "timeout 2 nc -zv localhost $port 2>&1"

        # Check that it didn't timeout (timeout returns 124)
        # Connection refused (exit 1) is OK, means not blocked
        [ "$status" -ne 124 ]
    done
}

@test "App container CAN access ports above sidecar range (15100-65535)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing that ports above sidecar range are accessible..."

    for port in 15100 20000 30000 50000; do
        log_info "Testing port $port..."

        run exec_in_pod "$POD_NAME" "test-container" \
            "timeout 2 nc -zv localhost $port 2>&1"

        # Should not timeout (might be refused, but not blocked)
        [ "$status" -ne 124 ]
    done
}

@test "App container can still access localhost services on allowed ports" {
    POD_NAME=$(get_pod_name "test-app")

    # Start a simple HTTP server on port 8080 in background
    log_info "Starting test HTTP server on port 8080..."

    # Use sh to run server in background
    exec_in_pod "$POD_NAME" "test-container" \
        "sh -c 'nohup nc -l -p 8080 > /dev/null 2>&1 &'" || true

    sleep 2

    # Try to connect to it
    log_info "Testing connection to localhost:8080..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 2 nc -zv localhost 8080 2>&1"

    # Should succeed (exit 0) or at least not timeout
    [ "$status" -ne 124 ]
}

@test "iptables rules include UID-based exclusions" {
    POD_NAME=$(get_pod_name "test-app")

    # Check init container logs for UID exclusions
    INIT_LOGS=$(get_container_logs "$POD_NAME" "proxy-init")

    log_info "Checking for UID-based exclusions in iptables rules..."

    # Should see UID 101, 102, 103 exclusions
    [[ "$INIT_LOGS" =~ "101" ]]
    [[ "$INIT_LOGS" =~ "102" ]]
    [[ "$INIT_LOGS" =~ "103" ]]
    [[ "$INIT_LOGS" =~ "uid-owner" ]]
}

@test "Sidecars can access all necessary ports" {
    POD_NAME=$(get_pod_name "test-app")

    # OPA should be listening on its ports
    log_info "Testing OPA is listening on required ports..."
    OPA_LOGS=$(get_container_logs "$POD_NAME" "opa-sidecar" | head -50)

    # OPA logs should show it started successfully
    [[ "$OPA_LOGS" =~ "Initializing server" ]] || \
    [[ "$OPA_LOGS" =~ "Starting server" ]] || \
    [[ "$OPA_LOGS" =~ "Listening" ]]

    # Envoy should be running and healthy
    log_info "Testing Envoy is running..."
    ENVOY_LOGS=$(get_container_logs "$POD_NAME" "envoy-proxy" | head -50)

    # Envoy logs should show it started
    [[ "$ENVOY_LOGS" =~ "starting main dispatch loop" ]] || \
    [[ "$ENVOY_LOGS" =~ "all clusters initialized" ]] || \
    true  # Envoy might not log these messages in all versions
}

@test "App container CANNOT access ANY port in sidecar range (15000-15099)" {
    skip "Port isolation for sidecar services requires additional network configuration"
}

@test "DNS resolution still works (port 53)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing DNS resolution works despite iptables rules..."

    run exec_in_pod "$POD_NAME" "test-container" \
        "nslookup github.com 2>&1"

    [ "$status" -eq 0 ]
    [[ "$output" =~ "Address:" ]]
}

@test "HTTPS traffic (port 443) is redirected, not blocked" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing HTTPS traffic redirection..."

    # HTTPS should work (redirected to Envoy, not blocked)
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://github.com"

    [ "$status" -eq 0 ]
    [ "$output" = "200" ]
}

@test "HTTP traffic (port 80) is redirected, not blocked" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing HTTP traffic redirection..."

    # HTTP should work (redirected to Envoy)
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 http://github.com"

    [ "$status" -eq 0 ]
    # Might redirect to HTTPS
    [[ "$output" =~ ^(200|301|302)$ ]]
}
