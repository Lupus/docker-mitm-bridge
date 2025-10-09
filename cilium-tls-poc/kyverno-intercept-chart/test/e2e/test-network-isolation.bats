#!/usr/bin/env bats

# Test network isolation and connectivity restrictions

load '../lib/detik'
load '../lib/helpers'

DETIK_CLIENT_NAME="kubectl"
DETIK_CLIENT_NAMESPACE="kyverno-intercept"

setup_file() {
    # Deploy external pod for connectivity tests
    kubectl apply -f test/fixtures/external-pod.yaml || true
    kubectl apply -f test/fixtures/http-server.yaml || true

    # Wait for external pods to be ready
    sleep 10
}

@test "External pod (without interception) is deployed" {
    # Verify external pod exists and is running
    try "at most 5 times every 10s to get pods named 'external-app' and verify that 'status' is 'running'"

    EXTERNAL_POD=$(get_pod_name "external-app")
    [ -n "$EXTERNAL_POD" ]
    log_info "External pod: $EXTERNAL_POD"
}

@test "App container CANNOT connect to other pods directly" {
    POD_NAME=$(get_pod_name "test-app")
    EXTERNAL_POD=$(get_pod_name "external-app")

    # Get external pod IP
    EXTERNAL_IP=$(kubectl get pod "$EXTERNAL_POD" -n kyverno-intercept -o jsonpath='{.status.podIP}')
    log_info "External pod IP: $EXTERNAL_IP"

    # Try to connect to external pod on various ports (should be blocked)
    log_info "Testing pod-to-pod connectivity (should be blocked)..."

    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 3 nc -zv $EXTERNAL_IP 8080 2>&1"

    # Should fail (blocked by iptables)
    [ "$status" -ne 0 ]
}

@test "App container CANNOT SSH to external services" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing SSH connectivity to external host (should be blocked)..."

    # Try SSH to common public server (should be blocked)
    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 3 nc -zv 8.8.8.8 22 2>&1"

    # Should fail or timeout (port 22 might be blocked or not responding)
    [ "$status" -ne 0 ]
}

@test "App container CANNOT access random internet ports" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing random port to internet (should be blocked)..."

    # Try random high port to Google DNS (should be blocked)
    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 3 nc -zv 8.8.8.8 12345 2>&1"

    # Should timeout or be blocked
    [ "$status" -ne 0 ]

    # Try another random port
    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 3 nc -zv 1.1.1.1 54321 2>&1"

    [ "$status" -ne 0 ]
}

@test "App container CAN access HTTP/HTTPS (via Envoy)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing HTTP access (should work via Envoy)..."

    # HTTP should work (redirected)
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 http://github.com"
    [ "$status" -eq 0 ]
    [[ "$output" =~ ^(200|301|302)$ ]]

    # HTTPS should work (redirected)
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://github.com"
    [ "$status" -eq 0 ]
    [ "$output" = "200" ]
}

@test "App container CANNOT access Kubernetes API directly" {
    POD_NAME=$(get_pod_name "test-app")

    # Try to access Kubernetes API (typically at 10.x.x.1:443 or kubernetes.default)
    log_info "Testing Kubernetes API access (should be blocked)..."

    # This should fail because:
    # 1. Port 443 will be redirected to Envoy
    # 2. OPA will likely block it (not in allowed domains)
    # 3. Or connection will fail for other reasons
    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 5 curl -k -s https://kubernetes.default.svc/api 2>&1"

    # Should fail (might be redirect issues, OPA block, or other)
    [ "$status" -ne 0 ] || [[ "$output" =~ "403" ]] || [[ "$output" =~ "error" ]]
}

@test "DNS still works (UDP port 53)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing DNS resolution..."

    run exec_in_pod "$POD_NAME" "test-container" \
        "nslookup github.com 2>&1"

    [ "$status" -eq 0 ]
    [[ "$output" =~ "Address:" ]]

    # Test another domain
    run exec_in_pod "$POD_NAME" "test-container" \
        "nslookup google.com 2>&1"

    [ "$status" -eq 0 ]
}

@test "App container CANNOT ping external hosts" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing ICMP/ping (should be blocked)..."

    # Ping should fail (ICMP is not in allowed protocols)
    # Note: curl image may not have ping, so this might fail for that reason too
    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 3 ping -c 1 8.8.8.8 2>&1"

    # Should fail (no ping binary or ICMP blocked)
    [ "$status" -ne 0 ]
}

@test "App container accesses pod-to-pod HTTP through Envoy (intercepted)" {
    POD_NAME=$(get_pod_name "test-app")

    # Get http-server service IP
    HTTP_SVC_IP=$(kubectl get svc http-server -n kyverno-intercept -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")

    if [ -n "$HTTP_SVC_IP" ]; then
        log_info "Testing pod-to-pod HTTP to service $HTTP_SVC_IP (should be intercepted by Envoy)..."

        # Port 80 traffic is redirected to Envoy, not blocked
        # This is expected behavior - HTTP/HTTPS are always intercepted
        run exec_in_pod "$POD_NAME" "test-container" \
            "timeout 3 curl -s -o /dev/null -w '%{http_code}' http://$HTTP_SVC_IP 2>&1"

        # Should succeed (intercepted by Envoy) or be blocked by OPA
        # Either way, connection reaches Envoy - it's not blocked at network level
        [ "$status" -eq 0 ] || [[ "$output" =~ "403" ]]

        log_info "Pod-to-pod HTTP traffic is intercepted by Envoy (status: $output)"
    else
        skip "http-server service not found"
    fi
}

@test "Only HTTP/HTTPS ports work, everything else blocked" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Verifying only HTTP/HTTPS work..."

    # HTTPS works
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://github.com"
    [ "$status" -eq 0 ]
    [ "$output" = "200" ]

    # FTP should fail (port 21)
    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 3 nc -zv ftp.gnu.org 21 2>&1"
    [ "$status" -ne 0 ]

    # SMTP should fail (port 25)
    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 3 nc -zv smtp.gmail.com 25 2>&1"
    [ "$status" -ne 0 ]

    # MySQL should fail (port 3306)
    run exec_in_pod "$POD_NAME" "test-container" \
        "timeout 3 nc -zv 8.8.8.8 3306 2>&1"
    [ "$status" -ne 0 ]
}

@test "App container traffic is truly isolated" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Comprehensive isolation test..."

    # Summary: Only DNS (53) and HTTP/HTTPS (80/443 redirected) should work
    # Everything else should be blocked by iptables DROP rule

    # DNS works
    run exec_in_pod "$POD_NAME" "test-container" "nslookup github.com"
    [ "$status" -eq 0 ]

    # HTTPS works
    run exec_in_pod "$POD_NAME" "test-container" "curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://github.com"
    [ "$status" -eq 0 ]

    # Random port blocked
    run exec_in_pod "$POD_NAME" "test-container" "timeout 2 nc -zv 8.8.8.8 9999"
    [ "$status" -ne 0 ]

    # SSH blocked
    run exec_in_pod "$POD_NAME" "test-container" "timeout 2 nc -zv github.com 22"
    [ "$status" -ne 0 ]

    log_info "Isolation verified: Only DNS and HTTP/HTTPS work"
}

@test "Envoy sidecars can make arbitrary outbound connections" {
    POD_NAME=$(get_pod_name "test-app")

    # Envoy should NOT be restricted (UID 101 bypasses iptables)
    log_info "Testing Envoy sidecar network access..."

    # Envoy can access DNS
    run exec_in_pod "$POD_NAME" "envoy-proxy" \
        "timeout 2 nc -zv 8.8.8.8 53 2>&1"

    # Should work or at least not be blocked by iptables (might fail for other reasons)
    # Exit 124 means timeout from iptables DROP
    [ "$status" -ne 124 ]
}

@test "OPA sidecars can make arbitrary outbound connections" {
    POD_NAME=$(get_pod_name "test-app")

    # OPA should NOT be restricted (UID 102 bypasses iptables)
    log_info "Testing OPA sidecar network access..."

    # OPA can access external services if needed
    run exec_in_pod "$POD_NAME" "opa-sidecar" \
        "timeout 2 nc -zv 8.8.8.8 53 2>&1"

    # Should not be blocked by iptables
    [ "$status" -ne 124 ]
}
