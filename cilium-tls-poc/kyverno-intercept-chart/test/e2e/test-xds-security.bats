#!/usr/bin/env bats

# Test xDS security - ensures non-whitelisted domains are properly blocked by OPA
# This test demonstrates the security vulnerability where the default filter chain
# bypasses ext_authz, allowing passthrough of non-whitelisted domains.

load '../lib/detik'
load '../lib/helpers'

DETIK_CLIENT_NAME="kubectl"
DETIK_CLIENT_NAMESPACE="kyverno-intercept"

@test "OPA blocks HTTPS access to non-whitelisted domain (google.com)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing HTTPS to google.com (NOT in whitelist, should be blocked with 403)..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://google.com"

    # Should return 403 Forbidden from OPA, not SSL errors or passthrough
    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
}

@test "OPA blocks HTTP access to non-whitelisted domain (google.com)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing HTTP to google.com (NOT in whitelist, should be blocked with 403)..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 http://google.com"

    # Should return 403 Forbidden from OPA
    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
}

@test "Non-whitelisted domain returns proper 403, not SSL connection errors" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing HTTPS to google.com - should get clean 403, not SSL/connection errors..."

    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -v --max-time 15 https://google.com 2>&1"

    # Should NOT see SSL errors like "wrong version number" (indicates passthrough mode)
    [[ ! "$output" =~ "wrong version number" ]]
    [[ ! "$output" =~ "SSL.*wrong" ]]

    # Should see 403 Forbidden (OPA rejection)
    [[ "$output" =~ "403" ]] || [[ "$output" =~ "Forbidden" ]]
}

@test "Non-whitelisted facebook.com is also blocked with 403" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing facebook.com (another non-whitelisted domain)..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://facebook.com"

    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
}

@test "Non-whitelisted twitter.com is also blocked with 403" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing twitter.com (another non-whitelisted domain)..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://twitter.com"

    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
}

@test "Envoy logs show ext_authz activity for non-whitelisted domains" {
    POD_NAME=$(get_pod_name "test-app")

    # Clear previous activity by getting fresh baseline
    log_info "Making request to non-whitelisted domain to trigger ext_authz..."
    exec_in_pod "$POD_NAME" "test-container" \
        "curl -s --max-time 10 https://google.com" || true

    sleep 3

    # Check Envoy logs for ext_authz activity
    ENVOY_LOGS=$(get_container_logs "$POD_NAME" "envoy-proxy" | tail -200)
    log_info "Checking Envoy logs for ext_authz evidence..."

    # Should see evidence of ext_authz processing the request
    # (Either "ext_authz" in logs or HTTP 403 response code)
    [[ "$ENVOY_LOGS" =~ "ext_authz" ]] || [[ "$ENVOY_LOGS" =~ "403" ]]
}

@test "OPA logs show policy denials for non-whitelisted domains" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Making request to trigger OPA policy evaluation..."
    exec_in_pod "$POD_NAME" "test-container" \
        "curl -s --max-time 10 https://google.com" || true

    sleep 2

    # Check OPA logs for decision
    OPA_LOGS=$(get_container_logs "$POD_NAME" "opa-sidecar" | tail -200)
    log_info "Checking OPA logs for policy decision..."

    # Should see evidence of policy evaluation and denial
    [[ "$OPA_LOGS" =~ "google.com" ]] || \
    [[ "$OPA_LOGS" =~ "decision" ]] || \
    [[ "$OPA_LOGS" =~ "deny" ]] || \
    [[ "$OPA_LOGS" =~ "false" ]]
}

@test "Whitelisted domains still work correctly (github.com)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Verifying whitelisted domain github.com still works..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://github.com"

    [ "$status" -eq 0 ]
    [ "$output" = "200" ]
}

@test "Whitelisted domains with POST still work (unrestricted domains)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Verifying unrestricted domain allows POST..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST https://api.anthropic.com"

    [ "$status" -eq 0 ]
    # Should NOT be 403 (OPA allows POST to unrestricted domains)
    [[ ! "$output" = "403" ]]
}

@test "Security: No bypass via Host header manipulation" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing if Host header manipulation can bypass OPA..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H 'Host: github.com' https://google.com"

    # Should still be blocked (SNI and Host should both be checked)
    [ "$status" -eq 0 ]
    # Either connection fails or gets 403
    [[ "$output" =~ ^(403|000)$ ]]
}
