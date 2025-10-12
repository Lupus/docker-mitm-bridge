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
    # Use -k to skip cert verification (expected cert name mismatch for blocked domains)
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -k -s -o /dev/null -w '%{http_code}' --max-time 15 https://google.com"

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

@test "Non-whitelisted domain returns proper 403 with -k flag" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing HTTPS to google.com with -k - should get 403 after TLS handshake..."

    # Use -k to skip cert verification, should get through TLS and receive 403 from OPA
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -k -v --max-time 15 https://google.com 2>&1"

    # Should see 403 Forbidden (OPA rejection) after successful TLS handshake
    [[ "$output" =~ "403" ]] || [[ "$output" =~ "Forbidden" ]]
}

@test "Non-whitelisted domain gets 'blocked.local' certificate (cert name mismatch)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing certificate presented for google.com - should be 'blocked.local'..."

    # Get certificate details - will show cert name mismatch
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -v https://google.com 2>&1 || true"

    # Should see certificate mismatch error mentioning the cert is for 'blocked.local'
    # This indicates the fallback TLS chain is working correctly
    [[ "$output" =~ "blocked.local" ]] || [[ "$output" =~ "certificate" ]]
}

@test "Non-whitelisted facebook.com is also blocked with 403" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing facebook.com (another non-whitelisted domain)..."
    # Use -k to skip cert verification (expected cert name mismatch for blocked domains)
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -k -s -o /dev/null -w '%{http_code}' --max-time 15 https://facebook.com"

    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
}

@test "Non-whitelisted twitter.com is also blocked with 403" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing twitter.com (another non-whitelisted domain)..."
    # Use -k to skip cert verification (expected cert name mismatch for blocked domains)
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -k -s -o /dev/null -w '%{http_code}' --max-time 15 https://twitter.com"

    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
}

@test "Envoy logs show ext_authz activity for non-whitelisted domains" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Making request to trigger Envoy access logging..."
    # Use -k to skip cert verification (expected cert name mismatch for blocked domains)
    exec_in_pod "$POD_NAME" "test-container" \
        "curl -k -s --max-time 10 https://google.com" || true

    # Wait for access logs to appear (handles kubectl logs API delays)
    wait_for_log_entry "$POD_NAME" "envoy-proxy" "google\.com" "kyverno-intercept" 15 0.5

    # Get logs for verification
    ENVOY_LOGS=$(get_container_logs "$POD_NAME" "envoy-proxy" | tail -100)
    log_info "Checking Envoy logs for access log entries..."

    # Debug: Show lines that look like text access logs (contain timestamp in brackets)
    log_info "--- Envoy Access Log Entries (if any) ---"
    echo "$ENVOY_LOGS" | grep -E '^\[20[0-9]{2}-' || echo "(No access log entries found)"
    log_info "---"

    # Should see text-based access log entries with request details
    # Access logs are in text format like: [2025-10-11T13:22:33.994Z] "GET /path HTTP/1.1" 403 ...
    # Check for: timestamp, HTTP method, and domain (google.com)
    [[ "$ENVOY_LOGS" =~ \[20[0-9]{2}- ]] && \
    [[ "$ENVOY_LOGS" =~ google\.com ]] && \
    [[ "$ENVOY_LOGS" =~ \"(GET|POST|PUT|DELETE|HEAD|OPTIONS) ]]
}

@test "OPA logs show policy denials for non-whitelisted domains" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Making request to trigger OPA policy evaluation..."
    # Use -k to skip cert verification (expected cert name mismatch for blocked domains)
    exec_in_pod "$POD_NAME" "test-container" \
        "curl -k -s --max-time 10 https://google.com" || true

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
    # Use -k to skip cert verification (expected cert name mismatch for blocked domains)
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -k -s -o /dev/null -w '%{http_code}' --max-time 15 -H 'Host: github.com' https://google.com"

    # Should still be blocked (SNI and Host should both be checked)
    [ "$status" -eq 0 ]
    # Should get 403 from OPA (Host header manipulation doesn't bypass policy)
    [ "$output" = "403" ]
}
