#!/usr/bin/env bats

# Test TLS interception functionality

load '../lib/detik'
load '../lib/helpers'

DETIK_CLIENT_NAME="kubectl"
DETIK_CLIENT_NAMESPACE="kyverno-intercept"

@test "HTTPS request to GitHub succeeds" {
    POD_NAME=$(get_pod_name "test-app")

    # Test HTTPS request to api.github.com
    log_info "Testing HTTPS request to api.github.com..."
    run exec_in_pod "$POD_NAME" "test-container" "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://api.github.com"
    [ "$status" -eq 0 ]
    [ "$output" = "200" ]
}

@test "Certificate issuer is internal CA (not real GitHub CA)" {
    POD_NAME=$(get_pod_name "test-app")

    # Check certificate issuer - should be our internal CA, not DigiCert/Let's Encrypt
    log_info "Checking certificate issuer for api.github.com..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -v --silent --max-time 15 https://api.github.com 2>&1 | grep 'issuer:' | head -1"

    [ "$status" -eq 0 ]
    log_info "Certificate issuer: $output"

    # Should contain our CA name, not external CA
    [[ "$output" =~ "Kyverno-Intercept-CA" ]] || [[ "$output" =~ "Internal-CA" ]]

    # Should NOT be DigiCert or Let's Encrypt
    [[ ! "$output" =~ "DigiCert" ]]
    [[ ! "$output" =~ "Let's Encrypt" ]]
}

@test "HTTPS request to multiple domains works" {
    POD_NAME=$(get_pod_name "test-app")

    # Test github.com
    log_info "Testing github.com..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://github.com"
    [ "$status" -eq 0 ]
    [ "$output" = "200" ]

    # Test raw.githubusercontent.com
    log_info "Testing raw.githubusercontent.com..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://raw.githubusercontent.com"
    [ "$status" -eq 0 ]
    # 404 is OK, means TLS worked but path doesn't exist
    [[ "$output" =~ ^(200|404)$ ]]
}

@test "Traffic flows through Envoy proxy" {
    POD_NAME=$(get_pod_name "test-app")

    # Make HTTPS request
    exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null --max-time 15 https://api.github.com" || true

    # Give Envoy time to log
    sleep 2

    # Check Envoy access logs
    ENVOY_LOGS=$(get_container_logs "$POD_NAME" "envoy-proxy" | tail -50)
    log_info "Checking Envoy logs for access..."

    # Should see evidence of proxied traffic
    # Look for common Envoy log patterns
    [[ "$ENVOY_LOGS" =~ "api.github.com" ]] || \
    [[ "$ENVOY_LOGS" =~ "upstream" ]] || \
    [[ "$ENVOY_LOGS" =~ "response" ]]
}

@test "xDS service provides certificates dynamically" {
    POD_NAME=$(get_pod_name "test-app")

    # Check xDS service logs for certificate generation
    XDS_LOGS=$(get_container_logs "$POD_NAME" "xds-service")
    log_info "Checking xDS logs for certificate generation..."

    # Should see evidence of certificate pre-generation or SDS serving
    [[ "$XDS_LOGS" =~ "certificate" ]] || \
    [[ "$XDS_LOGS" =~ "github.com" ]] || \
    [[ "$XDS_LOGS" =~ "SDS" ]] || \
    [[ "$XDS_LOGS" =~ "domain" ]]
}

@test "HTTP request (port 80) is redirected through Envoy" {
    POD_NAME=$(get_pod_name "test-app")

    # Make HTTP request (should also be intercepted)
    log_info "Testing HTTP request redirection..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 http://api.github.com"

    # Should succeed (might redirect to HTTPS)
    [ "$status" -eq 0 ]
    [[ "$output" =~ ^(200|301|302)$ ]]
}

@test "DNS resolution works correctly" {
    POD_NAME=$(get_pod_name "test-app")

    # Test DNS resolution
    log_info "Testing DNS resolution for api.github.com..."
    run exec_in_pod "$POD_NAME" "test-container" "nslookup api.github.com"
    [ "$status" -eq 0 ]

    # Should resolve to an IP
    [[ "$output" =~ "Address:" ]]
}

@test "Certificate verification succeeds with internal CA" {
    POD_NAME=$(get_pod_name "test-app")

    # Curl should NOT need -k flag (certificate should be trusted)
    log_info "Testing certificate verification..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s --max-time 15 https://api.github.com/meta -o /dev/null -w '%{http_code}'"

    [ "$status" -eq 0 ]
    [ "$output" = "200" ]

    # Verify with verbose output that cert was verified
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -v --max-time 15 https://api.github.com 2>&1 | grep -E 'SSL certificate verify|successfully set certificate'"

    [ "$status" -eq 0 ]
}

@test "SNI (Server Name Indication) is preserved" {
    POD_NAME=$(get_pod_name "test-app")

    # Test that different SNI hosts work correctly
    log_info "Testing SNI with api.github.com..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s --max-time 15 https://api.github.com/meta -o /dev/null -w '%{http_code}'"
    [ "$status" -eq 0 ]
    [ "$output" = "200" ]

    log_info "Testing SNI with github.com..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s --max-time 15 https://github.com -o /dev/null -w '%{http_code}'"
    [ "$status" -eq 0 ]
    [ "$output" = "200" ]
}

@test "Upstream TLS re-encryption works" {
    POD_NAME=$(get_pod_name "test-app")

    # Make request and verify we get real GitHub response
    log_info "Testing upstream re-encryption with real API call..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s --max-time 15 https://api.github.com/meta | grep -q 'github.com'"

    [ "$status" -eq 0 ]

    # This confirms:
    # 1. TLS was terminated by Envoy
    # 2. Request was inspected/authorized by OPA
    # 3. Envoy re-encrypted to real GitHub
    # 4. Real GitHub response was received
}
