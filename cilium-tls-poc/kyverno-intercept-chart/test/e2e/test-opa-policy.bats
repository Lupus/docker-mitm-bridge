#!/usr/bin/env bats

# Test OPA policy enforcement

load '../lib/detik'
load '../lib/helpers'

DETIK_CLIENT_NAME="kubectl"
DETIK_CLIENT_NAMESPACE="kyverno-intercept"

@test "OPA allows GET requests to github.com (restricted domain)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing GET request to github.com (should be allowed)..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X GET https://github.com"

    [ "$status" -eq 0 ]
    [ "$output" = "200" ]
}

@test "OPA allows HEAD requests to github.com (restricted domain)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing HEAD request to github.com (should be allowed)..."
    # Use -I (HEAD) instead of -X HEAD for better compatibility
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -I --max-time 30 https://api.github.com 2>&1 | head -1 | grep -oE '[0-9]{3}'"

    [ "$status" -eq 0 ]
    # HEAD requests typically return 200 or 301/302
    [[ "$output" =~ ^(200|301|302)$ ]]
}

@test "OPA blocks POST requests to github.com (restricted domain)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing POST request to api.github.com (should be blocked)..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST https://api.github.com/user"

    [ "$status" -eq 0 ]
    # OPA should return 403 Forbidden
    [ "$output" = "403" ]
}

@test "OPA blocks PUT requests to github.com (restricted domain)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing PUT request to api.github.com (should be blocked)..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X PUT https://api.github.com/repos/test/test"

    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
}

@test "OPA blocks DELETE requests to github.com (restricted domain)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing DELETE request to api.github.com (should be blocked)..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X DELETE https://api.github.com/repos/test/test"

    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
}

@test "OPA allows GET requests to api.anthropic.com (unrestricted domain)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing GET request to api.anthropic.com (unrestricted, should be allowed)..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X GET https://api.anthropic.com"

    [ "$status" -eq 0 ]
    # Should succeed (might get 404 or other status, but not 403)
    [[ ! "$output" = "403" ]]
}

@test "OPA allows POST requests to api.anthropic.com (unrestricted domain)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing POST request to api.anthropic.com (unrestricted, should be allowed)..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST https://api.anthropic.com"

    [ "$status" -eq 0 ]
    # Should NOT be 403 (OPA allows it, might get other status from server)
    [[ ! "$output" = "403" ]]
}

@test "OPA allows POST requests to api.openai.com (unrestricted domain)" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing POST request to api.openai.com (unrestricted, should be allowed)..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST https://api.openai.com"

    [ "$status" -eq 0 ]
    # Should NOT be 403
    [[ ! "$output" = "403" ]]
}

@test "OPA decision logs are generated" {
    POD_NAME=$(get_pod_name "test-app")

    # Make a request
    exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null --max-time 15 https://api.github.com" || true

    # Give OPA time to log
    sleep 2

    # Check OPA logs for decision
    OPA_LOGS=$(get_container_logs "$POD_NAME" "opa-sidecar" | tail -50)
    log_info "Checking OPA logs for policy decisions..."

    # Should see evidence of policy evaluation
    [[ "$OPA_LOGS" =~ "decision" ]] || \
    [[ "$OPA_LOGS" =~ "query" ]] || \
    [[ "$OPA_LOGS" =~ "allow" ]] || \
    [[ "$OPA_LOGS" =~ "intercept" ]]
}

@test "OPA gRPC ext_authz is working" {
    POD_NAME=$(get_pod_name "test-app")

    # Make request that should trigger OPA check and be blocked (POST to restricted domain)
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST https://api.github.com/user"

    # If OPA ext_authz is working, POST should be blocked with 403
    [ "$status" -eq 0 ]
    [ "$output" = "403" ]

    # Verify OPA logs show policy evaluation (ext_authz is being called)
    OPA_LOGS=$(get_container_logs "$POD_NAME" "opa-sidecar" | tail -100)

    # OPA logs should contain evidence of authz queries or decisions
    [[ "$OPA_LOGS" =~ "decision" ]] || \
    [[ "$OPA_LOGS" =~ "query" ]] || \
    [[ "$OPA_LOGS" =~ "ext_authz" ]] || \
    [[ "$OPA_LOGS" =~ "envoy" ]]
}

@test "OPA blocks requests with different user agents consistently" {
    POD_NAME=$(get_pod_name "test-app")

    # Test POST with custom user agent (should still be blocked)
    log_info "Testing POST with custom User-Agent..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST -H 'User-Agent: TestBot/1.0' https://api.github.com/repos"

    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
}

@test "OPA enforces method restrictions per domain" {
    POD_NAME=$(get_pod_name "test-app")

    # GitHub (restricted): GET OK, POST blocked
    log_info "Testing GitHub domain restrictions..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X GET https://api.github.com"
    [ "$output" != "403" ]

    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST https://api.github.com"
    [ "$output" = "403" ]

    # Anthropic (unrestricted): Both should work
    log_info "Testing Anthropic domain (unrestricted)..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X GET https://api.anthropic.com"
    [ "$output" != "403" ]

    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST https://api.anthropic.com"
    [ "$output" != "403" ]
}
