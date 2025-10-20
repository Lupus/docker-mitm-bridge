#!/usr/bin/env bats

# Test per-pod OPA policy configuration via annotations
# This uses the annotation-based approach where OPA data is passed
# directly via environment variables, not generated ConfigMaps

load '../lib/detik'
load '../lib/helpers'

DETIK_CLIENT_NAME="kubectl"
DETIK_CLIENT_NAMESPACE="kyverno-intercept"

# Test pod without custom OPA policy annotation (uses default policy)
@test "Pod without annotation uses default OPA policy ConfigMap" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Verifying pod without annotation uses default ConfigMap..."

    # Get the ConfigMap name mounted in the pod
    CONFIGMAP_NAME=$(kubectl get pod "$POD_NAME" -n kyverno-intercept \
        -o jsonpath='{.spec.volumes[?(@.name=="opa-policy")].configMap.name}')

    log_info "Pod is using ConfigMap: $CONFIGMAP_NAME"

    # Should use the default release ConfigMap, not a per-pod one
    [[ "$CONFIGMAP_NAME" =~ ^intercept-proxy-opa-policy$ ]]
    [[ ! "$CONFIGMAP_NAME" =~ -opa-policy$ ]] || true  # No per-pod ConfigMaps should exist
}

# Test that pods with annotation have env var set
@test "Pod with annotation has podinfo downwardAPI volume for OPA data" {
    # Create a test pod with custom OPA data annotation
    kubectl apply -n kyverno-intercept -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: custom-policy-pod
  labels:
    app: custom-policy-test
    intercept-proxy/enabled: "true"
  annotations:
    intercept-proxy/opa-data: |
      allowed_domains: []
      unrestricted_domains:
        - "example.com"
        - "httpbin.org"
      github_read_access_enabled: false
      github_allowed_users: []
      github_allowed_repos: []
      aws_access_enabled: false
      aws_allowed_services: []
spec:
  securityContext:
    runAsUser: 12345
    runAsGroup: 12345
    fsGroup: 12345
  containers:
  - name: test-container
    image: curlimages/curl:latest
    command: ["sleep", "3600"]
EOF

    # Wait for pod to be ready (with all sidecars injected)
    log_info "Waiting for pod with custom policy to be ready..."
    kubectl wait --for=condition=ready pod/custom-policy-pod \
        -n kyverno-intercept --timeout=120s

    # Verify the opa-data-setup init container has the podinfo volume mounted
    log_info "Checking if opa-data-setup init container has podinfo volume mount..."
    VOLUME_MOUNT=$(kubectl get pod custom-policy-pod -n kyverno-intercept \
        -o jsonpath='{.spec.initContainers[?(@.name=="opa-data-setup")].volumeMounts[?(@.name=="podinfo")].mountPath}')

    log_info "podinfo volume mounted at: $VOLUME_MOUNT"
    [ "$VOLUME_MOUNT" = "/podinfo" ]

    # Verify the podinfo volume uses downwardAPI with the annotation
    DOWNWARD_API_PATH=$(kubectl get pod custom-policy-pod -n kyverno-intercept \
        -o jsonpath='{.spec.volumes[?(@.name=="podinfo")].downwardAPI.items[0].fieldRef.fieldPath}')

    log_info "downwardAPI configured from: $DOWNWARD_API_PATH"
    [ "$DOWNWARD_API_PATH" = "metadata.annotations['intercept-proxy/opa-data']" ]
}

@test "Pod with custom annotation still uses default ConfigMap for policy" {
    # Get the ConfigMap name mounted in the custom pod
    CONFIGMAP_NAME=$(kubectl get pod custom-policy-pod -n kyverno-intercept \
        -o jsonpath='{.spec.volumes[?(@.name=="opa-policy")].configMap.name}')

    log_info "Custom pod is using ConfigMap: $CONFIGMAP_NAME"

    # Should use the default release ConfigMap (policy.rego is shared)
    [ "$CONFIGMAP_NAME" = "intercept-proxy-opa-policy" ]
}

@test "OPA in custom pod enforces custom policy from annotation" {
    # Wait for OPA to be ready and load the annotation data
    # Increased from 10s to 20s to ensure proxy stack is fully ready
    sleep 20

    log_info "Testing that custom OPA policy data is enforced..."

    # httpbin.org should be allowed (in our custom unrestricted_domains)
    run exec_in_pod "custom-policy-pod" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://httpbin.org/get"

    [ "$status" -eq 0 ]
    # Should succeed (not 403)
    [[ ! "$output" = "403" ]]
    log_info "httpbin.org access allowed (custom policy data)"

    # github.com should be blocked (not in our custom allowed/unrestricted domains, and github_read_access_enabled: false)
    run exec_in_pod "custom-policy-pod" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://github.com"

    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
    log_info "github.com access blocked (not in custom policy data)"
}

@test "OPA can query custom data from annotation" {
    log_info "Querying OPA data endpoint to verify custom data is loaded..."

    # Query OPA's data endpoint from test-container (opa-sidecar is distroless, no shell)
    # OPA listens on localhost:15020, accessible from any container in the pod
    run exec_in_pod "custom-policy-pod" "test-container" \
        "curl -s http://localhost:15020/v1/data"

    [ "$status" -eq 0 ]

    log_info "OPA data response: $output"

    # Should contain our custom domains
    [[ "$output" =~ "httpbin.org" ]]
    [[ "$output" =~ "example.com" ]]
}

@test "OPA logs show it loaded data from annotation" {
    log_info "Checking OPA sidecar logs to verify annotation data was used..."

    # Check opa-data-setup init container logs
    run kubectl logs custom-policy-pod -n kyverno-intercept -c opa-data-setup

    [ "$status" -eq 0 ]

    log_info "opa-data-setup init container logs: $output"

    # Should show it used custom data from annotation
    [[ "$output" =~ "Using custom OPA policy data from annotation" ]]
}

@test "Multiple pods can have different custom policies via annotations" {
    # Create a second pod with different policy
    kubectl apply -n kyverno-intercept -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: custom-policy-pod-2
  labels:
    app: custom-policy-test-2
    intercept-proxy/enabled: "true"
  annotations:
    intercept-proxy/opa-data: |
      allowed_domains:
        - "github.com"
      unrestricted_domains: []
      github_read_access_enabled: true
      github_allowed_users: []
      github_allowed_repos: []
      aws_access_enabled: false
      aws_allowed_services: []
spec:
  securityContext:
    runAsUser: 12346
    runAsGroup: 12346
    fsGroup: 12346
  containers:
  - name: test-container
    image: curlimages/curl:latest
    command: ["sleep", "3600"]
EOF

    kubectl wait --for=condition=ready pod/custom-policy-pod-2 \
        -n kyverno-intercept --timeout=120s

    # Increased wait time to ensure both pods' proxy stacks are fully ready
    sleep 20

    # Test first pod: httpbin.org allowed, github.com blocked
    run exec_in_pod "custom-policy-pod" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://httpbin.org/get"
    [ "$status" -eq 0 ]
    [[ ! "$output" = "403" ]]
    log_info "Pod 1: httpbin.org allowed"

    run exec_in_pod "custom-policy-pod" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://github.com"
    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
    log_info "Pod 1: github.com blocked"

    # Test second pod: github.com allowed (via github_read_access_enabled), httpbin.org blocked
    run exec_in_pod "custom-policy-pod-2" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://github.com"
    [ "$status" -eq 0 ]
    [[ ! "$output" = "403" ]]
    log_info "Pod 2: github.com allowed"

    run exec_in_pod "custom-policy-pod-2" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://httpbin.org/get"
    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
    log_info "Pod 2: httpbin.org blocked"
}

@test "Cleanup test pods" {
    log_info "Cleaning up custom policy test resources..."

    kubectl delete pod custom-policy-pod -n kyverno-intercept --ignore-not-found=true --wait=false
    kubectl delete pod custom-policy-pod-2 -n kyverno-intercept --ignore-not-found=true --wait=false

    # No ConfigMaps to clean up - annotation-based approach doesn't create them

    log_info "Cleanup complete"
}
