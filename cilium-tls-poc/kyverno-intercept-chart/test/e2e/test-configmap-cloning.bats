#!/usr/bin/env bats

# Test ConfigMap cloning across namespaces

load '../lib/detik'
load '../lib/helpers'

DETIK_CLIENT_NAME="kubectl"
DETIK_CLIENT_NAMESPACE="kyverno-intercept"

# Cleanup function to remove test namespace after tests
teardown_file() {
    # Clean up test namespace if it exists
    kubectl delete namespace cross-namespace-test --ignore-not-found=true --timeout=30s 2>/dev/null || true
}

@test "ClusterPolicy for ConfigMap cloning exists" {
    # Verify clone policy exists
    run kubectl get clusterpolicy -o name
    [ "$status" -eq 0 ]
    [[ "$output" =~ "intercept-proxy-clone-configmaps" ]]

    log_info "ConfigMap clone policy exists"
}

@test "Source ConfigMaps exist in chart namespace" {
    # Verify source ConfigMaps in kyverno-intercept namespace
    verify "there is 1 configmap named 'intercept-proxy-envoy-config'"
    verify "there is 1 configmap named 'intercept-proxy-opa-policy'"
    verify "there is 1 configmap named 'intercept-proxy-opa-config'"

    log_info "All source ConfigMaps exist in chart namespace"
}

@test "Pod deployed in different namespace triggers ConfigMap cloning" {
    # Create a test namespace different from the chart namespace
    TEST_NS="cross-namespace-test"
    kubectl create namespace "$TEST_NS" 2>/dev/null || true

    log_info "Created test namespace: $TEST_NS"

    # Deploy test pod in the new namespace
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cross-ns-test-app
  namespace: $TEST_NS
  labels:
    app: cross-ns-test-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cross-ns-test-app
  template:
    metadata:
      labels:
        app: cross-ns-test-app
        intercept-proxy/enabled: "true"  # Triggers sidecar injection and ConfigMap cloning
    spec:
      securityContext:
        runAsUser: 12345    # Different from sidecar UIDs
        runAsGroup: 12345
        fsGroup: 12345
      dnsConfig:
        options:
          - name: ndots
            value: "1"
      containers:
      - name: test-container
        image: nicolaka/netshoot:latest
        command:
          - sh
          - -c
          - |
            echo "Cross-namespace test pod started"
            while true; do sleep 3600; done
        resources:
          requests:
            memory: "32Mi"
            cpu: "10m"
          limits:
            memory: "64Mi"
            cpu: "50m"
EOF

    log_info "Deployed test pod in namespace: $TEST_NS"
}

@test "ConfigMaps are automatically cloned to target namespace" {
    TEST_NS="cross-namespace-test"

    log_info "Waiting for ConfigMaps to be cloned to $TEST_NS..."

    # Wait for ConfigMaps to be cloned (Kyverno should do this automatically)
    # Try multiple times as Kyverno may take a few seconds to process
    retry=0
    max_retries=20
    while [ $retry -lt $max_retries ]; do
        configmap_count=$(kubectl get configmap -n "$TEST_NS" -o name | grep -c "intercept-proxy" || echo "0")
        log_info "Found $configmap_count ConfigMaps in $TEST_NS (attempt $((retry+1))/$max_retries)"

        if [ "$configmap_count" -ge 3 ]; then
            break
        fi

        retry=$((retry+1))
        sleep 3
    done

    # Verify all 3 ConfigMaps were cloned
    run kubectl get configmap -n "$TEST_NS" -o name
    [ "$status" -eq 0 ]
    [[ "$output" =~ "intercept-proxy-envoy-config" ]]
    [[ "$output" =~ "intercept-proxy-opa-policy" ]]
    [[ "$output" =~ "intercept-proxy-opa-config" ]]

    log_info "All ConfigMaps successfully cloned to $TEST_NS"
}

@test "Cloned ConfigMaps have correct content" {
    TEST_NS="cross-namespace-test"

    # Get content from source ConfigMap
    SOURCE_ENVOY=$(kubectl get configmap intercept-proxy-envoy-config -n kyverno-intercept -o jsonpath='{.data.envoy\.yaml}')
    SOURCE_OPA_POLICY=$(kubectl get configmap intercept-proxy-opa-policy -n kyverno-intercept -o jsonpath='{.data.policy\.rego}')
    SOURCE_OPA_CONFIG=$(kubectl get configmap intercept-proxy-opa-config -n kyverno-intercept -o jsonpath='{.data.config\.yaml}')

    # Get content from cloned ConfigMaps
    CLONED_ENVOY=$(kubectl get configmap intercept-proxy-envoy-config -n "$TEST_NS" -o jsonpath='{.data.envoy\.yaml}')
    CLONED_OPA_POLICY=$(kubectl get configmap intercept-proxy-opa-policy -n "$TEST_NS" -o jsonpath='{.data.policy\.rego}')
    CLONED_OPA_CONFIG=$(kubectl get configmap intercept-proxy-opa-config -n "$TEST_NS" -o jsonpath='{.data.config\.yaml}')

    # Verify content matches
    [ "$SOURCE_ENVOY" = "$CLONED_ENVOY" ]
    [ "$SOURCE_OPA_POLICY" = "$CLONED_OPA_POLICY" ]
    [ "$SOURCE_OPA_CONFIG" = "$CLONED_OPA_CONFIG" ]

    log_info "Cloned ConfigMaps have correct content matching source"
}

@test "Pod in different namespace successfully deploys with sidecars" {
    TEST_NS="cross-namespace-test"

    log_info "Waiting for pod to be ready in $TEST_NS..."

    # Wait for pod to be ready
    kubectl wait --for=condition=ready pod \
        -l app=cross-ns-test-app \
        -n "$TEST_NS" \
        --timeout=120s

    # Get pod name
    POD_NAME=$(kubectl get pod -n "$TEST_NS" -l app=cross-ns-test-app -o jsonpath='{.items[0].metadata.name}')
    log_info "Cross-namespace test pod name: $POD_NAME"

    # Verify pod name exists
    [ -n "$POD_NAME" ]
}

@test "Cross-namespace pod has all sidecars (1 app + 3 sidecars)" {
    TEST_NS="cross-namespace-test"
    POD_NAME=$(kubectl get pod -n "$TEST_NS" -l app=cross-ns-test-app -o jsonpath='{.items[0].metadata.name}')

    # Count containers (should be 4: test-container + envoy-proxy + opa-sidecar + xds-service)
    CONTAINER_COUNT=$(kubectl get pod "$POD_NAME" -n "$TEST_NS" -o jsonpath='{.spec.containers[*].name}' | wc -w)
    log_info "Container count in cross-namespace pod: $CONTAINER_COUNT"
    [ "$CONTAINER_COUNT" -eq 4 ]

    # Verify container names
    run kubectl get pod "$POD_NAME" -n "$TEST_NS" -o jsonpath='{.spec.containers[*].name}'
    [ "$status" -eq 0 ]
    [[ "$output" =~ "test-container" ]]
    [[ "$output" =~ "envoy-proxy" ]]
    [[ "$output" =~ "opa-sidecar" ]]
    [[ "$output" =~ "xds-service" ]]

    log_info "All sidecars successfully injected in cross-namespace pod"
}

@test "Cross-namespace pod sidecars can access cloned ConfigMaps" {
    TEST_NS="cross-namespace-test"
    POD_NAME=$(kubectl get pod -n "$TEST_NS" -l app=cross-ns-test-app -o jsonpath='{.items[0].metadata.name}')

    # Check that Envoy has the config mounted (verify it's running and has config)
    ENVOY_READY=$(kubectl get pod "$POD_NAME" -n "$TEST_NS" \
        -o jsonpath='{.status.containerStatuses[?(@.name=="envoy-proxy")].ready}')
    log_info "Envoy ready status in cross-namespace pod: $ENVOY_READY"
    [ "$ENVOY_READY" = "true" ]

    # Check that OPA has config mounted
    OPA_READY=$(kubectl get pod "$POD_NAME" -n "$TEST_NS" \
        -o jsonpath='{.status.containerStatuses[?(@.name=="opa-sidecar")].ready}')
    log_info "OPA ready status in cross-namespace pod: $OPA_READY"
    [ "$OPA_READY" = "true" ]

    # Check xDS service is ready
    XDS_READY=$(kubectl get pod "$POD_NAME" -n "$TEST_NS" \
        -o jsonpath='{.status.containerStatuses[?(@.name=="xds-service")].ready}')
    log_info "xDS ready status in cross-namespace pod: $XDS_READY"
    [ "$XDS_READY" = "true" ]

    log_info "All sidecars successfully accessed cloned ConfigMaps"
}

@test "Cross-namespace pod can make HTTPS requests through interceptor" {
    TEST_NS="cross-namespace-test"
    POD_NAME=$(kubectl get pod -n "$TEST_NS" -l app=cross-ns-test-app -o jsonpath='{.items[0].metadata.name}')

    log_info "Testing HTTPS interception in cross-namespace pod..."

    # Test HTTPS request (should work without -k flag due to CA trust)
    run kubectl exec -n "$TEST_NS" "$POD_NAME" -c test-container -- \
        curl -s -o /dev/null -w "%{http_code}" https://api.github.com --max-time 30
    [ "$status" -eq 0 ]
    [ "$output" = "200" ] || [ "$output" = "301" ] || [ "$output" = "302" ]

    log_info "HTTPS request successful in cross-namespace pod: HTTP $output"
}

@test "ConfigMap updates in source namespace are synchronized to cloned ConfigMaps" {
    TEST_NS="cross-namespace-test"

    # Get original OPA config content
    ORIGINAL_CONFIG=$(kubectl get configmap intercept-proxy-opa-config -n kyverno-intercept -o jsonpath='{.data.config\.yaml}')

    # Add a test comment to the source ConfigMap
    kubectl patch configmap intercept-proxy-opa-config -n kyverno-intercept --type=json \
        -p='[{"op": "replace", "path": "/data/config.yaml", "value": "# Test sync comment\n'"$ORIGINAL_CONFIG"'"}]'

    log_info "Updated source ConfigMap, waiting for synchronization..."

    # Wait for Kyverno to synchronize (may take a few seconds)
    sleep 10

    # Check if cloned ConfigMap was updated
    CLONED_CONFIG=$(kubectl get configmap intercept-proxy-opa-config -n "$TEST_NS" -o jsonpath='{.data.config\.yaml}')

    # Verify the update was propagated
    [[ "$CLONED_CONFIG" =~ "Test sync comment" ]]

    log_info "ConfigMap synchronization verified"

    # Restore original content
    kubectl patch configmap intercept-proxy-opa-config -n kyverno-intercept --type=json \
        -p='[{"op": "replace", "path": "/data/config.yaml", "value": "'"$(echo "$ORIGINAL_CONFIG" | sed 's/"/\\"/g')"'"}]'
}

@test "Cleanup: Delete cross-namespace test resources" {
    TEST_NS="cross-namespace-test"

    log_info "Cleaning up test namespace: $TEST_NS"

    # Delete namespace (allow timeout since namespace deletion can be slow)
    kubectl delete namespace "$TEST_NS" --ignore-not-found=true --timeout=30s 2>/dev/null || {
        log_info "Namespace deletion timed out, continuing anyway (namespace will be deleted eventually)"
    }

    log_info "Cleanup initiated (namespace will be deleted in background)"
}
