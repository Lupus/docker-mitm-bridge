#!/usr/bin/env bats

# Test per-pod OPA policy configuration via annotations

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
    [[ ! "$CONFIGMAP_NAME" =~ -test-app-opa-policy$ ]]
}

# Test that Kyverno generates ConfigMap for pod with annotation
@test "Kyverno generates ConfigMap for pod with custom opa-data annotation" {
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

    # Wait a bit for Kyverno to generate the ConfigMap
    sleep 5

    # Verify the per-pod ConfigMap was created by Kyverno
    log_info "Checking if per-pod ConfigMap was generated..."
    run kubectl get configmap custom-policy-pod-opa-policy -n kyverno-intercept
    [ "$status" -eq 0 ]

    log_info "Per-pod ConfigMap created successfully"
}

@test "Generated ConfigMap contains policy.rego from chart" {
    # Verify the ConfigMap has the policy.rego file
    log_info "Verifying ConfigMap contains policy.rego..."

    POLICY_CONTENT=$(kubectl get configmap custom-policy-pod-opa-policy \
        -n kyverno-intercept -o jsonpath='{.data.policy\.rego}')

    # Check that policy contains expected OPA package and rules
    [[ "$POLICY_CONTENT" =~ "package intercept" ]]
    [[ "$POLICY_CONTENT" =~ "default allow = false" ]]
    [[ "$POLICY_CONTENT" =~ "unrestricted_domains" ]]
}

@test "Generated ConfigMap contains custom data from annotation" {
    # Verify the ConfigMap has the custom data from the annotation
    log_info "Verifying ConfigMap contains custom data.yml from annotation..."

    DATA_CONTENT=$(kubectl get configmap custom-policy-pod-opa-policy \
        -n kyverno-intercept -o jsonpath='{.data.data\.yml}')

    log_info "Data content: $DATA_CONTENT"

    # Check that data contains our custom domains
    [[ "$DATA_CONTENT" =~ "example.com" ]]
    [[ "$DATA_CONTENT" =~ "httpbin.org" ]]
    [[ "$DATA_CONTENT" =~ "unrestricted_domains" ]]
}

@test "Pod with custom annotation mounts per-pod ConfigMap" {
    # Get the ConfigMap name mounted in the custom pod
    CONFIGMAP_NAME=$(kubectl get pod custom-policy-pod -n kyverno-intercept \
        -o jsonpath='{.spec.volumes[?(@.name=="opa-policy")].configMap.name}')

    log_info "Custom pod is using ConfigMap: $CONFIGMAP_NAME"

    # Should use the per-pod ConfigMap
    [ "$CONFIGMAP_NAME" = "custom-policy-pod-opa-policy" ]
}

@test "OPA in custom pod enforces custom policy from annotation" {
    # Wait for OPA to be ready
    sleep 10

    log_info "Testing that custom OPA policy is enforced..."

    # httpbin.org should be allowed (in our custom unrestricted_domains)
    run exec_in_pod "custom-policy-pod" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://httpbin.org/get"

    [ "$status" -eq 0 ]
    # Should succeed (not 403)
    [[ ! "$output" = "403" ]]
    log_info "httpbin.org access allowed (custom policy)"

    # github.com should be blocked (not in our custom allowed/unrestricted domains, and github_read_access_enabled: false)
    run exec_in_pod "custom-policy-pod" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://github.com"

    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
    log_info "github.com access blocked (not in custom policy)"
}

@test "OPA can query custom data from annotation" {
    log_info "Querying OPA data endpoint to verify custom data is loaded..."

    # Query OPA's data endpoint to see what data it has loaded
    run exec_in_pod "custom-policy-pod" "opa-sidecar" \
        "curl -s http://localhost:15020/v1/data"

    [ "$status" -eq 0 ]

    log_info "OPA data response: $output"

    # Should contain our custom domains
    [[ "$output" =~ "httpbin.org" ]]
    [[ "$output" =~ "example.com" ]]
}

@test "Pod recreation with updated annotation creates updated ConfigMap" {
    # Note: Kyverno's synchronize: true ensures ConfigMap updates when pod annotations change.
    # However, running pods don't pick up ConfigMap changes without restart (standard K8s behavior).
    # This test verifies that recreating a pod with a new annotation generates an updated ConfigMap.

    kubectl delete pod custom-policy-pod -n kyverno-intercept --wait=true

    # Create pod with updated annotation
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
        - "httpbin.org"
        - "postman-echo.com"
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

    # Wait for new pod
    kubectl wait --for=condition=ready pod/custom-policy-pod \
        -n kyverno-intercept --timeout=120s

    # Wait for Kyverno to update ConfigMap
    sleep 5

    # Verify ConfigMap was updated with new domains
    DATA_CONTENT=$(kubectl get configmap custom-policy-pod-opa-policy \
        -n kyverno-intercept -o jsonpath='{.data.data\.yml}')

    log_info "Updated data content: $DATA_CONTENT"

    # Should have the new domain
    [[ "$DATA_CONTENT" =~ "postman-echo.com" ]]
    # Should NOT have the removed domain
    [[ ! "$DATA_CONTENT" =~ "example.com" ]]
}

@test "Multiple pods can have different custom policies" {
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

    sleep 5

    # Verify each pod has its own ConfigMap
    run kubectl get configmap custom-policy-pod-opa-policy -n kyverno-intercept
    [ "$status" -eq 0 ]

    run kubectl get configmap custom-policy-pod-2-opa-policy -n kyverno-intercept
    [ "$status" -eq 0 ]

    # Verify they have different content
    DATA1=$(kubectl get configmap custom-policy-pod-opa-policy \
        -n kyverno-intercept -o jsonpath='{.data.data\.yml}')
    DATA2=$(kubectl get configmap custom-policy-pod-2-opa-policy \
        -n kyverno-intercept -o jsonpath='{.data.data\.yml}')

    [[ "$DATA1" =~ "httpbin.org" ]]
    [[ "$DATA2" =~ "github.com" ]]
    [[ ! "$DATA1" =~ "github.com" ]]
    [[ ! "$DATA2" =~ "httpbin.org" ]]
}

@test "Deployment with custom annotation creates per-Deployment ConfigMap" {
    log_info "Creating Deployment with custom OPA policy annotation..."

    # Create a deployment with custom OPA annotation
    kubectl apply -n kyverno-intercept -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment-custom-opa
  labels:
    app: test-deployment-opa
spec:
  replicas: 2
  selector:
    matchLabels:
      app: test-deployment-opa
  template:
    metadata:
      labels:
        app: test-deployment-opa
        intercept-proxy/enabled: "true"
      annotations:
        intercept-proxy/opa-data: |
          allowed_domains: []
          unrestricted_domains:
            - "postman-echo.com"
            - "httpbin.org"
          github_read_access_enabled: false
          github_allowed_users: []
          github_allowed_repos: []
          aws_access_enabled: false
          aws_allowed_services: []
    spec:
      securityContext:
        runAsUser: 12347
        runAsGroup: 12347
        fsGroup: 12347
      containers:
      - name: test-container
        image: curlimages/curl:latest
        command: ["sleep", "3600"]
EOF

    # Wait for deployment to be ready
    log_info "Waiting for Deployment to be ready..."
    kubectl wait --for=condition=available deployment/test-deployment-custom-opa \
        -n kyverno-intercept --timeout=180s

    # Get the ReplicaSet name (owner of the pods)
    REPLICASET_NAME=$(kubectl get replicaset -n kyverno-intercept \
        -l app=test-deployment-opa -o jsonpath='{.items[0].metadata.name}')

    log_info "ReplicaSet name: $REPLICASET_NAME"

    # Wait for ConfigMap to be generated
    sleep 10

    # Verify the per-ReplicaSet ConfigMap was created by Kyverno
    log_info "Checking if per-ReplicaSet ConfigMap was generated..."
    run kubectl get configmap "${REPLICASET_NAME}-opa-policy" -n kyverno-intercept
    [ "$status" -eq 0 ]

    log_info "Per-ReplicaSet ConfigMap created successfully"
}

@test "Deployment ConfigMap contains policy and custom data" {
    # Get the ReplicaSet name
    REPLICASET_NAME=$(kubectl get replicaset -n kyverno-intercept \
        -l app=test-deployment-opa -o jsonpath='{.items[0].metadata.name}')

    # Verify policy.rego exists
    POLICY_CONTENT=$(kubectl get configmap "${REPLICASET_NAME}-opa-policy" \
        -n kyverno-intercept -o jsonpath='{.data.policy\.rego}')

    [[ "$POLICY_CONTENT" =~ "package intercept" ]]
    [[ "$POLICY_CONTENT" =~ "default allow = false" ]]
    log_info "Policy content verified"

    # Verify custom data exists
    DATA_CONTENT=$(kubectl get configmap "${REPLICASET_NAME}-opa-policy" \
        -n kyverno-intercept -o jsonpath='{.data.data\.yml}')

    [[ "$DATA_CONTENT" =~ "postman-echo.com" ]]
    [[ "$DATA_CONTENT" =~ "httpbin.org" ]]
    log_info "Custom data content verified"
}

@test "All Deployment pods mount the same per-Deployment ConfigMap" {
    # Get the ReplicaSet name
    REPLICASET_NAME=$(kubectl get replicaset -n kyverno-intercept \
        -l app=test-deployment-opa -o jsonpath='{.items[0].metadata.name}')

    # Get all pod names from the deployment
    POD_NAMES=$(kubectl get pods -n kyverno-intercept \
        -l app=test-deployment-opa -o jsonpath='{.items[*].metadata.name}')

    log_info "Checking ConfigMap mounts for pods: $POD_NAMES"

    # Verify each pod mounts the same ConfigMap
    for POD_NAME in $POD_NAMES; do
        CONFIGMAP_NAME=$(kubectl get pod "$POD_NAME" -n kyverno-intercept \
            -o jsonpath='{.spec.volumes[?(@.name=="opa-policy")].configMap.name}')

        log_info "Pod $POD_NAME uses ConfigMap: $CONFIGMAP_NAME"

        [ "$CONFIGMAP_NAME" = "${REPLICASET_NAME}-opa-policy" ]
    done

    log_info "All pods mount the same ConfigMap: ${REPLICASET_NAME}-opa-policy"
}

@test "Deployment pods enforce custom OPA policy" {
    # Get any pod from the deployment
    POD_NAME=$(kubectl get pods -n kyverno-intercept \
        -l app=test-deployment-opa -o jsonpath='{.items[0].metadata.name}')

    log_info "Testing custom OPA policy enforcement in pod: $POD_NAME"

    # Wait for OPA to be ready
    sleep 10

    # httpbin.org should be allowed (in unrestricted_domains)
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://httpbin.org/get"

    [ "$status" -eq 0 ]
    [[ ! "$output" = "403" ]]
    log_info "httpbin.org access allowed (custom Deployment policy)"

    # github.com should be blocked
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://github.com"

    [ "$status" -eq 0 ]
    [ "$output" = "403" ]
    log_info "github.com access blocked (not in custom Deployment policy)"
}

@test "Deployment update with new annotation updates ConfigMap" {
    # Update the Deployment with different policy
    kubectl patch deployment test-deployment-custom-opa -n kyverno-intercept --type=json -p='[
        {
            "op": "replace",
            "path": "/spec/template/metadata/annotations/intercept-proxy~1opa-data",
            "value": "allowed_domains: []\nunrestricted_domains:\n  - \"example.com\"\n  - \"httpstat.us\"\ngithub_read_access_enabled: false\ngithub_allowed_users: []\ngithub_allowed_repos: []\naws_access_enabled: false\naws_allowed_services: []"
        }
    ]'

    # Wait for rollout to complete
    log_info "Waiting for rollout to complete..."
    kubectl rollout status deployment/test-deployment-custom-opa -n kyverno-intercept --timeout=180s

    # Get the NEW ReplicaSet name (Deployment creates new ReplicaSet on update)
    sleep 10
    NEW_REPLICASET_NAME=$(kubectl get replicaset -n kyverno-intercept \
        -l app=test-deployment-opa --sort-by=.metadata.creationTimestamp \
        -o jsonpath='{.items[-1:].metadata.name}')

    log_info "New ReplicaSet name: $NEW_REPLICASET_NAME"

    # Wait for new ConfigMap to be generated
    sleep 10

    # Verify new ConfigMap exists
    run kubectl get configmap "${NEW_REPLICASET_NAME}-opa-policy" -n kyverno-intercept
    [ "$status" -eq 0 ]

    # Verify ConfigMap has updated content
    DATA_CONTENT=$(kubectl get configmap "${NEW_REPLICASET_NAME}-opa-policy" \
        -n kyverno-intercept -o jsonpath='{.data.data\.yml}')

    log_info "Updated ConfigMap data: $DATA_CONTENT"

    # Should have the new domains
    [[ "$DATA_CONTENT" =~ "example.com" ]]
    [[ "$DATA_CONTENT" =~ "httpstat.us" ]]
    # Should NOT have the old domains
    [[ ! "$DATA_CONTENT" =~ "postman-echo.com" ]]
}

@test "Cleanup test pods and ConfigMaps" {
    log_info "Cleaning up custom policy test resources..."

    kubectl delete pod custom-policy-pod -n kyverno-intercept --ignore-not-found=true --wait=false
    kubectl delete pod custom-policy-pod-2 -n kyverno-intercept --ignore-not-found=true --wait=false
    kubectl delete deployment test-deployment-custom-opa -n kyverno-intercept --ignore-not-found=true --wait=false

    # ConfigMaps should be cleaned up automatically by Kyverno when pods are deleted
    # Wait a bit to let cleanup happen
    sleep 5

    log_info "Cleanup complete"
}
