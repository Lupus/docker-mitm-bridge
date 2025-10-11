#!/bin/bash
set -e

CLUSTER_NAME="xds-test"
NAMESPACE="xds-test"
export KUBECONFIG="/tmp/${CLUSTER_NAME}-kubeconfig"

echo "==> Setting up ${CLUSTER_NAME} cluster..."

# Check if cluster exists
if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Cluster ${CLUSTER_NAME} already exists, reusing it"
    kind get kubeconfig --name ${CLUSTER_NAME} > ${KUBECONFIG}
else
    echo "Creating new cluster ${CLUSTER_NAME}"
    cat > /tmp/kind-config.yaml <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
nodes:
- role: control-plane
EOF
    kind create cluster --config /tmp/kind-config.yaml
fi

echo "==> Building and loading xDS service image..."
docker build -t xds-service:test .
kind load docker-image xds-service:test --name ${CLUSTER_NAME}

echo "==> Creating namespace..."
kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

echo "==> Generating CA certificate..."
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /tmp/test-ca-key.pem \
  -out /tmp/test-ca-cert.pem \
  -subj "/CN=Test CA" 2>/dev/null

kubectl create secret tls mitm-ca-secret \
  --cert=/tmp/test-ca-cert.pem \
  --key=/tmp/test-ca-key.pem \
  -n ${NAMESPACE} \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Creating OPA policy..."
kubectl create configmap opa-policy -n ${NAMESPACE} \
  --from-literal='policy.rego=package intercept

allow := false

allow if {
    input.attributes.request.http.host == "example.com"
}

required_domains := ["example.com"]' \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Creating Envoy bootstrap..."
kubectl create configmap envoy-bootstrap -n ${NAMESPACE} \
  --from-literal='envoy.yaml=node:
  id: envoy-test
  cluster: test-cluster

admin:
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 15000

dynamic_resources:
  cds_config:
    resource_api_version: V3
    api_config_source:
      api_type: GRPC
      transport_api_version: V3
      grpc_services:
      - envoy_grpc:
          cluster_name: xds_cluster

  lds_config:
    resource_api_version: V3
    api_config_source:
      api_type: GRPC
      transport_api_version: V3
      grpc_services:
      - envoy_grpc:
          cluster_name: xds_cluster

static_resources:
  clusters:
  - name: xds_cluster
    type: STATIC
    connect_timeout: 1s
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
    load_assignment:
      cluster_name: xds_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 15090' \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Deploying test pod..."
kubectl delete pod xds-test-pod -n ${NAMESPACE} --ignore-not-found=true
kubectl apply -n ${NAMESPACE} -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: xds-test-pod
spec:
  containers:
  - name: opa
    image: openpolicyagent/opa:latest
    args: ["run", "--server", "--addr=:15020", "--addr=:15021", "--log-level=info", "/policies"]
    ports:
    - containerPort: 15020
    - containerPort: 15021
    volumeMounts:
    - name: opa-policy
      mountPath: /policies
      readOnly: true

  - name: xds-service
    image: xds-service:test
    imagePullPolicy: Never
    env:
    - name: SDS_GRPC_PORT
      value: "15090"
    - name: CA_CERT_PATH
      value: "/ca-secret/tls.crt"
    - name: CA_KEY_PATH
      value: "/ca-secret/tls.key"
    - name: OPA_URL
      value: "http://localhost:15020"
    - name: OPA_GRPC_PORT
      value: "15021"
    ports:
    - containerPort: 15090
    volumeMounts:
    - name: ca-secret
      mountPath: /ca-secret
      readOnly: true

  - name: envoy
    image: envoyproxy/envoy:v1.32.2
    args: ["-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]
    ports:
    - containerPort: 15001
    - containerPort: 15000
    volumeMounts:
    - name: envoy-config
      mountPath: /etc/envoy
      readOnly: true

  - name: curl
    image: curlimages/curl:8.5.0
    command: ["sleep", "infinity"]

  volumes:
  - name: opa-policy
    configMap:
      name: opa-policy
  - name: ca-secret
    secret:
      secretName: mitm-ca-secret
  - name: envoy-config
    configMap:
      name: envoy-bootstrap
EOF

echo "==> Waiting for pod to be ready..."
kubectl wait --for=condition=ready pod xds-test-pod -n ${NAMESPACE} --timeout=120s || {
    echo "Pod failed to become ready, checking logs..."
    kubectl get pod xds-test-pod -n ${NAMESPACE}
    kubectl describe pod xds-test-pod -n ${NAMESPACE}
    exit 1
}

echo ""
echo "==> Pod is ready!"
echo ""

echo "==> Running test requests..."
echo ""
echo "Test 1: GET request"
kubectl exec -n ${NAMESPACE} xds-test-pod -c curl -- \
  curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  http://127.0.0.1:15001/ -H "Host: example.com"

sleep 1

echo ""
echo "Test 2: POST request with data"
kubectl exec -n ${NAMESPACE} xds-test-pod -c curl -- \
  curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://127.0.0.1:15001/api/v1/resource \
  -H "Host: example.com" -d "test data"

sleep 1

echo ""
echo "Test 3: Custom path and user agent"
kubectl exec -n ${NAMESPACE} xds-test-pod -c curl -- \
  curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  http://127.0.0.1:15001/test/path \
  -H "Host: example.com" -H "User-Agent: TestAgent/1.0"

sleep 2

echo ""
echo "==> Access logs from Envoy:"
kubectl logs -n ${NAMESPACE} xds-test-pod -c envoy | grep -E '^\[20' || echo "(No access logs found)"

echo ""
echo "==> Test complete!"
echo ""
echo "Useful commands:"
echo "  export KUBECONFIG=${KUBECONFIG}"
echo "  kubectl logs -n ${NAMESPACE} xds-test-pod -c envoy -f"
echo "  kubectl logs -n ${NAMESPACE} xds-test-pod -c xds-service"
echo "  kubectl logs -n ${NAMESPACE} xds-test-pod -c opa"
echo "  kubectl exec -n ${NAMESPACE} xds-test-pod -c curl -- curl http://127.0.0.1:15000/config_dump"
echo ""
echo "To cleanup:"
echo "  kind delete cluster --name ${CLUSTER_NAME}"
