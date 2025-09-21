# Cilium TLS Interception PoC

This proof-of-concept demonstrates how to implement TLS interception using Cilium L7 filtering and Kubernetes cert-manager, as an alternative to traditional MITM proxy solutions like the docker-mitm-bridge project.

## Overview

The solution uses:
- **Cilium** for L7 network policies with TLS termination/origination
- **cert-manager** for automatic certificate lifecycle management
- **Helm** for deployment and configuration management

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Workload   │────▶│   Cilium     │────▶│  External   │
│     Pod     │     │   L7 Proxy   │     │   Service   │
└─────────────┘     └──────────────┘     └─────────────┘
                           │
                    ┌──────▼──────┐
                    │ cert-manager│
                    │ Certificates│
                    └─────────────┘
```

## Components

### Helm Chart Structure
```
cilium-tls-intercept-chart/
├── Chart.yaml                  # Chart metadata
├── values.yaml                 # Configuration values
├── templates/
│   ├── namespace.yaml          # Namespaces for secrets and workloads
│   ├── ca-generator-job.yaml   # Job to generate internal CA
│   ├── clusterissuer.yaml      # cert-manager ClusterIssuer
│   ├── certificates.yaml       # Certificate resources for domains
│   ├── cilium-policy.yaml      # CiliumNetworkPolicy for TLS interception
│   ├── upstream-ca.yaml        # Upstream CA bundle for re-encryption
│   └── test-workload.yaml      # Test pod for verification
└── README.md                   # Chart documentation
```

## Installation

### Prerequisites
- Kubernetes cluster with Cilium CNI installed
- cert-manager installed in the cluster
- Cilium configured with L7 proxy support enabled

### Deploy the Helm Chart
```bash
# Install the TLS interception chart
helm install intercept ./cilium-tls-intercept-chart --create-namespace

# Check installation status
kubectl get certificates -n intercept-secrets
kubectl get cnp -n intercept-workload
kubectl get pods -n intercept-workload
```

## Configuration

The chart is configured via `values.yaml` with these key sections:

### Intercepted Domains
```yaml
intercept:
  github:
    enabled: true
    domains:
      - "github.com"
      - "*.github.com"
  aws:
    enabled: true
    domains:
      - "*.amazonaws.com"
  google:
    enabled: true
    domains:
      - "*.googleapis.com"
```

### Certificate Settings
```yaml
certificates:
  duration: 8760h  # 1 year
  renewBefore: 720h  # Renew 30 days before expiry
```

## How It Works

1. **CA Generation**: A Helm hook job creates an internal CA on installation
2. **Certificate Issuance**: cert-manager automatically issues certificates for configured domains using the internal CA
3. **TLS Interception**: Cilium NetworkPolicy with:
   - `terminatingTLS`: Terminates incoming TLS from pods using our certificates
   - `originatingTLS`: Re-encrypts traffic to upstream using system CA bundle
4. **Policy Enforcement**: Applied to pods with `app: intercept-workload` label

## Testing

### Verify Setup
```bash
# Check certificates are issued
kubectl get certificates -n intercept-secrets

# Verify Cilium policy is applied
kubectl describe cnp intercept-tls-policy -n intercept-workload

# Test from the test pod
kubectl exec -it intercept-test-pod -n intercept-workload -- sh

# Inside the pod, test connections
curl -v https://api.github.com/meta
```

## Current Status & Limitations

### ✅ Working Components
- Automated CA generation and certificate issuance
- cert-manager integration with automatic renewal
- Cilium NetworkPolicy properly configured
- Test infrastructure deployed
- Secrets properly managed in `cilium-secrets` namespace

### ⚠️ Known Issues
1. **TLS Interception Not Active**: While all components are configured correctly, actual TLS interception is not yet working. Traffic still goes directly to destination servers.

2. **Possible Causes**:
   - Cilium may require additional configuration flags for TLS interception
   - SDS (Secret Discovery Service) mode might need explicit enablement
   - External Envoy proxy configuration may need adjustment

### 🔧 Fixes Applied
- Removed `ca.crt` from terminatingTLS secrets (known bug causing connection failures)
- Moved secrets to `cilium-secrets` namespace (required by Cilium's `policy-secrets-namespace` setting)
- Fixed namespace references in CiliumNetworkPolicy

## Troubleshooting

### Check Cilium Configuration
```bash
# Verify L7 proxy is enabled
cilium config view | grep -E "(l7-proxy|tls|secret)"

# Check endpoint policy enforcement
kubectl exec -n kube-system ds/cilium -- cilium endpoint list | grep intercept

# Monitor traffic
kubectl exec -n kube-system ds/cilium -- cilium monitor --type drop
```

### Verify Secrets
```bash
# Check secrets in cilium-secrets namespace
kubectl get secrets -n cilium-secrets

# Verify certificate contents (should NOT have ca.crt)
kubectl describe secret intercept-github-tls -n cilium-secrets
```

### Debug Logs
```bash
# Cilium logs
kubectl logs -n kube-system ds/cilium | grep -i tls

# Cilium Envoy logs
kubectl logs -n kube-system ds/cilium-envoy
```

## Next Steps

To get TLS interception fully working:

1. **Enable SDS Mode**: Configure Cilium with explicit SDS support for better secret management
2. **Verify Envoy Configuration**: Check if Envoy needs specific listener configuration for TLS termination
3. **Test with Simple Policy**: Start with a basic HTTP policy without TLS to verify L7 filtering works
4. **Check Cilium Version Compatibility**: Ensure all required features are available in Cilium v1.18.0

## References

- [Cilium L7 Network Policies](https://docs.cilium.io/en/stable/security/policy/language/#layer-7-examples)
- [cert-manager Documentation](https://cert-manager.io/docs/)
- [Cilium TLS Visibility](https://docs.cilium.io/en/stable/security/tls-visibility/)

## Comparison with docker-mitm-bridge

| Feature | docker-mitm-bridge | Cilium TLS Interception |
|---------|-------------------|------------------------|
| Deployment | Docker Compose | Kubernetes/Helm |
| Proxy Type | mitmproxy | Cilium/Envoy |
| Certificate Management | Manual/Script | cert-manager (automatic) |
| Policy Engine | OPA | CiliumNetworkPolicy |
| Scalability | Single instance | Cloud-native, multi-pod |
| Integration | Standalone | Native Kubernetes |

## Contributing

This is a proof-of-concept implementation. Contributions and improvements are welcome to get full TLS interception working with Cilium.