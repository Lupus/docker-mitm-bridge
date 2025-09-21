# Cilium TLS Intercept Helm Chart

This Helm chart sets up TLS interception using Cilium L7 filtering and cert-manager, providing a Kubernetes-native alternative to traditional MITM proxy solutions.

## Prerequisites

- Kubernetes cluster with Cilium installed
- cert-manager installed in the cluster
- Cilium configured with L7 proxy support

## Features

- **Automatic CA Generation**: Creates an internal CA for signing interception certificates
- **cert-manager Integration**: Uses cert-manager for automatic certificate lifecycle management
- **Cilium L7 Policies**: Leverages Cilium's native TLS termination capabilities
- **Configurable Domains**: Easy configuration of domains to intercept
- **Test Workload**: Includes a test pod for verification

## Installation

```bash
# Install the chart
helm install intercept ./cilium-tls-intercept-chart

# Or with custom values
helm install intercept ./cilium-tls-intercept-chart -f custom-values.yaml
```

## Configuration

Key configuration options in `values.yaml`:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `namespace.secrets` | Namespace for TLS secrets | `intercept-secrets` |
| `namespace.workload` | Namespace for workloads | `intercept-workload` |
| `ca.generate` | Auto-generate internal CA | `true` |
| `intercept.github.enabled` | Intercept GitHub traffic | `true` |
| `intercept.aws.enabled` | Intercept AWS traffic | `true` |
| `intercept.google.enabled` | Intercept Google APIs | `true` |
| `testWorkload.enabled` | Deploy test pod | `true` |

## Testing

After installation, test the interception:

```bash
# Get into the test pod
kubectl exec -it intercept-test-pod -n intercept-workload -- /bin/sh

# Test GitHub interception
curl -v https://api.github.com/meta 2>&1 | grep issuer

# Verify the certificate issuer is our internal CA
echo | openssl s_client -connect github.com:443 -servername github.com 2>/dev/null | \
  openssl x509 -noout -issuer
```

## How It Works

1. **CA Generation**: A Helm pre-install hook creates an internal CA
2. **cert-manager**: Issues certificates for configured domains using the internal CA
3. **Cilium Policies**: Intercept TLS traffic and terminate with generated certificates
4. **Re-encryption**: Traffic is re-encrypted using system CA bundle for upstream

## Verification

Check the setup status:

```bash
# Check certificates
kubectl get certificates -n intercept-secrets

# Check Cilium policy
kubectl get ciliumnetworkpolicies -n intercept-workload

# View certificate details
kubectl describe certificate intercept-github-cert -n intercept-secrets
```

## Uninstallation

```bash
helm uninstall intercept
kubectl delete namespace intercept-secrets intercept-workload
```

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

## Troubleshooting

- Check Cilium status: `cilium status`
- View cert-manager logs: `kubectl logs -n cert-manager deploy/cert-manager`
- Check certificate status: `kubectl describe certificate -n intercept-secrets`
- View Cilium policy details: `kubectl describe cnp -n intercept-workload`