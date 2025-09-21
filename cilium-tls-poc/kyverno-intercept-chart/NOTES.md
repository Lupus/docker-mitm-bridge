# Kyverno Intercept Chart - Best Practices

## Namespace Management

This chart follows Helm best practices:
- **Does NOT create namespaces** - Use `helm install --create-namespace` flag
- **References namespace dynamically** - Uses `{{ .Release.Namespace }}`

## Installation

```bash
# Create namespace with Helm (recommended)
helm install intercept-proxy . --create-namespace -n kyverno-intercept

# Or create namespace manually
kubectl create ns kyverno-intercept
helm install intercept-proxy . -n kyverno-intercept
```

## Cluster-Scoped Resources

This chart creates cluster-scoped resources (ClusterPolicy). A pre-delete hook ensures proper cleanup during uninstall.

## Known Issues

1. **ClusterPolicy cleanup**: Helm doesn't automatically delete cluster-scoped resources when installed in a namespace context. The chart includes a pre-delete hook to handle this.

2. **Namespace ownership**: Never include namespace creation in the chart itself. Let Helm manage it via --create-namespace flag.

## Resource Preservation

To keep resources after uninstall, add annotation:
```yaml
metadata:
  annotations:
    "helm.sh/resource-policy": keep
```