# Bug Report: Envoy Dynamic Forward Proxy TLS Validation Fails for Multiple Hostnames on Same IP

**Status**: ✅ **FIXED**
**Fixed Date**: 2025-10-28
**Pull Request**: https://github.com/Lupus/docker-mitm-bridge/pull/11

**Severity**: High
**Component**: xDS Service / Envoy Dynamic Forward Proxy
**Envoy Version**: envoyproxy/envoy:v1.28-latest
**Related Upstream Issue**: https://github.com/envoyproxy/envoy/issues/18897

---

## RESOLUTION

### Fix Summary
The bug was fixed by disabling TLS session resumption in the `dynamic_forward_proxy_cluster_https` configuration. TLS session resumption was caching validation context per IP address instead of per (IP, hostname) tuple, causing certificate validation failures for subsequent hostnames sharing the same IP.

### Changes Made

**File**: `cilium-tls-poc/xds-service/main.go`

1. **Disabled TLS Session Resumption**:
   - Added `MaxSessionKeys: wrapperspb.UInt32(0)` to `UpstreamTlsContext`
   - Prevents caching of TLS validation context across different hostnames

2. **Optimized Connection Pooling**:
   - Added `CommonHttpProtocolOptions` with 600s idle timeout and unlimited requests per connection
   - Maintains performance despite disabling session resumption

3. **Added Circuit Breaker**:
   - Set `MaxConnections` to 2048 to handle increased connection load

4. **Enabled Auto-SNI**:
   - Configured `TypedExtensionProtocolOptions` with `HttpProtocolOptions` for correct SNI handling

### Testing
An automated test was added (`tests/test-multi-sni-same-ip.sh`) that:
- Deploys nginx with two virtual servers (test-a.local, test-b.local) on the same Service IP
- Uses CA-signed certificates with different CNs for each hostname
- Tests both access orders to verify both hostnames work regardless of sequence
- Validates no `CERTIFICATE_VERIFY_FAILED` errors appear in Envoy logs

### Verification
After the fix:
- ✅ Both `api.anthropic.com` and `console.anthropic.com` work in any access order
- ✅ No TLS validation errors in Envoy access logs
- ✅ Automated test passes in CI pipeline
- ✅ Performance maintained through connection pooling

---

## ORIGINAL BUG REPORT

## Summary

Envoy's `dynamic_forward_proxy` cluster incorrectly caches TLS validation context per IP address instead of per hostname. When multiple hostnames resolve to the same IP but serve different TLS certificates (different CAs, different CNs), only the first hostname accessed after pod startup will work. All subsequent hostnames sharing that IP will fail with `CERTIFICATE_VERIFY_FAILED`.

This is a **deterministic bug**, not an intermittent failure. The behavior depends entirely on which hostname is accessed first after pod restart.

## Impact

Any deployment using the Kyverno TLS interceptor to proxy multiple hostnames that:
1. Resolve to the same IP address (common with CDNs, cloud providers)
2. Serve different TLS certificates
3. Use the `dynamic_forward_proxy_cluster_https` configuration

Will experience consistent TLS verification failures for all hostnames except the first one accessed.

## Reproduction Steps

### Prerequisites
- Kyverno TLS interceptor deployed with xDS service
- Two or more domains resolving to the same IP with different certificates
- Example: `api.anthropic.com` and `console.anthropic.com` both resolve to `160.79.104.10`

### Test Case 1: api.anthropic.com accessed first
```bash
# Restart pod to clear any cached state
kubectl delete pod -l app=dev-main -n graphiti-dev
kubectl wait --for=condition=ready pod -l app=dev-main -n graphiti-dev

# Get new pod name
POD=$(kubectl get pods -n graphiti-dev -l app=dev-main -o jsonpath='{.items[0].metadata.name}')

# Access api.anthropic.com first
kubectl exec $POD -n graphiti-dev -c dev-main -- curl -v https://api.anthropic.com/api/hello
# Result: HTTP 200 OK ✅

# Now try console.anthropic.com
kubectl exec $POD -n graphiti-dev -c dev-main -- curl -v https://console.anthropic.com/v1/oauth/hello
# Result: HTTP 503, ERR_BAD_RESPONSE ❌
```

### Test Case 2: console.anthropic.com accessed first
```bash
# Restart pod again
kubectl delete pod $POD -n graphiti-dev
kubectl wait --for=condition=ready pod -l app=dev-main -n graphiti-dev

POD=$(kubectl get pods -n graphiti-dev -l app=dev-main -o jsonpath='{.items[0].metadata.name}')

# Access console.anthropic.com first
kubectl exec $POD -n graphiti-dev -c dev-main -- curl -v https://console.anthropic.com/v1/oauth/hello
# Result: HTTP 200 OK ✅

# Now try api.anthropic.com
kubectl exec $POD -n graphiti-dev -c dev-main -- curl -v https://api.anthropic.com/api/hello
# Result: HTTP 503, ERR_BAD_RESPONSE ❌
```

### Expected Behavior
Both domains should work regardless of access order.

### Actual Behavior
Only the first domain accessed works. The second domain consistently fails with `CERTIFICATE_VERIFY_FAILED`.

## Evidence

### Envoy Access Logs
```
# Both requests to same IP, sent 22ms apart:
[2025-10-28T13:16:50.176Z] "GET /api/hello HTTP/1.1" 200 - 0 20 686 683 "api.anthropic.com" "10.0.0.146:52462" "dynamic_forward_proxy_cluster_https" "160.79.104.10:443" ... "-"

[2025-10-28T13:16:50.198Z] "GET /v1/oauth/hello HTTP/1.1" 503 UF 0 216 385 - "console.anthropic.com" "10.0.0.146:52470" "dynamic_forward_proxy_cluster_https" "160.79.104.10:443" ... "TLS_error:|268435581:SSL_routines:OPENSSL_internal:CERTIFICATE_VERIFY_FAILED:TLS_error_end"
```

**Key observations**:
- Both requests go to the same IP: `160.79.104.10`
- `api.anthropic.com` returns 200 OK
- `console.anthropic.com` returns 503 UF with `CERTIFICATE_VERIFY_FAILED`
- Error code `268435581` = SSL certificate verification failed

### Certificate Differences

```bash
# api.anthropic.com certificate
$ openssl s_client -connect 160.79.104.10:443 -servername api.anthropic.com </dev/null 2>&1 | grep "subject=\|issuer="
subject=CN = api.anthropic.com
issuer=C = US, O = Google Trust Services, CN = WE1

# console.anthropic.com certificate
$ openssl s_client -connect 160.79.104.10:443 -servername console.anthropic.com </dev/null 2>&1 | grep "subject=\|issuer="
subject=CN = console.anthropic.com
issuer=C = US, O = Let's Encrypt, CN = E7
```

**Both certificates are valid and verify correctly** when tested manually with `openssl s_client`. The CA bundle `/etc/ssl/certs/ca-certificates.crt` contains both Google Trust Services and Let's Encrypt root certificates.

### DNS Resolution
```bash
$ dig +short api.anthropic.com
160.79.104.10

$ dig +short console.anthropic.com
160.79.104.10
```

Both domains resolve to the exact same IP address.

## Root Cause Analysis

### Envoy Behavior (Buggy)
1. **First connection** (e.g., to `api.anthropic.com`):
   - Envoy sends TLS ClientHello with SNI=`api.anthropic.com`
   - Server responds with certificate for `api.anthropic.com` (Google Trust Services CA)
   - Envoy validates certificate successfully
   - **Envoy caches validation context for IP `160.79.104.10`**

2. **Second connection** (e.g., to `console.anthropic.com`):
   - Envoy sends TLS ClientHello with SNI=`console.anthropic.com` ✅ (correct)
   - Server responds with certificate for `console.anthropic.com` (Let's Encrypt CA) ✅ (correct)
   - **BUG**: Envoy validates this certificate against the cached context from the first connection
   - Validation fails because:
     - Cached context expects CN=`api.anthropic.com`
     - Received certificate has CN=`console.anthropic.com`
     - Certificate CN mismatch → `CERTIFICATE_VERIFY_FAILED`

### Expected Behavior
Envoy should cache and validate TLS context per **(IP, hostname)** tuple, not just per IP. The SNI header is sent correctly, but the validation context is not hostname-aware.

## Configuration Details

### xDS Service Upstream TLS Configuration

File: `/path/to/xds-service/main.go` (lines 1217-1240)

```go
// dynamic_forward_proxy_cluster_https configuration
dynamicForwardProxyClusterHTTPS := &cluster.Cluster{
    Name:           "dynamic_forward_proxy_cluster_https",
    ConnectTimeout: durationpb.New(10 * time.Second),
    LbPolicy:       cluster.Cluster_CLUSTER_PROVIDED,
    ClusterDiscoveryType: &cluster.Cluster_ClusterType{
        ClusterType: &cluster.Cluster_CustomClusterType{
            Name: "envoy.clusters.dynamic_forward_proxy",
            TypedConfig: /* ... DnsCacheConfig ... */
        },
    },
    TransportSocket: &core.TransportSocket{
        Name: "envoy.transport_sockets.tls",
        ConfigType: &core.TransportSocket_TypedConfig{
            TypedConfig: func() *anypb.Any {
                upstreamTLS := &tlsv3.UpstreamTlsContext{
                    Sni: "{sni}",  // Dynamic SNI replacement
                    CommonTlsContext: &tlsv3.CommonTlsContext{
                        ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{
                            ValidationContext: &tlsv3.CertificateValidationContext{
                                TrustedCa: &core.DataSource{
                                    Specifier: &core.DataSource_Filename{
                                        Filename: "/etc/ssl/certs/ca-certificates.crt",
                                    },
                                },
                            },
                        },
                    },
                }
                any, _ := anypb.New(upstreamTLS)
                return any
            }(),
        },
    },
}
```

### OPA Policy Configuration

Both domains are correctly configured in OPA policy:

```yaml
unrestricted_domains:
  - api.anthropic.com
  - console.anthropic.com
```

### Cilium Network Policy

Both domains are correctly allowed:

```yaml
- toFQDNs:
  - matchName: "api.anthropic.com"
  - matchName: "console.anthropic.com"
  toPorts:
  - ports:
    - port: "443"
      protocol: TCP
```

## Related Issues

This appears to be the same underlying issue as:
- **https://github.com/envoyproxy/envoy/issues/18897** - "Dynamic forward proxy doesn't respect SNI for certificate validation"

The linked issue describes the exact same problem: dynamic forward proxy caches TLS validation context per IP without considering the hostname, causing failures when multiple hostnames share an IP with different certificates.

## Environment

- **Kubernetes Version**: K3s (Rancher Desktop)
- **Envoy Image**: `envoyproxy/envoy:v1.28-latest`
- **xDS Service**: Custom Go implementation (based on go-control-plane)
- **Kyverno Chart**: kyverno-intercept-chart (custom deployment)
- **Test Application**: Claude Code CLI connecting to Anthropic services

## Workarounds

### Workaround 1: Pre-warm Both Connections (Fragile)
Add a startup script that accesses both domains before the main application starts:

```bash
# In pod init container or startup script
curl -s https://api.anthropic.com/api/hello >/dev/null || true
curl -s https://console.anthropic.com/v1/oauth/hello >/dev/null || true
```

**Problem**: This is fragile and doesn't scale. Any new hostname added will break.

### Workaround 2: Create Separate Static Upstream Clusters (Recommended)
Instead of using a single dynamic forward proxy cluster, create dedicated clusters for each Anthropic domain:

```go
// api_anthropic_cluster - static cluster for api.anthropic.com
apiAnthropicCluster := &cluster.Cluster{
    Name:           "api_anthropic_cluster",
    ConnectTimeout: durationpb.New(10 * time.Second),
    ClusterDiscoveryType: &cluster.Cluster_Type{
        Type: cluster.Cluster_LOGICAL_DNS,
    },
    DnsLookupFamily: cluster.Cluster_V4_ONLY,
    LoadAssignment: &endpoint.ClusterLoadAssignment{
        ClusterName: "api_anthropic_cluster",
        Endpoints: []*endpoint.LocalityLbEndpoints{
            {
                LbEndpoints: []*endpoint.LbEndpoint{
                    {
                        HostIdentifier: &endpoint.LbEndpoint_Endpoint{
                            Endpoint: &endpoint.Endpoint{
                                Address: &core.Address{
                                    Address: &core.Address_SocketAddress{
                                        SocketAddress: &core.SocketAddress{
                                            Protocol: core.SocketAddress_TCP,
                                            Address:  "api.anthropic.com",
                                            PortSpecifier: &core.SocketAddress_PortValue{
                                                PortValue: 443,
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
    TransportSocket: &core.TransportSocket{
        Name: "envoy.transport_sockets.tls",
        ConfigType: &core.TransportSocket_TypedConfig{
            TypedConfig: func() *anypb.Any {
                upstreamTLS := &tlsv3.UpstreamTlsContext{
                    Sni: "api.anthropic.com",  // Static SNI
                    CommonTlsContext: &tlsv3.CommonTlsContext{
                        ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{
                            ValidationContext: &tlsv3.CertificateValidationContext{
                                TrustedCa: &core.DataSource{
                                    Specifier: &core.DataSource_Filename{
                                        Filename: "/etc/ssl/certs/ca-certificates.crt",
                                    },
                                },
                            },
                        },
                    },
                }
                any, _ := anypb.New(upstreamTLS)
                return any
            }(),
        },
    },
}

// Repeat for console_anthropic_cluster
```

Then route requests to the appropriate cluster based on SNI:

```go
// In LDS configuration, create separate filter chains
for _, domain := range []string{"api.anthropic.com", "console.anthropic.com"} {
    clusterName := strings.ReplaceAll(domain, ".", "_") + "_cluster"
    // Create filter chain with SNI matching and route to specific cluster
}
```

**Pros**:
- Reliable, works consistently
- Each domain gets its own TLS validation context

**Cons**:
- More configuration needed
- Loses dynamic nature of forward proxy
- Need to update xDS service for each new domain pair

## Recommended Actions

### For Kyverno Intercept Chart
1. **Document this limitation** in README.md under "Known Issues"
2. **Provide configuration examples** for creating separate upstream clusters
3. **Add detection/warning** in xDS service when multiple domains resolve to same IP
4. **Consider auto-generating separate clusters** for domains that fail with this pattern

### For Envoy Project
1. **Report bug** to Envoy project (reference https://github.com/envoyproxy/envoy/issues/18897)
2. **Propose fix**: Cache TLS validation context per (IP, SNI) tuple instead of just IP
3. **Test with Envoy newer versions** to see if already fixed in v1.29+

## Test Script

To reliably reproduce the issue:

```bash
#!/bin/bash
set -e

echo "=== Testing Envoy Dynamic Forward Proxy TLS Bug ==="
echo

NAMESPACE="graphiti-dev"
LABEL="app=dev-main"

test_sequence() {
    local first_domain=$1
    local second_domain=$2

    echo "Test: Access $first_domain first, then $second_domain"
    echo "---"

    # Restart pod
    kubectl delete pod -l $LABEL -n $NAMESPACE --wait=true
    kubectl wait --for=condition=ready pod -l $LABEL -n $NAMESPACE --timeout=120s

    POD=$(kubectl get pods -n $NAMESPACE -l $LABEL -o jsonpath='{.items[0].metadata.name}')
    echo "Pod: $POD"

    # Test first domain
    echo -n "Testing $first_domain: "
    RESULT1=$(kubectl exec $POD -n $NAMESPACE -c dev-main -- \
        curl -s -o /dev/null -w "%{http_code}" https://${first_domain}/api/hello 2>&1 || echo "FAILED")
    echo "$RESULT1"

    # Test second domain
    echo -n "Testing $second_domain: "
    RESULT2=$(kubectl exec $POD -n $NAMESPACE -c dev-main -- \
        curl -s -o /dev/null -w "%{http_code}" https://${second_domain}/v1/oauth/hello 2>&1 || echo "FAILED")
    echo "$RESULT2"

    echo
}

# Test Case 1: api.anthropic.com first
test_sequence "api.anthropic.com" "console.anthropic.com"

# Test Case 2: console.anthropic.com first
test_sequence "console.anthropic.com" "api.anthropic.com"

echo "=== Results ==="
echo "If bug exists:"
echo "  Test 1: api.anthropic.com should succeed (200), console.anthropic.com should fail (503)"
echo "  Test 2: console.anthropic.com should succeed (200), api.anthropic.com should fail (503)"
```

## Additional Resources

- Investigation document: `INVESTIGATION-upstream-tls-verification-failure.md`
- Troubleshooting guide: `/path/to/TROUBLESHOOTING-mcp-router-connectivity.md`
- xDS service source: `/path/to/xds-service/main.go`
- Kyverno chart: `/path/to/kyverno-intercept-chart/`

## Contacts

- Reporter: [Your Name/Team]
- Date: 2025-10-28
- Project: DevSpace GraphiTi PoC with Kyverno TLS Interceptor
