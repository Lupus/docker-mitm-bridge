# Security Vulnerability: Host Header Bypass in OPA Policy

## Status
🔴 **CRITICAL** - Unresolved Security Vulnerability

## Discovery Date
2025-10-10

## Summary
The OPA (Open Policy Agent) authorization policy checks the HTTP `Host` header (`:authority`) instead of the TLS certificate Common Name (SNI). This allows attackers to bypass domain whitelist policies by manipulating the Host header.

## Vulnerability Details

### Root Cause
The OPA policy in `templates/configmap-opa-policy.yaml` uses:
```rego
# Extract request details
method := http_request.method
host := http_request.host  # ← VULNERABLE: Uses HTTP Host header
path := http_request.path
```

The `http_request.host` field comes from the `:authority` HTTP header, which is **user-controllable** and can be easily spoofed.

### Attack Vector
An attacker can access any blocked domain by setting the Host header to a whitelisted domain:

```bash
# Normal request to blocked domain - correctly returns 403
curl -k https://blocked-site.com
# HTTP 403 Forbidden

# Attack: Same request with spoofed Host header - bypasses policy!
curl -k -H 'Host: github.com' https://blocked-site.com
# HTTP 200 OK - Policy bypassed!
```

### Evidence from Testing

#### Test Case (test-xds-security.bats:153-165)
```bash
@test "Security: No bypass via Host header manipulation" {
    POD_NAME=$(get_pod_name "test-app")

    log_info "Testing if Host header manipulation can bypass OPA..."
    run exec_in_pod "$POD_NAME" "test-container" \
        "curl -k -s -o /dev/null -w '%{http_code}' --max-time 15 -H 'Host: github.com' https://google.com"

    # Should still be blocked (SNI and Host should both be checked)
    [ "$status" -eq 0 ]
    [ "$output" = "403" ]  # Expected: 403
}
```

**Current Result**: Test fails - returns `200` instead of `403`

#### OPA Decision Logs
From actual test run showing the vulnerability:

1. **Normal request to google.com** (blocked correctly):
```json
{
  "input": {
    "attributes": {
      "destination": {"principal": "blocked.local"},
      "request": {
        "http": {
          "headers": {":authority": "google.com"},
          "host": "google.com"
        }
      }
    }
  },
  "result": false  // ✅ Correctly blocked
}
```

2. **Request with spoofed Host header** (bypass!):
```json
{
  "input": {
    "attributes": {
      "destination": {"principal": "blocked.local"},  // ← Still blocked.local!
      "request": {
        "http": {
          "headers": {":authority": "github.com"},  // ← Spoofed!
          "host": "github.com"                      // ← Spoofed!
        }
      }
    }
  },
  "result": true  // ❌ BYPASS! Policy allows it
}
```

**Key Observation**: Even though `destination.principal` is correctly "blocked.local" (from the TLS certificate), OPA only checks the user-controlled `host` field.

## Impact Assessment

### Severity: CRITICAL
- **Confidentiality**: HIGH - Attacker can access any external resource
- **Integrity**: HIGH - Attacker can send requests to blocked domains
- **Availability**: LOW - No DoS impact
- **CVSS Estimate**: 8.1 (High)

### Affected Components
- All deployments using the kyverno-intercept-chart
- Any pod with `intercept-proxy/enabled: true` label
- Both HTTP and HTTPS traffic on the HTTPS listener (port 15002)

### Attack Scenarios
1. **Data Exfiltration**: Access blocked cloud storage or APIs
2. **C2 Communication**: Connect to blocked command-and-control servers
3. **Policy Evasion**: Bypass security monitoring and logging
4. **Supply Chain Attacks**: Access blocked package repositories

## Fix Required

### Correct Implementation
The OPA policy MUST check the TLS certificate CN (SNI) instead of the HTTP Host header:

```rego
# BEFORE (vulnerable):
host := http_request.host

# AFTER (secure):
# Use the destination.principal which contains the TLS cert CN
host := input.attributes.destination.principal
```

The `destination.principal` field contains the actual TLS certificate Common Name:
- For whitelisted domains: `"github.com"`, `"api.anthropic.com"`, etc.
- For non-whitelisted domains: `"blocked.local"` (from the fallback TLS chain)

### File to Modify
`cilium-tls-poc/kyverno-intercept-chart/templates/configmap-opa-policy.yaml`

Located at approximately line 40-50 in the policy.rego section.

### Validation
After fix, the test should pass:
```bash
# This should return 403 after the fix
curl -k -H 'Host: github.com' https://google.com
# Expected: HTTP 403 Forbidden
```

## Workarounds
None. The vulnerability cannot be mitigated without fixing the OPA policy.

## References
- Test file: `test/e2e/test-xds-security.bats:153-165`
- OPA policy: `templates/configmap-opa-policy.yaml`
- Related: [RFC 7540 Section 8.1.2.3](https://tools.ietf.org/html/rfc7540#section-8.1.2.3) - HTTP/2 :authority header

## Timeline
- **2025-10-10**: Vulnerability discovered during E2E testing
- **2025-10-10**: Security issue documented
- **Pending**: Fix implementation
- **Pending**: Validation and re-testing

## Notes
- This vulnerability was caught by automated testing (test-xds-security.bats)
- The test infrastructure correctly validates security controls
- Test #7 (Envoy logs) is a separate, pre-existing logging issue - not security-related
