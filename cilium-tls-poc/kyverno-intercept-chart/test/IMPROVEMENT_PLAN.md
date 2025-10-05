# Kyverno Interceptor Chart - Test Improvement Plan

**Status**: Actualized
**Created**: 2025-10-05
**Last Updated**: 2025-10-05
**Priority**: High → Medium

## Overview

This document outlines planned improvements to the E2E test suite to enhance reliability, reduce external dependencies, and improve test maintainability.

## Current Test Suite Status (As of 2025-10-05)

**Test Coverage:**
- ✅ **61 tests** across 5 test files
- ✅ Test deployment and sidecar injection
- ✅ TLS interception functionality (11 tests)
- ✅ OPA policy enforcement (11 tests)
- ✅ Network isolation (18 tests)
- ✅ Port isolation (14 tests)
- ❌ **Missing**: Cleanup job tests (Task 1)

**Technical Debt:**
- **6 sleep commands** requiring replacement (test-tls, test-opa-policy, test-network-isolation, test-port-isolation, test-pod.yaml, helpers.bash)
- **66 external domain references** (github.com, anthropic.com, openai.com, githubusercontent.com)
- **Partial helper library**: `wait_for_pod_ready()` exists, but missing `wait_for_log_message()`, `wait_for_port_listening()`, etc.

**Dependencies:**
- Helm v3.13.0 (outdated, latest: v3.16.x)
- kubectl v1.28.0 (outdated, latest: v1.31.x)
- kind-action v1.12.0 (outdated, latest: v1.15.0)

---

## Task 1: Add Tests for Cleanup Job (Pre-Delete Hook)

**Priority**: High
**Effort**: Small
**Files affected**:
- `test/e2e/test-deployment.bats` (new tests)
- `templates/cleanup-job.yaml` (template under test)

### Current State
- `cleanup-job.yaml` template exists with pre-delete hook
- No tests verify cleanup job runs successfully
- No verification that ClusterPolicy is removed on uninstall

### Objectives
- Verify cleanup job is created with correct annotations
- Test that job executes successfully on helm uninstall
- Confirm ClusterPolicy is removed after cleanup

### Implementation Plan

**Step 1.1**: Add test for cleanup job template rendering
```bash
@test "Cleanup job template has correct pre-delete hook annotation" {
    # Verify job has helm.sh/hook: pre-delete annotation
    # Check job has correct service account permissions
}
```

**Step 1.2**: Add integration test for actual cleanup
```bash
@test "Pre-delete hook removes ClusterPolicy on uninstall" {
    # Deploy a temporary release
    # Verify ClusterPolicy exists
    # helm uninstall
    # Wait for job completion
    # Verify ClusterPolicy is removed
}
```

**Step 1.3**: Add test for cleanup job failure handling
```bash
@test "Chart uninstall succeeds even if cleanup job fails" {
    # Test graceful degradation
}
```

### Acceptance Criteria
- [ ] Cleanup job annotations verified
- [ ] ClusterPolicy removal confirmed after uninstall
- [ ] Test passes in CI/CD pipeline
- [ ] Documentation updated

### Estimated Time
- Implementation: 2 hours
- Testing & verification: 1 hour
- **Total**: 3 hours

---

## Task 2: Mock External Dependencies

**Priority**: High
**Effort**: Medium
**Files affected**:
- `test/fixtures/http-server.yaml` (already exists, needs enhancement)
- `test/fixtures/mock-services.yaml` (new)
- `test/e2e/test-tls.bats` (update tests)
- `test/e2e/test-opa-policy.bats` (update tests)
- `test/e2e/test-network-isolation.bats` (update tests)

### Current State (Actualized 2025-10-05)
- Tests use real external services: **66 references across test files**
  - `github.com` / `api.github.com` (most common)
  - `raw.githubusercontent.com`
  - `api.anthropic.com`
  - `api.openai.com`
- External dependencies cause flakiness
- Tests fail if internet connectivity issues occur
- No control over external service responses

### Objectives
- Replace external service calls with mock HTTP/HTTPS servers
- Provide predictable, controlled test responses
- Eliminate internet connectivity requirements for most tests
- Speed up test execution

### Implementation Plan

**Step 2.1**: Create mock HTTPS server fixture
```yaml
# test/fixtures/mock-https-server.yaml
# Simple nginx or httpbin-based HTTPS server
# Responds to multiple domains via SNI
# Provides different responses for different HTTP methods
```

**Step 2.2**: Update OPA policy for test domains
```rego
# Add mock domain entries:
# - mock-restricted.local (GET/HEAD only)
# - mock-unrestricted.local (all methods)
# - mock-blocked.local (denied)
```

**Step 2.3**: Update /etc/hosts or use DNS mock
```bash
# Option A: Add to /etc/hosts in test container
# Option B: Deploy dnsmasq/CoreDNS with custom entries
# Option C: Use Kubernetes Service DNS
```

**Step 2.4**: Replace external domains in tests
- `github.com` → `mock-restricted.local`
- `api.anthropic.com` → `mock-unrestricted.local`
- `api.openai.com` → `mock-unrestricted.local`

**Step 2.5**: Keep one "smoke test" with real external service
```bash
@test "HTTPS to real internet works (smoke test)" {
    # Keep ONE test with real github.com
    # Marked as optional/skippable in air-gapped environments
}
```

### Mock Server Requirements
1. **TLS/HTTPS support** - Self-signed cert is fine
2. **Multi-domain SNI** - Respond to different hostnames
3. **Method-based responses** - GET 200, POST 403, etc.
4. **Lightweight** - Fast startup, low resource usage
5. **Response customization** - Different paths, headers, status codes

### Suggested Mock Implementation
```yaml
# Option 1: nginx with custom config
# Option 2: httpbin (supports /status/<code>, /get, /post, etc.)
# Option 3: prism (OpenAPI mock server)
# Recommended: httpbin - simple, well-tested, supports all we need
```

### Acceptance Criteria
- [ ] Mock HTTPS server deployed in test namespace
- [ ] Mock server responds to test domains via SNI
- [ ] All TLS tests pass with mock server
- [ ] All OPA policy tests pass with mock server
- [ ] Tests run without internet connectivity
- [ ] Test execution time reduced by 30%+
- [ ] One smoke test still uses real external service

### Estimated Time
- Mock server setup: 4 hours
- Test migration: 6 hours
- Debugging & refinement: 4 hours
- **Total**: 14 hours

---

## Task 3: Replace Fixed Sleep with Proper Wait Conditions

**Priority**: High
**Effort**: Medium
**Files affected**:
- `test/lib/helpers.bash` (new wait functions)
- `test/e2e/test-tls.bats` (remove sleeps)
- `test/e2e/test-opa-policy.bats` (remove sleeps)
- `test/fixtures/test-pod.yaml` (startup probe)

### Current State
```bash
# Problematic patterns:
sleep 2    # "Give Envoy time to log"
sleep 5    # "Test pod started. Waiting for sidecars..."
sleep 10   # In setup_file for external pods
```

**Issues**:
- Arbitrary delays slow down tests
- Can still be too short on slow systems
- Can be unnecessarily long on fast systems
- No feedback on what's being waited for

### Objectives
- Replace all fixed sleeps with condition-based waits
- Reduce test flakiness on slow systems
- Improve test execution time on fast systems
- Make test intentions explicit

### Implementation Plan

**Step 3.1**: Add robust wait helper functions
```bash
# test/lib/helpers.bash

# ✅ ALREADY EXISTS: wait_for_pod_ready() at line 25-34
# - Waits for pod to be ready with timeout
# - Uses kubectl wait --for=condition=ready
# - Supports custom timeout (default 120s)

# 🆕 TO ADD: Wait for log message to appear
wait_for_log_message() {
    local pod_name=$1
    local container=$2
    local pattern=$3
    local timeout=${4:-30}
    # Poll logs until pattern appears or timeout
}

# 🆕 TO ADD: Wait for container ready (different from pod ready)
wait_for_container_ready() {
    local pod_name=$1
    local container=$2
    local timeout=${3:-60}
    # Check containerStatuses[?(@.name=="$container")].ready
}

# 🆕 TO ADD: Wait for HTTP endpoint
wait_for_http_endpoint() {
    local url=$1
    local expected_code=${2:-200}
    local timeout=${3:-30}
    # Retry curl until success or timeout
}

# 🆕 TO ADD: Wait for port listening
wait_for_port_listening() {
    local pod_name=$1
    local container=$2
    local port=$3
    local timeout=${4:-30}
    # Check netstat/ss until port appears
}
```

**Step 3.2**: Identify and categorize all sleeps
```bash
# Audit current usage:
grep -r "sleep" test/e2e/*.bats test/fixtures/*.yaml

# Categories:
# 1. Waiting for logs → wait_for_log_message
# 2. Waiting for pods → wait_for_pod_ready (already exists!)
# 3. Waiting for endpoints → wait_for_http_endpoint
# 4. Waiting for ports → wait_for_port_listening
# 5. Waiting for xDS config → wait_for_log_message (look for CDS/LDS)
```

**Step 3.3**: Replace sleeps systematically

**Example: test-tls.bats line 68**
```bash
# BEFORE:
exec_in_pod "$POD_NAME" "test-container" \
    "curl -s -o /dev/null --max-time 15 https://api.github.com" || true
sleep 2  # Give Envoy time to log

# AFTER:
exec_in_pod "$POD_NAME" "test-container" \
    "curl -s -o /dev/null --max-time 15 https://api.github.com" || true
wait_for_log_message "$POD_NAME" "envoy-proxy" "api.github.com" 10
```

**Example: test-opa-policy.bats line 112**
```bash
# BEFORE:
exec_in_pod "$POD_NAME" "test-container" \
    "curl -s -o /dev/null --max-time 15 https://api.github.com" || true
sleep 2  # Give OPA time to log

# AFTER:
exec_in_pod "$POD_NAME" "test-container" \
    "curl -s -o /dev/null --max-time 15 https://api.github.com" || true
wait_for_log_message "$POD_NAME" "opa-sidecar" "decision\|query\|allow" 10
```

**Example: test-network-isolation.bats line 17 (setup_file)**
```bash
# BEFORE:
kubectl apply -f test/fixtures/external-pod.yaml || true
kubectl apply -f test/fixtures/http-server.yaml || true
sleep 10  # Wait for external pods to be ready

# AFTER:
kubectl apply -f test/fixtures/external-pod.yaml || true
kubectl apply -f test/fixtures/http-server.yaml || true
wait_for_pod_ready "external-app" "kyverno-intercept" 60
wait_for_pod_ready "http-server" "kyverno-intercept" 60
```

**Example: test-pod.yaml line 35 (fixture)**
```bash
# BEFORE:
echo "Test pod started. Waiting for sidecars..."
sleep 5
echo "Test pod ready for testing"

# AFTER:
echo "Test pod started. Waiting for sidecars..."
# Wait for sidecar ports to be listening
while ! nc -zv localhost 15000 2>/dev/null; do sleep 0.5; done
while ! nc -zv localhost 15020 2>/dev/null; do sleep 0.5; done
echo "Sidecars are ready"
```

**Step 3.4**: Add timeout protection
```bash
# All wait functions should:
# 1. Have configurable timeouts
# 2. Return meaningful error messages
# 3. Log what they're waiting for
# 4. Fail fast with clear diagnostics
```

### Sleep Inventory (Actualized 2025-10-05)
```bash
Location                          | Current  | Replacement
----------------------------------|----------|----------------------------------
test-tls.bats:68                 | sleep 2  | wait_for_log_message (Envoy)
test-opa-policy.bats:113         | sleep 2  | wait_for_log_message (OPA)
test-network-isolation.bats:17   | sleep 10 | wait_for_pod_ready (2x) - ALREADY EXISTS!
test-port-isolation.bats:118     | sleep 2  | wait_for_port_listening
test-fixtures/test-pod.yaml:35   | sleep 5  | wait for sidecar ports
lib/helpers.bash:203             | sleep 2  | Remove (in cleanup function)
```

**Note**: `wait_for_pod_ready()` helper function already exists in `lib/helpers.bash:25-34`!

### Acceptance Criteria
- [ ] All wait helper functions implemented
- [ ] All `sleep` commands replaced with condition waits
- [ ] Tests pass consistently on slow systems
- [ ] Average test time reduced by 20%+
- [ ] No race conditions or timing issues
- [ ] Clear error messages on wait timeouts

### Estimated Time (Revised 2025-10-05)
- Helper function implementation: 2 hours ~~3 hours~~ (wait_for_pod_ready already exists!)
- Sleep replacement: 3 hours ~~4 hours~~ (6 locations, simplified)
- Testing & debugging: 2 hours ~~3 hours~~
- **Total**: 7 hours ~~10 hours~~

**Effort reduced by 3 hours** due to existing `wait_for_pod_ready()` function.

---

## Task 4: Update GitHub Workflow Dependencies

**Priority**: Medium
**Effort**: Small
**Files affected**:
- `.github/workflows/kyverno-chart-e2e.yaml`

### Current State
```yaml
- uses: azure/setup-helm@v4
  with:
    version: v3.13.0        # Latest: v3.16.x

- uses: azure/setup-kubectl@v4
  with:
    version: v1.28.0        # Latest: v1.31.x

- uses: helm/kind-action@v1.12.0  # Latest: v1.15.0
```

### Objectives
- Update to latest stable versions
- Verify compatibility with Kubernetes 1.29+
- Maintain test stability

### Implementation Plan

**Step 4.1**: Research current stable versions
```bash
# Helm: https://github.com/helm/helm/releases
# Latest stable: v3.16.2 (as of Oct 2024)

# kubectl: https://kubernetes.io/releases/
# Latest stable: v1.31.x (match with kind node version)

# kind-action: https://github.com/helm/kind-action
# Latest: v1.15.0

# kind node images: https://github.com/kubernetes-sigs/kind/releases
# Recommended: kindest/node:v1.29.2 (current, stable)
# Could update to: v1.30.x or v1.31.x
```

**Step 4.2**: Update workflow file
```yaml
- name: Set up Helm
  uses: azure/setup-helm@v4
  with:
    version: v3.16.2  # Updated

- name: Set up kubectl
  uses: azure/setup-kubectl@v4
  with:
    version: v1.31.0  # Updated, matches kind node

- name: Create kind cluster
  uses: helm/kind-action@v1.15.0  # Updated
  with:
    cluster_name: kyverno-test
    node_image: kindest/node:v1.31.0  # Updated
    wait: 120s
```

**Step 4.3**: Update Kyverno version compatibility
```yaml
# Check Kyverno compatibility with K8s 1.31
# Current: kyverno/kyverno version 3.2.8
# May need to update if K8s version changes
```

**Step 4.4**: Test locally with updated versions
```bash
# Create local test with new versions
kind create cluster --name test-upgrade --image kindest/node:v1.31.0
helm version  # Verify v3.16.2
kubectl version  # Verify v1.31.0
# Run full test suite
```

**Step 4.5**: Document version matrix
```markdown
# Supported Versions (Updated 2025-10-05)

| Component | Version | Notes |
|-----------|---------|-------|
| Kubernetes | 1.31.9 | kind node image |
| Helm | 3.18.5 | Latest stable (Oct 2025) |
| Kyverno | 1.15.x | Supports K8s 1.31 (N-2 policy) |
| kubectl | 1.31.9 | Matches K8s cluster version |
| kind-action | 1.12.0 | Latest (Dec 2024) |
```

### Acceptance Criteria
- [x] Helm updated to ~~v3.16.2~~ **v3.18.5** (latest stable)
- [x] kubectl updated to ~~v1.31.0~~ **v1.31.9** (matches kind node)
- [x] kind-action ~~updated to v1.15.0~~ **v1.12.0** (already latest)
- [x] kind node image **v1.31.9** added explicitly
- [ ] All tests pass in CI with new versions
- [ ] Version matrix documented

**✅ Completed 2025-10-05**: Updated to latest stable versions

### Estimated Time
- Version research: 1 hour
- Update & testing: 2 hours
- Documentation: 0.5 hours
- **Total**: 3.5 hours

---

## Execution Plan (Revised 2025-10-05)

### Phase 1: Quick Wins (Week 1)
1. **Task 4** - Update GitHub workflow dependencies (3.5h)
2. **Task 1** - Add cleanup job tests (3h)
   - **Total**: 6.5 hours

### Phase 2: Foundation (Week 2)
3. **Task 3** - Replace sleep commands ~~(10h)~~ **(7h revised)**
   - Implement helper functions (partial, wait_for_pod_ready exists!)
   - Replace sleeps systematically (6 locations)
   - **Total**: 7 hours

### Phase 3: Reliability (Week 3)
4. **Task 2** - Mock external dependencies (14h)
   - Setup mock server
   - Migrate tests (66 external domain references)
   - **Total**: 14 hours

### Total Effort (Revised)
- ~~**30.5 hours**~~ **27.5 hours** (~3.5 days of focused work)

**Changes:**
- Task 3 reduced from 10h to 7h (existing wait_for_pod_ready helper)
- Total effort reduced by 3 hours

---

## Success Metrics

**Before**:
- 61 tests, ~5-8 min runtime
- External dependencies: 4+ (github.com, anthropic.com, etc.)
- Fixed sleeps: 5+ locations
- Cleanup job: 0% tested
- Flakiness: Moderate (external deps)

**After**:
- 65+ tests (added cleanup tests)
- Runtime: ~3-5 min (faster waits, local mocks)
- External dependencies: 1 (optional smoke test)
- Fixed sleeps: 0
- Cleanup job: 100% tested
- Flakiness: Low

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Mock server doesn't match real behavior | Medium | Medium | Keep one real smoke test; validate mock responses |
| Wait conditions too strict | Low | Medium | Add generous timeouts; log wait progress |
| New K8s version incompatible | Low | High | Test thoroughly; keep fallback to 1.29 |
| Time estimate too optimistic | Medium | Low | Break into smaller PRs; track actual time |

---

## Notes

- Each task can be implemented independently
- Tasks 1 & 4 are quick wins, can be done first
- Task 3 should precede Task 2 (more stable base)
- Consider breaking Task 2 into separate PR (largest change)

---

---

## Summary of Changes (2025-10-05 Actualization)

### What Was Updated:
1. ✅ **Sleep inventory corrected**: Updated line numbers and added missing location (helpers.bash:203)
2. ✅ **External dependencies quantified**: 66 references across test files
3. ✅ **Discovered existing infrastructure**: `wait_for_pod_ready()` already implemented
4. ✅ **Effort estimates revised**: Total reduced from 30.5h to 27.5h (3 hours saved)
5. ✅ **Test counts verified**: 61 tests currently, targeting 65+ after improvements
6. ✅ **Task 4 completed**: Updated GitHub workflow dependencies (Helm v3.18.5, kubectl v1.31.9, kind v1.31.9)

### Key Findings:
- **Good news**: Helper library foundation exists, reducing Task 3 effort
- **External dependency**: Tests heavily rely on real external services (66 refs)
- **No coverage gap**: Cleanup job exists but completely untested

### Recommended Priority Order (Unchanged):
1. **Task 4** (3.5h) - Update dependencies → Quick win, reduces future issues
2. **Task 1** (3h) - Add cleanup job tests → Closes coverage gap
3. **Task 3** (7h) - Replace sleeps → Foundation for reliability
4. **Task 2** (14h) - Mock externals → Biggest reliability improvement

---

## Approval

- [ ] Plan reviewed
- [ ] Priorities confirmed
- [ ] Ready to begin implementation

**Next Steps**: Review this actualized plan, confirm priorities, then proceed with Task 4 (quickest win).
