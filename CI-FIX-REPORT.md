# CI Test Failure: Root Cause Analysis and Fix

## Problem Summary
The per-pod OPA policy feature was failing in CI. Pods with custom `intercept-proxy/opa-data` annotations were stuck at 1/4 Ready state. The root cause was that Kyverno generate rules were NOT creating the expected per-pod ConfigMaps.

## Root Cause
The bug was in `/cilium-tls-poc/kyverno-intercept-chart/templates/kyverno-policy.yaml` line 6:
```yaml
spec:
  background: false  # THIS WAS THE BUG!
```

With `background: false`, Kyverno's behavior is:
- **Mutation rules**: Applied during admission (when pod is created) ✅ WORKS
- **Generate rules**: Only applied to resources that existed BEFORE the policy was installed ❌ BROKEN

This explains why:
- Mutation rules successfully injected volumes referencing ConfigMaps
- Generate rules never created those ConfigMaps for new pods
- Pods failed to start because they couldn't mount non-existent ConfigMaps

## The Fix
Changed line 6 to enable background processing:
```yaml
spec:
  # IMPORTANT: background MUST be true for generate rules to work with new pods
  # With background: false, generate rules only apply to resources that existed before the policy
  background: true
  validationFailureAction: Audit
```

## Why This Fixes It
With `background: true`:
1. Kyverno's background controller monitors all resource events
2. When a new pod is created with the `intercept-proxy/opa-data` annotation
3. The generate rule triggers and creates the ConfigMap
4. The mutation rule injects the volume mount
5. Pod successfully starts with all containers ready

## Test Results After Fix
- Local test passes: `Kyverno generates ConfigMap for pod with custom opa-data annotation` ✅
- ConfigMaps are now created as expected
- Pods reach Ready state (4/4 containers)

## Key Learnings
1. **Kyverno generate rules require background processing** - This is a fundamental requirement that's easy to overlook
2. **Mutation and generate rules have different execution models**:
   - Mutation: Synchronous during admission
   - Generate: Asynchronous via background controller
3. **Testing should verify both rule types separately** to catch such issues early

## Files Changed
- `/cilium-tls-poc/kyverno-intercept-chart/templates/kyverno-policy.yaml` - Changed `background: false` to `background: true` with explanatory comment