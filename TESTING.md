# Docker MITM Bridge - Testing Documentation

## Overview
This document describes the comprehensive testing approach for Docker MITM Bridge, including automated test suites that ensure the tool works correctly and handles edge cases gracefully.

## Test Suites

### 1. Main Test Suite (`test_suite.py`)
Tests core functionality of the tool:

- **Network Creation**: Verifies that the isolated Docker network is created correctly with proper configuration
- **Proxy Deployment**: Ensures the mitmproxy boundary container starts and is accessible
- **Connectivity Filtering**: Tests that OPA policies correctly filter traffic:
  - Allowed domains with GET/HEAD methods work
  - Blocked domains return 403 Forbidden
  - Unrestricted domains allow all HTTP methods
  - CA certificate installation works correctly
- **Container Listing**: Verifies that containers connected to the network are properly tracked
- **Policy Updates**: Tests that OPA policies can be updated and proxy restarted
- **Resource Cleanup**: Ensures complete cleanup of network and containers

### 2. Idempotency Test Suite (`test_idempotency.py`)
Tests resilience and idempotent operations:

- **Repeated Initialization**: Verifies that `init` can be run multiple times safely
- **Start/Stop Cycles**: Tests multiple start/stop operations without issues
- **Partial Cleanup Recovery**: Ensures the tool recovers from partial/failed cleanups
- **Concurrent Containers**: Tests multiple containers using the proxy simultaneously
- **Destroy and Reinit**: Verifies complete teardown and rebuild works correctly

## Running Tests

### Quick Test Commands
```bash
# Run main test suite
make test

# Run idempotency tests
make test-idempotency

# Run all tests
make test-all

# Clean up after tests
make clean
```

### Manual Test Execution
```bash
# Activate virtual environment
source .venv/bin/activate

# Run specific test suite
python test_suite.py
python test_idempotency.py
```

## Test Results

### Successful Test Output
All tests have been verified to pass successfully:

```
============================================================
📊 Test Summary
============================================================
  Network Creation........................ ✅ PASSED
  Proxy Deployment........................ ✅ PASSED
  Connectivity Filtering.................. ✅ PASSED
  Container Listing....................... ✅ PASSED
  Policy Update........................... ✅ PASSED
  Resource Cleanup........................ ✅ PASSED
============================================================
Total: 6 passed, 0 failed
🎉 All tests passed!
```

### Test Coverage

1. **Network Management**
   - Creation of isolated network
   - Network persistence across restarts
   - Proper subnet configuration
   - Internal network flag enforcement

2. **Proxy Container**
   - Container deployment
   - Port exposure (8080 for proxy, 8081 for web UI)
   - Certificate generation and serving
   - Addon loading (OPA filter, cert server)

3. **Traffic Filtering**
   - Domain allowlisting (GET/HEAD only)
   - Domain blocking (403 responses)
   - Unrestricted domains (all methods)
   - CA certificate distribution
   - HTTPS interception

4. **Tool Operations**
   - CLI command functionality
   - Status reporting
   - Container listing
   - Policy updates
   - Clean shutdown and cleanup

5. **Error Handling**
   - Recovery from partial failures
   - Handling of existing resources
   - Graceful degradation
   - Clear error messages

## Key Test Scenarios

### Scenario 1: Fresh Installation
```bash
make clean
make init
# Verify network created and proxy running
make status
```

### Scenario 2: Policy Update
```bash
# Modify opa-policies/data.yaml
vim opa-policies/data.yaml
# Apply changes
make update-policy
# Test new policy rules
```

### Scenario 3: External Container Integration
```bash
# Create external container joining the network
docker run -it \
  --network mitm-filtered \
  -e HTTP_PROXY=http://mitm-boundary-proxy:8080 \
  -e HTTPS_PROXY=http://mitm-boundary-proxy:8080 \
  ubuntu:latest bash

# Inside container, install CA cert
curl -sSL http://mitm-boundary-proxy:8080/install-ca.sh | bash

# Test connectivity
curl https://github.com  # Should work (allowed)
curl https://example.com # Should be blocked (403)
```

## Continuous Testing

### Pre-commit Checks
Before committing changes:
1. Run `make test-all` to ensure all tests pass
2. Run `make clean` to verify cleanup works
3. Run `make init` to verify fresh installation works

### Integration Testing
The tool has been tested with:
- Ubuntu 22.04 containers
- Alpine Linux containers
- Multiple simultaneous containers
- Various HTTP clients (curl, wget)
- Different proxy configurations

## Known Test Limitations

1. **Certificate Testing**: Tests use HTTP endpoints or accept certificate warnings to avoid complex CA trust setup in test containers
2. **Timing**: Some tests include sleep delays to ensure services are fully started
3. **Docker API**: Tests require Docker daemon access and may fail in restricted environments

## Troubleshooting Tests

### Test Failures
If tests fail:
1. Run `make clean` to ensure clean state
2. Check Docker daemon is running: `docker ps`
3. Verify no conflicting networks: `docker network ls | grep mitm`
4. Check for port conflicts: `netstat -tlnp | grep -E '8080|8081'`

### Manual Verification
To manually verify functionality:
```bash
# Check network
docker network inspect mitm-filtered

# Check proxy logs
docker logs mitm-boundary-proxy

# Test proxy directly
curl -x http://localhost:8080 http://github.com

# Access web UI
open http://localhost:8081
```

## Test Maintenance

### Adding New Tests
1. Add test function to appropriate test file
2. Include in test suite's test list
3. Ensure proper cleanup in test function
4. Document expected behavior

### Updating Tests
When changing tool functionality:
1. Update relevant test cases
2. Run full test suite
3. Update this documentation
4. Verify idempotency still holds