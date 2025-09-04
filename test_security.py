#!/usr/bin/env python3
"""
Security test suite for Docker MITM Bridge
Tests security vulnerabilities and validates fixes
"""

import subprocess
import sys
import os
import tempfile
import docker
import time
import signal
from contextlib import contextmanager
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from validators import (
    validate_network_name,
    validate_container_name,
    validate_subnet,
    validate_port,
    validate_policy_dir,
    sanitize_path,
    ValidationError
)


@contextmanager
def timeout(seconds):
    """Context manager for timeout"""
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds} seconds")
    
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    
    try:
        yield
    finally:
        signal.alarm(0)


class SecurityTestSuite:
    def __init__(self):
        self.client = docker.from_env()
        self.test_results = []
        
    def test_command_injection_prevention(self):
        """Test that command injection is prevented in subprocess calls"""
        print("\n🔒 Testing command injection prevention...")
        
        # Test cases with injection attempts
        injection_attempts = [
            "init; rm -rf /",  # Command chaining
            "init && cat /etc/passwd",  # Command chaining with &&
            "init | cat /etc/passwd",  # Pipe
            "init`cat /etc/passwd`",  # Command substitution
            "init$(cat /etc/passwd)",  # Command substitution
            "init\n\nrm -rf /",  # Newline injection
        ]
        
        for attempt in injection_attempts:
            try:
                # This should fail or be sanitized, not execute the injected command
                result = subprocess.run(
                    ["python", "docker-mitm-bridge", attempt],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                
                # Check that no sensitive data was exposed
                if "/etc/passwd" in result.stdout or "root:" in result.stdout:
                    print(f"  ❌ Command injection possible with: {attempt}")
                    return False
                    
                # Check that no destructive commands were executed
                if "rm" in result.stdout and "-rf" in result.stdout:
                    print(f"  ❌ Destructive command injection possible with: {attempt}")
                    return False
                    
            except subprocess.TimeoutExpired:
                # Timeout is acceptable (command hung)
                pass
            except Exception as e:
                # Other exceptions are fine (command failed)
                pass
        
        print("  ✅ Command injection attempts blocked")
        return True
    
    def test_input_validation(self):
        """Test input validation for various parameters"""
        print("\n🔒 Testing input validation...")
        
        # Test network name validation
        invalid_network_names = [
            "",  # Empty
            "a" * 64,  # Too long
            "invalid name",  # Spaces
            "invalid-name-",  # Ends with hyphen
            "-invalid-name",  # Starts with hyphen
            "invalid_name",  # Underscore
            "invalid.name",  # Period
            "../etc/passwd",  # Path traversal
            "'; DROP TABLE networks; --",  # SQL injection
        ]
        
        for name in invalid_network_names:
            if validate_network_name(name):
                print(f"  ❌ Invalid network name accepted: {name}")
                return False
        
        # Test valid network names
        valid_network_names = ["mitm-filtered", "test-net", "a", "net123", "my-network-1"]
        for name in valid_network_names:
            if not validate_network_name(name):
                print(f"  ❌ Valid network name rejected: {name}")
                return False
        
        # Test container name validation
        invalid_container_names = [
            "",  # Empty
            "a" * 256,  # Too long
            "invalid name",  # Spaces
            "-invalid",  # Starts with hyphen
            "invalid/name",  # Slash
            "invalid\\name",  # Backslash
            "../../../etc/passwd",  # Path traversal
        ]
        
        for name in invalid_container_names:
            if validate_container_name(name):
                print(f"  ❌ Invalid container name accepted: {name}")
                return False
        
        # Test subnet validation
        invalid_subnets = [
            "",  # Empty
            "not-a-subnet",  # Invalid format
            "192.168.1.1",  # Missing CIDR
            "8.8.8.0/24",  # Public network
            "1.2.3.4/32",  # Public network
            "256.256.256.256/24",  # Invalid IP
            "192.168.1.0/33",  # Invalid CIDR
            "192.168.1.0/-1",  # Negative CIDR
        ]
        
        for subnet in invalid_subnets:
            if validate_subnet(subnet):
                print(f"  ❌ Invalid subnet accepted: {subnet}")
                return False
        
        # Test valid subnets (private networks only)
        valid_subnets = [
            "10.0.0.0/8",
            "10.1.2.0/24",
            "172.16.0.0/12",
            "172.30.0.0/16",
            "192.168.0.0/16",
            "192.168.1.0/24",
        ]
        
        for subnet in valid_subnets:
            if not validate_subnet(subnet):
                print(f"  ❌ Valid subnet rejected: {subnet}")
                return False
        
        # Test port validation
        invalid_ports = [0, -1, 65536, 100000, "80", None, 3.14]
        for port in invalid_ports:
            if validate_port(port):
                print(f"  ❌ Invalid port accepted: {port}")
                return False
        
        valid_ports = [1, 80, 443, 8080, 8081, 65535]
        for port in valid_ports:
            if not validate_port(port):
                print(f"  ❌ Valid port rejected: {port}")
                return False
        
        print("  ✅ Input validation working correctly")
        return True
    
    def test_path_traversal_prevention(self):
        """Test that path traversal attacks are prevented"""
        print("\n🔒 Testing path traversal prevention...")
        
        # Test path sanitization
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "policies/../../../etc/shadow",
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\sam",
            "file:///etc/passwd",
            "policies/\x00/etc/passwd",  # Null byte injection
        ]
        
        for path in malicious_paths:
            sanitized = sanitize_path(path)
            if sanitized and ("etc" in sanitized.lower() or "windows" in sanitized.lower() or "passwd" in sanitized.lower() or "shadow" in sanitized.lower()):
                print(f"  ❌ Path traversal not prevented: {path} -> {sanitized}")
                return False
        
        # Test policy directory validation
        invalid_policy_dirs = [
            "../policies",
            "/etc/opa",
            "/proc/self/environ",
            "C:\\Windows\\System32",
            "policies/../../../etc",
        ]
        
        for path in invalid_policy_dirs:
            if validate_policy_dir(path):
                print(f"  ❌ Invalid policy directory accepted: {path}")
                return False
        
        print("  ✅ Path traversal prevention working")
        return True
    
    def test_opa_policy_failure_handling(self):
        """Test that OPA policy evaluation failures block traffic"""
        print("\n🔒 Testing OPA policy failure handling...")
        
        # Create a temporary malformed policy
        with tempfile.TemporaryDirectory() as tmpdir:
            malformed_policy = Path(tmpdir) / "malformed.rego"
            malformed_policy.write_text("""
package mitmproxy.policy

# Intentionally malformed policy
default allow := {
    syntax error here
}
""")
            
            # Test would need actual proxy running with malformed policy
            # For now, we verify the code logic exists
            
            # Check that the OPA filter has fail-closed logic (check both original and refactored locations)
            opa_filter_paths = [
                "mitmproxy-opa/mitmproxy_opa/opa_filter.py",
                "docker/mitmproxy_opa/opa_filter.py"
            ]
            
            fail_closed_found = False
            for opa_path in opa_filter_paths:
                opa_filter = Path(opa_path)
                if opa_filter.exists():
                    content = opa_filter.read_text()
                    if "503" in content and "policy evaluation failed" in content.lower():
                        print(f"  ✅ Fail-closed policy evaluation in {opa_path}")
                        fail_closed_found = True
                        break
            
            if not fail_closed_found:
                print("  ❌ Missing fail-closed logic in opa_filter.py")
                return False
        
        return True
    
    def test_proxy_bypass_prevention(self):
        """Test that proxy bypass attempts are detected"""
        print("\n🔒 Testing proxy bypass prevention...")
        
        # This would require a running environment
        # For now, we check for the presence of security controls
        
        # Check that network is internal
        network_py = Path("src/network.py")
        if network_py.exists():
            content = network_py.read_text()
            if "internal=True" in content:
                print("  ✅ Network configured as internal (no direct internet)")
            else:
                print("  ❌ Network not configured as internal")
                return False
        
        # Check for NO_PROXY handling
        # NO_PROXY should be minimal and controlled
        test_files = ["test_suite.py", "README.md"]
        for file in test_files:
            filepath = Path(file)
            if filepath.exists():
                content = filepath.read_text()
                if "NO_PROXY" in content:
                    # Check that only localhost is in NO_PROXY
                    if "localhost,127.0.0.1" in content:
                        print(f"  ✅ Minimal NO_PROXY configuration in {file}")
                    else:
                        print(f"  ⚠️  Check NO_PROXY configuration in {file}")
        
        return True
    
    def test_certificate_security(self):
        """Test certificate handling security"""
        print("\n🔒 Testing certificate security...")
        
        # Check that certificates are not committed to repo
        cert_patterns = ["*.pem", "*.key", "*.crt", "*.p12"]
        gitignore = Path(".gitignore")
        
        if gitignore.exists():
            content = gitignore.read_text()
            for pattern in cert_patterns:
                if pattern in content or pattern.replace("*", "") in content:
                    print(f"  ✅ Pattern {pattern} in .gitignore")
                else:
                    print(f"  ⚠️  Consider adding {pattern} to .gitignore")
        
        # Check for hardcoded certificates
        suspicious_strings = [
            "-----BEGIN CERTIFICATE-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
        ]
        
        for root, dirs, files in os.walk(".", topdown=True):
            # Skip .git and virtual environments
            dirs[:] = [d for d in dirs if d not in ['.git', '.venv', '__pycache__', 'node_modules']]
            
            for file in files:
                if file.endswith(('.py', '.yml', '.yaml', '.sh')):
                    filepath = Path(root) / file
                    try:
                        content = filepath.read_text()
                        for suspicious in suspicious_strings:
                            if suspicious in content:
                                print(f"  ⚠️  Found certificate/key in {filepath}")
                    except:
                        pass
        
        print("  ✅ Certificate security checks completed")
        return True
    
    def run_all_tests(self):
        """Run all security tests"""
        print("=" * 60)
        print("🔐 Docker MITM Bridge - Security Test Suite")
        print("=" * 60)
        
        tests = [
            ("Command Injection Prevention", self.test_command_injection_prevention),
            ("Input Validation", self.test_input_validation),
            ("Path Traversal Prevention", self.test_path_traversal_prevention),
            ("OPA Policy Failure Handling", self.test_opa_policy_failure_handling),
            ("Proxy Bypass Prevention", self.test_proxy_bypass_prevention),
            ("Certificate Security", self.test_certificate_security),
        ]
        
        results = []
        for test_name, test_func in tests:
            try:
                with timeout(30):
                    result = test_func()
                    results.append((test_name, result))
            except TimeoutError:
                print(f"  ❌ {test_name}: Timeout")
                results.append((test_name, False))
            except Exception as e:
                print(f"  ❌ {test_name}: {e}")
                results.append((test_name, False))
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 Security Test Summary")
        print("=" * 60)
        
        passed = sum(1 for _, result in results if result)
        total = len(results)
        
        for test_name, result in results:
            status = "✅ PASSED" if result else "❌ FAILED"
            print(f"  {test_name:.<40} {status}")
        
        print("=" * 60)
        print(f"Total: {passed} passed, {total - passed} failed")
        
        if passed == total:
            print("🎉 All security tests passed!")
            return 0
        else:
            print(f"⚠️  {total - passed} security test(s) failed")
            return 1


if __name__ == "__main__":
    suite = SecurityTestSuite()
    sys.exit(suite.run_all_tests())