#!/usr/bin/env python3
"""
Automated test suite for Docker MITM Bridge
Tests network creation, proxy deployment, and connectivity filtering
"""

import subprocess
import time
import sys
import docker
import requests
from typing import Dict, Any, List, Tuple
import json
import signal
from contextlib import contextmanager


@contextmanager
def timeout(seconds):
    """Context manager for timeout"""
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds} seconds")
    
    # Set the signal handler and alarm
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    
    try:
        yield
    finally:
        # Cancel the alarm
        signal.alarm(0)


class TestSuite:
    def __init__(self):
        self.client = docker.from_env()
        self.network_name = "mitm-filtered"
        self.proxy_container = "mitm-boundary-proxy"
        self.test_results = []
        
    def run_command(self, cmd: List[str]) -> Tuple[int, str, str]:
        """Run a command and return exit code, stdout, stderr"""
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
        
    def cleanup(self):
        """Clean up any existing resources before testing"""
        print("🧹 Cleaning up existing resources...")
        
        # Stop and remove test containers in parallel
        containers_to_remove = []
        containers = self.client.containers.list(all=True)
        for container in containers:
            if 'test-mitm' in container.name or container.name == self.proxy_container:
                containers_to_remove.append(container)
        
        # Stop all containers first (in parallel)
        for container in containers_to_remove:
            try:
                print(f"  Stopping container: {container.name}")
                container.stop(timeout=2)
            except:
                pass
        
        # Then remove them
        for container in containers_to_remove:
            try:
                container.remove()
            except:
                pass
                    
        # Remove the network if it exists
        try:
            network = self.client.networks.get(self.network_name)
            print(f"  Removing network: {self.network_name}")
            network.remove()
        except docker.errors.NotFound:
            pass
            
        # Clean up with docker-compose
        subprocess.run(["docker", "compose", "down", "-v"], 
                      capture_output=True, text=True)
        
        print("  Cleanup complete\n")
        
    def test_network_creation(self) -> bool:
        """Test network creation"""
        print("🔧 Testing network creation...")
        
        # Initialize the environment
        code, stdout, stderr = self.run_command([
            "python", "docker-mitm-bridge", "init"
        ])
        
        if code != 0:
            print(f"  ❌ Failed to initialize: {stderr}")
            return False
            
        # Verify network exists
        try:
            network = self.client.networks.get(self.network_name)
            assert network.attrs['Internal'] == True
            print(f"  ✅ Network '{self.network_name}' created successfully")
            print(f"     Internal: {network.attrs['Internal']}")
            print(f"     Subnet: {network.attrs['IPAM']['Config'][0]['Subnet']}")
            return True
        except docker.errors.NotFound:
            print(f"  ❌ Network '{self.network_name}' not found")
            return False
        except Exception as e:
            print(f"  ❌ Error checking network: {e}")
            return False
            
    def test_proxy_deployment(self) -> bool:
        """Test proxy container deployment"""
        print("\n🐳 Testing proxy deployment...")
        
        # Wait for proxy to be fully up
        time.sleep(3)
        
        try:
            container = self.client.containers.get(self.proxy_container)
            
            if container.status != 'running':
                print(f"  ❌ Proxy container not running: {container.status}")
                return False
                
            print(f"  ✅ Proxy container running")
            
            # Check if web interface is accessible
            try:
                response = requests.get('http://localhost:8081', timeout=5)
                if response.status_code == 200:
                    print(f"  ✅ Web interface accessible at http://localhost:8081")
                else:
                    print(f"  ❌ Web interface returned status {response.status_code}")
                    return False
            except Exception as e:
                print(f"  ❌ Cannot access web interface: {e}")
                return False
                
            # Check if proxy port is accessible
            try:
                response = requests.get('http://localhost:8080/ca.crt', timeout=5)
                if response.status_code == 200:
                    print(f"  ✅ CA certificate endpoint accessible")
                else:
                    print(f"  ⚠️  CA certificate endpoint returned {response.status_code}")
            except:
                print(f"  ⚠️  CA certificate endpoint not directly accessible (expected)")
                
            return True
            
        except docker.errors.NotFound:
            print(f"  ❌ Proxy container not found")
            return False
        except Exception as e:
            print(f"  ❌ Error checking proxy: {e}")
            return False
            
    def test_connectivity_filtering(self) -> bool:
        """Test connectivity filtering through the proxy"""
        print("\n🔒 Testing connectivity filtering...")
        
        test_cases = [
            ("https://github.com", "GET", True, "GitHub (allowed domain, GET)"),
            ("https://pypi.org", "GET", True, "PyPI (allowed domain, GET)"),
            ("https://example.com", "GET", False, "example.com (not in allowed list)"),
            ("https://api.anthropic.com", "HEAD", True, "Anthropic API (unrestricted)"),
            ("https://github.com", "POST", False, "GitHub POST (restricted method)"),
        ]
        
        # Create a test container in the filtered network
        print("  Creating test container...")
        
        test_script = """#!/bin/bash
set -e

# Install CA certificate
echo "Installing CA certificate..."
apt-get update -qq && apt-get install -y -qq curl ca-certificates > /dev/null 2>&1
curl -sSL http://mitm-boundary-proxy:8080/ca.crt -o /tmp/mitmproxy-ca.crt
cp /tmp/mitmproxy-ca.crt /usr/local/share/ca-certificates/
update-ca-certificates > /dev/null 2>&1

# Test connectivity
echo "Testing connectivity..."
"""
        
        for url, method, should_pass, description in test_cases:
            if method in ["GET", "HEAD"]:
                test_script += f"""
echo -n "  Testing {description}... "
response=$(curl -s -o /dev/null -w "%{{http_code}}" -X {method} {url})
if [ "$response" = "403" ]; then
    echo "❌ Blocked (403)"
    {"exit 1" if should_pass else ""}
elif echo "$response" | grep -q "^[234]"; then
    echo "✅ Allowed ($response)"
    {"" if should_pass else "exit 1"}
else
    echo "❌ Failed ($response)"
    {"exit 1" if should_pass else ""}
fi
"""
            else:
                test_script += f"""
echo -n "  Testing {description}... "
response=$(curl -s -o /dev/null -w "%{{http_code}}" -X {method} {url} || echo "000")
if [ "$response" = "403" ]; then
    echo "❌ Blocked (403)"
    {"exit 1" if should_pass else ""}
elif echo "$response" | grep -q "^[234]"; then
    echo "✅ Allowed ($response)"
    {"" if should_pass else "exit 1"}
else
    echo "❌ Failed ($response)"
    {"exit 1" if should_pass else ""}
fi
"""
        
        # Create test script and tar archive
        import tarfile
        import io
        
        # Create tar archive with test script
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode='w') as tar:
            script_data = test_script.encode('utf-8')
            tarinfo = tarfile.TarInfo(name='test_connectivity.sh')
            tarinfo.size = len(script_data)
            tarinfo.mode = 0o755
            tar.addfile(tarinfo, io.BytesIO(script_data))
        tar_stream.seek(0)
        
        # Run test container
        try:
            # First, remove any existing test container
            try:
                old_container = self.client.containers.get("test-mitm-filtering")
                old_container.stop()
                old_container.remove()
            except:
                pass
                
            container = self.client.containers.run(
                "ubuntu:22.04",
                command="sleep 30",
                network=self.network_name,
                environment={
                    "HTTP_PROXY": f"http://{self.proxy_container}:8080",
                    "HTTPS_PROXY": f"http://{self.proxy_container}:8080",
                    "http_proxy": f"http://{self.proxy_container}:8080",
                    "https_proxy": f"http://{self.proxy_container}:8080",
                    "NO_PROXY": "localhost,127.0.0.1",
                },
                name="test-mitm-filtering",
                detach=True
            )
            
            # Copy and execute the test script
            container.put_archive('/', tar_stream.read())
            exit_code, output = container.exec_run("/bin/bash /test_connectivity.sh")
            
            print(output.decode('utf-8'))
            
            # Clean up
            container.stop(timeout=5)
            container.remove()
            
            if exit_code == 0:
                print("  ✅ All connectivity tests passed")
                return True
            else:
                print("  ❌ Some connectivity tests failed")
                return False
            
        except docker.errors.ContainerError as e:
            print(f"  ❌ Connectivity test failed:")
            print(e.container.logs().decode('utf-8'))
            return False
        except Exception as e:
            print(f"  ❌ Error running test container: {e}")
            return False
            
    def test_container_listing(self) -> bool:
        """Test listing containers in the network"""
        print("\n📋 Testing container listing...")
        
        # Create a test container
        try:
            container = self.client.containers.run(
                "alpine:latest",
                command="sleep 10",
                network=self.network_name,
                name="test-mitm-list",
                detach=True
            )
            
            # List containers
            code, stdout, stderr = self.run_command([
                "python", "docker-mitm-bridge", "list-containers"
            ])
            
            if code != 0:
                print(f"  ❌ Failed to list containers: {stderr}")
                container.stop()
                container.remove()
                return False
                
            if "test-mitm-list" in stdout:
                print("  ✅ Test container found in listing")
                container.stop(timeout=5)
                container.remove()
                return True
            else:
                print("  ❌ Test container not found in listing")
                container.stop(timeout=5)
                container.remove()
                return False
                
        except Exception as e:
            print(f"  ❌ Error testing container listing: {e}")
            return False
            
    def test_policy_update(self) -> bool:
        """Test OPA policy updates"""
        print("\n🔄 Testing policy updates...")
        
        # Update policy
        code, stdout, stderr = self.run_command([
            "python", "docker-mitm-bridge", "update-policy"
        ])
        
        if code != 0:
            print(f"  ❌ Failed to update policy: {stderr}")
            return False
            
        # Wait for restart
        time.sleep(3)
        
        # Check if proxy is still running
        try:
            container = self.client.containers.get(self.proxy_container)
            if container.status == 'running':
                print("  ✅ Proxy restarted successfully after policy update")
                return True
            else:
                print(f"  ❌ Proxy not running after update: {container.status}")
                return False
        except Exception as e:
            print(f"  ❌ Error checking proxy after update: {e}")
            return False
            
    def test_cleanup_resources(self) -> bool:
        """Test resource cleanup"""
        print("\n🧹 Testing resource cleanup...")
        
        # Destroy everything
        code, stdout, stderr = self.run_command([
            "python", "docker-mitm-bridge", "destroy"
        ])
        
        if code != 0:
            print(f"  ⚠️  Destroy command had issues: {stderr}")
            
        # Verify cleanup
        try:
            # Check network is gone
            try:
                network = self.client.networks.get(self.network_name)
                print(f"  ❌ Network still exists after destroy")
                return False
            except docker.errors.NotFound:
                print(f"  ✅ Network removed successfully")
                
            # Check proxy container is gone
            try:
                container = self.client.containers.get(self.proxy_container)
                print(f"  ❌ Proxy container still exists after destroy")
                return False
            except docker.errors.NotFound:
                print(f"  ✅ Proxy container removed successfully")
                
            return True
            
        except Exception as e:
            print(f"  ❌ Error verifying cleanup: {e}")
            return False
            
    def run_all_tests(self):
        """Run all tests in sequence"""
        print("=" * 60)
        print("🚀 Docker MITM Bridge - Automated Test Suite")
        print("=" * 60)
        
        # Initial cleanup
        self.cleanup()
        
        tests = [
            ("Network Creation", self.test_network_creation),
            ("Proxy Deployment", self.test_proxy_deployment),
            ("Connectivity Filtering", self.test_connectivity_filtering),
            ("Container Listing", self.test_container_listing),
            ("Policy Update", self.test_policy_update),
            ("Resource Cleanup", self.test_cleanup_resources),
        ]
        
        results = []
        for name, test_func in tests:
            try:
                # Apply timeout to each test (30 seconds per test)
                with timeout(30):
                    result = test_func()
                    results.append((name, result))
            except TimeoutError as e:
                print(f"\n⏱️  Test '{name}' timed out: {e}")
                results.append((name, False))
            except Exception as e:
                print(f"\n❌ Test '{name}' failed with exception: {e}")
                results.append((name, False))
                
        # Print summary
        print("\n" + "=" * 60)
        print("📊 Test Summary")
        print("=" * 60)
        
        passed = 0
        failed = 0
        
        for name, result in results:
            status = "✅ PASSED" if result else "❌ FAILED"
            print(f"  {name:.<40} {status}")
            if result:
                passed += 1
            else:
                failed += 1
                
        print("=" * 60)
        print(f"Total: {passed} passed, {failed} failed")
        
        if failed == 0:
            print("🎉 All tests passed!")
            return 0
        else:
            print(f"❌ {failed} test(s) failed")
            return 1


if __name__ == "__main__":
    # Ensure we're in the virtual environment
    import os
    venv_path = os.path.join(os.path.dirname(__file__), '.venv', 'bin', 'activate')
    
    suite = TestSuite()
    exit_code = suite.run_all_tests()
    sys.exit(exit_code)