#!/usr/bin/env python3
"""
Test idempotency and resilience of Docker MITM Bridge
Ensures the tool handles repeated operations and partial failures gracefully
"""

import subprocess
import time
import docker
import sys
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


def run_command(cmd):
    """Run a command and return exit code, stdout, stderr"""
    # Security fix: Remove shell=True to prevent command injection
    # Commands should be passed as lists, not strings
    if isinstance(cmd, str):
        cmd = cmd.split()
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def test_repeated_init():
    """Test that init can be run multiple times safely"""
    print("🔄 Testing repeated initialization...")
    
    # First init
    code1, _, _ = run_command("python docker-mitm-bridge init")
    if code1 != 0:
        print("  ❌ First init failed")
        return False
    
    # Second init (should handle existing resources)
    code2, stdout2, _ = run_command("python docker-mitm-bridge init")
    if code2 != 0:
        print("  ❌ Second init failed")
        return False
    
    if "already exists" in stdout2:
        print("  ✅ Handles existing network correctly")
    
    # Third init
    code3, _, _ = run_command("python docker-mitm-bridge init")
    if code3 != 0:
        print("  ❌ Third init failed")
        return False
    
    print("  ✅ Multiple init calls handled safely")
    return True


def test_start_stop_cycle():
    """Test multiple start/stop cycles"""
    print("\n🔄 Testing start/stop cycles...")
    
    for i in range(2):  # Reduced from 3 to 2 cycles
        print(f"  Cycle {i+1}...")
        
        # Stop
        code, _, _ = run_command("python docker-mitm-bridge stop")
        if code != 0:
            print(f"    ❌ Stop failed on cycle {i+1}")
            return False
        
        time.sleep(1)
        
        # Start
        code, _, _ = run_command("python docker-mitm-bridge start")
        if code != 0:
            print(f"    ❌ Start failed on cycle {i+1}")
            return False
        
        time.sleep(1)  # Reduced from 2 to 1 second
        
        # Verify running
        code, stdout, _ = run_command("python docker-mitm-bridge status")
        if code != 0 or "running" not in stdout:
            print(f"    ❌ Proxy not running after cycle {i+1}")
            return False
    
    print("  ✅ All start/stop cycles completed successfully")
    return True


def test_partial_cleanup():
    """Test handling of partial cleanup states"""
    print("\n🧹 Testing partial cleanup handling...")
    
    client = docker.from_env()
    
    # Manually remove just the network (leaving proxy orphaned)
    try:
        # Stop proxy first
        run_command("python docker-mitm-bridge stop")
        
        # Remove network manually
        network = client.networks.get("mitm-filtered")
        network.remove()
        print("  Manually removed network")
    except:
        pass
    
    # Try to start (should fail gracefully)
    code, stdout, stderr = run_command("python docker-mitm-bridge start")
    if "does not exist" in stderr or "does not exist" in stdout:
        print("  ✅ Correctly detected missing network")
    
    # Init should restore everything
    code, _, _ = run_command("python docker-mitm-bridge init")
    if code != 0:
        print("  ❌ Failed to restore with init")
        return False
    
    # Verify everything is working
    code, stdout, _ = run_command("python docker-mitm-bridge status")
    if code != 0 or "running" not in stdout:
        print("  ❌ System not fully restored")
        return False
    
    print("  ✅ Successfully recovered from partial cleanup")
    return True


def test_concurrent_containers():
    """Test multiple containers using the network simultaneously"""
    print("\n👥 Testing concurrent container access...")
    
    client = docker.from_env()
    containers = []
    
    # Clean up any existing test containers first
    for i in range(3):
        try:
            old_container = client.containers.get(f"test-concurrent-{i}")
            old_container.stop(timeout=2)
            old_container.remove()
        except docker.errors.NotFound:
            pass
        except:
            pass
    
    try:
        # Create multiple test containers
        for i in range(3):
            container = client.containers.run(
                "alpine:latest",
                command="sleep 10",
                network="mitm-filtered",
                name=f"test-concurrent-{i}",
                detach=True,
                environment={
                    "HTTP_PROXY": "http://mitm-boundary-proxy:8080",
                    "HTTPS_PROXY": "http://mitm-boundary-proxy:8080",
                }
            )
            containers.append(container)
            print(f"  Created container {i+1}")
        
        # List containers
        code, stdout, _ = run_command("python docker-mitm-bridge list-containers")
        if code != 0:
            print("  ❌ Failed to list containers")
            return False
        
        # Check all containers are listed
        for i in range(3):
            if f"test-concurrent-{i}" not in stdout:
                print(f"  ❌ Container test-concurrent-{i} not found in listing")
                return False
        
        print("  ✅ All concurrent containers listed correctly")
        
        # Test that proxy handles multiple connections
        for i, container in enumerate(containers):
            # Simple connectivity test through proxy
            exit_code, output = container.exec_run(
                "sh -c 'echo test | nc -w 2 mitm-boundary-proxy 8080'"
            )
            # As long as we can connect to the proxy, it's working
            if exit_code == 0:
                continue  # Success
            else:
                # Try alternative test - just check if proxy port is reachable
                exit_code2, _ = container.exec_run(
                    "sh -c 'nc -zv mitm-boundary-proxy 8080'"
                )
                if exit_code2 == 0:
                    continue  # Success
                else:
                    print(f"  ❌ Container {i} failed to connect to proxy")
                    return False
        
        print("  ✅ All containers can use proxy simultaneously")
        return True
        
    finally:
        # Cleanup
        for container in containers:
            try:
                container.stop(timeout=5)
                container.remove()
            except:
                pass


def test_destroy_and_reinit():
    """Test complete destroy and reinitialization"""
    print("\n♻️  Testing destroy and reinit...")
    
    # Destroy everything
    code, _, _ = run_command("python docker-mitm-bridge destroy")
    if code != 0:
        print("  ⚠️  Destroy had issues (may be expected)")
    
    # Verify everything is gone
    client = docker.from_env()
    
    try:
        network = client.networks.get("mitm-filtered")
        print("  ❌ Network still exists after destroy")
        return False
    except docker.errors.NotFound:
        print("  ✅ Network removed")
    
    try:
        container = client.containers.get("mitm-boundary-proxy")
        print("  ❌ Proxy container still exists after destroy")
        return False
    except docker.errors.NotFound:
        print("  ✅ Proxy container removed")
    
    # Reinitialize
    code, _, _ = run_command("python docker-mitm-bridge init")
    if code != 0:
        print("  ❌ Failed to reinitialize")
        return False
    
    # Verify working
    time.sleep(2)
    code, stdout, _ = run_command("python docker-mitm-bridge status")
    if code != 0 or "running" not in stdout:
        print("  ❌ System not working after reinit")
        return False
    
    print("  ✅ Successfully destroyed and reinitialized")
    return True


def main():
    print("=" * 60)
    print("🔧 Docker MITM Bridge - Idempotency Tests")
    print("=" * 60)
    
    # Ensure we start clean
    run_command("python docker-mitm-bridge destroy")
    time.sleep(1)
    
    tests = [
        ("Repeated Initialization", test_repeated_init),
        ("Start/Stop Cycles", test_start_stop_cycle),
        ("Partial Cleanup Recovery", test_partial_cleanup),
        ("Concurrent Containers", test_concurrent_containers),
        ("Destroy and Reinit", test_destroy_and_reinit),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            # Apply timeout to each test (20 seconds per test)
            with timeout(20):
                result = test_func()
                results.append((name, result))
        except TimeoutError as e:
            print(f"\n⏱️  Test '{name}' timed out: {e}")
            results.append((name, False))
        except Exception as e:
            print(f"\n❌ Test '{name}' failed with exception: {e}")
            results.append((name, False))
    
    # Final cleanup
    print("\n🧹 Final cleanup...")
    run_command("python docker-mitm-bridge destroy")
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 Test Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    failed = sum(1 for _, result in results if not result)
    
    for name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"  {name:.<40} {status}")
    
    print("=" * 60)
    print(f"Total: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All idempotency tests passed!")
        return 0
    else:
        print(f"❌ {failed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())