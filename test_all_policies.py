#!/usr/bin/env python3
"""
Run all policy tests for Docker MITM Bridge
"""

import subprocess
import sys

def run_test(test_name, test_file):
    """Run a single test file and return success status"""
    print(f"{'='*60}")
    print(f"🧪 Running {test_name}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run([
            sys.executable, test_file
        ], check=True, capture_output=False)
        print(f"✅ {test_name} PASSED\n")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {test_name} FAILED (exit code {e.returncode})\n")
        return False

def main():
    """Run all policy tests"""
    print("🚀 Docker MITM Bridge - Complete Policy Test Suite")
    print("=" * 60)
    
    tests = [
        ("General Policy Tests", "test_general_policy.py"),
        ("GitHub Policy Tests", "test_github_policy.py"),
        ("Security Tests", "test_security.py")
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_file in tests:
        if run_test(test_name, test_file):
            passed += 1
    
    print("=" * 60)
    print("📊 FINAL RESULTS")
    print("=" * 60)
    print(f"Tests Passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED!")
        return True
    else:
        print(f"💥 {total - passed} test suite(s) failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)