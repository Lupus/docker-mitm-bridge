#!/usr/bin/env python3
"""
Test general OPA policy logic for Docker MITM Bridge (non-GitHub domains)
"""

import json
import subprocess
import tempfile
import os
from typing import Dict, Any, List

class GeneralPolicyTest:
    def __init__(self):
        self.policy_path = "opa-policies/policy.rego"
        self.data_path = "opa-policies/data.yml"
        self.test_results = []
        
    def create_test_data(self) -> str:
        """Create temporary data file with comprehensive test configuration"""
        test_data = """
# Domains with restricted access (only GET/HEAD allowed)
allowed_domains:
  - pypi.org
  - registry.npmjs.org
  - gitlab.com
  - archive.ubuntu.com

# Domains with unrestricted access (all HTTP methods allowed)
unrestricted_domains:
  - api.anthropic.com
  - api.openai.com
  - sentry.io

# GitHub access control configuration
github_read_access_enabled: true

github_allowed_users:
  - "testuser"

github_allowed_repos:
  - "testorg/testrepo"
"""
        
        fd, temp_path = tempfile.mkstemp(suffix='.yml')
        with os.fdopen(fd, 'w') as f:
            f.write(test_data)
        return temp_path
        
    def test_opa_policy(self, input_data: Dict[str, Any], data_file: str) -> Dict[str, Any]:
        """Test OPA policy with given input"""
        # Create temporary input file
        fd, input_file = tempfile.mkstemp(suffix='.json')
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(input_data, f)
            
            cmd = [
                "opa", "eval",
                "-d", self.policy_path,
                "-d", data_file,
                "-i", input_file,
                "data.mitmproxy.policy.decision"
            ]
        
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                output = json.loads(result.stdout)
                return output["result"][0]["expressions"][0]["value"]
            except subprocess.CalledProcessError as e:
                print(f"OPA command failed: {e}")
                print(f"stderr: {e.stderr}")
                return {"allow": False, "reason": f"Policy evaluation failed: {e}"}
            except (json.JSONDecodeError, KeyError, IndexError) as e:
                print(f"Failed to parse OPA output: {e}")
                return {"allow": False, "reason": f"Output parsing failed: {e}"}
        finally:
            # Clean up input file
            os.unlink(input_file)
    
    def run_general_policy_tests(self):
        """Run comprehensive general policy tests"""
        print("🔍 Testing General OPA Policy Logic (Non-GitHub)...")
        
        test_data_file = self.create_test_data()
        
        try:
            test_cases = [
                # Unrestricted domains - all methods should be allowed
                {
                    "name": "Unrestricted domain - GET request",
                    "input": {
                        "request": {
                            "host": "api.anthropic.com",
                            "method": "GET",
                            "path": "/v1/models"
                        }
                    },
                    "expected": True
                },
                {
                    "name": "Unrestricted domain - POST request",
                    "input": {
                        "request": {
                            "host": "api.anthropic.com",
                            "method": "POST",
                            "path": "/v1/messages"
                        }
                    },
                    "expected": True
                },
                {
                    "name": "Unrestricted domain - PUT request",
                    "input": {
                        "request": {
                            "host": "api.openai.com",
                            "method": "PUT",
                            "path": "/v1/files/abc"
                        }
                    },
                    "expected": True
                },
                {
                    "name": "Unrestricted domain - DELETE request",
                    "input": {
                        "request": {
                            "host": "sentry.io",
                            "method": "DELETE",
                            "path": "/api/projects/123"
                        }
                    },
                    "expected": True
                },
                
                # Allowed domains - only GET/HEAD should be allowed
                {
                    "name": "Allowed domain - GET request (should work)",
                    "input": {
                        "request": {
                            "host": "pypi.org",
                            "method": "GET",
                            "path": "/simple/requests/"
                        }
                    },
                    "expected": True
                },
                {
                    "name": "Allowed domain - HEAD request (should work)",
                    "input": {
                        "request": {
                            "host": "registry.npmjs.org",
                            "method": "HEAD",
                            "path": "/lodash"
                        }
                    },
                    "expected": True
                },
                {
                    "name": "Allowed domain - POST request (should be blocked)",
                    "input": {
                        "request": {
                            "host": "gitlab.com",
                            "method": "POST",
                            "path": "/api/projects"
                        }
                    },
                    "expected": False
                },
                {
                    "name": "Allowed domain - PUT request (should be blocked)",
                    "input": {
                        "request": {
                            "host": "archive.ubuntu.com",
                            "method": "PUT",
                            "path": "/ubuntu/dists/jammy/Release"
                        }
                    },
                    "expected": False
                },
                {
                    "name": "Allowed domain - DELETE request (should be blocked)",
                    "input": {
                        "request": {
                            "host": "pypi.org",
                            "method": "DELETE",
                            "path": "/simple/requests/"
                        }
                    },
                    "expected": False
                },
                
                # Unknown domains - should be blocked entirely
                {
                    "name": "Unknown domain - GET request (should be blocked)",
                    "input": {
                        "request": {
                            "host": "evil.com",
                            "method": "GET",
                            "path": "/malware"
                        }
                    },
                    "expected": False
                },
                {
                    "name": "Unknown domain - POST request (should be blocked)",
                    "input": {
                        "request": {
                            "host": "unknown-site.net",
                            "method": "POST",
                            "path": "/upload"
                        }
                    },
                    "expected": False
                },
                
                # Edge cases
                {
                    "name": "Case sensitivity - lowercase allowed domain",
                    "input": {
                        "request": {
                            "host": "pypi.org",
                            "method": "GET",
                            "path": "/test"
                        }
                    },
                    "expected": True
                },
                {
                    "name": "Domain with subdomain (not in allowed list)",
                    "input": {
                        "request": {
                            "host": "api.pypi.org",
                            "method": "GET",
                            "path": "/test"
                        }
                    },
                    "expected": False
                },
                {
                    "name": "Empty path",
                    "input": {
                        "request": {
                            "host": "api.anthropic.com",
                            "method": "GET",
                            "path": ""
                        }
                    },
                    "expected": True
                }
            ]
            
            success_count = 0
            for test_case in test_cases:
                result = self.test_opa_policy(test_case["input"], test_data_file)
                passed = result["allow"] == test_case["expected"]
                
                status = "✅ PASS" if passed else "❌ FAIL"
                print(f"{status} {test_case['name']}")
                print(f"      Expected: {test_case['expected']}, Got: {result['allow']}")
                print(f"      Reason: {result.get('reason', 'N/A')}")
                
                if passed:
                    success_count += 1
                    
                self.test_results.append({
                    "test": test_case["name"],
                    "passed": passed,
                    "expected": test_case["expected"],
                    "actual": result["allow"],
                    "reason": result.get("reason", "N/A")
                })
            
            print(f"\n📊 Results: {success_count}/{len(test_cases)} tests passed")
            return success_count == len(test_cases)
            
        finally:
            # Clean up temp file
            os.unlink(test_data_file)

def main():
    """Run general policy tests"""
    tester = GeneralPolicyTest()
    
    # Check if OPA is installed
    try:
        subprocess.run(["opa", "version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ OPA not found. Please install OPA (https://www.openpolicyagent.org/docs/latest/#running-opa)")
        return False
        
    success = tester.run_general_policy_tests()
    
    if success:
        print("\n🎉 All general policy tests passed!")
        return True
    else:
        print("\n💥 Some tests failed. Check the policy logic.")
        return False

if __name__ == "__main__":
    import sys
    success = main()
    sys.exit(0 if success else 1)