#!/usr/bin/env python3
"""
Test GitHub-specific OPA policy logic for Docker MITM Bridge
"""

import json
import subprocess
import tempfile
import os
from typing import Dict, Any, List

class GitHubPolicyTest:
    def __init__(self):
        self.policy_path = "opa-policies/policy.rego"
        self.data_path = "opa-policies/data.yml"
        self.test_results = []
        
    def create_test_data(self, github_users: List[str], github_repos: List[str]) -> str:
        """Create temporary data file with test configuration"""
        test_data = f"""
allowed_domains:
  - github.com
  - api.github.com

unrestricted_domains:
  - api.anthropic.com

github_allowed_users:
{chr(10).join([f'  - "{user}"' for user in github_users])}

github_allowed_repos:
{chr(10).join([f'  - "{repo}"' for repo in github_repos])}
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
    
    def run_github_tests(self):
        """Run comprehensive GitHub policy tests"""
        print("🔍 Testing GitHub OPA Policy Logic...")
        
        # Test configuration: allow user "testuser" and specific repo "org/specific-repo"
        test_data_file = self.create_test_data(
            github_users=["testuser", "alloweduser"], 
            github_repos=["org/specific-repo", "team/project"]
        )
        
        try:
            test_cases = [
                # Read operations (should be allowed for all GitHub repos)
                {
                    "name": "GitHub clone (GET info/refs)",
                    "input": {
                        "request": {
                            "host": "github.com",
                            "method": "GET",
                            "path": "/testuser/repo.git/info/refs",
                            "query": "service=git-upload-pack"
                        }
                    },
                    "expected": True
                },
                {
                    "name": "GitHub fetch (POST git-upload-pack)",
                    "input": {
                        "request": {
                            "host": "github.com", 
                            "method": "POST",
                            "path": "/anyuser/anyrepo.git/git-upload-pack"
                        }
                    },
                    "expected": True
                },
                {
                    "name": "GitHub web interface (GET)",
                    "input": {
                        "request": {
                            "host": "github.com",
                            "method": "GET", 
                            "path": "/testuser/repo"
                        }
                    },
                    "expected": True
                },
                
                # Write operations - authorized user
                {
                    "name": "GitHub push discovery (authorized user)",
                    "input": {
                        "request": {
                            "host": "github.com",
                            "method": "GET",
                            "path": "/testuser/repo.git/info/refs",
                            "query": "service=git-receive-pack"
                        }
                    },
                    "expected": True
                },
                {
                    "name": "GitHub push (authorized user)",
                    "input": {
                        "request": {
                            "host": "github.com",
                            "method": "POST",
                            "path": "/testuser/myrepo.git/git-receive-pack"
                        }
                    },
                    "expected": True
                },
                
                # Write operations - authorized specific repo
                {
                    "name": "GitHub push (authorized specific repo)",
                    "input": {
                        "request": {
                            "host": "github.com",
                            "method": "POST", 
                            "path": "/org/specific-repo.git/git-receive-pack"
                        }
                    },
                    "expected": True
                },
                
                # Write operations - unauthorized
                {
                    "name": "GitHub push (unauthorized user)",
                    "input": {
                        "request": {
                            "host": "github.com",
                            "method": "POST",
                            "path": "/unauthorizeduser/repo.git/git-receive-pack"
                        }
                    },
                    "expected": False
                },
                {
                    "name": "GitHub push discovery (unauthorized)",
                    "input": {
                        "request": {
                            "host": "github.com",
                            "method": "GET",
                            "path": "/baduser/repo.git/info/refs",
                            "query": "service=git-receive-pack"
                        }
                    },
                    "expected": False
                },
                
                # API calls
                {
                    "name": "GitHub API (GET)",
                    "input": {
                        "request": {
                            "host": "api.github.com",
                            "method": "GET",
                            "path": "/user"
                        }
                    },
                    "expected": True
                },
                
                # Raw content
                {
                    "name": "GitHub raw content", 
                    "input": {
                        "request": {
                            "host": "raw.githubusercontent.com",
                            "method": "GET",
                            "path": "/user/repo/main/file.txt"
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
    """Run GitHub policy tests"""
    tester = GitHubPolicyTest()
    
    # Check if OPA is installed
    try:
        subprocess.run(["opa", "version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ OPA not found. Please install OPA (https://www.openpolicyagent.org/docs/latest/#running-opa)")
        return False
        
    success = tester.run_github_tests()
    
    if success:
        print("\n🎉 All GitHub policy tests passed!")
        return True
    else:
        print("\n💥 Some tests failed. Check the policy logic.")
        return False

if __name__ == "__main__":
    import sys
    success = main()
    sys.exit(0 if success else 1)