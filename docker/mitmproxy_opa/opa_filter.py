#!/usr/bin/env python3
"""
Mitmproxy addon that integrates with OPA for traffic filtering using Regorus
"""
import sys
import yaml
from pathlib import Path
from typing import Optional

from mitmproxy import http, ctx
import regorus


class OPAFilter:
    def __init__(self):
        # Look for policy files in the mounted bundle directory
        self.bundle_path = Path("/app/bundle")
        self.data_file = self.bundle_path / "data.yml"
        self.engine: Optional[regorus.Engine] = None
        self._has_ctx = False
        
    def load(self, loader):
        # Check if ctx is available
        try:
            ctx.log
            self._has_ctx = True
        except AttributeError:
            self._has_ctx = False
            
        if self._has_ctx:
            ctx.log.info(f"Loading OPA policies from: {self.bundle_path}")
        
        try:
            # Create Regorus engine
            self.engine = regorus.Engine()
            
            # Load all .rego policy files from bundle directory
            rego_files = list(self.bundle_path.glob("*.rego"))
            if not rego_files:
                raise FileNotFoundError(f"No .rego policy files found in {self.bundle_path}")
                
            for rego_file in rego_files:
                if self._has_ctx:
                    ctx.log.info(f"Loading policy file: {rego_file}")
                self.engine.add_policy_from_file(str(rego_file))
            
            # Load data from single data.yml file only
            if not self.data_file.exists():
                raise FileNotFoundError(f"Required data.yml file not found at {self.data_file}")
            
            if self._has_ctx:
                ctx.log.info(f"Loading data file: {self.data_file}")
            
            with open(self.data_file, 'r') as f:
                yaml_data = yaml.safe_load(f)
                if not yaml_data:
                    raise ValueError(f"data.yml file is empty or invalid: {self.data_file}")
                self.engine.add_data(yaml_data)
                
            if self._has_ctx:
                ctx.log.info(f"Regorus engine loaded successfully with {len(rego_files)} policies and data from {self.data_file}")
        except Exception as e:
            if self._has_ctx:
                ctx.log.error(f"Failed to load Regorus policy: {e}")
            else:
                print(f"Failed to load Regorus policy: {e}")
            sys.exit(1)
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept and filter requests based on OPA policy using Regorus"""
        if not self.engine:
            if self._has_ctx:
                ctx.log.error("Regorus engine not loaded")
            return
        
        # Prepare input for OPA
        headers = {k: v for k, v in flow.request.headers.items()}
        
        # Convert query to dict
        query = {}
        if flow.request.query:
            query = {k: v for k, v in flow.request.query.items()}
        
        opa_input = {
            "request": {
                "method": flow.request.method,
                "host": flow.request.host,
                "port": flow.request.port,
                "path": flow.request.path,
                "query": query,
                "headers": headers,
                "scheme": flow.request.scheme,
            }
        }
        
        try:
            # Set input for Regorus engine
            self.engine.set_input(opa_input)
            
            # Evaluate the decision rule - enforce structured decision format only
            decision_result = self.engine.eval_rule("data.mitmproxy.policy.decision")
            
            # Strict validation of policy response format
            if not isinstance(decision_result, dict):
                raise ValueError(f"Policy must return a dict, got {type(decision_result)}")
            
            if "allow" not in decision_result:
                raise ValueError("Policy decision must contain 'allow' field")
            
            if not isinstance(decision_result["allow"], bool):
                raise ValueError(f"Policy 'allow' field must be boolean, got {type(decision_result['allow'])}")
            
            allowed = decision_result["allow"]
            reason = decision_result.get("reason", "No reason provided")
            
            if self._has_ctx:
                ctx.log.info(f"Regorus decision for {flow.request.method} {flow.request.url}: "
                            f"allowed={allowed}, reason={reason}")
            
            if not allowed:
                # Block the request
                flow.response = http.Response.make(
                    403,
                    f"Forbidden by OPA policy: {reason}",
                    {"Content-Type": "text/plain"}
                )
                if self._has_ctx:
                    ctx.log.warn(f"Blocked request: {flow.request.method} {flow.request.url}")
                
        except Exception as e:
            # Security fix: Block traffic on policy evaluation errors (fail-closed)
            if self._has_ctx:
                ctx.log.error(f"Error evaluating Regorus policy: {e}")
                ctx.log.error("Blocking request due to policy evaluation error")
            
            # Return 503 Service Unavailable when policy evaluation fails
            flow.response = http.Response.make(
                503,
                "Service temporarily unavailable: Policy evaluation failed",
                {"Content-Type": "text/plain"}
            )