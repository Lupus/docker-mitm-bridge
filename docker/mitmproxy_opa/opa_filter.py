#!/usr/bin/env python3
"""
Mitmproxy addon that integrates with OPA for traffic filtering using Regorus
"""
import json
import sys
import yaml
from pathlib import Path
from typing import Optional, Dict, Any

from mitmproxy import http, ctx
import regorus


class OPAFilter:
    def __init__(self):
        # Look for policy files in the mounted bundle directory
        self.bundle_path = Path("/app/bundle")
        self.engine: Optional[regorus.Engine] = None
        self.data: Dict[str, Any] = {}
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
            
            # Load data from YAML files
            yaml_files = list(self.bundle_path.glob("*.yaml")) + list(self.bundle_path.glob("*.yml"))
            for yaml_file in yaml_files:
                if self._has_ctx:
                    ctx.log.info(f"Loading data file: {yaml_file}")
                with open(yaml_file, 'r') as f:
                    yaml_data = yaml.safe_load(f)
                    if yaml_data:
                        self.engine.add_data(yaml_data)
                        self.data.update(yaml_data)
            
            # Load data from JSON files  
            json_files = list(self.bundle_path.glob("*.json"))
            for json_file in json_files:
                if self._has_ctx:
                    ctx.log.info(f"Loading data file: {json_file}")
                with open(json_file, 'r') as f:
                    json_data = json.load(f)
                    if json_data:
                        self.engine.add_data(json_data)
                        self.data.update(json_data)
                
            if self._has_ctx:
                ctx.log.info(f"Regorus engine loaded successfully with {len(rego_files)} policies and {len(self.data)} data keys")
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
            
            # Evaluate the decision rule - try to get the structured decision first
            try:
                decision_result = self.engine.eval_rule("data.mitmproxy.policy.decision")
                allowed = decision_result.get("allow", False)
                reason = decision_result.get("reason", "No reason provided")
            except:
                # Fallback to simple allow rule
                allowed = self.engine.eval_rule("data.mitmproxy.policy.allow")
                reason = "Policy evaluation result"
            
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