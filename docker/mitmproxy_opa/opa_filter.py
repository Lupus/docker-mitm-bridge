#!/usr/bin/env python3
"""
Mitmproxy addon that integrates with OPA for traffic filtering
"""
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any

from mitmproxy import http, ctx
from opa_wasm import OPAPolicy


class OPAFilter:
    def __init__(self):
        # Look for bundle in the output directory
        self.bundle_path = Path("/app/opa-output/bundle.tar.gz")
        self.policy: Optional[OPAPolicy] = None
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
            ctx.log.info(f"Loading OPA bundle from: {self.bundle_path}")
        try:
            import tarfile
            import tempfile
            
            # Create a temporary directory for extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract all files from bundle
                with tarfile.open(self.bundle_path, 'r:gz') as tar:
                    for member in tar.getmembers():
                        member.name = member.name.lstrip('/')
                        tar.extract(member, temp_dir)
                    if self._has_ctx:
                        ctx.log.info(f"Extracted bundle contents to {temp_dir}")
                
                # Load policy.wasm
                wasm_path = Path(temp_dir) / "policy.wasm"
                if not wasm_path.exists():
                    raise FileNotFoundError(f"policy.wasm not found in bundle at {wasm_path}")
                
                # Load data.json if it exists
                data_path = Path(temp_dir) / "data.json"
                if data_path.exists():
                    with open(data_path, 'r') as f:
                        self.data = json.load(f)
                    if self._has_ctx:
                        ctx.log.info(f"Loaded data.json with {len(self.data)} keys")
                
                # Initialize OPA policy with WASM file
                self.policy = OPAPolicy(str(wasm_path))
                
                # Set data if available
                if self.data:
                    self.policy.set_data(self.data)
                
            if self._has_ctx:
                ctx.log.info("OPA policy loaded successfully")
        except Exception as e:
            if self._has_ctx:
                ctx.log.error(f"Failed to load OPA policy: {e}")
            else:
                print(f"Failed to load OPA policy: {e}")
            sys.exit(1)
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept and filter requests based on OPA policy"""
        if not self.policy:
            if self._has_ctx:
                ctx.log.error("OPA policy not loaded")
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
            # Evaluate policy
            result = self.policy.evaluate(opa_input)
            
            allowed = False
            reason = "No decision from policy"
            
            if isinstance(result, list) and len(result) > 0:
                if isinstance(result[0], dict) and 'result' in result[0]:
                    policy_output = result[0]['result']
                    if isinstance(policy_output, dict):
                        allowed = policy_output.get('allow', False)
                        reason = policy_output.get('reason', 'No reason provided')
                    else:
                        allowed = bool(policy_output)
                else:
                    allowed = bool(result[0])
            elif isinstance(result, dict):
                if "result" in result:
                    allowed = bool(result["result"])
                elif "allow" in result:
                    allowed = result["allow"]
                    reason = result.get("reason", "No reason provided")
            
            if self._has_ctx:
                ctx.log.info(f"OPA decision for {flow.request.method} {flow.request.url}: "
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
                ctx.log.error(f"Error evaluating OPA policy: {e}")
                ctx.log.error("Blocking request due to policy evaluation error")
            
            # Return 503 Service Unavailable when policy evaluation fails
            flow.response = http.Response.make(
                503,
                "Service temporarily unavailable: Policy evaluation failed",
                {"Content-Type": "text/plain"}
            )