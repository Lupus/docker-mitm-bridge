#!/usr/bin/env python3
"""
Proxy management for Docker MITM Bridge
"""

import docker
import subprocess
import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path
from validators import validate_container_name, ValidationError


class ProxyManager:
    def __init__(self, container_name: str = "mitm-boundary-proxy"):
        # Validate container name to prevent injection attacks
        if not validate_container_name(container_name):
            raise ValidationError(f"Invalid container name: {container_name}")
        
        self.client = docker.from_env()
        self.container_name = container_name
        self.compose_file = Path(__file__).parent.parent / "docker-compose.yml"
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from config.yaml"""
        config_path = self.compose_file.parent / "config.yaml"
        if not config_path.exists():
            return {}
        
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def _prepare_environment(self) -> Dict[str, str]:
        """Prepare environment variables for docker-compose"""
        config = self._load_config()
        env = os.environ.copy()
        
        # Set OPA policy directory from config
        if config.get('opa', {}).get('policy_dir'):
            env['OPA_POLICY_DIR'] = config['opa']['policy_dir']
        
        return env
        
    def container_exists(self) -> bool:
        """Check if the proxy container exists"""
        try:
            self.client.containers.get(self.container_name)
            return True
        except docker.errors.NotFound:
            return False
            
    def is_running(self) -> bool:
        """Check if the proxy container is running"""
        try:
            container = self.client.containers.get(self.container_name)
            return container.status == "running"
        except docker.errors.NotFound:
            return False
            
    def start(self) -> Dict[str, Any]:
        """Start the proxy using docker-compose"""
        try:
            # Change to project directory for docker-compose
            project_dir = self.compose_file.parent
            env = self._prepare_environment()
            
            result = subprocess.run(
                ["docker", "compose", "up", "-d", "--build"],
                cwd=project_dir,
                env=env,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {
                    "status": "started",
                    "message": "Boundary proxy started successfully"
                }
            else:
                return {
                    "status": "error",
                    "message": f"Failed to start proxy: {result.stderr}"
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to start proxy: {str(e)}"
            }
            
    def stop(self) -> Dict[str, Any]:
        """Stop the proxy using docker-compose"""
        try:
            project_dir = self.compose_file.parent
            env = self._prepare_environment()
            
            result = subprocess.run(
                ["docker", "compose", "down"],
                cwd=project_dir,
                env=env,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {
                    "status": "stopped",
                    "message": "Boundary proxy stopped successfully"
                }
            else:
                return {
                    "status": "error",
                    "message": f"Failed to stop proxy: {result.stderr}"
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to stop proxy: {str(e)}"
            }
            
    def restart(self) -> Dict[str, Any]:
        """Restart the proxy (useful for policy updates)"""
        try:
            project_dir = self.compose_file.parent
            env = self._prepare_environment()
            
            result = subprocess.run(
                ["docker", "compose", "restart"],
                cwd=project_dir,
                env=env,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {
                    "status": "restarted",
                    "message": "Boundary proxy restarted successfully"
                }
            else:
                return {
                    "status": "error",
                    "message": f"Failed to restart proxy: {result.stderr}"
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to restart proxy: {str(e)}"
            }
            
    def get_logs(self, tail: int = 100) -> str:
        """Get logs from the proxy container"""
        try:
            container = self.client.containers.get(self.container_name)
            logs = container.logs(tail=tail, timestamps=True)
            return logs.decode('utf-8')
        except docker.errors.NotFound:
            return "Container not found"
        except Exception as e:
            return f"Error getting logs: {str(e)}"
            
    def get_status(self) -> Dict[str, Any]:
        """Get detailed status of the proxy"""
        try:
            container = self.client.containers.get(self.container_name)
            
            # Get container stats
            stats = container.stats(stream=False)
            
            # Calculate memory usage
            memory_stats = stats.get('memory_stats', {})
            memory_usage = memory_stats.get('usage', 0) / (1024 * 1024)  # Convert to MB
            memory_limit = memory_stats.get('limit', 0) / (1024 * 1024)  # Convert to MB
            
            return {
                "exists": True,
                "running": container.status == "running",
                "status": container.status,
                "id": container.id[:12],
                "image": container.image.tags[0] if container.image.tags else "unknown",
                "created": container.attrs['Created'],
                "ports": container.attrs['NetworkSettings']['Ports'],
                "memory_usage_mb": round(memory_usage, 2),
                "memory_limit_mb": round(memory_limit, 2) if memory_limit > 0 else "unlimited"
            }
            
        except docker.errors.NotFound:
            return {
                "exists": False,
                "running": False,
                "status": "not_found"
            }
        except Exception as e:
            return {
                "exists": False,
                "running": False,
                "status": "error",
                "error": str(e)
            }
            
    def export_ca_cert(self, output_path: str = "./mitmproxy-ca.crt") -> Dict[str, Any]:
        """Export the CA certificate from the proxy container"""
        try:
            container = self.client.containers.get(self.container_name)
            
            # Get the certificate from the container
            cert_data, _ = container.exec_run(
                "cat /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem"
            )
            
            # Write to file
            with open(output_path, 'wb') as f:
                f.write(cert_data)
                
            return {
                "status": "exported",
                "message": f"CA certificate exported to {output_path}"
            }
            
        except docker.errors.NotFound:
            return {
                "status": "error",
                "message": "Proxy container not found"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to export certificate: {str(e)}"
            }


if __name__ == "__main__":
    # Test the proxy manager
    pm = ProxyManager()
    
    print("Container exists:", pm.container_exists())
    print("Is running:", pm.is_running())
    print("Status:", pm.get_status())