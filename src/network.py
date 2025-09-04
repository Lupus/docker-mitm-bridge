#!/usr/bin/env python3
"""
Network management for Docker MITM Bridge
"""

import docker
import sys
from typing import Optional, Dict, Any
from validators import validate_network_name, validate_subnet, ValidationError


class NetworkManager:
    def __init__(self, network_name: str = "mitm-filtered", subnet: str = "172.30.0.0/16"):
        # Validate inputs to prevent injection attacks
        if not validate_network_name(network_name):
            raise ValidationError(f"Invalid network name: {network_name}")
        if not validate_subnet(subnet):
            raise ValidationError(f"Invalid subnet: {subnet}")
        
        self.client = docker.from_env()
        self.network_name = network_name
        self.subnet = subnet
        
    def network_exists(self) -> bool:
        """Check if the network already exists"""
        try:
            self.client.networks.get(self.network_name)
            return True
        except docker.errors.NotFound:
            return False
            
    def create_network(self) -> Dict[str, Any]:
        """Create the external network for filtered containers"""
        if self.network_exists():
            return {"status": "exists", "message": f"Network '{self.network_name}' already exists"}
            
        try:
            # Create IPAM config for the subnet
            ipam_pool = docker.types.IPAMPool(
                subnet=self.subnet
            )
            ipam_config = docker.types.IPAMConfig(
                pool_configs=[ipam_pool]
            )
            
            # Create the network
            network = self.client.networks.create(
                name=self.network_name,
                driver="bridge",
                internal=True,  # No direct internet access
                ipam=ipam_config,
                labels={
                    "managed-by": "docker-mitm-bridge",
                    "purpose": "filtered-network"
                }
            )
            
            return {
                "status": "created",
                "message": f"Network '{self.network_name}' created successfully",
                "network_id": network.id
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to create network: {str(e)}"
            }
            
    def remove_network(self) -> Dict[str, Any]:
        """Remove the network (will fail if containers are connected)"""
        if not self.network_exists():
            return {"status": "not_found", "message": f"Network '{self.network_name}' does not exist"}
            
        try:
            network = self.client.networks.get(self.network_name)
            network.remove()
            return {
                "status": "removed",
                "message": f"Network '{self.network_name}' removed successfully"
            }
        except docker.errors.APIError as e:
            if "has active endpoints" in str(e):
                return {
                    "status": "error",
                    "message": f"Cannot remove network: containers are still connected"
                }
            return {
                "status": "error",
                "message": f"Failed to remove network: {str(e)}"
            }
            
    def get_network_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the network"""
        if not self.network_exists():
            return None
            
        try:
            network = self.client.networks.get(self.network_name)
            containers = []
            
            # Get connected containers
            for container_id, container_info in network.attrs.get('Containers', {}).items():
                containers.append({
                    'id': container_id[:12],
                    'name': container_info.get('Name', 'unknown'),
                    'ipv4': container_info.get('IPv4Address', '').split('/')[0]
                })
                
            return {
                'id': network.id[:12],
                'name': network.name,
                'driver': network.attrs.get('Driver'),
                'internal': network.attrs.get('Internal', False),
                'ipam': network.attrs.get('IPAM', {}),
                'containers': containers,
                'container_count': len(containers),
                'labels': network.attrs.get('Labels', {})
            }
            
        except Exception as e:
            return None
            
    def list_connected_containers(self) -> list:
        """List all containers connected to the network"""
        info = self.get_network_info()
        if info:
            return info.get('containers', [])
        return []


if __name__ == "__main__":
    # Test the network manager
    nm = NetworkManager()
    
    print("Network exists:", nm.network_exists())
    print("Creating network:", nm.create_network())
    print("Network info:", nm.get_network_info())