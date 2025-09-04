#!/usr/bin/env python3
"""
Input validation for Docker MITM Bridge
Provides security validation for user inputs to prevent injection attacks
"""

import re
import ipaddress
from typing import Optional


def validate_network_name(name: str) -> bool:
    """
    Validate Docker network name
    - Must be 1-63 characters
    - Can contain lowercase letters, numbers, and hyphens
    - Must start with a letter or number
    - Must end with a letter or number
    """
    if not name or len(name) > 63:
        return False
    
    # Docker network name pattern
    pattern = r'^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$'
    return bool(re.match(pattern, name.lower()))


def validate_container_name(name: str) -> bool:
    """
    Validate Docker container name
    - Must be 1-255 characters
    - Can contain letters, numbers, underscores, periods, and hyphens
    - Must start with a letter, number, or underscore
    """
    if not name or len(name) > 255:
        return False
    
    # Docker container name pattern
    pattern = r'^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$'
    return bool(re.match(pattern, name))


def validate_subnet(subnet: str) -> bool:
    """
    Validate IPv4 subnet in CIDR notation
    - Must be valid CIDR format (e.g., 172.30.0.0/16)
    - Must be a private network range
    """
    try:
        # Check for CIDR notation
        if '/' not in subnet:
            return False
        
        network = ipaddress.IPv4Network(subnet, strict=False)
        
        # Check if it's a private network
        # RFC 1918 private ranges:
        # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        private_networks = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
        ]
        
        # Check if the network is within any private range
        for private_net in private_networks:
            if network.overlaps(private_net):
                return True
        
        return False
        
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False


def validate_port(port: int) -> bool:
    """
    Validate TCP/UDP port number
    - Must be between 1 and 65535
    """
    return isinstance(port, int) and 1 <= port <= 65535


def sanitize_path(path: str) -> Optional[str]:
    """
    Sanitize file path to prevent directory traversal
    Returns sanitized path or None if invalid
    """
    if not path:
        return None
    
    # List of dangerous path components that should never appear
    dangerous_components = [
        'etc', 'passwd', 'shadow', 'proc', 'sys', 'dev',
        'windows', 'system32', 'config', 'boot', 'root',
        'bin', 'sbin', 'usr', 'var', 'tmp', 'home'
    ]
    
    # Remove any null bytes first
    sanitized = path.replace('\x00', '')
    
    # Remove all directory traversal attempts more thoroughly
    while '../' in sanitized or '..\\' in sanitized:
        sanitized = sanitized.replace('../', '').replace('..\\', '')
    
    # Also remove leading slashes that could escape to root
    while sanitized.startswith('/'):
        sanitized = sanitized[1:]
    
    # Remove Windows drive letters
    if len(sanitized) > 2 and sanitized[1] == ':':
        sanitized = sanitized[2:].lstrip('\\/')
    
    # Check for dangerous path components
    path_lower = sanitized.lower()
    for dangerous in dangerous_components:
        if dangerous in path_lower:
            return None  # Reject paths containing dangerous components
    
    # Final check - if it still contains suspicious patterns, reject it
    if '..' in sanitized or sanitized.startswith('/'):
        return None
    
    return sanitized


def validate_policy_dir(path: str) -> bool:
    """
    Validate OPA policy directory path
    - Must not contain directory traversal
    - Must be a relative path or absolute path without suspicious patterns
    """
    if not path:
        return False
    
    # Check for directory traversal
    if '..' in path or '\x00' in path:
        return False
    
    # Allow relative paths and absolute paths
    # but not paths with suspicious patterns
    suspicious_patterns = [
        '/etc/',
        '/proc/',
        '/sys/',
        '/dev/',
        'C:\\Windows',
        'C:\\System',
    ]
    
    path_lower = path.lower()
    for pattern in suspicious_patterns:
        if pattern.lower() in path_lower:
            return False
    
    return True


class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass


def validate_config(config: dict) -> dict:
    """
    Validate entire configuration dictionary
    Raises ValidationError if any validation fails
    Returns validated config
    """
    errors = []
    
    # Validate network configuration
    if 'network' in config:
        if 'name' in config['network']:
            if not validate_network_name(config['network']['name']):
                errors.append(f"Invalid network name: {config['network']['name']}")
        
        if 'subnet' in config['network']:
            if not validate_subnet(config['network']['subnet']):
                errors.append(f"Invalid subnet: {config['network']['subnet']}")
    
    # Validate proxy configuration
    if 'proxy' in config:
        if 'container_name' in config['proxy']:
            if not validate_container_name(config['proxy']['container_name']):
                errors.append(f"Invalid container name: {config['proxy']['container_name']}")
        
        if 'listen_port' in config['proxy']:
            if not validate_port(config['proxy']['listen_port']):
                errors.append(f"Invalid listen port: {config['proxy']['listen_port']}")
        
        if 'web_port' in config['proxy']:
            if not validate_port(config['proxy']['web_port']):
                errors.append(f"Invalid web port: {config['proxy']['web_port']}")
    
    # Validate OPA configuration
    if 'opa' in config:
        if 'policy_dir' in config['opa']:
            if not validate_policy_dir(config['opa']['policy_dir']):
                errors.append(f"Invalid policy directory: {config['opa']['policy_dir']}")
    
    if errors:
        raise ValidationError("Configuration validation failed:\n" + "\n".join(errors))
    
    return config