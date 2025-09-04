#!/usr/bin/env python3
"""
CLI for Docker MITM Bridge
"""

import click
import yaml
import sys
import os
from pathlib import Path
from typing import Dict, Any
from tabulate import tabulate

from network import NetworkManager
from proxy import ProxyManager
from validators import validate_config, ValidationError


def load_config() -> Dict[str, Any]:
    """Load configuration from config.yaml"""
    config_path = Path(__file__).parent.parent / "config.yaml"
    if not config_path.exists():
        click.echo(click.style("Error: config.yaml not found", fg="red"))
        sys.exit(1)
        
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Validate configuration for security
    try:
        return validate_config(config)
    except ValidationError as e:
        click.echo(click.style(f"Configuration validation error: {e}", fg="red"))
        sys.exit(1)


@click.group()
def cli():
    """Docker MITM Bridge - Manage filtered Docker networks with mitmproxy"""
    pass


@cli.command()
def init():
    """Initialize the network and start the boundary proxy"""
    config = load_config()
    
    # Create network
    click.echo("Creating network...")
    nm = NetworkManager(
        network_name=config['network']['name'],
        subnet=config['network']['subnet']
    )
    result = nm.create_network()
    
    if result['status'] == 'error':
        click.echo(click.style(f"✗ {result['message']}", fg="red"))
        sys.exit(1)
    elif result['status'] == 'exists':
        click.echo(click.style(f"ℹ {result['message']}", fg="yellow"))
    else:
        click.echo(click.style(f"✓ {result['message']}", fg="green"))
    
    # Start proxy
    click.echo("Starting boundary proxy...")
    pm = ProxyManager(container_name=config['proxy']['container_name'])
    result = pm.start()
    
    if result['status'] == 'error':
        click.echo(click.style(f"✗ {result['message']}", fg="red"))
        sys.exit(1)
    else:
        click.echo(click.style(f"✓ {result['message']}", fg="green"))
        
    click.echo("")
    click.echo(click.style("Initialization complete!", fg="green", bold=True))
    click.echo(f"Network: {config['network']['name']}")
    click.echo(f"Proxy: http://localhost:{config['proxy']['listen_port']}")


@cli.command()
def start():
    """Start the boundary proxy (network must exist)"""
    config = load_config()
    
    # Check if network exists
    nm = NetworkManager(network_name=config['network']['name'])
    if not nm.network_exists():
        click.echo(click.style(f"✗ Network '{config['network']['name']}' does not exist. Run 'init' first.", fg="red"))
        sys.exit(1)
    
    # Start proxy
    pm = ProxyManager(container_name=config['proxy']['container_name'])
    result = pm.start()
    
    if result['status'] == 'error':
        click.echo(click.style(f"✗ {result['message']}", fg="red"))
        sys.exit(1)
    else:
        click.echo(click.style(f"✓ {result['message']}", fg="green"))


@cli.command()
def stop():
    """Stop the boundary proxy (network remains)"""
    config = load_config()
    
    pm = ProxyManager(container_name=config['proxy']['container_name'])
    result = pm.stop()
    
    if result['status'] == 'error':
        click.echo(click.style(f"✗ {result['message']}", fg="red"))
        sys.exit(1)
    else:
        click.echo(click.style(f"✓ {result['message']}", fg="green"))


@cli.command()
def destroy():
    """Stop proxy and remove network"""
    config = load_config()
    
    # Stop proxy first
    click.echo("Stopping boundary proxy...")
    pm = ProxyManager(container_name=config['proxy']['container_name'])
    result = pm.stop()
    
    if result['status'] == 'error':
        click.echo(click.style(f"⚠ {result['message']}", fg="yellow"))
    else:
        click.echo(click.style(f"✓ {result['message']}", fg="green"))
    
    # Remove network
    click.echo("Removing network...")
    nm = NetworkManager(network_name=config['network']['name'])
    result = nm.remove_network()
    
    if result['status'] == 'error':
        click.echo(click.style(f"✗ {result['message']}", fg="red"))
        sys.exit(1)
    elif result['status'] == 'not_found':
        click.echo(click.style(f"ℹ {result['message']}", fg="yellow"))
    else:
        click.echo(click.style(f"✓ {result['message']}", fg="green"))
        
    click.echo(click.style("Cleanup complete!", fg="green", bold=True))


@cli.command()
def status():
    """Show network and proxy status"""
    config = load_config()
    
    # Network status
    nm = NetworkManager(network_name=config['network']['name'])
    network_info = nm.get_network_info()
    
    click.echo(click.style("Network Status", fg="cyan", bold=True))
    click.echo("=" * 40)
    
    if network_info:
        click.echo(f"Name: {network_info['name']}")
        click.echo(f"ID: {network_info['id']}")
        click.echo(f"Internal: {network_info['internal']}")
        click.echo(f"Connected containers: {network_info['container_count']}")
        if network_info.get('ipam', {}).get('Config'):
            subnet = network_info['ipam']['Config'][0].get('Subnet', 'N/A')
            click.echo(f"Subnet: {subnet}")
    else:
        click.echo(click.style("Network not found", fg="red"))
    
    click.echo("")
    
    # Proxy status
    pm = ProxyManager(container_name=config['proxy']['container_name'])
    proxy_status = pm.get_status()
    
    click.echo(click.style("Proxy Status", fg="cyan", bold=True))
    click.echo("=" * 40)
    
    if proxy_status['exists']:
        status_color = "green" if proxy_status['running'] else "yellow"
        click.echo(f"Status: {click.style(proxy_status['status'], fg=status_color)}")
        click.echo(f"Container ID: {proxy_status['id']}")
        if proxy_status['running']:
            click.echo(f"Memory usage: {proxy_status['memory_usage_mb']} MB")
            click.echo(f"Proxy port: {config['proxy']['listen_port']}")
    else:
        click.echo(click.style("Proxy container not found", fg="red"))


@cli.command()
def list_containers():
    """List all containers in the filtered network"""
    config = load_config()
    
    nm = NetworkManager(network_name=config['network']['name'])
    containers = nm.list_connected_containers()
    
    if not containers:
        click.echo("No containers connected to the network")
        return
    
    # Prepare table data
    table_data = []
    for container in containers:
        table_data.append([
            container['id'],
            container['name'],
            container['ipv4']
        ])
    
    click.echo(click.style(f"Containers in '{config['network']['name']}' network:", fg="cyan", bold=True))
    click.echo(tabulate(table_data, headers=['Container ID', 'Name', 'IP Address'], tablefmt='grid'))


@cli.command()
@click.option('--output', '-o', default='./mitmproxy-ca.crt', help='Output path for CA certificate')
def get_ca(output):
    """Export CA certificate and installation script"""
    config = load_config()
    
    pm = ProxyManager(container_name=config['proxy']['container_name'])
    
    # Check if proxy is running
    if not pm.is_running():
        click.echo(click.style("✗ Proxy is not running. Start it first.", fg="red"))
        sys.exit(1)
    
    # Export certificate
    result = pm.export_ca_cert(output)
    
    if result['status'] == 'error':
        click.echo(click.style(f"✗ {result['message']}", fg="red"))
        sys.exit(1)
    else:
        click.echo(click.style(f"✓ {result['message']}", fg="green"))
        
    # Show installation instructions
    click.echo("")
    click.echo(click.style("Installation Instructions:", fg="cyan", bold=True))
    click.echo("=" * 40)
    click.echo("From inside a container in the filtered network:")
    click.echo("")
    click.echo("  curl -sSL http://mitm-boundary-proxy:8080/install-ca.sh | bash")
    click.echo("")
    click.echo("Or manually install the exported certificate:")
    click.echo(f"  {output}")


@cli.command()
def update_policy():
    """Restart proxy with updated OPA policies"""
    config = load_config()
    
    pm = ProxyManager(container_name=config['proxy']['container_name'])
    
    # Check if proxy is running
    if not pm.is_running():
        click.echo(click.style("✗ Proxy is not running", fg="red"))
        sys.exit(1)
    
    click.echo("Restarting proxy to apply policy changes...")
    result = pm.restart()
    
    if result['status'] == 'error':
        click.echo(click.style(f"✗ {result['message']}", fg="red"))
        sys.exit(1)
    else:
        click.echo(click.style(f"✓ {result['message']}", fg="green"))


@cli.command()
@click.option('--tail', '-n', default=100, help='Number of lines to show')
def logs(tail):
    """Show proxy logs"""
    config = load_config()
    
    pm = ProxyManager(container_name=config['proxy']['container_name'])
    logs = pm.get_logs(tail=tail)
    
    click.echo(logs)


@cli.command()
def config():
    """Show current configuration"""
    config = load_config()
    click.echo(yaml.dump(config, default_flow_style=False))


@cli.command()
def get_compose_snippet():
    """Get docker-compose snippet for external projects"""
    config = load_config()
    
    snippet = f"""# Add this to your docker-compose.yml

networks:
  {config['network']['name']}:
    external: true
    name: {config['network']['name']}

services:
  your-service:
    networks:
      - {config['network']['name']}
    environment:
      - HTTP_PROXY=http://{config['proxy']['container_name']}:{config['proxy']['listen_port']}
      - HTTPS_PROXY=http://{config['proxy']['container_name']}:{config['proxy']['listen_port']}
      - http_proxy=http://{config['proxy']['container_name']}:{config['proxy']['listen_port']}
      - https_proxy=http://{config['proxy']['container_name']}:{config['proxy']['listen_port']}
      - NO_PROXY=localhost,127.0.0.1
      - no_proxy=localhost,127.0.0.1"""
    
    click.echo(snippet)


if __name__ == "__main__":
    cli()