

import ipaddress
import os
import json
import platform
import subprocess
from typing import Optional, Dict, Any, List
from pathlib import Path
from datetime import datetime


def validate_ip_address(ip: str) -> bool:
    """
    Validate if string is a valid IP address.
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_or_localhost(ip: str) -> bool:
    """
    Check if IP is private or localhost.
    
    Args:
        ip (str): IP address to check
        
    Returns:
        bool: True if private/localhost, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        return False


def get_project_root() -> Path:
    """
    Get the project root directory.
    
    Returns:
        Path: Path to project root
    """
    return Path(__file__).parent.parent


def ensure_directory_exists(directory: str) -> bool:
    """
    Ensure a directory exists, create if it doesn't.
    
    Args:
        directory (str): Directory path
        
    Returns:
        bool: True if directory exists or was created, False on error
    """
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception:
        return False


def read_json_file(filepath: str, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Safely read a JSON file.
    
    Args:
        filepath (str): Path to JSON file
        default (dict): Default value if file doesn't exist or is invalid
        
    Returns:
        dict: JSON data or default value
    """
    if default is None:
        default = {}
    
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError):
        pass
    
    return default


def write_json_file(filepath: str, data: Dict[str, Any], indent: int = 2) -> bool:
    """
    Safely write data to a JSON file.
    
    Args:
        filepath (str): Path to JSON file
        data (dict): Data to write
        indent (int): JSON indentation level
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=indent)
        return True
    except (IOError, TypeError):
        return False


def format_bytes(bytes_count: int) -> str:
    """
    Format byte count to human readable string.
    
    Args:
        bytes_count (int): Number of bytes
        
    Returns:
        str: Formatted string (e.g., "1.5 KB", "2.3 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def format_timestamp(timestamp: Optional[datetime] = None) -> str:
    """
    Format timestamp to standard string.
    
    Args:
        timestamp (datetime): Timestamp to format (default: now)
        
    Returns:
        str: Formatted timestamp string
    """
    if timestamp is None:
        timestamp = datetime.now()
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def calculate_uptime(start_time: datetime) -> str:
    """
    Calculate uptime from start time.
    
    Args:
        start_time (datetime): Start timestamp
        
    Returns:
        str: Formatted uptime string (e.g., "2:15:30")
    """
    uptime = datetime.now() - start_time
    return str(uptime).split('.')[0]  # Remove microseconds


def get_network_interfaces() -> List[Dict[str, str]]:
    """
    Get list of available network interfaces on the system.
    
    Returns:
        list: List of dictionaries containing interface info (name, status, type)
    """
    interfaces = []
    system = platform.system()
    
    try:
        if system == "Linux":
            # Use ip command to get interfaces
            result = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                    
                parts = line.split(': ')
                if len(parts) >= 2:
                    iface_name = parts[1].split('@')[0]  # Remove @if123 suffix
                    
                    # Skip loopback interface
                    if iface_name == 'lo':
                        continue
                    
                    # Determine if interface is up
                    is_up = 'UP' in line and 'state UP' in line
                    
                    # Determine interface type
                    iface_type = 'unknown'
                    if iface_name.startswith('eth') or iface_name.startswith('enp'):
                        iface_type = 'ethernet'
                    elif iface_name.startswith('wl') or iface_name.startswith('wlp'):
                        iface_type = 'wireless'
                    elif iface_name.startswith('docker') or iface_name.startswith('br-'):
                        iface_type = 'virtual'
                    elif iface_name.startswith('veth'):
                        iface_type = 'virtual'
                    
                    interfaces.append({
                        'name': iface_name,
                        'status': 'up' if is_up else 'down',
                        'type': iface_type
                    })
        
        elif system == "Windows":
            # Use ipconfig to get interfaces
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse Windows interface names (simplified)
            for line in result.stdout.split('\n'):
                if 'adapter' in line.lower():
                    # Extract interface name
                    parts = line.split('adapter')
                    if len(parts) >= 2:
                        iface_name = parts[1].strip().rstrip(':')
                        interfaces.append({
                            'name': iface_name,
                            'status': 'unknown',
                            'type': 'unknown'
                        })
    
    except Exception as e:
        # Fallback: return empty list if detection fails
        pass
    
    return interfaces


def get_default_network_interface() -> Optional[str]:
    """
    Automatically detect the default/active network interface.
    
    Returns:
        str: Name of default network interface, or None if detection fails
    """
    interfaces = get_network_interfaces()
    
    if not interfaces:
        return None
    
    # Priority order:
    # 1. First active (up) ethernet interface
    # 2. First active wireless interface
    # 3. First active interface of any type
    # 4. First interface regardless of status
    
    # Check for active ethernet
    for iface in interfaces:
        if iface['status'] == 'up' and iface['type'] == 'ethernet':
            return iface['name']
    
    # Check for active wireless
    for iface in interfaces:
        if iface['status'] == 'up' and iface['type'] == 'wireless':
            return iface['name']
    
    # Check for any active non-virtual interface
    for iface in interfaces:
        if iface['status'] == 'up' and iface['type'] != 'virtual':
            return iface['name']
    
    # Check for any active interface
    for iface in interfaces:
        if iface['status'] == 'up':
            return iface['name']
    
    # Return first interface regardless of status
    return interfaces[0]['name'] if interfaces else None


# Test the module if run directly
if __name__ == "__main__":
    print("="*70)
    print("TESTING UTILITY FUNCTIONS")
    print("="*70)
    print()
    
    # Test IP validation
    print("Test 1: IP address validation")
    test_ips = ["192.168.1.1", "10.0.0.1", "256.1.1.1", "invalid", "8.8.8.8"]
    for ip in test_ips:
        valid = validate_ip_address(ip)
        private = is_private_or_localhost(ip) if valid else False
        print(f"  {ip:20} - Valid: {valid:5} Private/Localhost: {private}")
    
    print()
    print("Test 2: Project root")
    print(f"  Project root: {get_project_root()}")
    
    print()
    print("Test 3: Format bytes")
    test_sizes = [100, 1024, 1024*1024, 1024*1024*1024]
    for size in test_sizes:
        print(f"  {size:15} bytes = {format_bytes(size)}")
    
    print()
    print("Test 4: Timestamp formatting")
    print(f"  Current time: {format_timestamp()}")
    
    print()
    print("Test 5: Uptime calculation")
    from datetime import timedelta
    past_time = datetime.now() - timedelta(hours=2, minutes=30, seconds=45)
    print(f"  Uptime: {calculate_uptime(past_time)}")
    
    print()
    print("Test 6: Network interface detection")
    interfaces = get_network_interfaces()
    print(f"  Found {len(interfaces)} network interface(s):")
    for iface in interfaces:
        print(f"    - {iface['name']:20} Status: {iface['status']:10} Type: {iface['type']}")
    
    default_iface = get_default_network_interface()
    print(f"\n  Default interface: {default_iface}")
    
    print()
    print("="*70)
    print("ALL TESTS COMPLETE")
    print("="*70)
