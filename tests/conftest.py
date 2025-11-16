"""
Pytest configuration and fixtures for DDoS Detection System tests

This file contains shared fixtures and configuration for all test modules.
"""

import pytest
import os
import sys
import shutil
import tempfile
from pathlib import Path
from datetime import datetime

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def temp_log_dir():
    """Create a temporary directory for logs during testing."""
    temp_dir = tempfile.mkdtemp(prefix='ddos_test_logs_')
    yield temp_dir
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def clean_stats_file():
    """Ensure stats.json is cleaned up after tests."""
    stats_file = Path(__file__).parent.parent / 'stats.json'
    
    # Backup if exists
    backup_file = None
    if stats_file.exists():
        backup_file = stats_file.with_suffix('.json.backup')
        shutil.copy(stats_file, backup_file)
    
    yield stats_file
    
    # Cleanup
    if stats_file.exists():
        stats_file.unlink()
    
    # Restore backup
    if backup_file and backup_file.exists():
        shutil.copy(backup_file, stats_file)
        backup_file.unlink()


@pytest.fixture
def sample_ip_addresses():
    """Provide sample IP addresses for testing."""
    return {
        'valid': [
            '192.168.1.100',
            '10.0.0.50',
            '172.16.0.1',
            '8.8.8.8'
        ],
        'invalid': [
            'not_an_ip',
            '256.1.1.1',
            '192.168.1',
            '',
            None
        ],
        'localhost': [
            '127.0.0.1',
            '::1'
        ],
        'private': [
            '192.168.1.1',
            '10.0.0.1',
            '172.16.0.1'
        ]
    }


@pytest.fixture
def mock_packet():
    """Create mock packet data for testing."""
    from unittest.mock import Mock
    
    packet = Mock()
    packet.haslayer = Mock(return_value=True)
    
    # Mock IP layer
    ip_layer = Mock()
    ip_layer.src = '192.168.1.100'
    ip_layer.dst = '192.168.1.1'
    packet.__getitem__ = Mock(return_value=ip_layer)
    
    return packet


@pytest.fixture
def mock_tcp_syn_packet():
    """Create mock TCP SYN packet for testing."""
    from unittest.mock import Mock
    
    packet = Mock()
    
    # Mock IP layer
    ip_layer = Mock()
    ip_layer.src = '192.168.1.100'
    ip_layer.dst = '192.168.1.1'
    
    # Mock TCP layer
    tcp_layer = Mock()
    tcp_layer.flags = 'S'  # SYN flag
    tcp_layer.sport = 12345
    tcp_layer.dport = 80
    
    def haslayer(layer_type):
        return True
    
    def getitem(key):
        from scapy.all import IP, TCP
        if key == IP:
            return ip_layer
        elif key == TCP:
            return tcp_layer
        return None
    
    packet.haslayer = haslayer
    packet.__getitem__ = getitem
    
    return packet


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables and state before each test."""
    # Store original environment
    original_env = os.environ.copy()
    
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def test_config():
    """Provide test configuration values."""
    return {
        'NETWORK_INTERFACE': 'lo',
        'PACKET_THRESHOLD': 10,
        'SYN_THRESHOLD': 5,
        'TIME_WINDOW': 1.0,
        'ALLOW_LOOPBACK_DETECTION': True,
        'TESTING_MODE': True,
        'LOG_DIRECTORY': 'test_logs'
    }
