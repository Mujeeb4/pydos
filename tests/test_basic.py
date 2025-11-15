"""
Unit tests for DDoS Detection System

Run with: pytest tests/test_basic.py -v
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from src.utils import (
    validate_ip_address,
    is_private_or_localhost,
    format_bytes,
    read_json_file,
    write_json_file
)


class TestIPValidation:
    """Test IP address validation functions."""
    
    def test_valid_ipv4_addresses(self):
        """Test that valid IPv4 addresses are recognized."""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "127.0.0.1",
            "8.8.8.8",
            "255.255.255.255"
        ]
        for ip in valid_ips:
            assert validate_ip_address(ip), f"{ip} should be valid"
    
    def test_invalid_ip_addresses(self):
        """Test that invalid IP addresses are rejected."""
        invalid_ips = [
            "256.1.1.1",
            "192.168.1",
            "invalid",
            "",
            "192.168.1.1.1"
        ]
        for ip in invalid_ips:
            assert not validate_ip_address(ip), f"{ip} should be invalid"
    
    def test_private_ip_detection(self):
        """Test private IP address detection."""
        private_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1"
        ]
        for ip in private_ips:
            assert is_private_or_localhost(ip), f"{ip} should be private/localhost"
    
    def test_public_ip_detection(self):
        """Test public IP address detection."""
        public_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "151.101.1.140"
        ]
        for ip in public_ips:
            assert not is_private_or_localhost(ip), f"{ip} should be public"


class TestUtilityFunctions:
    """Test utility helper functions."""
    
    def test_format_bytes(self):
        """Test byte formatting."""
        assert "100.00 B" in format_bytes(100)
        assert "KB" in format_bytes(1024)
        assert "MB" in format_bytes(1024 * 1024)
        assert "GB" in format_bytes(1024 * 1024 * 1024)
    
    def test_read_nonexistent_json(self):
        """Test reading non-existent JSON file returns default."""
        result = read_json_file("/nonexistent/file.json", {"default": True})
        assert result == {"default": True}
    
    def test_write_and_read_json(self, tmp_path):
        """Test writing and reading JSON files."""
        test_file = tmp_path / "test.json"
        test_data = {"key": "value", "number": 42}
        
        # Write data
        assert write_json_file(str(test_file), test_data)
        
        # Read back
        result = read_json_file(str(test_file))
        assert result == test_data


class TestMitigator:
    """Test Mitigator class (basic tests only)."""
    
    def test_mitigator_initialization(self):
        """Test that Mitigator can be initialized."""
        from src.mitigator import Mitigator
        
        mitigator = Mitigator()
        assert mitigator is not None
        assert mitigator.get_blocked_count() == 0
    
    def test_block_tracking(self):
        """Test that blocked IPs are tracked correctly."""
        from src.mitigator import Mitigator
        
        mitigator = Mitigator()
        
        # Simulated block (won't actually use iptables)
        mitigator.block_ip("192.168.1.100")
        
        assert mitigator.is_blocked("192.168.1.100")
        assert mitigator.get_blocked_count() == 1
        assert "192.168.1.100" in mitigator.get_blocked_ips()


class TestAnalyzer:
    """Test TrafficAnalyzer class."""
    
    def test_analyzer_initialization(self):
        """Test that TrafficAnalyzer can be initialized."""
        from src.analyzer import TrafficAnalyzer
        
        analyzer = TrafficAnalyzer()
        assert analyzer is not None
        assert len(analyzer.traffic_history) == 0
    
    def test_add_traffic_snapshot(self):
        """Test adding traffic snapshots."""
        from src.analyzer import TrafficAnalyzer
        
        analyzer = TrafficAnalyzer()
        analyzer.add_traffic_snapshot(
            {'192.168.1.1': 100, '192.168.1.2': 50},
            {'192.168.1.1': 50}
        )
        
        assert len(analyzer.traffic_history) == 1
        assert analyzer.ip_statistics['192.168.1.1']['total_packets'] == 100
    
    def test_get_top_talkers(self):
        """Test getting top talkers."""
        from src.analyzer import TrafficAnalyzer
        
        analyzer = TrafficAnalyzer()
        analyzer.add_traffic_snapshot(
            {'192.168.1.1': 100, '192.168.1.2': 50, '192.168.1.3': 75},
            {}
        )
        
        top_talkers = analyzer.get_top_talkers(2)
        assert len(top_talkers) == 2
        assert top_talkers[0][0] == '192.168.1.1'  # Highest count
        assert top_talkers[0][1] == 100


class TestLogger:
    """Test logging functionality."""
    
    def test_logger_initialization(self):
        """Test that logger can be initialized."""
        from src.logger import get_logger
        
        logger = get_logger()
        assert logger is not None
    
    def test_log_system_event(self):
        """Test logging system events."""
        from src.logger import get_logger
        
        logger = get_logger()
        # Should not raise exception
        logger.log_system_event("Test event")


if __name__ == "__main__":
    print("Run tests with: pytest tests/test_basic.py -v")
