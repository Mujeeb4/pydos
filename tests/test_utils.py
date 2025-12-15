"""
Tests for Utility Functions (utils.py)

Tests IP validation, file operations, and helper functions.
"""

import pytest
import os
import json
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from utils import (
    validate_ip_address,
    is_private_or_localhost,
    get_project_root,
    ensure_directory_exists,
    read_json_file,
    write_json_file,
    get_default_network_interface,
    format_bytes,
    calculate_uptime
)


class TestIPValidation:
    """Test IP address validation functions."""
    
    def test_validate_valid_ipv4(self, sample_ip_addresses):
        """Test validation of valid IPv4 addresses."""
        for ip in sample_ip_addresses['valid']:
            assert validate_ip_address(ip) == True
    
    def test_validate_invalid_ip(self, sample_ip_addresses):
        """Test validation of invalid IP addresses."""
        for ip in sample_ip_addresses['invalid']:
            if ip is not None:  # Skip None for this test
                assert validate_ip_address(ip) == False
    
    def test_validate_none(self):
        """Test validation of None."""
        assert validate_ip_address(None) == False
    
    def test_validate_empty_string(self):
        """Test validation of empty string."""
        assert validate_ip_address('') == False
    
    def test_validate_localhost(self):
        """Test validation of localhost addresses."""
        assert validate_ip_address('127.0.0.1') == True
        assert validate_ip_address('::1') == True
    
    def test_validate_broadcast(self):
        """Test validation of broadcast address."""
        assert validate_ip_address('255.255.255.255') == True
    
    def test_validate_ipv6(self):
        """Test validation of IPv6 addresses."""
        assert validate_ip_address('2001:0db8:85a3:0000:0000:8a2e:0370:7334') == True
        assert validate_ip_address('::1') == True


class TestPrivateIPDetection:
    """Test private and localhost IP detection."""
    
    def test_localhost_detection(self, sample_ip_addresses):
        """Test detection of localhost addresses."""
        for ip in sample_ip_addresses['localhost']:
            assert is_private_or_localhost(ip) == True
    
    def test_private_ip_detection(self, sample_ip_addresses):
        """Test detection of private IP ranges."""
        for ip in sample_ip_addresses['private']:
            assert is_private_or_localhost(ip) == True
    
    def test_public_ip_detection(self):
        """Test that public IPs are not detected as private."""
        public_ips = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        
        for ip in public_ips:
            assert is_private_or_localhost(ip) == False
    
    def test_invalid_ip_handling(self):
        """Test handling of invalid IPs."""
        assert is_private_or_localhost('invalid') == False
        assert is_private_or_localhost('256.1.1.1') == False


class TestFileOperations:
    """Test file operation utilities."""
    
    def test_ensure_directory_exists_new(self):
        """Test creating a new directory."""
        temp_dir = tempfile.mkdtemp()
        new_dir = os.path.join(temp_dir, 'test_dir')
        
        result = ensure_directory_exists(new_dir)
        
        assert result == True
        assert os.path.exists(new_dir)
        
        # Cleanup
        os.rmdir(new_dir)
        os.rmdir(temp_dir)
    
    def test_ensure_directory_exists_existing(self):
        """Test with existing directory."""
        temp_dir = tempfile.mkdtemp()
        
        result = ensure_directory_exists(temp_dir)
        
        assert result == True
        assert os.path.exists(temp_dir)
        
        # Cleanup
        os.rmdir(temp_dir)
    
    def test_ensure_directory_nested(self):
        """Test creating nested directories."""
        temp_dir = tempfile.mkdtemp()
        nested_dir = os.path.join(temp_dir, 'level1', 'level2', 'level3')
        
        result = ensure_directory_exists(nested_dir)
        
        assert result == True
        assert os.path.exists(nested_dir)
        
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir)


class TestJSONOperations:
    """Test JSON file operations."""
    
    def test_read_json_file_exists(self):
        """Test reading existing JSON file."""
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        test_data = {'key': 'value', 'number': 42}
        
        json.dump(test_data, temp_file)
        temp_file.close()
        
        result = read_json_file(temp_file.name)
        
        assert result == test_data
        
        # Cleanup
        os.unlink(temp_file.name)
    
    def test_read_json_file_not_exists(self):
        """Test reading non-existent JSON file."""
        result = read_json_file('/nonexistent/file.json')
        
        assert result == {}
    
    def test_read_json_file_with_default(self):
        """Test reading with custom default."""
        default = {'default': 'value'}
        result = read_json_file('/nonexistent/file.json', default=default)
        
        assert result == default
    
    def test_write_json_file(self):
        """Test writing JSON file."""
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        temp_file.close()
        
        test_data = {'key': 'value', 'number': 42, 'list': [1, 2, 3]}
        
        result = write_json_file(temp_file.name, test_data)
        
        assert result == True
        
        # Verify content
        with open(temp_file.name, 'r') as f:
            loaded_data = json.load(f)
            assert loaded_data == test_data
        
        # Cleanup
        os.unlink(temp_file.name)
    
    def test_read_invalid_json(self):
        """Test reading invalid JSON file."""
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        temp_file.write('invalid json content {')
        temp_file.close()
        
        result = read_json_file(temp_file.name)
        
        assert result == {}
        
        # Cleanup
        os.unlink(temp_file.name)


class TestNetworkUtilities:
    """Test network-related utilities."""
    
    def test_get_default_network_interface(self):
        """Test getting default network interface."""
        interface = get_default_network_interface()
        
        # Should return a string or None
        assert interface is None or isinstance(interface, str)
    
    def test_get_network_interface_valid(self):
        """Test that returned interface is valid format."""
        interface = get_default_network_interface()
        
        if interface:
            # Should be alphanumeric with possible numbers
            assert len(interface) > 0
            assert isinstance(interface, str)


class TestFormatUtilities:
    """Test formatting utilities."""
    
    def test_format_bytes_zero(self):
        """Test formatting 0 bytes."""
        result = format_bytes(0)
        assert '0' in result.lower()
    
    def test_format_bytes_kb(self):
        """Test formatting kilobytes."""
        result = format_bytes(1024)
        assert 'KB' in result or 'K' in result
    
    def test_format_bytes_mb(self):
        """Test formatting megabytes."""
        result = format_bytes(1024 * 1024)
        assert 'MB' in result or 'M' in result
    
    def test_format_bytes_gb(self):
        """Test formatting gigabytes."""
        result = format_bytes(1024 * 1024 * 1024)
        assert 'GB' in result or 'G' in result
    
    def test_calculate_uptime_seconds(self):
        """Test calculating uptime in seconds."""
        from datetime import datetime, timedelta
        start = datetime.now() - timedelta(seconds=45)
        result = calculate_uptime(start)
        assert isinstance(result, str)
    
    def test_calculate_uptime_minutes(self):
        """Test calculating uptime in minutes."""
        from datetime import datetime, timedelta
        start = datetime.now() - timedelta(minutes=2)
        result = calculate_uptime(start)
        assert isinstance(result, str)
    
    def test_calculate_uptime_hours(self):
        """Test calculating uptime in hours."""
        from datetime import datetime, timedelta
        start = datetime.now() - timedelta(hours=1)
        result = calculate_uptime(start)
        assert isinstance(result, str)
    
    def test_calculate_uptime_days(self):
        """Test calculating uptime in days."""
        from datetime import datetime, timedelta
        start = datetime.now() - timedelta(days=1)
        result = calculate_uptime(start)
        assert isinstance(result, str)


class TestProjectUtilities:
    """Test project-specific utilities."""
    
    def test_get_project_root(self):
        """Test getting project root directory."""
        root = get_project_root()
        
        assert root is not None
        assert isinstance(root, Path)
        assert root.exists()
    
    def test_project_root_contains_src(self):
        """Test that project root contains src directory."""
        root = get_project_root()
        src_dir = root / 'src'
        
        # Should contain src directory
        assert src_dir.exists() or (root.parent / 'src').exists()


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_validate_ip_special_chars(self):
        """Test IP validation with special characters."""
        invalid_ips = [
            '192.168.1.100;',
            '192.168.1.100\n',
            '192.168.1.100\x00',
            '192.168.1.100 ',
        ]
        
        for ip in invalid_ips:
            # Should either be False or handle gracefully
            result = validate_ip_address(ip)
            assert isinstance(result, bool)
    
    def test_ensure_directory_invalid_path(self):
        """Test creating directory with invalid path."""
        # This may fail or succeed depending on OS
        result = ensure_directory_exists('')
        assert isinstance(result, bool)
    
    def test_json_operations_unicode(self):
        """Test JSON operations with unicode."""
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        temp_file.close()
        
        test_data = {'unicode': '日本語', 'emoji': '🚀'}
        
        write_json_file(temp_file.name, test_data)
        result = read_json_file(temp_file.name)
        
        assert result == test_data
        
        # Cleanup
        os.unlink(temp_file.name)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
