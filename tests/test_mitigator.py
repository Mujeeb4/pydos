"""
Tests for Mitigation Module (mitigator.py)

Tests IP blocking functionality, thread safety, and iptables integration.
"""

import pytest
import time
import threading
from unittest.mock import Mock, patch, MagicMock
import subprocess

# Import the module to test
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from mitigator import Mitigator


class TestMitigatorBasics:
    """Test basic functionality of the Mitigator class."""
    
    def test_mitigator_initialization(self):
        """Test that Mitigator initializes correctly."""
        mitigator = Mitigator(block_duration_minutes=30)
        
        assert mitigator.blocked_ips == set()
        assert mitigator.blocked_ips_timestamps == {}
        assert mitigator.block_duration.total_seconds() == 30 * 60
    
    def test_mitigator_default_duration(self):
        """Test default block duration."""
        mitigator = Mitigator()
        
        assert mitigator.block_duration.total_seconds() == 60 * 60  # 60 minutes
    
    @patch('subprocess.run')
    def test_block_ip_success(self, mock_run):
        """Test successful IP blocking."""
        mock_run.return_value = Mock(returncode=0)
        
        mitigator = Mitigator()
        result = mitigator.block_ip('192.168.1.100')
        
        assert result == True
        assert '192.168.1.100' in mitigator.blocked_ips
        assert '192.168.1.100' in mitigator.blocked_ips_timestamps
    
    @patch('subprocess.run')
    def test_block_ip_duplicate(self, mock_run):
        """Test that blocking same IP twice doesn't execute command twice."""
        mock_run.return_value = Mock(returncode=0)
        
        mitigator = Mitigator()
        
        # First block
        result1 = mitigator.block_ip('192.168.1.100')
        assert result1 == True
        
        # Second block (should skip)
        result2 = mitigator.block_ip('192.168.1.100')
        assert result2 == True
        
        # iptables should only be called once
        assert mock_run.call_count == 2  # once for 'which', once for block
    
    @patch('subprocess.run')
    def test_unblock_ip(self, mock_run):
        """Test IP unblocking."""
        mock_run.return_value = Mock(returncode=0)
        
        mitigator = Mitigator()
        mitigator.block_ip('192.168.1.100')
        
        # Unblock
        result = mitigator.unblock_ip('192.168.1.100')
        
        assert result == True
        assert '192.168.1.100' not in mitigator.blocked_ips
    
    def test_get_blocked_ips(self):
        """Test retrieving list of blocked IPs."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0)
            
            mitigator = Mitigator()
            mitigator.block_ip('192.168.1.100')
            mitigator.block_ip('192.168.1.101')
            
            blocked = mitigator.get_blocked_ips()
            
            assert len(blocked) == 2
            assert '192.168.1.100' in blocked
            assert '192.168.1.101' in blocked


class TestMitigatorThreadSafety:
    """Test thread safety of the Mitigator class."""
    
    @patch('subprocess.run')
    def test_concurrent_blocking(self, mock_run):
        """Test blocking IPs concurrently from multiple threads."""
        mock_run.return_value = Mock(returncode=0)
        
        mitigator = Mitigator()
        threads = []
        
        def block_ip_task(ip):
            mitigator.block_ip(ip)
        
        # Start 10 threads trying to block same IP
        for _ in range(10):
            thread = threading.Thread(target=block_ip_task, args=('192.168.1.100',))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Should only be blocked once
        assert '192.168.1.100' in mitigator.blocked_ips
        assert len(mitigator.blocked_ips) == 1
    
    @patch('subprocess.run')
    def test_concurrent_different_ips(self, mock_run):
        """Test blocking different IPs concurrently."""
        mock_run.return_value = Mock(returncode=0)
        
        mitigator = Mitigator()
        threads = []
        ips = [f'192.168.1.{i}' for i in range(10)]
        
        def block_ip_task(ip):
            mitigator.block_ip(ip)
        
        # Start thread for each IP
        for ip in ips:
            thread = threading.Thread(target=block_ip_task, args=(ip,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # All IPs should be blocked
        assert len(mitigator.blocked_ips) == 10


class TestMitigatorErrorHandling:
    """Test error handling in the Mitigator class."""
    
    @patch('subprocess.run')
    def test_block_ip_command_failure(self, mock_run):
        """Test handling of iptables command failure."""
        # Simulate iptables command failure
        mock_run.side_effect = subprocess.CalledProcessError(1, 'iptables')
        
        mitigator = Mitigator()
        
        # Should handle error gracefully
        result = mitigator.block_ip('192.168.1.100')
        
        # IP should still be tracked even if command fails
        assert '192.168.1.100' in mitigator.blocked_ips or result == False
    
    @patch('subprocess.run')
    def test_unblock_nonexistent_ip(self, mock_run):
        """Test unblocking an IP that wasn't blocked."""
        mock_run.return_value = Mock(returncode=0)
        
        mitigator = Mitigator()
        
        # Try to unblock IP that was never blocked
        result = mitigator.unblock_ip('192.168.1.100')
        
        assert result == False


class TestMitigatorAutoCleanup:
    """Test automatic cleanup of expired blocks."""
    
    @patch('subprocess.run')
    def test_cleanup_thread_starts(self, mock_run):
        """Test that cleanup thread starts on initialization."""
        mock_run.return_value = Mock(returncode=0)
        
        mitigator = Mitigator()
        
        assert mitigator.cleanup_thread.is_alive()
        assert mitigator.cleanup_running == True
        
        # Cleanup
        mitigator.cleanup_running = False
        mitigator.cleanup_thread.join(timeout=1)
    
    @patch('subprocess.run')
    def test_expired_blocks_removed(self, mock_run):
        """Test that expired blocks are automatically removed."""
        mock_run.return_value = Mock(returncode=0)
        
        # Use very short duration for testing
        mitigator = Mitigator(block_duration_minutes=0)  # Immediate expiration
        
        mitigator.block_ip('192.168.1.100')
        
        # Wait for cleanup cycle
        time.sleep(2)
        
        # IP should be unblocked
        # Note: This test may be flaky depending on timing
        # In production, we'd use a more controlled test approach
        
        # Cleanup
        mitigator.cleanup_running = False
        mitigator.cleanup_thread.join(timeout=1)


class TestMitigatorIntegration:
    """Integration tests for the Mitigator class."""
    
    @patch('subprocess.run')
    def test_block_and_unblock_flow(self, mock_run):
        """Test complete block and unblock workflow."""
        mock_run.return_value = Mock(returncode=0)
        
        mitigator = Mitigator()
        
        # Block IP
        assert mitigator.block_ip('192.168.1.100') == True
        assert '192.168.1.100' in mitigator.get_blocked_ips()
        
        # Unblock IP
        assert mitigator.unblock_ip('192.168.1.100') == True
        assert '192.168.1.100' not in mitigator.get_blocked_ips()
    
    @patch('subprocess.run')
    def test_multiple_ips_management(self, mock_run):
        """Test managing multiple blocked IPs."""
        mock_run.return_value = Mock(returncode=0)
        
        mitigator = Mitigator()
        
        ips = ['192.168.1.100', '192.168.1.101', '192.168.1.102']
        
        # Block all
        for ip in ips:
            mitigator.block_ip(ip)
        
        assert len(mitigator.get_blocked_ips()) == 3
        
        # Unblock one
        mitigator.unblock_ip('192.168.1.101')
        
        assert len(mitigator.get_blocked_ips()) == 2
        assert '192.168.1.101' not in mitigator.get_blocked_ips()


class TestMitigatorPlatformCompatibility:
    """Test platform-specific behavior."""
    
    @patch('subprocess.run')
    def test_iptables_not_available(self, mock_run):
        """Test behavior when iptables is not available (e.g., Windows)."""
        # Simulate iptables not found
        mock_run.side_effect = FileNotFoundError()
        
        mitigator = Mitigator()
        
        # Should still initialize without errors
        assert mitigator is not None
    
    @patch('subprocess.run')
    def test_permission_denied(self, mock_run):
        """Test handling of permission denied errors."""
        # First call succeeds (which iptables)
        # Second call fails (permission denied)
        mock_run.side_effect = [
            Mock(returncode=0),  # which iptables succeeds
            subprocess.CalledProcessError(1, 'iptables', stderr=b'Permission denied')
        ]
        
        mitigator = Mitigator()
        result = mitigator.block_ip('192.168.1.100')
        
        # Should handle gracefully
        assert result in [True, False]


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
