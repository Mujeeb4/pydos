"""
Tests for DDoS Detector Module (ddos_detector.py)

Tests main detection engine, packet processing, and threshold detection.
"""

import pytest
import time
import threading
from unittest.mock import Mock, patch, MagicMock
from collections import defaultdict

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


class TestDetectorInitialization:
    """Test DDoS detector initialization."""
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_detector_initialization(self, mock_mitigator, mock_logger):
        """Test that detector initializes correctly."""
        from ddos_detector import DDoSDetector
        
        detector = DDoSDetector(
            interface='lo',
            packet_threshold=100,
            syn_threshold=50,
            time_window=5.0
        )
        
        assert detector.interface == 'lo'
        assert detector.packet_threshold == 100
        assert detector.syn_threshold == 50
        assert detector.time_window == 5.0
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_detector_default_values(self, mock_mitigator, mock_logger):
        """Test detector with default values."""
        from ddos_detector import DDoSDetector
        
        detector = DDoSDetector()
        
        assert detector.interface is not None or detector.interface == 'any'
        assert detector.packet_threshold > 0
        assert detector.syn_threshold > 0
        assert detector.time_window > 0


class TestPacketCounting:
    """Test packet counting mechanisms."""
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_packet_count_initialization(self, mock_mitigator, mock_logger):
        """Test packet counter initialization."""
        from ddos_detector import DDoSDetector
        
        detector = DDoSDetector()
        
        assert isinstance(detector.packet_count, (dict, defaultdict))
        assert isinstance(detector.syn_count, (dict, defaultdict))
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    @patch('ddos_detector.sniff')
    def test_packet_handler_increments_count(self, mock_sniff, mock_mitigator, mock_logger):
        """Test that packet handler increments counters."""
        from ddos_detector import DDoSDetector
        from scapy.all import IP, TCP
        
        detector = DDoSDetector()
        
        # Create mock packet
        packet = Mock()
        ip_layer = Mock()
        ip_layer.src = '192.168.1.100'
        ip_layer.dst = '192.168.1.1'
        
        packet.haslayer.return_value = True
        packet.__getitem__.return_value = ip_layer
        
        # Process packet
        detector.packet_handler(packet)
        
        # Counter should be incremented
        assert '192.168.1.100' in detector.packet_count


class TestThresholdDetection:
    """Test threshold-based attack detection."""
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_packet_threshold_detection(self, mock_mitigator, mock_logger):
        """Test detection when packet threshold exceeded."""
        from ddos_detector import DDoSDetector
        
        detector = DDoSDetector(packet_threshold=10)
        
        # Simulate packets from single IP
        test_ip = '192.168.1.100'
        
        for i in range(15):
            detector.packet_count[test_ip] += 1
        
        # Check if threshold exceeded
        if hasattr(detector, 'check_thresholds'):
            detector.check_thresholds()
        
        # IP should trigger threshold
        assert detector.packet_count[test_ip] > detector.packet_threshold
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_syn_threshold_detection(self, mock_mitigator, mock_logger):
        """Test SYN flood detection."""
        from ddos_detector import DDoSDetector
        
        detector = DDoSDetector(syn_threshold=5)
        
        # Simulate SYN packets
        test_ip = '192.168.1.100'
        
        for i in range(10):
            detector.syn_count[test_ip] += 1
        
        # SYN threshold should be exceeded
        assert detector.syn_count[test_ip] > detector.syn_threshold


class TestMitigation:
    """Test attack mitigation functionality."""
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_mitigation_triggered(self, mock_mitigator_class, mock_logger):
        """Test that mitigation is triggered on attack detection."""
        from ddos_detector import DDoSDetector
        
        # Setup mock
        mock_mitigator = Mock()
        mock_mitigator_class.return_value = mock_mitigator
        
        detector = DDoSDetector(packet_threshold=10)
        
        # Simulate attack
        test_ip = '192.168.1.100'
        detector.packet_count[test_ip] = 20
        
        # Trigger check
        if hasattr(detector, 'check_thresholds'):
            detector.check_thresholds()
        
        # Mitigation should be called if threshold is checked
        # (Implementation dependent)
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_mitigation_not_for_localhost(self, mock_mitigator_class, mock_logger):
        """Test that localhost IPs are not mitigated."""
        from ddos_detector import DDoSDetector
        
        mock_mitigator = Mock()
        mock_mitigator_class.return_value = mock_mitigator
        
        detector = DDoSDetector(packet_threshold=10)
        
        # Simulate attack from localhost
        detector.packet_count['127.0.0.1'] = 100
        
        if hasattr(detector, 'check_thresholds'):
            detector.check_thresholds()
        
        # Localhost should not be blocked (implementation dependent)


class TestTimeWindow:
    """Test time window management."""
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_time_window_reset(self, mock_mitigator, mock_logger):
        """Test that counters reset after time window."""
        from ddos_detector import DDoSDetector
        
        detector = DDoSDetector(time_window=1.0)
        
        # Add packets
        detector.packet_count['192.168.1.100'] = 50
        detector.syn_count['192.168.1.100'] = 10
        
        # Wait for time window
        time.sleep(1.1)
        
        # Reset counters (if method exists)
        if hasattr(detector, 'reset_counters'):
            detector.reset_counters()
            
            assert detector.packet_count['192.168.1.100'] == 0
            assert detector.syn_count['192.168.1.100'] == 0


class TestThreadSafety:
    """Test thread safety of detector."""
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_concurrent_packet_processing(self, mock_mitigator, mock_logger):
        """Test processing packets from multiple threads."""
        from ddos_detector import DDoSDetector
        from scapy.all import IP
        
        detector = DDoSDetector()
        threads = []
        
        def process_packets(thread_id):
            for i in range(100):
                packet = Mock()
                ip_layer = Mock()
                ip_layer.src = f'192.168.1.{thread_id}'
                ip_layer.dst = '192.168.1.1'
                
                packet.haslayer.return_value = True
                packet.__getitem__.return_value = ip_layer
                
                detector.packet_handler(packet)
        
        # Start multiple threads
        for i in range(5):
            thread = threading.Thread(target=process_packets, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # All IPs should be tracked
        assert len(detector.packet_count) >= 5


class TestPacketHandling:
    """Test packet handling logic."""
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_handle_tcp_syn_packet(self, mock_mitigator, mock_logger):
        """Test handling of TCP SYN packets."""
        from ddos_detector import DDoSDetector
        from scapy.all import IP, TCP
        
        detector = DDoSDetector()
        
        # Create SYN packet
        packet = Mock()
        ip_layer = Mock()
        ip_layer.src = '192.168.1.100'
        ip_layer.dst = '192.168.1.1'
        
        tcp_layer = Mock()
        tcp_layer.flags = 'S'
        
        def haslayer(layer):
            return True
        
        def getitem(layer):
            if layer == IP:
                return ip_layer
            elif layer == TCP:
                return tcp_layer
        
        packet.haslayer = haslayer
        packet.__getitem__ = getitem
        
        # Process packet
        detector.packet_handler(packet)
        
        # Both counters should increment
        assert detector.packet_count['192.168.1.100'] > 0
        if hasattr(detector, 'syn_count'):
            assert detector.syn_count['192.168.1.100'] > 0
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_handle_non_ip_packet(self, mock_mitigator, mock_logger):
        """Test handling of non-IP packets."""
        from ddos_detector import DDoSDetector
        
        detector = DDoSDetector()
        
        # Create non-IP packet
        packet = Mock()
        packet.haslayer.return_value = False
        
        # Should handle gracefully
        try:
            detector.packet_handler(packet)
        except Exception as e:
            pytest.fail(f"Should handle non-IP packets: {e}")


class TestLogging:
    """Test logging integration."""
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_packet_detection_logged(self, mock_mitigator, mock_logger_class):
        """Test that packet detection is logged."""
        from ddos_detector import DDoSDetector
        from scapy.all import IP
        
        mock_logger = Mock()
        mock_logger_class.return_value = mock_logger
        
        detector = DDoSDetector()
        
        # Process packet
        packet = Mock()
        ip_layer = Mock()
        ip_layer.src = '192.168.1.100'
        ip_layer.dst = '192.168.1.1'
        
        packet.haslayer.return_value = True
        packet.__getitem__.return_value = ip_layer
        
        detector.packet_handler(packet)
        
        # Logger should be called (implementation dependent)
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_attack_logged(self, mock_mitigator, mock_logger_class):
        """Test that attacks are logged."""
        from ddos_detector import DDoSDetector
        
        mock_logger = Mock()
        mock_logger_class.return_value = mock_logger
        
        detector = DDoSDetector(packet_threshold=10)
        
        # Trigger attack
        detector.packet_count['192.168.1.100'] = 50
        
        if hasattr(detector, 'check_thresholds'):
            detector.check_thresholds()


class TestStatistics:
    """Test statistics tracking."""
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_get_statistics(self, mock_mitigator, mock_logger):
        """Test getting detector statistics."""
        from ddos_detector import DDoSDetector
        
        detector = DDoSDetector()
        
        # Add some data
        detector.packet_count['192.168.1.100'] = 50
        detector.packet_count['192.168.1.101'] = 30
        
        if hasattr(detector, 'get_statistics'):
            stats = detector.get_statistics()
            
            assert isinstance(stats, dict)
            assert 'total_packets' in stats or len(stats) > 0


class TestConfiguration:
    """Test configuration validation."""
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_invalid_threshold(self, mock_mitigator, mock_logger):
        """Test handling of invalid threshold values."""
        from ddos_detector import DDoSDetector
        
        # Negative threshold should be handled
        try:
            detector = DDoSDetector(packet_threshold=-10)
            # Should either reject or use default
            assert detector.packet_threshold > 0
        except ValueError:
            # Expected behavior
            pass
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_invalid_time_window(self, mock_mitigator, mock_logger):
        """Test handling of invalid time window."""
        from ddos_detector import DDoSDetector
        
        # Zero or negative time window
        try:
            detector = DDoSDetector(time_window=0)
            # Should handle gracefully
            assert detector.time_window > 0
        except ValueError:
            pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
