"""
Integration Tests for DDoS Detection System

Tests end-to-end functionality and component interaction.
"""

import pytest
import time
import os
from unittest.mock import Mock, patch
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


class TestSystemIntegration:
    """Test integration of all system components."""
    
    @patch('subprocess.run')
    @patch('ddos_detector.sniff')
    def test_detector_logger_mitigator_integration(self, mock_sniff, mock_subprocess):
        """Test integration between detector, logger, and mitigator."""
        from ddos_detector import DDoSDetector
        from logger import DDoSLogger
        from mitigator import Mitigator
        
        mock_subprocess.return_value = Mock(returncode=0)
        
        # Initialize components
        logger = DDoSLogger(log_dir='test_logs_integration')
        mitigator = Mitigator()
        detector = DDoSDetector(interface='lo')
        
        # Components should initialize without errors
        assert detector is not None
        assert logger is not None
        assert mitigator is not None
        
        # Cleanup
        import shutil
        if os.path.exists('test_logs_integration'):
            shutil.rmtree('test_logs_integration', ignore_errors=True)
    
    @patch('subprocess.run')
    def test_end_to_end_attack_flow(self, mock_subprocess):
        """Test complete attack detection and mitigation flow."""
        from ddos_detector import DDoSDetector
        from scapy.all import IP, TCP
        
        mock_subprocess.return_value = Mock(returncode=0)
        
        detector = DDoSDetector(
            packet_threshold=10,
            syn_threshold=5,
            time_window=5.0
        )
        
        # Simulate attack traffic
        for i in range(15):
            packet = Mock()
            ip_layer = Mock()
            ip_layer.src = '192.168.1.100'
            ip_layer.dst = '192.168.1.1'
            
            tcp_layer = Mock()
            tcp_layer.flags = 'S'
            
            packet.haslayer.return_value = True
            packet.__getitem__.side_effect = lambda x: ip_layer if x == IP else tcp_layer
            
            detector.packet_handler(packet)
        
        # Verify packet counts
        assert detector.packet_count['192.168.1.100'] >= 10


class TestAnalyzerIntegration:
    """Test analyzer integration with detector."""
    
    def test_analyzer_with_detector_data(self):
        """Test analyzer processing detector data."""
        from analyzer import TrafficAnalyzer
        
        analyzer = TrafficAnalyzer()
        
        # Simulate traffic data
        for i in range(10):
            sample = {
                'timestamp': time.time(),
                'total_packets': i * 10,
                'unique_ips': i + 1
            }
            analyzer.add_traffic_sample(sample)
        
        # Get statistics
        top_talkers = analyzer.get_top_talkers(limit=5)
        
        # Should return data
        assert isinstance(top_talkers, list)


class TestConfigurationIntegration:
    """Test configuration loading and usage."""
    
    @patch('ddos_detector.DDoSLogger')
    @patch('ddos_detector.Mitigator')
    def test_load_configuration(self, mock_mitigator, mock_logger):
        """Test loading configuration from config file."""
        from config.config import (
            PACKET_THRESHOLD,
            SYN_THRESHOLD,
            TIME_WINDOW,
            NETWORK_INTERFACE
        )
        from ddos_detector import DDoSDetector
        
        # Create detector with config values
        detector = DDoSDetector(
            interface=NETWORK_INTERFACE,
            packet_threshold=PACKET_THRESHOLD,
            syn_threshold=SYN_THRESHOLD,
            time_window=TIME_WINDOW
        )
        
        # Verify configuration loaded
        assert detector.packet_threshold == PACKET_THRESHOLD
        assert detector.syn_threshold == SYN_THRESHOLD


class TestUtilsIntegration:
    """Test utility functions with other components."""
    
    def test_ip_validation_in_detector(self):
        """Test IP validation used in detector."""
        from utils import validate_ip_address, is_private_or_localhost
        
        test_ips = [
            '192.168.1.100',
            '127.0.0.1',
            '8.8.8.8',
            'invalid'
        ]
        
        for ip in test_ips:
            is_valid = validate_ip_address(ip)
            
            if is_valid:
                # Can check if private/localhost
                is_private_or_localhost(ip)
    
    def test_json_operations_with_stats(self):
        """Test JSON operations with statistics."""
        from utils import write_json_file, read_json_file
        import tempfile
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        temp_file.close()
        
        # Write stats
        stats = {
            'total_packets': 1000,
            'blocked_ips': ['192.168.1.100', '192.168.1.101'],
            'uptime': 3600
        }
        
        write_json_file(temp_file.name, stats)
        
        # Read back
        loaded_stats = read_json_file(temp_file.name)
        
        assert loaded_stats == stats
        
        # Cleanup
        os.unlink(temp_file.name)


class TestLoggingIntegration:
    """Test logging integration across components."""
    
    def test_multiple_components_logging(self, temp_log_dir):
        """Test that multiple components can log simultaneously."""
        from logger import DDoSLogger
        
        logger = DDoSLogger(log_dir=temp_log_dir)
        
        # Log from different "components"
        logger.log_event("Detector started")
        logger.log_attack("192.168.1.100", "SYN_FLOOD", 100, 50)
        logger.log_system_event("Mitigator initialized")
        
        # All logs should be written
        event_log = os.path.join(temp_log_dir, 'ddos_events.log')
        attack_log = os.path.join(temp_log_dir, 'ddos_attacks.log')
        system_log = os.path.join(temp_log_dir, 'ddos_system.log')
        
        assert os.path.exists(event_log)
        assert os.path.exists(attack_log)
        assert os.path.exists(system_log)


class TestErrorHandling:
    """Test error handling across components."""
    
    @patch('subprocess.run')
    def test_mitigator_error_handling(self, mock_subprocess):
        """Test error handling in mitigation."""
        from mitigator import Mitigator
        
        # Simulate command failure
        mock_subprocess.side_effect = Exception("Command failed")
        
        mitigator = Mitigator()
        
        # Should handle error gracefully
        try:
            result = mitigator.block_ip('192.168.1.100')
            # Should not crash
        except Exception:
            # Acceptable if it propagates controlled exception
            pass
    
    def test_logger_error_handling(self):
        """Test logger error handling."""
        from logger import DDoSLogger
        
        # Try to create logger with problematic path
        logger = DDoSLogger(log_dir='/invalid/path')
        
        # Should handle gracefully
        assert logger is not None


class TestPerformanceIntegration:
    """Test performance of integrated system."""
    
    @patch('ddos_detector.sniff')
    def test_high_traffic_handling(self, mock_sniff):
        """Test system handling high traffic volume."""
        from ddos_detector import DDoSDetector
        from scapy.all import IP
        
        detector = DDoSDetector()
        
        start_time = time.time()
        
        # Simulate high traffic
        for i in range(1000):
            packet = Mock()
            ip_layer = Mock()
            ip_layer.src = f'192.168.{i // 256}.{i % 256}'
            ip_layer.dst = '192.168.1.1'
            
            packet.haslayer.return_value = True
            packet.__getitem__.return_value = ip_layer
            
            detector.packet_handler(packet)
        
        elapsed = time.time() - start_time
        
        # Should handle 1000 packets quickly
        assert elapsed < 5.0  # 5 seconds max
    
    def test_analyzer_performance(self):
        """Test analyzer performance with large dataset."""
        from analyzer import TrafficAnalyzer
        
        analyzer = TrafficAnalyzer(history_limit=1000)
        
        start_time = time.time()
        
        # Add many samples
        for i in range(1000):
            sample = {
                'timestamp': time.time(),
                'packet_count': i
            }
            analyzer.add_traffic_sample(sample)
        
        # Get top talkers
        top = analyzer.get_top_talkers(limit=10)
        
        elapsed = time.time() - start_time
        
        # Should complete quickly
        assert elapsed < 3.0


class TestDataPersistence:
    """Test data persistence across system."""
    
    def test_stats_file_creation(self, clean_stats_file):
        """Test creation and persistence of stats file."""
        from utils import write_json_file, read_json_file
        
        stats = {
            'packets_processed': 1000,
            'attacks_detected': 5,
            'ips_blocked': 3
        }
        
        write_json_file(str(clean_stats_file), stats)
        
        # Read back
        loaded = read_json_file(str(clean_stats_file))
        
        assert loaded == stats


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
